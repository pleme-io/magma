//! Non-panic Result-returning wrappers for the universal law
//! batteries. The substrate's `assert_*` helpers panic on
//! violation — perfect for `#[test]` code, wrong for production
//! preflight in pangea-operator startup or `magma flight-check`
//! CLI.
//!
//! `preflight::check_*` functions return `Result<(), PreflightError>`
//! so consumers can:
//!
//! * Log every violation found (rather than just the first)
//! * Refuse to start a reconcile cycle without panicking the
//!   operator process
//! * Surface typed errors to the K8s CR status / metrics labels
//!
//! Gated behind the `preflight` feature (which transitively
//! enables `architecture-laws` + `workspace-laws` + `chain-laws`).
//!
//! ```ignore
//! use magma_test_laws::preflight;
//! match preflight::check_workspace(&cfg) {
//!     Ok(()) => proceed_with_reconcile(),
//!     Err(violations) => mark_cr_blocked(violations),
//! }
//! ```

use std::panic::{catch_unwind, AssertUnwindSafe};

use serde::{Deserialize, Serialize};

/// One typed preflight violation. Carries the law's name + the
/// panic message the underlying `assert_*` helper produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightViolation {
    /// Stable identifier for the broken law (e.g. "architecture::no_dangling_references").
    pub law:     String,
    /// Human-readable message from the underlying assertion.
    pub message: String,
}

/// Result of a preflight check. `Ok(())` means every law passed;
/// `Err` carries every violation found in the pass (the underlying
/// `assert_*` helpers panic on the first violation, so each
/// `check_*` returns at most one).
pub type PreflightResult = Result<(), PreflightViolation>;

// ── Helpers ───────────────────────────────────────────────────────

fn run_assertion<F: FnOnce()>(law: &str, f: F) -> PreflightResult {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(()) => Ok(()),
        Err(panic) => {
            let message = if let Some(s) = panic.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "<unknown panic>".to_string()
            };
            Err(PreflightViolation { law: law.into(), message })
        }
    }
}

// ── Architecture preflight ────────────────────────────────────────

/// Run the full architecture composition law battery against a
/// rendered `magma_config::Config`. Returns `Ok(())` if every law
/// passes; `Err(violation)` on the first failure.
pub fn check_architecture(cfg: &magma_config::Config) -> PreflightResult {
    run_assertion("architecture::assert_all_laws", || {
        crate::architecture::assert_all_laws(cfg)
    })
}

// ── Workspace preflight ───────────────────────────────────────────

/// Run the full workspace lifecycle law battery against a
/// rendered `magma_config::Config`. Returns `Ok(())` if every law
/// passes.
pub fn check_workspace(cfg: &magma_config::Config) -> PreflightResult {
    run_assertion("workspace::assert_all_laws", || {
        crate::workspace::assert_all_laws(cfg)
    })
}

// ── Chain preflight ───────────────────────────────────────────────

/// Run the full chain law battery against a `magma_flow::FlowFile`.
pub fn check_chain(flow: &magma_flow::FlowFile) -> PreflightResult {
    run_assertion("chain::assert_all_laws", || {
        crate::chain::assert_all_laws(flow)
    })
}

// ── Composite ─────────────────────────────────────────────────────

/// Run architecture + workspace preflight against a Config. Returns
/// every violation found (up to one per layer). Empty Vec = all
/// laws passed. The operator's per-CR preflight should call this on
/// the rendered workspace; if non-empty, refuse to start the
/// reconcile cycle and surface the violations to CR status.
pub fn check_workspace_full(cfg: &magma_config::Config) -> Vec<PreflightViolation> {
    let mut violations = vec![];
    if let Err(v) = check_architecture(cfg) {
        violations.push(v);
    }
    if let Err(v) = check_workspace(cfg) {
        violations.push(v);
    }
    violations
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(v: serde_json::Value) -> magma_config::Config {
        magma_config::Config::from_json(v).expect("Config::from_json")
    }

    #[test]
    fn check_architecture_returns_ok_for_clean_workspace() {
        let c = cfg(json!({
            "terraform": { "required_providers": { "aws": { "source": "hashicorp/aws" } } },
            "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
        }));
        assert!(check_architecture(&c).is_ok());
    }

    #[test]
    fn check_architecture_returns_err_for_dangling_ref() {
        let c = cfg(json!({
            "terraform": { "required_providers": { "aws": { "source": "hashicorp/aws" } } },
            "resource": {
                "aws_subnet": {
                    "web": { "vpc_id": "${aws_vpc.main.id}" } // dangling
                }
            }
        }));
        let result = check_architecture(&c);
        assert!(result.is_err(), "expected violation for dangling ref");
        let v = result.unwrap_err();
        assert_eq!(v.law, "architecture::assert_all_laws");
        assert!(
            v.message.contains("dangling reference"),
            "expected dangling ref message, got: {}", v.message,
        );
    }

    #[test]
    fn check_workspace_returns_ok_for_minimal_workspace() {
        let c = cfg(json!({
            "terraform": { "required_providers": { "aws": { "source": "hashicorp/aws" } } },
            "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
        }));
        assert!(check_workspace(&c).is_ok());
    }

    #[test]
    fn check_workspace_full_returns_empty_for_clean_workspace() {
        let c = cfg(json!({
            "terraform": { "required_providers": { "aws": { "source": "hashicorp/aws" } } },
            "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
        }));
        let violations = check_workspace_full(&c);
        assert!(
            violations.is_empty(),
            "expected no violations, got: {violations:?}",
        );
    }

    #[test]
    fn check_workspace_full_aggregates_violations() {
        // Architecturally broken: dangling reference.
        let c = cfg(json!({
            "terraform": { "required_providers": { "aws": { "source": "hashicorp/aws" } } },
            "resource": {
                "aws_subnet": { "web": { "vpc_id": "${aws_vpc.main.id}" } }
            }
        }));
        let violations = check_workspace_full(&c);
        // architecture violates; workspace lifecycle still passes because
        // the dangling reference doesn't impede magma_plan (refs are
        // resolved at apply time, not plan time).
        assert!(!violations.is_empty());
        assert!(
            violations.iter().any(|v| v.message.contains("dangling reference")),
            "expected dangling-ref violation, got: {violations:?}",
        );
    }
}
