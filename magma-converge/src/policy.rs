//! Typed policy cascade — the canonical `CascadePolicy` trait every
//! fleet-wide multi-layer-override system consumes.
//! Spec: `theory/CONVERGENCE-ADOPTION.md` §II.2, Phase 0.4.
//!
//! Subsumes the hand-rolled "innermost-wins per-field merge" shapes
//! that previously lived in:
//!
//! - `pangea-operator::reactive::EffectiveReactivePolicy::resolve` —
//!   three-level cascade (gem → workspace → template) on
//!   `ReactivePolicy { failure_escalation, phase_timeout, verified_blocked }`
//! - `lava-operator::policy::resolve_policy` — mirrors the pattern
//!   on `LavaPolicy`
//! - Future: `tend::reaction::ReactionPolicy::resolve` (SAFE-CONVERGENCE M3)
//!
//! # The cascade rule
//!
//! Layers iterate in declared order; each non-`None` field in a layer
//! overrides the accumulator. Hard defaults fill any field no layer
//! set. The result is the merged value with **innermost-wins per
//! field**.
//!
//! Concretely, given policy layers `[A, B, C]` and a hard default `D`:
//!
//!   start: result = D
//!   for layer in [A, B, C]:
//!     for each field F: if layer.F is Some(v), result.F = v
//!   return result
//!
//! C's fields override B's override A's override D's. Composition is
//! associative + idempotent (when layers carry the same Option shape):
//! `resolve([A, A]) == resolve([A])`.
//!
//! # The trait
//!
//! ```ignore
//! pub trait CascadePolicy: Sized + Clone {
//!     fn merge(&mut self, layer: &Self);
//! }
//! ```
//!
//! Implementors write `merge` once — typically a `if let Some(v) = &layer.field { self.field = Some(v.clone()); }` line per `Option<F>` field. The blanket `resolve` method iterates layers and returns the typed merged value.
//!
//! A derive macro (`#[derive(CascadePolicy)]`) auto-generates `merge`
//! from struct fields with `Option<F>` types — coming in 0.4b. For
//! now consumers impl `merge` manually; the trait + tests are the
//! immediate compounding value.

use serde::{Deserialize, Serialize};

// The `CascadePolicy` trait was RE-HOMED to lightweight
// `shigoto-types::policy` (2026-06-02, theory/CONVERGENCE-ADOPTION.md): it
// is a pure, general per-field merge primitive with no IaC coupling, and
// keeping it here forced lightweight controllers (pangea/lava) to take
// magma's whole executor closure to adopt it. Re-exported for back-compat;
// the pangea-shaped `ReactivePolicy` reference impl below stays as the
// magma-side example + law-test vehicle.
pub use shigoto_types::policy::CascadePolicy;

// ── Reference impl: ReactivePolicy (mirrors pangea-operator) ──────
//
// The canonical first impl. Three fields, each `Option<...>`. The
// merge logic is mechanical — every Option field gets its own
// `if let Some(...)` branch. Future derive macro will generate this.

/// Reference policy mirroring pangea-operator's `EffectiveReactivePolicy`
/// shape. Three optional fields the cascade controls. This impl is the
/// canonical first consumer of `CascadePolicy`; consumer crates
/// (pangea-operator, lava-operator) mirror the shape for their domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactivePolicy {
    pub failure_escalation: Option<FailureEscalation>,
    pub phase_timeout: Option<PhaseTimeoutPolicy>,
    pub verified_blocked: Option<VerifiedBlockedPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureEscalation {
    pub max_consecutive_failures: u32,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTimeoutPolicy {
    pub compiling: String,
    pub planning: String,
    pub applying: String,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBlockedPolicy {
    pub timeout: String,
    pub action: String,
}

impl CascadePolicy for ReactivePolicy {
    fn merge(&mut self, layer: &Self) {
        if let Some(v) = &layer.failure_escalation {
            self.failure_escalation = Some(v.clone());
        }
        if let Some(v) = &layer.phase_timeout {
            self.phase_timeout = Some(v.clone());
        }
        if let Some(v) = &layer.verified_blocked {
            self.verified_blocked = Some(v.clone());
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(n: u32, action: &str) -> FailureEscalation {
        FailureEscalation {
            max_consecutive_failures: n,
            action: action.into(),
        }
    }

    fn pt(c: &str, p: &str, a: &str, action: &str) -> PhaseTimeoutPolicy {
        PhaseTimeoutPolicy {
            compiling: c.into(),
            planning: p.into(),
            applying: a.into(),
            action: action.into(),
        }
    }

    fn vb(t: &str, action: &str) -> VerifiedBlockedPolicy {
        VerifiedBlockedPolicy {
            timeout: t.into(),
            action: action.into(),
        }
    }

    fn default_policy() -> ReactivePolicy {
        ReactivePolicy {
            failure_escalation: Some(fe(5, "Alert")),
            phase_timeout: Some(pt("5m", "10m", "30m", "Alert")),
            verified_blocked: Some(vb("10m", "Alert")),
        }
    }

    #[test]
    fn reactive_policy_obeys_the_cascade_law_harness() {
        // The cascade laws (resolve-identity, empty-layer, idempotence,
        // merge-self-identity, innermost-wins fold-order, determinism)
        // are proven generically by the canonical harness in
        // shigoto-types::testing — they live with the trait, not
        // re-spelled per domain impl. Samples exercise each field plus an
        // overlapping field so the per-field + innermost-wins laws
        // actually witness on this 3-field reference policy.
        shigoto_types::testing::assert_cascade_laws_with_default(
            default_policy(),
            &[
                ReactivePolicy {
                    failure_escalation: Some(fe(10, "Alert")),
                    ..Default::default()
                },
                ReactivePolicy {
                    phase_timeout: Some(pt("1m", "2m", "3m", "Suspend")),
                    ..Default::default()
                },
                ReactivePolicy {
                    verified_blocked: Some(vb("1m", "Page")),
                    ..Default::default()
                },
                ReactivePolicy {
                    failure_escalation: Some(fe(99, "Page")),
                    ..Default::default()
                },
            ],
        );
    }

    #[test]
    fn none_layer_is_skipped() {
        // A None layer slot is skipped — useful when a layer is
        // conditionally present (e.g. workspace policy absent).
        let inner = ReactivePolicy {
            failure_escalation: Some(fe(5, "Page")),
            ..Default::default()
        };

        let result =
            ReactivePolicy::resolve(&[None, Some(&inner), None], ReactivePolicy::default());

        assert_eq!(result.failure_escalation, Some(fe(5, "Page")));
    }

    #[test]
    fn roundtrip_serde() {
        let policy = default_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let back: ReactivePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}
