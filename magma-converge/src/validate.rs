//! `Validate` — operator-supplied-value validation trait.
//!
//! Spec: `theory/PATTERN-EXTRACTION.md` Pattern 7 (Validate).
//!
//! Multiple primitives in `magma-converge` ship typed predicates
//! over their fields:
//!
//!   - `LabelSelector::has_invalid_requirements()` — Exists /
//!     DoesNotExist carrying non-empty `values`
//!   - `LabelSelectorRequirement::has_invalid_values()` — same per
//!     requirement
//!   - (planned) `OpenSourceRepoConfig::unsafe_delete` requires
//!     `archived: true`
//!   - (planned) `ArtifactDigest::new` — length + lowercase-hex
//!
//! Each repeats the same "predicate over typed fields" shape.
//! `Validate` codifies that shape: every primitive that wants to
//! expose operator-facing validity checks impls `Validate`, returns
//! a typed `Vec<Violation>`, and downstream tooling (operator CLIs,
//! K8s admission webhooks, magma plan validation) iterates the
//! violations mechanically.
//!
//! # Why a Vec, not Result
//!
//! Returning `Result<(), Error>` reports the FIRST violation and
//! drops the rest. Operator-facing validation wants ALL violations
//! surfaced at once so the operator fixes them in one pass. `Vec`
//! preserves that.
//!
//! # The trait law
//!
//! For any `Validate` impl:
//!
//!   - **Determinism:** `v.validate() == v.validate()` (pure;
//!     no I/O, no time, no shared state)
//!   - **Empty-vec means valid:** `validate().is_empty()` ⇔
//!     "all invariants hold"
//!   - **Each Violation names its field:** the `path` field
//!     carries the typed path (dot-separated) to the offending
//!     field, so operators can navigate directly
//!
//! # When to impl Validate vs. parse-don't-validate
//!
//! Validate is for fields that **operator-supplied YAML / JSON**
//! can produce but a typed Rust constructor cannot (since the
//! struct is reachable from `serde::Deserialize` directly). For
//! invariants enforceable at construction, use a typed builder or
//! a `from_*` constructor that returns `Result<Self, Error>`.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// Operator-facing validation contract. Implementations report
/// every violation in a single pass via `validate() -> Vec<Violation>`.
pub trait Validate {
    /// Run every validity check. Returns an empty vec on success.
    fn validate(&self) -> Vec<Violation>;

    /// Convenience: `true` when `validate()` returns no violations.
    fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/// A typed validation failure. Identifies the offending field
/// path + carries an operator-facing message + a stable
/// `kind` discriminant for metrics labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Dot-separated path to the offending field, e.g.
    /// `"matchExpressions[0].values"`.
    pub path: String,
    /// Stable, lowercase, snake_case identifier for the violation
    /// kind. Used as a metrics label / audit-log tag. Example:
    /// `"non_empty_values_for_exists_op"`.
    pub kind: String,
    /// Operator-facing message describing the violation and how
    /// to fix it.
    pub message: String,
}

impl Violation {
    /// Construct a new violation. The most common shape.
    pub fn new(
        path: impl Into<String>,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            kind: kind.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysValid;
    impl Validate for AlwaysValid {
        fn validate(&self) -> Vec<Violation> {
            Vec::new()
        }
    }

    struct AlwaysInvalid;
    impl Validate for AlwaysInvalid {
        fn validate(&self) -> Vec<Violation> {
            vec![Violation::new("self", "always_invalid", "by design")]
        }
    }

    #[test]
    fn always_valid_is_valid() {
        assert!(AlwaysValid.is_valid());
        assert!(AlwaysValid.validate().is_empty());
    }

    #[test]
    fn always_invalid_is_not_valid() {
        assert!(!AlwaysInvalid.is_valid());
        let vs = AlwaysInvalid.validate();
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].kind, "always_invalid");
    }

    #[test]
    fn violation_construction() {
        let v = Violation::new("a.b.c", "bad_value", "must be > 0");
        assert_eq!(v.path, "a.b.c");
        assert_eq!(v.kind, "bad_value");
        assert!(v.message.contains("> 0"));
    }

    #[test]
    fn violation_round_trips_through_json() {
        let v = Violation::new("a", "bad", "msg");
        let json: String = serde_json::to_string(&v).unwrap();
        let back: Violation = serde_json::from_str(json.as_str()).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn determinism_law() {
        // Pure trait: same impl returns the same vec every call.
        struct Pure(u32);
        impl Validate for Pure {
            fn validate(&self) -> Vec<Violation> {
                if self.0 > 100 {
                    vec![Violation::new("0", "too_big", format!("got {}", self.0))]
                } else {
                    Vec::new()
                }
            }
        }
        let p1 = Pure(50);
        assert_eq!(p1.validate(), p1.validate());
        let p2 = Pure(150);
        assert_eq!(p2.validate(), p2.validate());
    }
}
