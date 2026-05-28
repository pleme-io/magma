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

/// Innermost-wins per-field policy merge. Implementors define `merge`;
/// the blanket `resolve` walks a layer slice + hard default.
pub trait CascadePolicy: Sized + Clone {
    /// Merge `layer` over `self`, field by field. Fields present in
    /// `layer` (`Some(v)`) override `self`'s value; fields absent
    /// (`None`) preserve `self`.
    ///
    /// Implementors MUST satisfy:
    ///
    /// 1. **Idempotent.** `self.merge(layer); self.merge(layer)` yields
    ///    the same state as `self.merge(layer)` once. Required so
    ///    re-resolving the same layer set produces the same result.
    /// 2. **Per-field.** Each `Option` field in `layer` controls only
    ///    that field on `self`. Don't read other fields.
    /// 3. **No I/O.** Pure value transformation; no clock reads, no
    ///    randomness.
    fn merge(&mut self, layer: &Self);

    /// Cascade through layers in order (rightmost / innermost wins
    /// per field), starting from `default`. `None` slots in `layers`
    /// are skipped — useful when a layer is conditionally present.
    fn resolve(layers: &[Option<&Self>], default: Self) -> Self {
        let mut result = default;
        for layer in layers.iter().flatten() {
            result.merge(layer);
        }
        result
    }
}

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
    fn resolve_with_no_layers_returns_default() {
        let result = ReactivePolicy::resolve(&[], default_policy());
        assert_eq!(result, default_policy());
    }

    #[test]
    fn resolve_with_empty_layer_returns_default() {
        // An empty layer (all None) shouldn't change the default.
        let layer = ReactivePolicy::default();
        let result = ReactivePolicy::resolve(&[Some(&layer)], default_policy());
        assert_eq!(result, default_policy());
    }

    #[test]
    fn single_layer_overrides_per_field() {
        // Layer sets only failure_escalation — phase_timeout +
        // verified_blocked must keep default values.
        let layer = ReactivePolicy {
            failure_escalation: Some(fe(99, "Page")),
            ..Default::default()
        };
        let result = ReactivePolicy::resolve(&[Some(&layer)], default_policy());

        assert_eq!(result.failure_escalation, Some(fe(99, "Page")));
        // Other fields unchanged.
        assert_eq!(result.phase_timeout, default_policy().phase_timeout);
        assert_eq!(result.verified_blocked, default_policy().verified_blocked);
    }

    #[test]
    fn innermost_wins_per_field() {
        // Three layers — outermost (gem) sets one field, middle sets
        // another, innermost sets yet another. Result has each field
        // from its respective layer.
        let outer = ReactivePolicy {
            failure_escalation: Some(fe(10, "Alert")),
            ..Default::default()
        };
        let middle = ReactivePolicy {
            phase_timeout: Some(pt("1m", "2m", "3m", "Suspend")),
            ..Default::default()
        };
        let inner = ReactivePolicy {
            verified_blocked: Some(vb("1m", "Page")),
            ..Default::default()
        };

        let result = ReactivePolicy::resolve(
            &[Some(&outer), Some(&middle), Some(&inner)],
            ReactivePolicy::default(),
        );

        assert_eq!(result.failure_escalation, Some(fe(10, "Alert")));
        assert_eq!(result.phase_timeout, Some(pt("1m", "2m", "3m", "Suspend")));
        assert_eq!(result.verified_blocked, Some(vb("1m", "Page")));
    }

    #[test]
    fn innermost_field_overrides_outer_field() {
        // Two layers set the SAME field — innermost wins.
        let outer = ReactivePolicy {
            failure_escalation: Some(fe(10, "Alert")),
            ..Default::default()
        };
        let inner = ReactivePolicy {
            failure_escalation: Some(fe(50, "Page")),
            ..Default::default()
        };

        let result = ReactivePolicy::resolve(
            &[Some(&outer), Some(&inner)],
            ReactivePolicy::default(),
        );

        assert_eq!(
            result.failure_escalation,
            Some(fe(50, "Page")),
            "innermost layer wins for the same field"
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
    fn merge_is_idempotent() {
        // self.merge(layer); self.merge(layer) == self.merge(layer)
        let mut once = default_policy();
        let mut twice = default_policy();
        let layer = ReactivePolicy {
            failure_escalation: Some(fe(99, "Page")),
            ..Default::default()
        };

        once.merge(&layer);
        twice.merge(&layer);
        twice.merge(&layer);

        assert_eq!(
            once, twice,
            "merge must be idempotent — re-applying the same layer is a no-op"
        );
    }

    #[test]
    fn merge_per_field() {
        // Merging a layer with one field set should only touch that
        // field — other fields unchanged.
        let mut policy = default_policy();
        let original_phase = policy.phase_timeout.clone();
        let original_blocked = policy.verified_blocked.clone();

        let layer = ReactivePolicy {
            failure_escalation: Some(fe(42, "Suspend")),
            ..Default::default()
        };
        policy.merge(&layer);

        assert_eq!(policy.failure_escalation, Some(fe(42, "Suspend")));
        assert_eq!(policy.phase_timeout, original_phase, "phase_timeout untouched");
        assert_eq!(policy.verified_blocked, original_blocked, "verified_blocked untouched");
    }

    #[test]
    fn resolve_associativity_when_same_field() {
        // When all layers touch the same field, resolve is independent
        // of how the operation is grouped (the cascade is left-fold
        // associative across the layer slice).
        let outer = ReactivePolicy {
            failure_escalation: Some(fe(1, "A")),
            ..Default::default()
        };
        let middle = ReactivePolicy {
            failure_escalation: Some(fe(2, "B")),
            ..Default::default()
        };
        let inner = ReactivePolicy {
            failure_escalation: Some(fe(3, "C")),
            ..Default::default()
        };

        let result = ReactivePolicy::resolve(
            &[Some(&outer), Some(&middle), Some(&inner)],
            ReactivePolicy::default(),
        );

        assert_eq!(
            result.failure_escalation,
            Some(fe(3, "C")),
            "innermost (rightmost) wins"
        );
    }

    #[test]
    fn determinism_law() {
        // Same input layers → same output, every time.
        let layers = vec![
            ReactivePolicy {
                failure_escalation: Some(fe(1, "A")),
                ..Default::default()
            },
            ReactivePolicy {
                phase_timeout: Some(pt("1m", "2m", "3m", "Page")),
                ..Default::default()
            },
        ];
        let refs: Vec<Option<&ReactivePolicy>> = layers.iter().map(Some).collect();

        let a = ReactivePolicy::resolve(&refs, default_policy());
        let b = ReactivePolicy::resolve(&refs, default_policy());

        assert_eq!(a, b, "resolve must be deterministic for the same layer set");
    }

    #[test]
    fn roundtrip_serde() {
        let policy = default_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let back: ReactivePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}
