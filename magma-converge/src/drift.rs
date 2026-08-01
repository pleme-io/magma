//! Typed drift-correction policy — the canonical `DriftPolicy` enum
//! every reconciler that detects live-vs-declared divergence uses.
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III, P1.0.
//!
//! Subsumes the inline "what do we do when the cluster diverged from
//! the manifest?" decision currently scattered across lava-operator's
//! controllers and FluxCD's HelmRelease `driftDetection` field. Typed
//! so consumers can attest, override per-workspace, and reason about
//! drift behavior without parsing strings.
//!
//! # Variants
//!
//! - `Disabled`  — never check for drift; reconciler only acts on
//!   spec / source revision changes
//! - `Warn`      — detect drift, emit a typed event, but do NOT
//!   re-apply; operator-visible signal only
//! - `Enabled`   — detect drift, emit event, AND re-apply the
//!   manifest to correct the live state
//!
//! `Enabled` carries an `ignore_paths: Vec<String>` list — JSONPath-
//! shaped patterns that opt fields out of drift detection. Used for
//! controller-managed fields (replicas, status, last-applied
//! annotations) that the reconciler must not fight.
//!
//! # Default
//!
//! The default is `Warn` — never silently mutate the live cluster
//! without a typed declaration. Operators opt in to auto-correction
//! by declaring `Enabled` per-workspace or per-resource.

use serde::{Deserialize, Serialize};

/// What to do when the reconciler detects the live cluster has
/// diverged from the declared manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, gen_platform::Discriminant)]
#[discriminant(method = "mode", case = "lower")]
#[serde(tag = "mode")]
pub enum DriftPolicy {
    /// Don't check for drift at all. The reconciler reacts only to
    /// spec / source revision changes.
    Disabled,

    /// Detect drift and emit a typed event for operator visibility,
    /// but do NOT re-apply. Operator decides whether to manually fix
    /// or to escalate to `Enabled`.
    Warn,

    /// Detect drift, emit the event, AND re-apply the declared
    /// manifest to bring the cluster back to spec. `ignore_paths`
    /// lists JSONPath-shaped patterns opted out of drift detection
    /// (e.g. `/spec/replicas` for HPA-managed fields, `/status` for
    /// controller-written status, `/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration`).
    Enabled {
        #[serde(default)]
        ignore_paths: Vec<String>,
    },
}

impl Default for DriftPolicy {
    /// Default is `Warn` — never silently mutate the live cluster
    /// without typed operator opt-in. The safer default for any
    /// reconciler that might touch operator-managed state.
    fn default() -> Self {
        Self::Warn
    }
}

impl DriftPolicy {
    /// `true` when the reconciler should detect (but not necessarily
    /// correct) drift.
    pub fn detects(&self) -> bool {
        matches!(self, DriftPolicy::Warn | DriftPolicy::Enabled { .. })
    }

    /// `true` when the reconciler should re-apply the manifest to
    /// correct detected drift.
    pub fn corrects(&self) -> bool {
        matches!(self, DriftPolicy::Enabled { .. })
    }

    /// `true` when the given JSONPath should be ignored from drift
    /// detection. Always `true` for `Disabled` (nothing detected).
    /// For `Warn` (no ignore-list field), always `false`. For
    /// `Enabled`, checks the `ignore_paths` list for exact match.
    ///
    /// Future enhancement: glob-style prefix match. Today's exact-
    /// match is conservative and won't false-positively skip a real
    /// drift field.
    pub fn should_ignore_path(&self, path: &str) -> bool {
        match self {
            DriftPolicy::Disabled => true,
            DriftPolicy::Warn => false,
            DriftPolicy::Enabled { ignore_paths } => ignore_paths.iter().any(|p| p == path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_warn() {
        let p = DriftPolicy::default();
        assert_eq!(p.mode(), "warn");
        assert!(p.detects(), "Warn must detect");
        assert!(!p.corrects(), "Warn must NOT auto-correct");
    }

    #[test]
    fn disabled_does_not_detect() {
        let p = DriftPolicy::Disabled;
        assert!(!p.detects());
        assert!(!p.corrects());
    }

    #[test]
    fn enabled_detects_and_corrects() {
        let p = DriftPolicy::Enabled {
            ignore_paths: vec![],
        };
        assert!(p.detects());
        assert!(p.corrects());
    }

    #[test]
    fn warn_detects_but_not_corrects() {
        let p = DriftPolicy::Warn;
        assert!(p.detects());
        assert!(!p.corrects());
    }

    #[test]
    fn detect_corrects_are_a_lattice() {
        // corrects → detects (every policy that corrects must detect)
        for p in [
            DriftPolicy::Disabled,
            DriftPolicy::Warn,
            DriftPolicy::Enabled {
                ignore_paths: vec![],
            },
        ] {
            if p.corrects() {
                assert!(
                    p.detects(),
                    "{p:?} corrects but doesn't detect — invariant broken"
                );
            }
        }
    }

    #[test]
    fn disabled_ignores_every_path() {
        let p = DriftPolicy::Disabled;
        assert!(p.should_ignore_path("/spec/replicas"));
        assert!(p.should_ignore_path("/metadata/labels"));
        assert!(p.should_ignore_path("/anything"));
    }

    #[test]
    fn warn_ignores_no_path() {
        // Warn detects everything — there's no ignore-list at this
        // mode (operator hasn't opted in to corrections so there's
        // nothing to opt back out of).
        let p = DriftPolicy::Warn;
        assert!(!p.should_ignore_path("/spec/replicas"));
        assert!(!p.should_ignore_path("/status"));
    }

    #[test]
    fn enabled_respects_ignore_paths() {
        let p = DriftPolicy::Enabled {
            ignore_paths: vec!["/spec/replicas".into(), "/status".into()],
        };
        assert!(p.should_ignore_path("/spec/replicas"));
        assert!(p.should_ignore_path("/status"));
        assert!(!p.should_ignore_path("/spec/template"));
        assert!(!p.should_ignore_path("/metadata/labels"));
    }

    #[test]
    fn enabled_with_empty_ignore_corrects_everything() {
        let p = DriftPolicy::Enabled {
            ignore_paths: vec![],
        };
        assert!(p.corrects());
        assert!(!p.should_ignore_path("/spec/replicas"));
    }

    #[test]
    fn mode_is_stable_discriminant() {
        assert_eq!(DriftPolicy::Disabled.mode(), "disabled");
        assert_eq!(DriftPolicy::Warn.mode(), "warn");
        assert_eq!(
            DriftPolicy::Enabled {
                ignore_paths: vec![]
            }
            .mode(),
            "enabled"
        );
    }

    #[test]
    fn serde_round_trip_disabled() {
        let p = DriftPolicy::Disabled;
        let json = serde_json::to_string(&p).unwrap();
        let back: DriftPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn serde_round_trip_warn() {
        let p = DriftPolicy::Warn;
        let json = serde_json::to_string(&p).unwrap();
        let back: DriftPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn serde_round_trip_enabled_with_paths() {
        let p = DriftPolicy::Enabled {
            ignore_paths: vec![
                "/spec/replicas".into(),
                "/status".into(),
                "/metadata/annotations/last-applied".into(),
            ],
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: DriftPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
