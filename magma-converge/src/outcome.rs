//! Typed outcome lattice — the canonical `Outcome` trait that
//! unifies every typed outcome enum (`ReadyState`, `ApplyStatus`,
//! `ConditionStatus`, and future outcomes like `SettlingOutcome`,
//! `CostOutcome`, `LatencyOutcome`) under **one lattice algebra**.
//!
//! Spec: `theory/LATTICE-OF-OUTCOMES.md` §X.3.
//!
//! # The lattice
//!
//! Every outcome enum in the substrate is a **totally-ordered chain
//! by severity** (higher numeric severity = "worse"). The trait gives
//! consumers four operations:
//!
//! - `severity(&self) -> u32` — numeric severity for ordering
//! - `baseline() -> Self`     — the best-case outcome (severity = 0)
//! - `worst(a, b)`            — operator-facing "worst-case combination"
//! - `best(a, b)`             — operator-facing "best-case combination"
//!
//! And two mathematical aliases for tatara-lattice / convention
//! consistency:
//!
//! - `meet(a, b)`  — greatest-lower-bound = best (lower severity)
//! - `join(a, b)`  — least-upper-bound    = worst (higher severity)
//!
//! Plus two reducer helpers for the canonical aggregator pattern:
//!
//! - `worst_of(iter)` — fold an iterator of outcomes to their worst
//!   case, with `baseline()` as the identity element
//! - `best_of(iter)`  — fold to the best case; returns `Option<O>`
//!   (no identity element on the "best" side without a bounded upper)
//!
//! # The laws
//!
//! Every `Outcome` impl MUST satisfy the lattice laws (verified by
//! the test suite for the canonical impls):
//!
//! 1. **Idempotent**: `worst(a, a) == a`, `best(a, a) == a`
//! 2. **Commutative**: `worst(a, b) == worst(b, a)`
//! 3. **Associative**: `worst(worst(a, b), c) == worst(a, worst(b, c))`
//! 4. **Baseline is `worst`'s identity**: `worst(a, baseline) == a`
//! 5. **Determinism**: `worst(a, b) == worst(a, b)` for the same inputs
//!
//! # Composition
//!
//! With this trait, every aggregator in the substrate
//! (`HealthReport::overall()`, `ApplyReport::overall_status()`,
//! `ConditionSet::overall_ready()`, future `SettlingTracker::status()`,
//! future Viggy `PromessaOutcome::aggregate()`) becomes one shape:
//!
//! ```ignore
//! let overall = outcome::worst_of(report.outcomes.iter().cloned());
//! ```
//!
//! The hand-rolled per-aggregator severity comparison in each module
//! becomes one line consuming the trait. Future outcome additions
//! (cost, latency, security, KPI per Viggy) impl Outcome once and
//! get the entire aggregator stack for free.

use crate::condition::ConditionStatus;
use crate::health::ReadyState;
use crate::apply::ApplyStatus;

/// The canonical typed-outcome lattice trait. Every outcome enum in
/// the substrate impls this so they share one algebra.
///
/// # Severity convention
///
/// `severity()` returns a `u32` where **higher = worse**. The
/// baseline (best-case outcome) has severity 0. Operators reason in
/// terms of `worst`/`best`; the `meet`/`join` aliases follow math
/// convention (meet = greatest-lower-bound = best; join =
/// least-upper-bound = worst).
pub trait OutcomeLattice: Clone + PartialEq {
    /// Numeric severity. Higher = worse. The baseline outcome has
    /// severity 0.
    fn severity(&self) -> u32;

    /// The best-case outcome — `worst`'s identity element and the
    /// initial accumulator for `worst_of`.
    fn baseline() -> Self;

    /// **Worst-case combination of two outcomes.** Returns the
    /// higher-severity input (ties: self wins for determinism).
    /// Operator-facing canonical aggregator op.
    fn worst(&self, other: &Self) -> Self {
        if self.severity() >= other.severity() {
            self.clone()
        } else {
            other.clone()
        }
    }

    /// **Best-case combination.** Returns the lower-severity input
    /// (ties: self wins).
    fn best(&self, other: &Self) -> Self {
        if self.severity() <= other.severity() {
            self.clone()
        } else {
            other.clone()
        }
    }

    /// Mathematical alias for [`Self::best`] — greatest-lower-bound
    /// in the severity-ordered lattice. Matches tatara-lattice's
    /// `Lattice::meet` semantics.
    fn meet(&self, other: &Self) -> Self {
        self.best(other)
    }

    /// Mathematical alias for [`Self::worst`] — least-upper-bound
    /// in the severity-ordered lattice. Matches tatara-lattice's
    /// `Lattice::join` semantics.
    fn join(&self, other: &Self) -> Self {
        self.worst(other)
    }

    /// `true` when this outcome is the baseline (severity 0; best
    /// possible).
    fn is_baseline(&self) -> bool {
        self.severity() == 0
    }
}

/// Fold an iterator of outcomes to their worst case. Uses
/// `Outcome::baseline()` as the identity element, so an empty
/// iterator returns the baseline (best-case) outcome.
///
/// This is the canonical aggregator-fold shape. Every
/// `*Report::overall_*()` method in the substrate is one call to
/// this helper.
pub fn worst_of<O: OutcomeLattice>(iter: impl IntoIterator<Item = O>) -> O {
    iter.into_iter()
        .fold(O::baseline(), |acc, o| acc.worst(&o))
}

/// Fold an iterator of outcomes to their best case. Returns `None`
/// for an empty iterator — there is no "best of nothing"; consumers
/// decide what to do with the empty case (typically: return baseline
/// or skip).
pub fn best_of<O: OutcomeLattice>(iter: impl IntoIterator<Item = O>) -> Option<O> {
    iter.into_iter().reduce(|acc, o| acc.best(&o))
}

// ── Outcome impls for the typed substrate's existing outcome enums ──

// ReadyState's OutcomeLattice impl is auto-generated via
// gen_platform::OutcomeLattice — see crate::health.

// ApplyStatus's OutcomeLattice impl is auto-generated via
// gen_platform::OutcomeLattice — see crate::apply.
//
// `Empty` and `AllSucceeded` share severity 0 — both represent
// "nothing to escalate" states. `Conflict > Failed` because conflict
// requires operator action (takeover/scope-narrowing), never a
// simple retry. Tie-break for severity-0 falls to canonical
// declaration order (Empty wins per the OutcomeLattice tie-break
// rule "self wins for determinism").
///
// ConditionStatus's OutcomeLattice impl is auto-generated via
// gen_platform::OutcomeLattice — see crate::condition.

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> ReadyState {
        ReadyState::InProgress {
            reason: s.to_string(),
        }
    }
    fn fl(s: &str) -> ReadyState {
        ReadyState::Failed {
            reason: s.to_string(),
        }
    }

    // ── Severity assignments per impl ──────────────────────────────

    #[test]
    fn ready_state_severity_ordering() {
        assert!(ReadyState::Ready.severity() < ReadyState::Unknown.severity());
        assert!(ReadyState::Unknown.severity() < ip("x").severity());
        assert!(ip("x").severity() < fl("x").severity());
    }

    #[test]
    fn apply_status_severity_ordering() {
        assert!(ApplyStatus::AllSucceeded.severity() < ApplyStatus::SucceededWithSkipped.severity());
        assert!(ApplyStatus::SucceededWithSkipped.severity() < ApplyStatus::Failed.severity());
        assert!(ApplyStatus::Failed.severity() < ApplyStatus::Conflict.severity());
        // Empty and AllSucceeded both severity 0 — both are "no escalation".
        assert_eq!(ApplyStatus::Empty.severity(), ApplyStatus::AllSucceeded.severity());
    }

    #[test]
    fn condition_status_severity_ordering() {
        assert!(ConditionStatus::True.severity() < ConditionStatus::Unknown.severity());
        assert!(ConditionStatus::Unknown.severity() < ConditionStatus::False.severity());
    }

    // ── Baselines ──────────────────────────────────────────────────

    #[test]
    fn baselines_are_severity_zero() {
        assert_eq!(<ReadyState as OutcomeLattice>::baseline().severity(), 0);
        assert_eq!(<ApplyStatus as OutcomeLattice>::baseline().severity(), 0);
        assert_eq!(<ConditionStatus as OutcomeLattice>::baseline().severity(), 0);
    }

    #[test]
    fn baselines_identify_best_state() {
        assert!(matches!(<ReadyState as OutcomeLattice>::baseline(), ReadyState::Ready));
        assert!(matches!(<ApplyStatus as OutcomeLattice>::baseline(), ApplyStatus::Empty));
        assert!(matches!(<ConditionStatus as OutcomeLattice>::baseline(), ConditionStatus::True));
    }

    #[test]
    fn is_baseline_classifies_correctly() {
        assert!(<ReadyState as OutcomeLattice>::is_baseline(&ReadyState::Ready));
        assert!(!<ReadyState as OutcomeLattice>::is_baseline(&fl("x")));

        assert!(<ApplyStatus as OutcomeLattice>::is_baseline(&ApplyStatus::Empty));
        // AllSucceeded also has severity 0 → is_baseline returns true.
        assert!(<ApplyStatus as OutcomeLattice>::is_baseline(&ApplyStatus::AllSucceeded));
        assert!(!<ApplyStatus as OutcomeLattice>::is_baseline(&ApplyStatus::Failed));

        assert!(<ConditionStatus as OutcomeLattice>::is_baseline(&ConditionStatus::True));
        assert!(!<ConditionStatus as OutcomeLattice>::is_baseline(&ConditionStatus::False));
    }

    // ── worst / best — operator-facing semantics ───────────────────

    #[test]
    fn worst_returns_higher_severity() {
        let r = ReadyState::Ready;
        let f = fl("broken");
        assert!(matches!(r.worst(&f), ReadyState::Failed { .. }));
        assert!(matches!(f.worst(&r), ReadyState::Failed { .. }));
    }

    #[test]
    fn best_returns_lower_severity() {
        let r = ReadyState::Ready;
        let f = fl("broken");
        assert!(matches!(r.best(&f), ReadyState::Ready));
        assert!(matches!(f.best(&r), ReadyState::Ready));
    }

    #[test]
    fn worst_ties_prefer_self_for_determinism() {
        let f1 = fl("first reason");
        let f2 = fl("second reason");
        // Same severity (both Failed) — self (LHS) wins.
        match f1.worst(&f2) {
            ReadyState::Failed { reason } => assert_eq!(reason, "first reason"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn best_ties_prefer_self() {
        let f1 = fl("first reason");
        let f2 = fl("second reason");
        match f1.best(&f2) {
            ReadyState::Failed { reason } => assert_eq!(reason, "first reason"),
            other => panic!("expected Failed (LHS), got {other:?}"),
        }
    }

    // ── meet / join — math-convention aliases ──────────────────────

    #[test]
    fn meet_alias_matches_best() {
        let r = ReadyState::Ready;
        let f = fl("x");
        assert_eq!(r.meet(&f), r.best(&f));
    }

    #[test]
    fn join_alias_matches_worst() {
        let r = ReadyState::Ready;
        let f = fl("x");
        assert_eq!(r.join(&f), r.worst(&f));
    }

    // ── Lattice laws — verified for ReadyState as the canonical case

    fn ready_states() -> Vec<ReadyState> {
        vec![
            ReadyState::Ready,
            ReadyState::Unknown,
            ip("p1"),
            ip("p2"),
            fl("f1"),
            fl("f2"),
        ]
    }

    #[test]
    fn law_idempotent_worst() {
        for r in ready_states() {
            assert_eq!(r.worst(&r), r, "worst not idempotent on {r:?}");
        }
    }

    #[test]
    fn law_idempotent_best() {
        for r in ready_states() {
            assert_eq!(r.best(&r), r, "best not idempotent on {r:?}");
        }
    }

    #[test]
    fn law_commutative_worst() {
        // worst(a, b) and worst(b, a) have same severity. Reasons
        // differ on ties (self wins), but the lattice element is
        // equivalent.
        for a in ready_states() {
            for b in ready_states() {
                assert_eq!(
                    a.worst(&b).severity(),
                    b.worst(&a).severity(),
                    "worst not commutative (severity) for ({a:?}, {b:?})"
                );
            }
        }
    }

    #[test]
    fn law_commutative_best() {
        for a in ready_states() {
            for b in ready_states() {
                assert_eq!(
                    a.best(&b).severity(),
                    b.best(&a).severity(),
                    "best not commutative (severity) for ({a:?}, {b:?})"
                );
            }
        }
    }

    #[test]
    fn law_associative_worst() {
        for a in ready_states() {
            for b in ready_states() {
                for c in ready_states() {
                    let left = a.worst(&b).worst(&c);
                    let right = a.worst(&b.worst(&c));
                    assert_eq!(
                        left.severity(),
                        right.severity(),
                        "worst not associative (severity) for ({a:?}, {b:?}, {c:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn law_associative_best() {
        for a in ready_states() {
            for b in ready_states() {
                for c in ready_states() {
                    let left = a.best(&b).best(&c);
                    let right = a.best(&b.best(&c));
                    assert_eq!(
                        left.severity(),
                        right.severity(),
                        "best not associative (severity) for ({a:?}, {b:?}, {c:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn law_baseline_is_worst_identity() {
        // baseline is the lowest severity; worst(a, baseline) should
        // always return a (since a's severity >= baseline's).
        let baseline = <ReadyState as OutcomeLattice>::baseline();
        for a in ready_states() {
            assert_eq!(
                a.worst(&baseline),
                a,
                "baseline not identity for worst on {a:?}"
            );
        }
    }

    #[test]
    fn law_baseline_absorbs_in_best() {
        // best(a, baseline) always returns baseline (since baseline
        // has the lowest severity).
        let baseline = <ReadyState as OutcomeLattice>::baseline();
        for a in ready_states() {
            assert_eq!(
                a.best(&baseline),
                baseline,
                "baseline doesn't absorb in best for {a:?}"
            );
        }
    }

    // ── Reducer helpers ────────────────────────────────────────────

    #[test]
    fn worst_of_empty_returns_baseline() {
        let r: ReadyState = worst_of(std::iter::empty::<ReadyState>());
        assert!(matches!(r, ReadyState::Ready));
    }

    #[test]
    fn worst_of_singleton_returns_element() {
        let r: ReadyState = worst_of(vec![fl("x")]);
        assert!(matches!(r, ReadyState::Failed { .. }));
    }

    #[test]
    fn worst_of_many_returns_worst() {
        let r: ReadyState = worst_of(vec![
            ReadyState::Ready,
            ip("rolling"),
            ReadyState::Unknown,
            ReadyState::Ready,
        ]);
        // Worst is InProgress.
        assert!(matches!(r, ReadyState::InProgress { .. }));
    }

    #[test]
    fn worst_of_finds_global_worst() {
        let r: ReadyState = worst_of(vec![
            ReadyState::Ready,
            ip("p"),
            fl("hard failure"),
            ip("p2"),
        ]);
        match r {
            ReadyState::Failed { reason } => assert_eq!(reason, "hard failure"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn best_of_empty_returns_none() {
        let r: Option<ReadyState> = best_of(std::iter::empty::<ReadyState>());
        assert!(r.is_none());
    }

    #[test]
    fn best_of_singleton_returns_element() {
        let r = best_of(vec![fl("x")]).unwrap();
        assert!(matches!(r, ReadyState::Failed { .. }));
    }

    #[test]
    fn best_of_many_returns_best() {
        let r = best_of(vec![
            fl("x"),
            ip("rolling"),
            ReadyState::Ready,
            ReadyState::Unknown,
        ])
        .unwrap();
        // Best is Ready.
        assert!(matches!(r, ReadyState::Ready));
    }

    // ── Cross-impl coverage: every Outcome impl obeys the laws ─────

    #[test]
    fn apply_status_baseline_is_worst_identity() {
        let baseline = <ApplyStatus as OutcomeLattice>::baseline();
        for a in [
            ApplyStatus::Empty,
            ApplyStatus::AllSucceeded,
            ApplyStatus::SucceededWithSkipped,
            ApplyStatus::Failed,
            ApplyStatus::Conflict,
        ] {
            assert_eq!(
                a.worst(&baseline).severity(),
                a.severity(),
                "ApplyStatus baseline not worst-identity for {a:?}"
            );
        }
    }

    #[test]
    fn apply_status_worst_of_finds_conflict() {
        // Conflict takes precedence over Failed.
        let r = worst_of(vec![
            ApplyStatus::AllSucceeded,
            ApplyStatus::Failed,
            ApplyStatus::Conflict,
        ]);
        assert_eq!(r, ApplyStatus::Conflict);
    }

    #[test]
    fn apply_status_best_of_finds_all_succeeded() {
        let r = best_of(vec![
            ApplyStatus::Failed,
            ApplyStatus::AllSucceeded,
            ApplyStatus::Conflict,
        ])
        .unwrap();
        // AllSucceeded has severity 0 (tied with Empty as baseline).
        assert!(matches!(r, ApplyStatus::AllSucceeded));
    }

    #[test]
    fn condition_status_worst_of_finds_false() {
        let r = worst_of(vec![
            ConditionStatus::True,
            ConditionStatus::Unknown,
            ConditionStatus::False,
        ]);
        assert_eq!(r, ConditionStatus::False);
    }

    #[test]
    fn condition_status_best_of_finds_true() {
        let r = best_of(vec![
            ConditionStatus::False,
            ConditionStatus::Unknown,
            ConditionStatus::True,
        ])
        .unwrap();
        assert_eq!(r, ConditionStatus::True);
    }

    // ── Determinism law across all impls ──────────────────────────

    #[test]
    fn worst_determinism_across_impls() {
        // Same inputs must produce same outputs.
        let r1 = ReadyState::Ready;
        let r2 = fl("x");
        assert_eq!(r1.worst(&r2), r1.worst(&r2));
        assert_eq!(r1.best(&r2), r1.best(&r2));

        assert_eq!(
            ApplyStatus::Conflict.worst(&ApplyStatus::Failed),
            ApplyStatus::Conflict.worst(&ApplyStatus::Failed)
        );
    }

    // ── Compatibility with existing aggregators ───────────────────

    /// Demonstrates that HealthReport::overall(), ConditionSet::overall_ready,
    /// and ApplyReport::overall_status all express what worst_of does —
    /// the trait is the unified shape of the existing aggregators.
    #[test]
    fn worst_of_replaces_health_report_overall() {
        use crate::health::HealthReport;
        use crate::inventory::ResourceRef;

        let mut report = HealthReport::new();
        report.set(
            ResourceRef::namespaced("apps", "v1", "Deployment", "ns", "a"),
            ReadyState::Ready,
        );
        report.set(
            ResourceRef::namespaced("apps", "v1", "Deployment", "ns", "b"),
            ip("rolling"),
        );
        report.set(
            ResourceRef::namespaced("apps", "v1", "Deployment", "ns", "c"),
            fl("broken"),
        );

        // Existing API: report.overall() returns ReadyState::Failed.
        let existing = report.overall();
        // Trait-based equivalent: worst_of the iterator of ReadyStates.
        let trait_based: ReadyState = worst_of(report.iter().map(|(_, s)| s.clone()));

        // Both should agree on the worst-case classification (severity).
        assert_eq!(existing.severity(), trait_based.severity());
        assert!(existing.is_failed());
        assert!(trait_based.is_failed());
    }
}
