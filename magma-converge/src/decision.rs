//! Typed pure-decision function — the canonical `Decision` trait
//! every fleet-wide deterministic state-transition rule consumes.
//! Spec: `theory/CONVERGENCE-ADOPTION.md` §II.3, Phase 0.5.
//!
//! Subsumes the hand-rolled `decide_*` free functions that previously
//! lived in:
//!
//! - `tatara::decide_pool_reconcile(pool, members, now) → PoolDecision`
//! - `tatara::decide_allocation_reconcile(alloc, pools, members, now)
//!   → AllocationDecision`
//! - `pangea-operator::reactive::evaluate(template, policy, now)
//!   → Escalation`
//! - `lava-operator::drift_scan(architecture, observed, now)
//!   → DriftScanOutcome`
//! - `tend::derive_from_receipt(receipt) → Vec<DriftEvent>`
//!
//! # The shape
//!
//! Every "given the current observed state + a triggering event + the
//! operator's declared policy + ambient observations (clock/metrics),
//! decide what to do" function has the same four-typed-input,
//! one-typed-output shape:
//!
//! ```ignore
//! pub trait Decision: Send + Sync {
//!     type State;     // current observed state
//!     type Event;     // triggering event
//!     type Policy;    // operator-declared policy
//!     type Observed;  // ambient observations (clock, metrics, ...)
//!     type Output;    // typed decision
//!
//!     fn decide(
//!         state:    &Self::State,
//!         event:    &Self::Event,
//!         policy:   &Self::Policy,
//!         observed: &Self::Observed,
//!     ) -> Self::Output;
//! }
//! ```
//!
//! No `self` receiver — implementors are zero-sized markers
//! (`pub struct MyDecision;`); the decide associated function is the
//! pure rule. This forbids `&mut self` patterns and accidental
//! stateful caching at the trait boundary.
//!
//! # The trait law
//!
//! For any `Decision` impl `D` and any inputs `(s, e, p, o)`:
//!
//!   `D::decide(&s, &e, &p, &o) == D::decide(&s, &e, &p, &o)`
//!                                                  (determinism)
//!
//! No I/O, no randomness, no hidden state. The whole point of the
//! trait is to make every reconciler's decision logic proptest-able
//! without mocks — the signature forbids side effects.
//!
//! # The canonical Observed: Clock
//!
//! Most pure decisions need "now" for elapsed-time math.
//! `chrono::DateTime<Utc>` is the canonical Observed type when the
//! only ambient observation is the wall clock. Decisions that need
//! more (metrics, cluster state) carry richer Observed structs.

use serde::{Deserialize, Serialize};

/// Pure decision function — typed inputs, typed output, NO I/O. The
/// substrate's canonical "given (state, event, policy, observed),
/// decide what to do" abstraction. Implementations are unit structs
/// (`pub struct MyDecision;`); the decide associated function is
/// the entire rule.
pub trait Decision: Send + Sync {
    /// Current observed state (e.g. workspace status, pod phase, CR
    /// condition). Read-only — Decision never mutates state.
    type State;

    /// Triggering event (e.g. pull-failed, drift detected, timer
    /// expired). Read-only.
    type Event;

    /// Operator-declared policy (e.g. retry budget, threshold,
    /// allowlist). Read-only.
    type Policy;

    /// Ambient observations that aren't state, event, or policy.
    /// Most commonly a clock (`chrono::DateTime<Utc>`); can be
    /// richer for decisions that need fleet metrics.
    type Observed;

    /// Typed decision the controller acts on.
    type Output;

    /// The decision rule. Pure function of its inputs.
    fn decide(
        state: &Self::State,
        event: &Self::Event,
        policy: &Self::Policy,
        observed: &Self::Observed,
    ) -> Self::Output;
}

// ── Reference impl: a tiny pool-decision (mirrors tatara) ─────────
//
// The canonical first impl. Demonstrates the shape every consumer
// follows: zero-sized marker struct, four typed associated types,
// one associated function.

/// Demo: the "should the pool spawn more members?" decision shape.
/// Mirrors the structure of `tatara::decide_pool_reconcile`. The
/// reference impl below shows the migration target for the real
/// tatara function in Phase 0.5 consumer work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolStateDemo {
    pub current_members: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoolEventDemo {
    HeartbeatTick,
    MemberFailed,
    MemberJoined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolPolicyDemo {
    pub min_size: u32,
    pub max_size: u32,
    pub desired_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockNow(pub i64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum PoolDecisionDemo {
    NoOp,
    Spawn { count: u32 },
    ReapExcess { count: u32 },
}

/// The reference Decision impl. Zero-sized marker; decide is the
/// entire rule. This is the canonical migration target shape for
/// every existing `fn decide_*` free function in the fleet.
#[derive(Debug, Default, Copy, Clone)]
pub struct PoolDecisionDemoImpl;

impl Decision for PoolDecisionDemoImpl {
    type State = PoolStateDemo;
    type Event = PoolEventDemo;
    type Policy = PoolPolicyDemo;
    type Observed = ClockNow;
    type Output = PoolDecisionDemo;

    fn decide(
        state: &Self::State,
        _event: &Self::Event,
        policy: &Self::Policy,
        _observed: &Self::Observed,
    ) -> Self::Output {
        let current = state.current_members;
        let desired = policy.desired_size.clamp(policy.min_size, policy.max_size);
        if current < desired {
            PoolDecisionDemo::Spawn {
                count: desired - current,
            }
        } else if current > desired {
            PoolDecisionDemo::ReapExcess {
                count: current - desired,
            }
        } else {
            PoolDecisionDemo::NoOp
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u32) -> PoolStateDemo {
        PoolStateDemo {
            current_members: n,
        }
    }
    fn p(min: u32, max: u32, desired: u32) -> PoolPolicyDemo {
        PoolPolicyDemo {
            min_size: min,
            max_size: max,
            desired_size: desired,
        }
    }
    fn ev() -> PoolEventDemo {
        PoolEventDemo::HeartbeatTick
    }
    fn now() -> ClockNow {
        ClockNow(0)
    }

    #[test]
    fn at_desired_size_is_noop() {
        let out = PoolDecisionDemoImpl::decide(&s(3), &ev(), &p(1, 10, 3), &now());
        assert_eq!(out, PoolDecisionDemo::NoOp);
    }

    #[test]
    fn below_desired_spawns_delta() {
        let out = PoolDecisionDemoImpl::decide(&s(2), &ev(), &p(1, 10, 5), &now());
        assert_eq!(out, PoolDecisionDemo::Spawn { count: 3 });
    }

    #[test]
    fn above_desired_reaps_delta() {
        let out = PoolDecisionDemoImpl::decide(&s(8), &ev(), &p(1, 10, 5), &now());
        assert_eq!(out, PoolDecisionDemo::ReapExcess { count: 3 });
    }

    #[test]
    fn desired_clamped_by_policy_bounds() {
        // desired=20 > max=10 — clamped to max.
        let out = PoolDecisionDemoImpl::decide(&s(5), &ev(), &p(1, 10, 20), &now());
        assert_eq!(
            out,
            PoolDecisionDemo::Spawn { count: 5 },
            "desired must be clamped to max"
        );

        // desired=0 < min=2 — clamped to min.
        let out = PoolDecisionDemoImpl::decide(&s(5), &ev(), &p(2, 10, 0), &now());
        assert_eq!(
            out,
            PoolDecisionDemo::ReapExcess { count: 3 },
            "desired must be clamped to min"
        );
    }

    /// The trait law: same inputs → same output, every time.
    #[test]
    fn determinism_law() {
        let cases = [(s(0), p(1, 5, 3)), (s(3), p(1, 5, 3)), (s(7), p(1, 5, 3))];
        for (state, policy) in cases.iter() {
            let a = PoolDecisionDemoImpl::decide(state, &ev(), policy, &now());
            let b = PoolDecisionDemoImpl::decide(state, &ev(), policy, &now());
            assert_eq!(a, b, "non-deterministic for state={state:?} policy={policy:?}");
        }
    }

    /// The trait permits dyn dispatch via a single typed
    /// associated-function table — but the more common pattern is
    /// generic over Decision impls (each impl is a unit struct, so
    /// monomorphization is cheap).
    #[test]
    fn generic_consumer_pattern() {
        fn run_one<D: Decision>(
            s: &D::State,
            e: &D::Event,
            p: &D::Policy,
            o: &D::Observed,
        ) -> D::Output {
            D::decide(s, e, p, o)
        }

        let out = run_one::<PoolDecisionDemoImpl>(&s(2), &ev(), &p(1, 10, 5), &now());
        assert_eq!(out, PoolDecisionDemo::Spawn { count: 3 });
    }

    #[test]
    fn decision_output_serde_roundtrip() {
        let d = PoolDecisionDemo::Spawn { count: 7 };
        let json = serde_json::to_string(&d).unwrap();
        let back: PoolDecisionDemo = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
