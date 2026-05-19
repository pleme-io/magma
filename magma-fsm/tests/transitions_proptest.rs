//! Property-based proofs for the reconcile lifecycle FSM.
//!
//! The FSM's behavior is defined by a typed transition table
//! (`is_transition_allowed`). These proptests verify the
//! load-bearing contracts an operator depends on:
//!
//! 1. `transition()` is total: for every (from, to) pair across
//!    the 9 phases, the call either succeeds or returns a typed
//!    `TransitionError::Disallowed`. No panics, no silent passes.
//! 2. Failed transitions are state-preserving: a `Disallowed`
//!    result leaves `current`, `entered_at`, and `history`
//!    untouched.
//! 3. Successful transitions are history-monotonic: each ok
//!    transition extends history by exactly one entry.
//! 4. Serde round-trip preserves equality of (current, history,
//!    plan_ids).
//! 5. Random valid walks never desync history.last().to from
//!    state.current — the recorded transition matches the
//!    observed phase.

use magma_converge::PlanId;
use magma_fsm::{LifecycleState, Phase, TransitionError};
use proptest::prelude::*;

const ALL_PHASES: &[Phase] = &[
    Phase::Idle,
    Phase::Planning,
    Phase::Approving,
    Phase::Applying,
    Phase::Verifying,
    Phase::Stable,
    Phase::Failed,
    Phase::Retrying,
    Phase::Refused,
];

fn arb_phase() -> impl Strategy<Value = Phase> {
    proptest::sample::select(ALL_PHASES.to_vec())
}

fn arb_plan_id() -> impl Strategy<Value = Option<PlanId>> {
    prop_oneof![Just(None), "[a-f0-9]{64}".prop_map(|s| Some(PlanId(s))),]
}

// ── Property 1: transition() is total over phase × phase ───────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn transition_call_is_total(
        from in arb_phase(),
        to   in arb_phase(),
        plan_id in arb_plan_id(),
    ) {
        // Construct a state with `current = from` via direct field
        // assignment using the public to_json/from_json API to seed
        // the lifecycle. (No `with_current` constructor — round-trip
        // is the typed entrypoint.)
        let mut s = LifecycleState::new();
        let mut blob = s.to_json();
        blob["current"] = serde_json::to_value(from).unwrap();
        s = LifecycleState::from_json(blob).unwrap();

        let result = s.transition(to, plan_id, "proptest");
        match result {
            Ok(()) => {
                // Successful transition: current must equal `to`.
                prop_assert_eq!(s.current, to);
            }
            Err(TransitionError::Disallowed { from: f, to: t }) => {
                // Error variant must echo the input pair.
                prop_assert_eq!(f, from);
                prop_assert_eq!(t, to);
            }
        }
    }
}

// ── Property 2: failed transitions are state-preserving ────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn disallowed_transition_does_not_mutate_state(
        from in arb_phase(),
        to   in arb_phase(),
    ) {
        let mut s = LifecycleState::new();
        let mut blob = s.to_json();
        blob["current"] = serde_json::to_value(from).unwrap();
        s = LifecycleState::from_json(blob).unwrap();
        let before_current    = s.current;
        let before_entered_at = s.entered_at;
        let before_history_n  = s.history.len();

        if let Err(_) = s.transition(to, None, "test") {
            prop_assert_eq!(s.current,         before_current);
            prop_assert_eq!(s.entered_at,      before_entered_at);
            prop_assert_eq!(s.history.len(),   before_history_n);
        }
    }
}

// ── Property 3: history extends by exactly one on success ──────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn successful_transition_extends_history_by_one(
        from in arb_phase(),
        to   in arb_phase(),
    ) {
        let mut s = LifecycleState::new();
        let mut blob = s.to_json();
        blob["current"] = serde_json::to_value(from).unwrap();
        s = LifecycleState::from_json(blob).unwrap();
        let before_n = s.history.len();

        if s.transition(to, None, "test").is_ok() {
            prop_assert_eq!(s.history.len(), before_n + 1);
            let last = s.history.last().unwrap();
            prop_assert_eq!(last.from, from);
            prop_assert_eq!(last.to,   to);
        }
    }
}

// ── Property 4: serde round-trip preserves equality ────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn serde_round_trip_preserves_state(
        sequence in proptest::collection::vec((arb_phase(), arb_plan_id()), 0..16),
    ) {
        let mut s = LifecycleState::new();
        for (to, pid) in sequence {
            let _ = s.transition(to, pid, "test"); // ignore disallowed
        }
        let json = s.to_json();
        let restored = LifecycleState::from_json(json).expect("from_json");
        prop_assert_eq!(s.current,        restored.current);
        prop_assert_eq!(s.history.len(),  restored.history.len());
        for (a, b) in s.history.iter().zip(restored.history.iter()) {
            prop_assert_eq!(a.from,    b.from);
            prop_assert_eq!(a.to,      b.to);
            prop_assert_eq!(&a.plan_id,&b.plan_id);
            prop_assert_eq!(&a.reason, &b.reason);
        }
    }
}

// ── Property 5: random valid walks keep current == history.last().to

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn current_matches_last_successful_transition(
        sequence in proptest::collection::vec(arb_phase(), 0..16),
    ) {
        let mut s = LifecycleState::new();
        for to in sequence {
            let _ = s.transition(to, None, "test"); // some fail; ignore
        }
        if let Some(last) = s.history.last() {
            prop_assert_eq!(s.current, last.to);
        } else {
            // No transitions occurred — must still be Idle.
            prop_assert_eq!(s.current, Phase::Idle);
        }
    }
}

// ── Property 6: terminal/active classification stays stable ────────

#[test]
fn terminal_and_active_are_mutually_exclusive() {
    for p in ALL_PHASES {
        assert!(
            !(p.is_terminal() && p.is_active()),
            "{p:?} reports both terminal and active",
        );
    }
}

// ── Property 7: soft deadlines are non-negative ────────────────────

#[test]
fn soft_deadlines_are_non_negative() {
    for p in ALL_PHASES {
        let d = p.soft_deadline();
        assert!(
            d >= chrono::Duration::zero(),
            "{p:?} reports negative soft deadline {d:?}",
        );
    }
}
