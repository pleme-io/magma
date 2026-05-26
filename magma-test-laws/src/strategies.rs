//! Shared proptest strategies for the magma substrate.
//!
//! Every property-based test across the magma workspace builds on
//! these typed generators. Putting them in one place means:
//!
//! * One canonical "what does a random Plan look like" shape — when
//!   the Plan type grows a field, this file updates and every
//!   downstream proptest gets the new field for free.
//! * No drift between magma-stream's chain proptest and
//!   magma-replay's roundtrip proptest: they share `arb_event_payload`.
//! * New consumers (magma-drift policy proptests, magma-budget
//!   retry proptests, …) get the substrate strategies in 1 line.
//!
//! Gated behind the `strategies` feature so the law-battery base
//! crate stays lean. Enable with
//! `magma-test-laws = { version = "…", features = ["strategies"] }`
//! in `[dev-dependencies]`.

use magma_converge::{Action, Plan, PlanId, change};
use magma_fsm::{LifecycleState, Phase};
use magma_stream::{Event, EventPayload};
use proptest::prelude::*;

// ── Reconciler primitives ────────────────────────────────────────

/// Random `Action` covering the universal action surface
/// (Create / Update / Delete / Replace / NoOp). Magma-converge
/// re-shapes any granular backend action into one of these five.
pub fn arb_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Create),
        Just(Action::Update),
        Just(Action::Delete),
        Just(Action::Replace),
        Just(Action::NoOp),
    ]
}

/// Random `PlanId` (64-char hex). Equivalent in distribution to the
/// BLAKE3 hex produced by `Plan::new`.
pub fn arb_plan_id() -> impl Strategy<Value = PlanId> {
    "[a-f0-9]{64}".prop_map(PlanId)
}

/// Random optional `PlanId` — covers the common "may or may not
/// have a plan_id" shape (e.g. lifecycle transitions, audit events).
pub fn arb_optional_plan_id() -> impl Strategy<Value = Option<PlanId>> {
    prop_oneof![Just(None), arb_plan_id().prop_map(Some),]
}

/// Random `Plan` with 0-8 changes over random typed addresses.
/// Plan id is computed from changes (deterministic) by `Plan::new`.
pub fn arb_plan() -> impl Strategy<Value = Plan> {
    (
        "[a-z][a-z_]{2,11}", // reconciler kind
        proptest::collection::vec(
            ("[a-z][a-z0-9_]{0,15}\\.[a-z][a-z0-9_]{0,15}", arb_action()),
            0..=8,
        ),
    )
        .prop_map(|(kind, changes_spec)| {
            let changes = changes_spec
                .into_iter()
                .map(|(addr, act)| change(addr, act, None, None))
                .collect();
            Plan::new(kind, changes)
        })
}

// ── FSM primitives ────────────────────────────────────────────────

/// All 9 phases as a random selector.
pub fn arb_phase() -> impl Strategy<Value = Phase> {
    proptest::sample::select(vec![
        Phase::Idle,
        Phase::Planning,
        Phase::Approving,
        Phase::Applying,
        Phase::Verifying,
        Phase::Stable,
        Phase::Failed,
        Phase::Retrying,
        Phase::Refused,
    ])
}

/// Random `LifecycleState` representing a happy-path walk of
/// 0-4 transitions. Useful for bundle/replay tests that need a
/// plausible reconcile trace.
pub fn arb_lifecycle_happy_walk() -> impl Strategy<Value = LifecycleState> {
    (0usize..=4usize).prop_map(|n| {
        let mut l = LifecycleState::new();
        let walk = [
            Phase::Planning,
            Phase::Applying,
            Phase::Verifying,
            Phase::Stable,
        ];
        for p in walk.iter().take(n) {
            l.transition(*p, None, "proptest").unwrap();
        }
        l
    })
}

// ── Stream primitives ────────────────────────────────────────────

/// Random `EventPayload` covering all four payload variants
/// (PlanComputed, DriftClassified, ApplyOutcome, Custom). Bounded
/// counts + bounded string lengths keep proptest cycles short.
pub fn arb_event_payload() -> impl Strategy<Value = EventPayload> {
    prop_oneof![
        // PlanComputed
        ("[a-z]{3,12}", arb_plan_id(), 0usize..32usize).prop_map(|(r, p, c)| {
            EventPayload::PlanComputed {
                reconciler: r,
                plan_id: p,
                changes: c,
            }
        }),
        // DriftClassified
        (
            "[a-z]{3,12}",
            arb_plan_id(),
            0usize..32usize,
            0usize..16usize,
            0usize..16usize,
            0usize..16usize,
            0usize..16usize,
        )
            .prop_map(|(r, p, t, ac, acw, aw, rf)| EventPayload::DriftClassified {
                reconciler: r,
                plan_id: p,
                total: t,
                auto_corrected: ac,
                auto_corrected_with_alert: acw,
                awaiting_approval: aw,
                refused: rf,
            }),
        // ApplyOutcome
        (
            "[a-z]{3,12}",
            arb_plan_id(),
            0usize..32usize,
            0usize..16usize,
        )
            .prop_map(|(r, p, a, f)| EventPayload::ApplyOutcome {
                reconciler: r,
                plan_id: p,
                applied: a,
                failed: f,
            }),
        // Custom
        ("[a-z]{3,12}", "[a-z ]{0,40}").prop_map(|(c, m)| EventPayload::Custom {
            category: c,
            message: m,
        }),
    ]
}

/// Random valid event chain (0-N events) — each event's prev_hash
/// matches the previous event's hash + the first event's prev_hash
/// is 64 zeros. The result always passes `magma_stream::verify_chain`.
pub fn arb_event_chain(max_len: usize) -> impl Strategy<Value = Vec<Event>> {
    proptest::collection::vec(arb_event_payload(), 0..=max_len).prop_map(|payloads| {
        let mut events = vec![];
        let mut prev_hash = "0".repeat(64);
        for (i, payload) in payloads.into_iter().enumerate() {
            let e = Event::new(i as u64, payload, prev_hash.clone());
            prev_hash = e.hash.clone();
            events.push(e);
        }
        events
    })
}
