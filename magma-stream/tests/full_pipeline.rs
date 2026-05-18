//! End-to-end convergence pipeline integration test.
//!
//! Wires magma-converge + magma-drift + magma-fsm + magma-stream
//! into ONE pipeline and proves they compose:
//!
//! 1. **Reconciler** computes a typed Plan.
//! 2. **Drift classifier** classifies each Change under policy.
//! 3. **FSM** transitions Idle → Planning → Approving →
//!    Applying → Verifying → Stable per the typed allow-list.
//! 4. **Stream** emits typed events with BLAKE3 chain at every
//!    transition.
//! 5. **JSON-lines audit sink** persists every event.
//! 6. **Verifier** confirms the chain is intact end-to-end.
//!
//! This is the "justify the whole" test. If this passes, every
//! reconciler kind in the ecosystem (InMemory, GitHub, DNS,
//! Helm, Terraform, … and every future kind) gets the same
//! lifecycle for free.

use std::sync::Arc;

use magma_converge::{
    inmemory::InMemoryKvReconciler,
    Reconciler,
};
use magma_drift::{classify, DriftDecision, DriftPolicy};
use magma_fsm::{LifecycleState, Phase};
use magma_stream::{
    verify_chain, InMemorySink, JsonLinesSink, PlanStream, TracingSink,
};
use serde_json::json;

#[tokio::test]
async fn full_pipeline_reconciler_drift_fsm_stream_audit_chain() {
    // ── 1. Reconciler with empty state, desired config of 3 KVs ──
    let reconciler = InMemoryKvReconciler::new();
    let config = json!({
        "a": 1,
        "b": "hello",
        "c": { "nested": true },
    });

    // ── 2. Stream with three sinks ───────────────────────────────
    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.jsonl");
    let in_mem = Arc::new(InMemorySink::new("in_mem"));
    let mut stream = PlanStream::new();
    stream
        .register(in_mem.clone())
        .register(Arc::new(JsonLinesSink::new("audit", &audit_path)))
        .register(Arc::new(TracingSink::new("tracing")));

    // ── 3. FSM starts Idle, transitions through each phase ───────
    let mut fsm = LifecycleState::new();
    assert_eq!(fsm.current, Phase::Idle);

    // Trigger: Idle → Planning
    fsm.transition(Phase::Planning, None, "external trigger").unwrap();
    assert_eq!(fsm.current, Phase::Planning);

    // ── 4. compute_plan ─────────────────────────────────────────
    let state = reconciler.read_state().await.unwrap();
    let plan = reconciler.compute_plan(&config, &state).unwrap();
    assert_eq!(plan.change_count(), 3);

    // Emit PlanComputed event
    let plan_id = plan.id.clone();
    stream.emit_plan("inmemory_kv", &plan).await;

    // ── 5. Drift classification ─────────────────────────────────
    let policy = DriftPolicy::conservative_default();
    let drift_report = classify(&plan, &policy);
    assert_eq!(drift_report.events.len(), 3);
    // All 3 are Create → severity Functional → AutoCorrectWithAlert
    assert_eq!(drift_report.summary.auto_corrected_with_alert, 3);
    assert_eq!(drift_report.summary.awaiting_approval, 0);
    for event in &drift_report.events {
        assert_eq!(event.decision, DriftDecision::AutoCorrectWithAlert);
    }
    stream.emit_drift(&drift_report).await;

    // ── 6. FSM transition based on classification ───────────────
    // Functional-only drift → no approval needed (auto-correct
    // with alert routes straight to Applying).
    fsm.transition(Phase::Applying, Some(plan_id.clone()), "policy: auto-correct").unwrap();
    assert_eq!(fsm.current, Phase::Applying);

    // ── 7. Apply ───────────────────────────────────────────────
    let outcome = reconciler.apply(&plan).await.unwrap();
    assert!(outcome.fully_succeeded());
    assert_eq!(outcome.applied.len(), 3);
    stream.emit_outcome(&outcome).await;

    // ── 8. FSM transitions to Verifying then Stable ─────────────
    fsm.transition(Phase::Verifying, Some(plan_id.clone()), "applied").unwrap();
    let post_drift = reconciler.detect_drift(&config).await.unwrap();
    assert!(post_drift.is_noop(), "post-apply drift should be empty");
    fsm.transition(Phase::Stable, Some(plan_id.clone()), "verified no drift").unwrap();
    assert!(fsm.current.is_terminal());

    // ── 9. Audit log + chain verification ───────────────────────
    let events = in_mem.events();
    assert_eq!(events.len(), 3); // plan + drift + outcome
    assert!(verify_chain(&events).is_ok(), "BLAKE3 chain must verify");

    // JSON-lines audit file contains the same events.
    let audit_contents = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = audit_contents.trim().lines().collect();
    assert_eq!(lines.len(), 3);

    // ── 10. FSM serializes + restores across "operator restart" ─
    let fsm_json = fsm.to_json();
    let restored = LifecycleState::from_json(fsm_json).unwrap();
    assert_eq!(restored.current, Phase::Stable);
    assert_eq!(restored.len(), 4); // Idle→Planning→Applying→Verifying→Stable = 4 transitions
}

#[tokio::test]
async fn critical_drift_routes_through_approving_phase() {
    let reconciler = InMemoryKvReconciler::with_state(
        [
            ("critical_key".to_string(), json!("old_value")),
        ]
        .into_iter()
        .collect(),
    );
    let config = json!({});  // Empty config = delete the key

    // The InMemoryKvReconciler emits Delete actions with default
    // Critical severity. Conservative policy routes Critical →
    // RequireApproval. The FSM must visit Approving.
    let mut fsm = LifecycleState::new();
    let mut stream = PlanStream::new();
    let in_mem = Arc::new(InMemorySink::new("test"));
    stream.register(in_mem.clone());

    fsm.transition(Phase::Planning, None, "trigger").unwrap();

    let state = reconciler.read_state().await.unwrap();
    let plan = reconciler.compute_plan(&config, &state).unwrap();
    stream.emit_plan("inmemory_kv", &plan).await;

    let policy = DriftPolicy::conservative_default();
    let drift_report = classify(&plan, &policy);
    assert_eq!(drift_report.summary.awaiting_approval, 1);
    assert_eq!(drift_report.events[0].decision, DriftDecision::RequireApproval);
    stream.emit_drift(&drift_report).await;

    // Policy says RequireApproval → FSM enters Approving
    fsm.transition(Phase::Approving, Some(plan.id.clone()), "policy: critical").unwrap();
    assert_eq!(fsm.current, Phase::Approving);

    // Approver eventually approves → Applying
    fsm.transition(Phase::Applying, Some(plan.id.clone()), "approved").unwrap();
    reconciler.apply(&plan).await.unwrap();
    fsm.transition(Phase::Verifying, Some(plan.id.clone()), "applied").unwrap();
    fsm.transition(Phase::Stable, Some(plan.id.clone()), "verified").unwrap();

    // Audit chain still intact even with the Approving step.
    let events = in_mem.events();
    assert!(verify_chain(&events).is_ok());
}

#[tokio::test]
async fn failure_during_apply_transitions_to_failed_with_chain_intact() {
    // The InMemoryKvReconciler can't realistically fail apply, so
    // we synthesize the FSM-side failure path and verify the chain
    // tolerates it.
    let mut fsm = LifecycleState::new();
    let in_mem = Arc::new(InMemorySink::new("test"));
    let mut stream = PlanStream::new();
    stream.register(in_mem.clone());

    fsm.transition(Phase::Planning, None, "trigger").unwrap();
    fsm.transition(Phase::Applying, None, "auto").unwrap();
    stream.emit(magma_stream::EventPayload::Custom {
        category: "apply_attempt".into(),
        message:  "starting".into(),
    }).await;

    // Simulated failure.
    fsm.transition(Phase::Failed, None, "transient API 503").unwrap();
    stream.emit(magma_stream::EventPayload::Custom {
        category: "apply_failed".into(),
        message:  "transient API 503".into(),
    }).await;

    // Retry path.
    fsm.transition(Phase::Retrying, None, "backoff").unwrap();
    fsm.transition(Phase::Planning, None, "replan").unwrap();

    let events = in_mem.events();
    assert_eq!(events.len(), 2);
    assert!(verify_chain(&events).is_ok());

    // FSM history includes the failure path.
    assert!(fsm.history.iter().any(|t| t.to == Phase::Failed));
    assert!(fsm.history.iter().any(|t| t.to == Phase::Retrying));
}

#[tokio::test]
async fn audit_chain_tampering_is_detected() {
    // End-to-end tamper-evidence proof.
    let mut stream = PlanStream::new();
    let in_mem = Arc::new(InMemorySink::new("test"));
    stream.register(in_mem.clone());

    for i in 0..5 {
        stream.emit(magma_stream::EventPayload::Custom {
            category: "test".into(),
            message:  format!("event-{i}"),
        }).await;
    }

    let mut events = in_mem.events();
    // Tamper with the middle event.
    if let magma_stream::EventPayload::Custom { ref mut message, .. } = events[2].payload {
        *message = "tampered after emission".to_string();
    }
    let result = verify_chain(&events);
    assert_eq!(result, Err(2), "tampering at index 2 should be detected");
}
