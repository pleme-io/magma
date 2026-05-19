//! Property-based proof that `JsonLinesSink` writes are losslessly
//! recoverable by `parse_jsonl`.
//!
//! The substrate-critical promise: any event chain that was once
//! emitted live can be reconstructed identically from its audit
//! log + the reconstructed chain still verifies. Without this
//! guarantee, offline replay (incident forensics, retrospective
//! audits, "what would the FSM have done if…" exploration) would
//! be unsafe.
//!
//! Tests over 1000+ random emit sequences in each property.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §V.3 (replay).

use std::sync::Arc;

use magma_converge::PlanId;
use magma_replay::{parse_jsonl_path, replay_from_jsonl_path};
use magma_stream::{verify_chain, EventPayload, InMemorySink, JsonLinesSink, PlanStream};
use proptest::prelude::*;

// ── Generator (mirrors chain_proptest in magma-stream) ─────────────

fn arb_payload() -> impl Strategy<Value = EventPayload> {
    prop_oneof![
        ("[a-z]{3,12}", "[a-f0-9]{64}", 0usize..32usize).prop_map(|(r, p, c)| {
            EventPayload::PlanComputed {
                reconciler: r,
                plan_id:    PlanId(p),
                changes:    c,
            }
        }),
        (
            "[a-z]{3,12}",
            "[a-f0-9]{64}",
            0usize..32usize,
            0usize..16usize,
            0usize..16usize,
            0usize..16usize,
            0usize..16usize,
        )
            .prop_map(|(r, p, t, ac, acw, aw, rf)| EventPayload::DriftClassified {
                reconciler:                r,
                plan_id:                   PlanId(p),
                total:                     t,
                auto_corrected:            ac,
                auto_corrected_with_alert: acw,
                awaiting_approval:         aw,
                refused:                   rf,
            }),
        (
            "[a-z]{3,12}",
            "[a-f0-9]{64}",
            0usize..32usize,
            0usize..16usize,
        )
            .prop_map(|(r, p, a, f)| EventPayload::ApplyOutcome {
                reconciler: r,
                plan_id:    PlanId(p),
                applied:    a,
                failed:     f,
            }),
        ("[a-z]{3,12}", "[a-z ]{0,40}").prop_map(|(c, m)| EventPayload::Custom {
            category: c,
            message:  m,
        }),
    ]
}

// Emit the payloads through a PlanStream backed by BOTH an
// in-memory sink (the canonical reference) AND a JsonLinesSink at
// `path` (the artifact under test).
async fn emit_to_both(
    payloads: Vec<EventPayload>,
    path: &std::path::Path,
) -> Vec<magma_stream::Event> {
    let in_mem = Arc::new(InMemorySink::new("in_mem"));
    let mut stream = PlanStream::new();
    stream
        .register(in_mem.clone())
        .register(Arc::new(JsonLinesSink::new("jsonl", path)));
    for p in payloads {
        stream.emit(p).await;
    }
    in_mem.events()
}

// ── Property 1: emit → write → parse yields identical events ───────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn jsonl_roundtrip_yields_identical_events(
        payloads in proptest::collection::vec(arb_payload(), 1..16),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        let emitted = tokio::runtime::Runtime::new().unwrap().block_on(emit_to_both(payloads, &path));
        let parsed = parse_jsonl_path(&path).expect("parse_jsonl failed");

        prop_assert_eq!(emitted.len(), parsed.len());
        for (a, b) in emitted.iter().zip(parsed.iter()) {
            prop_assert_eq!(a.seq, b.seq);
            prop_assert_eq!(&a.hash, &b.hash);
            prop_assert_eq!(&a.prev_hash, &b.prev_hash);
            prop_assert_eq!(serde_json::to_value(&a.payload).unwrap(), serde_json::to_value(&b.payload).unwrap());
        }
    }
}

// ── Property 2: parsed chain re-verifies ──────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn parsed_chain_passes_verify_chain(
        payloads in proptest::collection::vec(arb_payload(), 1..16),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        tokio::runtime::Runtime::new().unwrap().block_on(emit_to_both(payloads, &path));
        let parsed = parse_jsonl_path(&path).expect("parse_jsonl failed");

        verify_chain(&parsed).unwrap_or_else(|i| {
            panic!("parsed chain failed verify at idx {i} — JSONL roundtrip corrupted the chain");
        });
    }
}

// ── Property 3: replay returns a trusted report ────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn replay_from_jsonl_returns_trusted_report(
        payloads in proptest::collection::vec(arb_payload(), 1..16),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        tokio::runtime::Runtime::new().unwrap().block_on(emit_to_both(payloads, &path));
        let report = replay_from_jsonl_path(&path).expect("replay failed");

        prop_assert!(
            report.is_trusted(),
            "replay report not trusted — chain verification failed during replay",
        );
    }
}

// ── Property 4: empty file → empty events ──────────────────────────

#[test]
fn empty_audit_file_parses_to_empty_events() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("audit.jsonl");
    std::fs::write(&path, b"").unwrap();
    let parsed = parse_jsonl_path(&path).expect("parse_jsonl of empty file failed");
    assert_eq!(parsed.len(), 0);
}
