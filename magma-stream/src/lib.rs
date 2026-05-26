//! magma-stream — plan-as-data pipeline.
//!
//! Every reconcile produces typed data: a `Plan`, a `DriftReport`,
//! an `Outcome`. This crate turns that data into structured signals
//! every consumer downstream can act on:
//!
//! * **JSON-lines audit log** — append-only, one event per line.
//! * **In-memory sink** — accumulates events for tests.
//! * **Tracing sink** — `tracing::info!` + structured fields.
//! * **Merkle chain** — each event hashed against the previous one,
//!   producing a tamper-evident chain. Critical for compliance/audit.
//!
//! Fan-out via `PlanStream`: one event in, every registered sink
//! receives it. Sinks can fail independently without affecting the
//! reconcile path.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §IV.3.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

use magma_converge::{Outcome, Plan, PlanId};
use magma_drift::DriftReport;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StreamError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("sink: {0}")]
    Sink(String),
}

// ── Typed event shape ─────────────────────────────────────────────

/// Event kinds the stream carries. Every reconcile lifecycle stage
/// can emit one; downstream consumers can filter by kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventPayload {
    /// A `compute_plan` produced a typed Plan.
    PlanComputed {
        reconciler: String,
        plan_id: PlanId,
        changes: usize,
    },
    /// A drift classification ran (output of `magma-drift::classify`).
    DriftClassified {
        reconciler: String,
        plan_id: PlanId,
        total: usize,
        auto_corrected: usize,
        auto_corrected_with_alert: usize,
        awaiting_approval: usize,
        refused: usize,
    },
    /// An `apply` ran; carries the Outcome summary.
    ApplyOutcome {
        reconciler: String,
        plan_id: PlanId,
        applied: usize,
        failed: usize,
    },
    /// An operator-defined free-form event for things outside the
    /// reconciler-trait surface (e.g. lifecycle escalations).
    Custom { category: String, message: String },
}

/// One emitted event. Contains payload + timestamps + BLAKE3 hash
/// chained against the previous event. Designed so a consumer can
/// verify the chain end-to-end with no out-of-band metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Sequence number from the producing stream's perspective.
    pub seq: u64,
    pub emitted_at: DateTime<Utc>,
    pub payload: EventPayload,
    /// BLAKE3 hash of the previous event's `hash` || canonical bytes
    /// of (seq, payload). For seq=0, prev_hash is "0"*64.
    pub prev_hash: String,
    pub hash: String,
}

impl Event {
    /// Compute this event's canonical hash given the previous chain
    /// hash + the canonical projection of (seq, payload). The
    /// timestamp is NOT in the hash so chain verification is stable
    /// against clock skew between producer + verifier.
    fn compute_hash(seq: u64, payload: &EventPayload, prev_hash: &str) -> String {
        let canonical = serde_json::json!({
            "seq":       seq,
            "payload":   payload,
            "prev_hash": prev_hash,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        hex::encode(blake3::hash(&bytes).as_bytes())
    }

    /// Build helpers — exposed for tests + sinks that synthesize
    /// events without a full PlanStream.
    pub fn new(seq: u64, payload: EventPayload, prev_hash: String) -> Self {
        let hash = Self::compute_hash(seq, &payload, &prev_hash);
        Self {
            seq,
            emitted_at: Utc::now(),
            payload,
            prev_hash,
            hash,
        }
    }
}

// ── Sink trait ────────────────────────────────────────────────────

/// What a stream sink does. Object-safe; one `Arc<dyn EventSink>`
/// per registered consumer.
///
/// Implementations should be tolerant of partial failures — a slow
/// sink can't block the reconcile path. `PlanStream` calls sinks
/// independently and surfaces failures via the returned
/// `Vec<(name, Result)>`.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Sink-specific identifier used for routing + debug.
    fn name(&self) -> &str;

    /// Receive one event. Sinks may buffer, persist, or drop on
    /// failure — that's a sink-local concern.
    async fn handle(&self, event: &Event) -> Result<(), StreamError>;
}

pub type SharedSink = Arc<dyn EventSink>;

// ── PlanStream — the fan-out engine ───────────────────────────────

/// Holds a Merkle-chained sequence + a list of sinks. Emit events
/// via the typed helpers; the stream computes the next hash, fans
/// out to every sink, and returns per-sink results.
pub struct PlanStream {
    sinks: Vec<SharedSink>,
    state: Mutex<ChainState>,
}

#[derive(Debug, Clone, Default)]
struct ChainState {
    next_seq: u64,
    last_hash: String,
}

impl PlanStream {
    /// Empty stream. Hash chain seeded with `0x00…00` per Event::new.
    pub fn new() -> Self {
        Self {
            sinks: vec![],
            state: Mutex::new(ChainState {
                next_seq: 0,
                last_hash: "0".repeat(64),
            }),
        }
    }

    /// Register a sink. Returns `&mut Self` for chaining.
    pub fn register(&mut self, sink: SharedSink) -> &mut Self {
        self.sinks.push(sink);
        self
    }

    /// Number of registered sinks.
    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }

    /// Current chain head (last emitted hash). For audit verification.
    pub fn chain_head(&self) -> String {
        self.state.lock().unwrap().last_hash.clone()
    }

    /// Number of events emitted so far.
    pub fn count(&self) -> u64 {
        self.state.lock().unwrap().next_seq
    }

    /// Emit one event to every sink. Returns per-sink results.
    pub async fn emit(&self, payload: EventPayload) -> Vec<(String, Result<(), StreamError>)> {
        let (event, sinks) = {
            let mut state = self.state.lock().unwrap();
            let event = Event::new(state.next_seq, payload, state.last_hash.clone());
            state.next_seq += 1;
            state.last_hash = event.hash.clone();
            (event, self.sinks.clone())
        };
        let mut results = vec![];
        for sink in sinks {
            let res = sink.handle(&event).await;
            results.push((sink.name().to_string(), res));
        }
        results
    }

    /// Typed helpers for the common emit shapes.
    pub async fn emit_plan(
        &self,
        reconciler: &str,
        plan: &Plan,
    ) -> Vec<(String, Result<(), StreamError>)> {
        self.emit(EventPayload::PlanComputed {
            reconciler: reconciler.to_string(),
            plan_id: plan.id.clone(),
            changes: plan.change_count(),
        })
        .await
    }

    pub async fn emit_drift(&self, report: &DriftReport) -> Vec<(String, Result<(), StreamError>)> {
        self.emit(EventPayload::DriftClassified {
            reconciler: report.kind.clone(),
            plan_id: report.plan_id.clone(),
            total: report.summary.total_changes,
            auto_corrected: report.summary.auto_corrected,
            auto_corrected_with_alert: report.summary.auto_corrected_with_alert,
            awaiting_approval: report.summary.awaiting_approval,
            refused: report.summary.refused,
        })
        .await
    }

    pub async fn emit_outcome(&self, outcome: &Outcome) -> Vec<(String, Result<(), StreamError>)> {
        self.emit(EventPayload::ApplyOutcome {
            reconciler: outcome.kind.clone(),
            plan_id: outcome.plan_id.clone(),
            applied: outcome.applied.len(),
            failed: outcome.failed.len(),
        })
        .await
    }
}

impl Default for PlanStream {
    fn default() -> Self {
        Self::new()
    }
}

// ── Chain verification ────────────────────────────────────────────

/// Verify that a sequence of events forms a valid Merkle chain
/// (each event's `hash` equals BLAKE3 of (seq, payload, prev_hash)
/// AND `prev_hash` equals the previous event's `hash`).
///
/// Returns `Ok(())` if valid, `Err(IndexOfFirstBadEvent)` otherwise.
pub fn verify_chain(events: &[Event]) -> Result<(), usize> {
    let mut expected_prev = "0".repeat(64);
    for (idx, e) in events.iter().enumerate() {
        if e.prev_hash != expected_prev {
            return Err(idx);
        }
        let recomputed = Event::compute_hash(e.seq, &e.payload, &e.prev_hash);
        if recomputed != e.hash {
            return Err(idx);
        }
        expected_prev = e.hash.clone();
    }
    Ok(())
}

// ── Built-in sinks ────────────────────────────────────────────────

/// In-memory sink — accumulates events in a Vec. Tests use this.
#[derive(Default)]
pub struct InMemorySink {
    name: String,
    events: Mutex<Vec<Event>>,
}

impl InMemorySink {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            events: Mutex::new(vec![]),
        }
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.lock().unwrap().is_empty()
    }
}

#[async_trait]
impl EventSink for InMemorySink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, event: &Event) -> Result<(), StreamError> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

/// JSON-lines sink — appends one line per event to a file.
pub struct JsonLinesSink {
    name: String,
    path: PathBuf,
}

impl JsonLinesSink {
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[async_trait]
impl EventSink for JsonLinesSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, event: &Event) -> Result<(), StreamError> {
        let line = serde_json::to_string(event)?;
        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        f.write_all(line.as_bytes()).await?;
        f.write_all(b"\n").await?;
        Ok(())
    }
}

/// Tracing sink — emits a `tracing::info!` for each event with
/// structured fields. Useful for production observability.
pub struct TracingSink {
    name: String,
}

impl TracingSink {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl EventSink for TracingSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, event: &Event) -> Result<(), StreamError> {
        // Use info! with structured fields. Higher-level controllers
        // can filter by `kind=magma-stream` if needed.
        tracing::info!(
            sink = %self.name,
            seq = event.seq,
            hash = %event.hash,
            payload = ?event.payload,
            "magma-stream event"
        );
        Ok(())
    }
}

/// Failing sink — for tests of partial-failure behavior. Always
/// returns `Err(StreamError::Sink)`. Production code shouldn't use
/// this.
pub struct FailingSink {
    name: String,
}

impl FailingSink {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl EventSink for FailingSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, _event: &Event) -> Result<(), StreamError> {
        Err(StreamError::Sink("intentional test failure".into()))
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(seq: u64) -> EventPayload {
        EventPayload::Custom {
            category: "test".into(),
            message: format!("event-{seq}"),
        }
    }

    #[tokio::test]
    async fn empty_stream_has_zero_count_and_zero_hash_head() {
        let s = PlanStream::new();
        assert_eq!(s.count(), 0);
        assert_eq!(s.chain_head(), "0".repeat(64));
    }

    #[tokio::test]
    async fn emit_increments_seq_and_chain_head() {
        let mut s = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        s.register(sink.clone());

        s.emit(sample_payload(0)).await;
        assert_eq!(s.count(), 1);
        let head1 = s.chain_head();
        assert_ne!(head1, "0".repeat(64));

        s.emit(sample_payload(1)).await;
        assert_eq!(s.count(), 2);
        let head2 = s.chain_head();
        assert_ne!(head1, head2);

        // Sink received both.
        assert_eq!(sink.len(), 2);
    }

    #[tokio::test]
    async fn chain_verification_passes_for_valid_emission() {
        let mut s = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        s.register(sink.clone());

        for i in 0..5 {
            s.emit(sample_payload(i)).await;
        }
        let events = sink.events();
        assert!(verify_chain(&events).is_ok());
    }

    #[tokio::test]
    async fn chain_verification_detects_tampered_event() {
        let mut s = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        s.register(sink.clone());

        for i in 0..3 {
            s.emit(sample_payload(i)).await;
        }
        let mut events = sink.events();
        // Tamper with the middle event's payload (without
        // recomputing the hash).
        if let EventPayload::Custom {
            ref mut message, ..
        } = events[1].payload
        {
            *message = "tampered".to_string();
        }
        // Verification should flag event index 1.
        assert_eq!(verify_chain(&events), Err(1));
    }

    #[tokio::test]
    async fn chain_verification_detects_broken_prev_hash_link() {
        let mut s = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        s.register(sink.clone());

        for i in 0..3 {
            s.emit(sample_payload(i)).await;
        }
        let mut events = sink.events();
        // Re-link event[1] to a wrong previous hash.
        events[1].prev_hash = "f".repeat(64);
        assert_eq!(verify_chain(&events), Err(1));
    }

    #[tokio::test]
    async fn multiple_sinks_each_receive_every_event() {
        let mut s = PlanStream::new();
        let a = Arc::new(InMemorySink::new("a"));
        let b = Arc::new(InMemorySink::new("b"));
        s.register(a.clone()).register(b.clone());
        s.emit(sample_payload(0)).await;
        s.emit(sample_payload(1)).await;
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
    }

    #[tokio::test]
    async fn failing_sink_does_not_block_other_sinks() {
        let mut s = PlanStream::new();
        let good = Arc::new(InMemorySink::new("good"));
        let bad = Arc::new(FailingSink::new("bad"));
        s.register(good.clone()).register(bad.clone());

        let results = s.emit(sample_payload(0)).await;
        assert_eq!(results.len(), 2);
        // good succeeds, bad fails — both surfaced in the result vec.
        let by_name: std::collections::HashMap<_, _> = results.into_iter().collect();
        assert!(by_name["good"].is_ok());
        assert!(by_name["bad"].is_err());
        // The good sink received the event despite the bad sink failing.
        assert_eq!(good.len(), 1);
    }

    #[tokio::test]
    async fn json_lines_sink_appends_one_event_per_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let mut s = PlanStream::new();
        let sink = Arc::new(JsonLinesSink::new("audit", &path));
        s.register(sink);
        for i in 0..3 {
            s.emit(sample_payload(i)).await;
        }
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let parsed: Event = serde_json::from_str(line).unwrap();
            assert!(matches!(parsed.payload, EventPayload::Custom { .. }));
        }
    }

    #[tokio::test]
    async fn typed_helpers_emit_correct_payloads() {
        use magma_converge::{Action, Plan, change};
        let mut s = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        s.register(sink.clone());

        let plan = Plan::new(
            "inmemory_kv",
            vec![change(
                "kv.a",
                Action::Create,
                None,
                Some(serde_json::json!(1)),
            )],
        );
        s.emit_plan("inmemory_kv", &plan).await;
        let event = &sink.events()[0];
        match &event.payload {
            EventPayload::PlanComputed {
                reconciler,
                changes,
                ..
            } => {
                assert_eq!(reconciler, "inmemory_kv");
                assert_eq!(*changes, 1);
            }
            other => panic!("expected PlanComputed, got {other:?}"),
        }
    }
}
