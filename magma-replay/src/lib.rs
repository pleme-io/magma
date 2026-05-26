//! magma-replay — reconstruct reconcile history from an audit chain.
//!
//! Every reconcile emits typed `Event`s into the magma-stream
//! pipeline. Given those events back, this crate reconstructs:
//!
//! * **`Timeline`** — chronological event list with derived
//!   summaries (total reconciles, applied vs failed, plan_ids,
//!   reconciler kinds touched).
//! * **`PlanHistory`** — sequence of distinct plan_ids observed.
//! * **`KindActivity`** — per-kind: how many plans, how many
//!   applies, how many failures, what severities classified.
//!
//! Powers forensic queries — "what happened during incident X?",
//! "which kinds saw critical drift last week?", "did this CR's
//! reconcile actually run?".
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §IV.3.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use magma_converge::PlanId;
use magma_stream::{Event, EventPayload, verify_chain};

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("invalid chain at event index {0}")]
    InvalidChain(usize),
    #[error("empty event sequence")]
    Empty,
    #[error("io reading audit log: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error at line {line}: {source}")]
    ParseLine {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
}

// ── Reconstructed views ──────────────────────────────────────────

/// Per-kind activity summary derived from the event stream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KindActivity {
    pub kind: String,
    pub plans_computed: usize,
    pub applies: usize,
    pub apply_failures: usize,
    pub drift_classified: usize,
    pub auto_corrected: usize,
    pub auto_corrected_with_alert: usize,
    pub approvals_required: usize,
    pub refusals: usize,
    /// Plan ids observed for this kind, in order of first appearance.
    pub plan_ids: Vec<PlanId>,
}

/// Chronological timeline summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timeline {
    pub event_count: usize,
    pub first_at: Option<DateTime<Utc>>,
    pub last_at: Option<DateTime<Utc>>,
    /// All distinct reconciler kinds that appeared.
    pub kinds: Vec<String>,
    /// All distinct plan_ids observed, in first-seen order.
    pub plan_ids: Vec<PlanId>,
}

/// Aggregate replay result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayReport {
    pub timeline: Timeline,
    /// Per-kind activity (sorted by kind name).
    pub activity: Vec<KindActivity>,
    /// Whether the BLAKE3 chain verified end-to-end.
    pub chain_verified: bool,
    /// If chain verification failed, the first bad index.
    pub chain_break_at: Option<usize>,
}

impl ReplayReport {
    /// True iff the chain verified AND there's at least one event.
    pub fn is_trusted(&self) -> bool {
        self.chain_verified && self.timeline.event_count > 0
    }
}

// ── Replay engine ────────────────────────────────────────────────

/// Reconstruct a `ReplayReport` from a sequence of events. Also
/// runs chain verification — a tampered chain is reported but
/// doesn't abort the replay (partial data is still useful for
/// forensics).
pub fn replay(events: &[Event]) -> Result<ReplayReport, ReplayError> {
    if events.is_empty() {
        return Err(ReplayError::Empty);
    }

    let (chain_verified, chain_break_at) = match verify_chain(events) {
        Ok(()) => (true, None),
        Err(idx) => (false, Some(idx)),
    };

    let mut timeline = Timeline {
        event_count: events.len(),
        first_at: events.first().map(|e| e.emitted_at),
        last_at: events.last().map(|e| e.emitted_at),
        kinds: vec![],
        plan_ids: vec![],
    };

    let mut kinds_seen: HashSet<String> = HashSet::new();
    let mut plan_ids_seen: HashSet<String> = HashSet::new();
    let mut activity: BTreeMap<String, KindActivity> = BTreeMap::new();
    let mut kind_plan_seen: HashMap<String, HashSet<String>> = HashMap::new();

    for e in events {
        let (kind, plan_id_opt) = extract_kind_and_plan_id(&e.payload);
        if let Some(k) = &kind {
            if kinds_seen.insert(k.clone()) {
                timeline.kinds.push(k.clone());
            }
            let act = activity.entry(k.clone()).or_insert_with(|| KindActivity {
                kind: k.clone(),
                ..Default::default()
            });
            update_activity(act, &e.payload);
            if let Some(pid) = &plan_id_opt {
                let kind_seen = kind_plan_seen.entry(k.clone()).or_default();
                if kind_seen.insert(pid.0.clone()) {
                    act.plan_ids.push(pid.clone());
                }
            }
        }
        if let Some(pid) = &plan_id_opt {
            if plan_ids_seen.insert(pid.0.clone()) {
                timeline.plan_ids.push(pid.clone());
            }
        }
    }

    Ok(ReplayReport {
        timeline,
        activity: activity.into_values().collect(),
        chain_verified,
        chain_break_at,
    })
}

/// Extract activity from a single payload. Internal helper for `replay`.
fn update_activity(act: &mut KindActivity, payload: &EventPayload) {
    match payload {
        EventPayload::PlanComputed { .. } => {
            act.plans_computed += 1;
        }
        EventPayload::DriftClassified {
            total,
            auto_corrected,
            auto_corrected_with_alert,
            awaiting_approval,
            refused,
            ..
        } => {
            act.drift_classified += total;
            act.auto_corrected += auto_corrected;
            act.auto_corrected_with_alert += auto_corrected_with_alert;
            act.approvals_required += awaiting_approval;
            act.refusals += refused;
        }
        EventPayload::ApplyOutcome {
            applied, failed, ..
        } => {
            act.applies += applied;
            act.apply_failures += failed;
        }
        EventPayload::Custom { .. } => {}
    }
}

/// Extract (kind, plan_id) from a payload. Returns Nones for
/// payloads that don't carry these fields (`Custom`).
fn extract_kind_and_plan_id(payload: &EventPayload) -> (Option<String>, Option<PlanId>) {
    match payload {
        EventPayload::PlanComputed {
            reconciler,
            plan_id,
            ..
        }
        | EventPayload::ApplyOutcome {
            reconciler,
            plan_id,
            ..
        }
        | EventPayload::DriftClassified {
            reconciler,
            plan_id,
            ..
        } => (Some(reconciler.clone()), Some(plan_id.clone())),
        EventPayload::Custom { .. } => (None, None),
    }
}

/// Find every plan_id that appeared in the events, in order of
/// first occurrence. Useful when you want JUST the plan history
/// without the full kind-activity report.
pub fn extract_plan_history(events: &[Event]) -> Vec<PlanId> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = vec![];
    for e in events {
        let (_, pid) = extract_kind_and_plan_id(&e.payload);
        if let Some(pid) = pid {
            if seen.insert(pid.0.clone()) {
                out.push(pid);
            }
        }
    }
    out
}

/// Find events related to one specific plan_id. Useful for
/// "show me everything about this plan".
pub fn filter_by_plan_id<'a>(events: &'a [Event], plan_id: &PlanId) -> Vec<&'a Event> {
    events
        .iter()
        .filter(|e| {
            let (_, pid) = extract_kind_and_plan_id(&e.payload);
            pid.as_ref().map(|p| p.0 == plan_id.0).unwrap_or(false)
        })
        .collect()
}

/// Find events from one specific reconciler kind.
pub fn filter_by_kind<'a>(events: &'a [Event], kind: &str) -> Vec<&'a Event> {
    events
        .iter()
        .filter(|e| {
            let (k, _) = extract_kind_and_plan_id(&e.payload);
            k.as_deref() == Some(kind)
        })
        .collect()
}

// ── JSONL importers (close the loop with magma-stream's JsonLinesSink) ──

/// Parse a JSON-lines audit reader into a typed `Vec<Event>`.
/// Mirrors what `magma_stream::JsonLinesSink` writes: one event
/// per line, canonical serde shape. Empty lines + lines starting
/// with `#` are skipped (the latter is a convention for inline
/// audit annotations).
///
/// Returns a typed `ReplayError::ParseLine { line, source }` so
/// the operator can point at the exact offending line.
pub fn parse_jsonl<R: Read>(reader: R) -> Result<Vec<Event>, ReplayError> {
    let mut out = vec![];
    for (idx, line) in BufReader::new(reader).lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let event: Event =
            serde_json::from_str(trimmed).map_err(|source| ReplayError::ParseLine {
                line: idx + 1,
                source,
            })?;
        out.push(event);
    }
    Ok(out)
}

/// Convenience: read + parse a JSON-lines audit file from disk.
pub fn parse_jsonl_path(path: impl AsRef<Path>) -> Result<Vec<Event>, ReplayError> {
    let file = std::fs::File::open(path)?;
    parse_jsonl(file)
}

/// Full forensics pipeline: read a JSON-lines audit log + run
/// `replay()` on it. One call for the canonical "I have the audit
/// file from the prod operator, what happened?" use case.
pub fn replay_from_jsonl_path(path: impl AsRef<Path>) -> Result<ReplayReport, ReplayError> {
    let events = parse_jsonl_path(path)?;
    replay(&events)
}

/// Same as `replay_from_jsonl_path` but takes any `Read`.
pub fn replay_from_jsonl_reader<R: Read>(reader: R) -> Result<ReplayReport, ReplayError> {
    let events = parse_jsonl(reader)?;
    replay(&events)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_stream::{Event, EventPayload, InMemorySink, PlanStream};
    use std::sync::Arc;

    async fn emit_plan(stream: &PlanStream, kind: &str, plan_id: &str, changes: usize) {
        stream
            .emit(EventPayload::PlanComputed {
                reconciler: kind.into(),
                plan_id: PlanId(plan_id.into()),
                changes,
            })
            .await;
    }

    async fn emit_drift(
        stream: &PlanStream,
        kind: &str,
        plan_id: &str,
        total: usize,
        refused: usize,
    ) {
        stream
            .emit(EventPayload::DriftClassified {
                reconciler: kind.into(),
                plan_id: PlanId(plan_id.into()),
                total,
                auto_corrected: 0,
                auto_corrected_with_alert: total - refused,
                awaiting_approval: 0,
                refused,
            })
            .await;
    }

    async fn emit_outcome(
        stream: &PlanStream,
        kind: &str,
        plan_id: &str,
        applied: usize,
        failed: usize,
    ) {
        stream
            .emit(EventPayload::ApplyOutcome {
                reconciler: kind.into(),
                plan_id: PlanId(plan_id.into()),
                applied,
                failed,
            })
            .await;
    }

    #[tokio::test]
    async fn replay_empty_returns_err() {
        let events: Vec<Event> = vec![];
        match replay(&events) {
            Err(ReplayError::Empty) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn replay_single_reconcile_cycle() {
        let mut stream = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        stream.register(sink.clone());

        emit_plan(&stream, "terraform", "p1", 3).await;
        emit_drift(&stream, "terraform", "p1", 3, 0).await;
        emit_outcome(&stream, "terraform", "p1", 3, 0).await;

        let events = sink.events();
        let report = replay(&events).unwrap();
        assert!(report.is_trusted());
        assert_eq!(report.timeline.event_count, 3);
        assert_eq!(report.timeline.kinds, vec!["terraform"]);
        assert_eq!(report.timeline.plan_ids.len(), 1);

        assert_eq!(report.activity.len(), 1);
        let act = &report.activity[0];
        assert_eq!(act.kind, "terraform");
        assert_eq!(act.plans_computed, 1);
        assert_eq!(act.applies, 3);
        assert_eq!(act.apply_failures, 0);
        assert_eq!(act.drift_classified, 3);
    }

    #[tokio::test]
    async fn replay_multi_kind_activity_separated() {
        let mut stream = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        stream.register(sink.clone());

        emit_plan(&stream, "terraform", "p1", 5).await;
        emit_plan(&stream, "github_repo", "p2", 2).await;
        emit_drift(&stream, "github_repo", "p2", 2, 0).await;
        emit_outcome(&stream, "github_repo", "p2", 2, 0).await;
        emit_drift(&stream, "terraform", "p1", 5, 1).await;
        emit_outcome(&stream, "terraform", "p1", 4, 1).await;

        let report = replay(&sink.events()).unwrap();
        assert_eq!(report.timeline.event_count, 6);

        // Find each kind's activity.
        let tf = report
            .activity
            .iter()
            .find(|a| a.kind == "terraform")
            .unwrap();
        let gh = report
            .activity
            .iter()
            .find(|a| a.kind == "github_repo")
            .unwrap();

        assert_eq!(tf.plans_computed, 1);
        assert_eq!(tf.applies, 4);
        assert_eq!(tf.apply_failures, 1);
        assert_eq!(tf.refusals, 1);

        assert_eq!(gh.plans_computed, 1);
        assert_eq!(gh.applies, 2);
        assert_eq!(gh.apply_failures, 0);
    }

    #[tokio::test]
    async fn replay_records_chain_verification_state() {
        let mut stream = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        stream.register(sink.clone());

        emit_plan(&stream, "k", "p1", 1).await;
        emit_outcome(&stream, "k", "p1", 1, 0).await;

        // Untampered: trusted.
        let report = replay(&sink.events()).unwrap();
        assert!(report.chain_verified);
        assert!(report.chain_break_at.is_none());
        assert!(report.is_trusted());

        // Tampered: chain_verified false, break_at points at the bad index.
        let mut events = sink.events();
        if let EventPayload::PlanComputed {
            ref mut changes, ..
        } = events[0].payload
        {
            *changes = 999;
        }
        let report2 = replay(&events).unwrap();
        assert!(!report2.chain_verified);
        assert_eq!(report2.chain_break_at, Some(0));
        assert!(!report2.is_trusted());
    }

    #[tokio::test]
    async fn extract_plan_history_in_order() {
        let mut stream = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        stream.register(sink.clone());

        emit_plan(&stream, "k", "p1", 1).await;
        emit_plan(&stream, "k", "p2", 2).await;
        emit_plan(&stream, "k", "p1", 1).await; // duplicate plan_id

        let history = extract_plan_history(&sink.events());
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].0, "p1");
        assert_eq!(history[1].0, "p2");
    }

    #[tokio::test]
    async fn filter_by_plan_id_returns_only_matches() {
        let mut stream = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        stream.register(sink.clone());

        emit_plan(&stream, "k", "p1", 1).await;
        emit_plan(&stream, "k", "p2", 1).await;
        emit_outcome(&stream, "k", "p1", 1, 0).await;

        let events = sink.events();
        let filtered = filter_by_plan_id(&events, &PlanId("p1".into()));
        assert_eq!(filtered.len(), 2);
    }

    #[tokio::test]
    async fn filter_by_kind_returns_only_matches() {
        let mut stream = PlanStream::new();
        let sink = Arc::new(InMemorySink::new("test"));
        stream.register(sink.clone());

        emit_plan(&stream, "terraform", "p1", 1).await;
        emit_plan(&stream, "github_repo", "p2", 1).await;

        let events = sink.events();
        let tf = filter_by_kind(&events, "terraform");
        assert_eq!(tf.len(), 1);
        let gh = filter_by_kind(&events, "github_repo");
        assert_eq!(gh.len(), 1);
    }

    // ── JSONL roundtrip with magma-stream's JsonLinesSink ────────

    #[tokio::test]
    async fn jsonl_round_trip_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let mut stream = PlanStream::new();
        let jsonl = Arc::new(magma_stream::JsonLinesSink::new("audit", &path));
        stream.register(jsonl);

        emit_plan(&stream, "terraform", "p1", 3).await;
        emit_drift(&stream, "terraform", "p1", 3, 0).await;
        emit_outcome(&stream, "terraform", "p1", 3, 0).await;

        let events = parse_jsonl_path(&path).unwrap();
        assert_eq!(events.len(), 3);
        let report = replay(&events).unwrap();
        assert!(report.is_trusted());
        assert_eq!(report.timeline.kinds, vec!["terraform"]);
    }

    #[tokio::test]
    async fn replay_from_jsonl_path_one_call_pipeline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let mut stream = PlanStream::new();
        stream.register(Arc::new(magma_stream::JsonLinesSink::new("audit", &path)));
        emit_plan(&stream, "helm_release", "p9", 1).await;
        emit_outcome(&stream, "helm_release", "p9", 1, 0).await;

        let report = replay_from_jsonl_path(&path).unwrap();
        assert_eq!(report.timeline.event_count, 2);
        let act = report
            .activity
            .iter()
            .find(|a| a.kind == "helm_release")
            .unwrap();
        assert_eq!(act.plans_computed, 1);
        assert_eq!(act.applies, 1);
    }

    #[test]
    fn parse_jsonl_skips_empty_and_comment_lines() {
        let raw = b"
# preamble comment
{\"seq\":0,\"emitted_at\":\"2026-01-01T00:00:00Z\",\"payload\":{\"kind\":\"custom\",\"category\":\"t\",\"message\":\"x\"},\"prev_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"hash\":\"deadbeef\"}

# trailing comment
".as_slice();
        let events = parse_jsonl(raw).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 0);
    }

    #[test]
    fn parse_jsonl_reports_typed_line_number_on_error() {
        let raw = b"
{\"seq\":0,\"emitted_at\":\"2026-01-01T00:00:00Z\",\"payload\":{\"kind\":\"custom\",\"category\":\"t\",\"message\":\"x\"},\"prev_hash\":\"00\",\"hash\":\"x\"}
not-valid-json
".as_slice();
        match parse_jsonl(raw) {
            Err(ReplayError::ParseLine { line, .. }) => assert_eq!(line, 3),
            other => panic!("expected ParseLine {{ line: 3 }}, got {other:?}"),
        }
    }
}
