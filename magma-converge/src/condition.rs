//! Typed K8s status condition — the canonical `Condition` +
//! `ConditionSet` primitive every CRD status surface writes against.
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III (extends the typed
//! substrate surface beyond the original 9 gaps).
//!
//! Subsumes the K8s metav1.Condition shape that every FluxCD CRD
//! (and every pleme-io CRD) reports status through. Lifts into a
//! typed primitive so:
//!
//! - The substrate never depends on kube-rs (`metav1::Condition`
//!   lives in k8s-openapi which pulls in the full client cake);
//!   adapters convert to/from the kube-rs shape at the API boundary.
//! - Per-controller "set Ready=True, set Reconciling=False" code
//!   becomes typed `ConditionSet::touch(...)` calls with
//!   transition-aware `last_transition_time` updates.
//! - `ConditionSet` composes with [`crate::ReadyState`] (the
//!   canonical "is this resource ready?" answer) and with
//!   [`crate::TimeoutWatcher<S>`] (PhaseTimeout fires when a typed
//!   Condition has been in a non-Ready status for too long).
//!
//! # Wire format
//!
//! The serde representation is **byte-identical to K8s
//! metav1.Condition** JSON:
//!
//! ```json
//! {
//!   "type": "Ready",
//!   "status": "True",
//!   "reason": "ReconciliationSucceeded",
//!   "message": "Applied revision abc123",
//!   "lastTransitionTime": "2026-05-28T00:00:00Z",
//!   "observedGeneration": 5
//! }
//! ```
//!
//! `camelCase` field naming + `r#type` field name + Title-case
//! `ConditionStatus` variants (`"True"` / `"False"` / `"Unknown"`).
//! Round-trips with any K8s API-emitted condition.
//!
//! # Composition
//!
//! `ConditionSet::overall_ready()` returns the typed [`crate::ReadyState`]
//! from the canonical convention:
//!
//!   - Ready=True   ⇒ ReadyState::Ready
//!   - Ready=False  ⇒ ReadyState::Failed { reason }
//!   - Ready=Unknown / Ready absent ⇒ ReadyState::Unknown
//!   - Reconciling=True ⇒ ReadyState::InProgress { reason }  (takes
//!     precedence over Ready being Unknown)

use std::cmp::Ordering;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::health::ReadyState;

/// Common K8s condition type names. Each is a `&'static str` so
/// consumers compare with `==` and never typo.
pub const READY: &str = "Ready";
pub const RECONCILING: &str = "Reconciling";
pub const HEALTHY: &str = "Healthy";
pub const STALLED: &str = "Stalled";
pub const PROGRESSING: &str = "Progressing";
pub const AVAILABLE: &str = "Available";

/// K8s metav1.ConditionStatus tri-state. Wire format matches K8s
/// JSON exactly: `"True"`, `"False"`, `"Unknown"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, magma_converge_derive::Discriminant)]
#[discriminant(method = "name", case = "title")]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

impl ConditionStatus {
    /// `true` when status is exactly `True`. The most common predicate.
    pub fn is_true(self) -> bool {
        matches!(self, ConditionStatus::True)
    }

    /// `true` when status is exactly `False`.
    pub fn is_false(self) -> bool {
        matches!(self, ConditionStatus::False)
    }

    /// `true` when status is exactly `Unknown`.
    pub fn is_unknown(self) -> bool {
        matches!(self, ConditionStatus::Unknown)
    }

}

/// K8s metav1.Condition shape. Wire format is byte-identical to
/// `metav1.Condition` JSON via `#[serde(rename_all = "camelCase")]`
/// + explicit `rename = "type"` on the keyword-reserved field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Condition type (e.g. `"Ready"`, `"Reconciling"`). Stored as
    /// `String` since callers add custom types beyond the built-in
    /// constants; use `READY` / `RECONCILING` / etc. for the
    /// well-known ones.
    #[serde(rename = "type")]
    pub r#type: String,
    /// Tri-state status.
    pub status: ConditionStatus,
    /// Machine-readable reason (`CamelCase` per K8s convention).
    pub reason: String,
    /// Human-readable message.
    pub message: String,
    /// When the status last transitioned.
    pub last_transition_time: DateTime<Utc>,
    /// Generation observed when the condition was set. `None` when
    /// the controller doesn't track generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl Condition {
    /// Construct a new condition with the given fields. The caller
    /// supplies `last_transition_time`; `ConditionSet::touch` is the
    /// canonical entry point that handles transition-aware updates.
    pub fn new(
        r#type: impl Into<String>,
        status: ConditionStatus,
        reason: impl Into<String>,
        message: impl Into<String>,
        last_transition_time: DateTime<Utc>,
    ) -> Self {
        Self {
            r#type: r#type.into(),
            status,
            reason: reason.into(),
            message: message.into(),
            last_transition_time,
            observed_generation: None,
        }
    }

    /// Attach an observed-generation value. Returns self for chaining.
    #[must_use]
    pub fn with_observed_generation(mut self, generation: i64) -> Self {
        self.observed_generation = Some(generation);
        self
    }
}

/// Typed set of K8s status conditions, indexed by condition type.
/// Each type appears at most once (K8s convention — duplicate types
/// in the same status are an API error).
///
/// Internal storage is a sorted `Vec<Condition>` so the set
/// serializes deterministically across reconcile cycles and JSON
/// representations match K8s exactly (status.conditions is a JSON
/// array, not an object).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConditionSet {
    /// Sorted by condition type. Use `set` / `touch` to maintain
    /// the invariant.
    conditions: Vec<Condition>,
}

impl ConditionSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrite (or insert) a condition by type. Caller is
    /// responsible for `last_transition_time` semantics; prefer
    /// `touch` for transition-aware updates.
    pub fn set(&mut self, c: Condition) {
        match self
            .conditions
            .binary_search_by(|existing| existing.r#type.cmp(&c.r#type))
        {
            Ok(idx) => self.conditions[idx] = c,
            Err(idx) => self.conditions.insert(idx, c),
        }
    }

    /// **The canonical mutating API.** Updates the condition with
    /// the given type, preserving `last_transition_time` when the
    /// status hasn't changed (per K8s convention — the timestamp
    /// records when the status flipped, not when the controller
    /// last touched the condition).
    ///
    /// Equivalent kube-rs idiom: `Condition::set_status` /
    /// `meta_object.set_condition`.
    pub fn touch(
        &mut self,
        r#type: &str,
        status: ConditionStatus,
        reason: impl Into<String>,
        message: impl Into<String>,
        now: DateTime<Utc>,
    ) {
        let r#type = r#type.to_string();
        let reason = reason.into();
        let message = message.into();

        match self.find_idx(&r#type) {
            Some(idx) => {
                let existing_status = self.conditions[idx].status;
                let observed_generation = self.conditions[idx].observed_generation;
                let last_transition_time = if existing_status == status {
                    self.conditions[idx].last_transition_time
                } else {
                    now
                };
                self.conditions[idx] = Condition {
                    r#type,
                    status,
                    reason,
                    message,
                    last_transition_time,
                    observed_generation,
                };
            }
            None => {
                let c = Condition::new(r#type, status, reason, message, now);
                self.set(c);
            }
        }
    }

    /// Convenience: touch with an observed-generation update.
    pub fn touch_observed(
        &mut self,
        r#type: &str,
        status: ConditionStatus,
        reason: impl Into<String>,
        message: impl Into<String>,
        now: DateTime<Utc>,
        observed_generation: i64,
    ) {
        self.touch(r#type, status, reason, message, now);
        if let Some(idx) = self.find_idx(r#type) {
            self.conditions[idx].observed_generation = Some(observed_generation);
        }
    }

    /// Lookup by type. O(log n) binary search over the sorted vec.
    pub fn get(&self, r#type: &str) -> Option<&Condition> {
        self.find_idx(r#type).map(|i| &self.conditions[i])
    }

    fn find_idx(&self, r#type: &str) -> Option<usize> {
        self.conditions
            .binary_search_by(|c| c.r#type.as_str().cmp(r#type))
            .ok()
    }

    /// Remove a condition by type. Returns the removed condition,
    /// or `None` if no condition of that type was present.
    pub fn remove(&mut self, r#type: &str) -> Option<Condition> {
        match self.find_idx(r#type) {
            Some(idx) => Some(self.conditions.remove(idx)),
            None => None,
        }
    }

    /// `true` when the condition exists AND its status is `True`.
    pub fn is_true(&self, r#type: &str) -> bool {
        self.get(r#type).map(|c| c.status.is_true()).unwrap_or(false)
    }

    /// `true` when the condition exists AND its status is `False`.
    pub fn is_false(&self, r#type: &str) -> bool {
        self.get(r#type).map(|c| c.status.is_false()).unwrap_or(false)
    }

    /// Number of conditions in the set.
    pub fn len(&self) -> usize {
        self.conditions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    /// Iterate conditions in canonical (sorted-by-type) order.
    pub fn iter(&self) -> impl Iterator<Item = &Condition> {
        self.conditions.iter()
    }

    /// The canonical readiness projection from K8s convention:
    ///
    ///   - `Reconciling=True`         ⇒ `InProgress { reason }`
    ///     (reconciler hasn't reached steady state yet — takes
    ///     precedence over Ready being absent/Unknown)
    ///   - `Ready=True`               ⇒ `Ready`
    ///   - `Ready=False`              ⇒ `Failed { reason }`
    ///   - `Ready=Unknown` or absent  ⇒ `Unknown`
    ///
    /// Use this in reconcilers that already track readiness via the
    /// Ready+Reconciling condition pair; `HealthCheck<R>` impls can
    /// delegate to this when the resource's status carries the same
    /// shape.
    pub fn overall_ready(&self) -> ReadyState {
        if let Some(c) = self.get(RECONCILING) {
            if c.status.is_true() {
                return ReadyState::InProgress {
                    reason: condition_reason_message(c),
                };
            }
        }
        match self.get(READY) {
            Some(c) if c.status.is_true() => ReadyState::Ready,
            Some(c) if c.status.is_false() => ReadyState::Failed {
                reason: condition_reason_message(c),
            },
            Some(_) | None => ReadyState::Unknown,
        }
    }
}

/// Format a condition's reason+message into a single operator-
/// facing string. Used by `overall_ready` to populate ReadyState
/// reason fields.
fn condition_reason_message(c: &Condition) -> String {
    if c.message.is_empty() {
        c.reason.clone()
    } else if c.reason.is_empty() {
        c.message.clone()
    } else {
        format!("{}: {}", c.reason, c.message)
    }
}

impl Ord for Condition {
    fn cmp(&self, other: &Self) -> Ordering {
        self.r#type.cmp(&other.r#type)
    }
}

impl PartialOrd for Condition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn ready_true() -> Condition {
        Condition::new(
            READY,
            ConditionStatus::True,
            "ReconciliationSucceeded",
            "Applied revision abc123",
            t(1000),
        )
    }

    fn ready_false() -> Condition {
        Condition::new(
            READY,
            ConditionStatus::False,
            "HelmInstallFailed",
            "Chart not found",
            t(1000),
        )
    }

    fn reconciling_true() -> Condition {
        Condition::new(
            RECONCILING,
            ConditionStatus::True,
            "Progressing",
            "Applying revision abc123",
            t(1500),
        )
    }

    // ── ConditionStatus ────────────────────────────────────────────

    #[test]
    fn status_predicates() {
        assert!(ConditionStatus::True.is_true());
        assert!(!ConditionStatus::True.is_false());

        assert!(ConditionStatus::False.is_false());
        assert!(!ConditionStatus::False.is_true());

        assert!(ConditionStatus::Unknown.is_unknown());
        assert!(!ConditionStatus::Unknown.is_true());
    }

    #[test]
    fn status_names_match_k8s_wire_format() {
        assert_eq!(ConditionStatus::True.name(), "True");
        assert_eq!(ConditionStatus::False.name(), "False");
        assert_eq!(ConditionStatus::Unknown.name(), "Unknown");
    }

    #[test]
    fn status_serde_uses_titlecase_per_k8s() {
        // K8s wire format: "True" / "False" / "Unknown" — not
        // lowercase, not kebab-case.
        let s = ConditionStatus::True;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"True\"");

        let back: ConditionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    // ── Condition (wire format conformance) ────────────────────────

    #[test]
    fn condition_serde_camel_case_matches_k8s() {
        let c = ready_true();
        let json = serde_json::to_string(&c).unwrap();
        // K8s field names: type, status, reason, message,
        // lastTransitionTime, observedGeneration.
        assert!(json.contains("\"type\":\"Ready\""), "got {json:?}");
        assert!(json.contains("\"status\":\"True\""));
        assert!(json.contains("\"lastTransitionTime\""));
        // observedGeneration is None, should be skipped.
        assert!(!json.contains("\"observedGeneration\""));
    }

    #[test]
    fn condition_with_observed_generation_is_emitted() {
        let c = ready_true().with_observed_generation(7);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"observedGeneration\":7"), "got {json:?}");
    }

    #[test]
    fn condition_round_trip_matches() {
        let c = ready_true().with_observed_generation(3);
        let json = serde_json::to_string(&c).unwrap();
        let back: Condition = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn condition_deserializes_real_k8s_payload() {
        // A real-world-shape K8s condition JSON should parse cleanly.
        let payload = r#"{
            "type": "Ready",
            "status": "False",
            "reason": "ReconciliationFailed",
            "message": "post-build step failed",
            "lastTransitionTime": "2026-05-28T12:00:00Z",
            "observedGeneration": 12
        }"#;
        let c: Condition = serde_json::from_str(payload).unwrap();
        assert_eq!(c.r#type, "Ready");
        assert!(c.status.is_false());
        assert_eq!(c.observed_generation, Some(12));
    }

    // ── ConditionSet basics ────────────────────────────────────────

    #[test]
    fn empty_set() {
        let s = ConditionSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(s.get(READY).is_none());
        assert!(!s.is_true(READY));
    }

    #[test]
    fn set_inserts_and_overwrites() {
        let mut s = ConditionSet::new();
        s.set(ready_true());
        assert_eq!(s.len(), 1);
        assert!(s.is_true(READY));

        // Overwrite same type.
        s.set(ready_false());
        assert_eq!(s.len(), 1);
        assert!(s.is_false(READY));
        assert!(!s.is_true(READY));
    }

    #[test]
    fn iter_in_canonical_type_order() {
        let mut s = ConditionSet::new();
        s.set(reconciling_true()); // type=Reconciling
        s.set(ready_true());        // type=Ready
        // Sorted by type: "Ready" < "Reconciling" alphabetically.
        let types: Vec<&str> = s.iter().map(|c| c.r#type.as_str()).collect();
        assert_eq!(types, vec![READY, RECONCILING]);
    }

    #[test]
    fn remove_returns_removed() {
        let mut s = ConditionSet::new();
        s.set(ready_true());
        let removed = s.remove(READY).unwrap();
        assert!(removed.status.is_true());
        assert!(s.is_empty());
        assert!(s.remove(READY).is_none());
    }

    // ── touch — transition-aware updates ───────────────────────────

    #[test]
    fn touch_inserts_when_absent() {
        let mut s = ConditionSet::new();
        s.touch(READY, ConditionStatus::True, "Ok", "all good", t(1000));
        let c = s.get(READY).unwrap();
        assert!(c.status.is_true());
        assert_eq!(c.last_transition_time, t(1000));
    }

    #[test]
    fn touch_preserves_transition_time_on_unchanged_status() {
        let mut s = ConditionSet::new();
        s.touch(READY, ConditionStatus::True, "Ok", "msg1", t(1000));
        s.touch(READY, ConditionStatus::True, "Ok2", "msg2", t(2000));

        let c = s.get(READY).unwrap();
        // Status didn't change True→True, so lastTransitionTime stays at 1000.
        assert_eq!(c.last_transition_time, t(1000));
        // Reason + message DO update.
        assert_eq!(c.reason, "Ok2");
        assert_eq!(c.message, "msg2");
    }

    #[test]
    fn touch_updates_transition_time_on_status_change() {
        let mut s = ConditionSet::new();
        s.touch(READY, ConditionStatus::True, "Ok", "ok", t(1000));
        s.touch(READY, ConditionStatus::False, "Bad", "broke", t(2000));

        let c = s.get(READY).unwrap();
        assert!(c.status.is_false());
        // Status flipped True→False: lastTransitionTime updates to 2000.
        assert_eq!(c.last_transition_time, t(2000));
    }

    #[test]
    fn touch_observed_sets_observed_generation() {
        let mut s = ConditionSet::new();
        s.touch_observed(READY, ConditionStatus::True, "Ok", "ok", t(1000), 5);
        let c = s.get(READY).unwrap();
        assert_eq!(c.observed_generation, Some(5));
    }

    #[test]
    fn set_set_set_preserves_canonical_order() {
        // Pushing conditions in arbitrary insert order must yield
        // canonical (sorted-by-type) iteration.
        let mut s = ConditionSet::new();
        s.set(Condition::new("Z", ConditionStatus::True, "", "", t(0)));
        s.set(Condition::new("A", ConditionStatus::True, "", "", t(0)));
        s.set(Condition::new("M", ConditionStatus::True, "", "", t(0)));
        let types: Vec<&str> = s.iter().map(|c| c.r#type.as_str()).collect();
        assert_eq!(types, vec!["A", "M", "Z"]);
    }

    // ── overall_ready — projection to ReadyState ───────────────────

    #[test]
    fn overall_ready_empty_is_unknown() {
        let s = ConditionSet::new();
        assert!(s.overall_ready().is_unknown());
    }

    #[test]
    fn overall_ready_ready_true_is_ready() {
        let mut s = ConditionSet::new();
        s.set(ready_true());
        assert!(s.overall_ready().is_ready());
    }

    #[test]
    fn overall_ready_ready_false_is_failed() {
        let mut s = ConditionSet::new();
        s.set(ready_false());
        match s.overall_ready() {
            ReadyState::Failed { reason } => {
                assert!(reason.contains("HelmInstallFailed"));
                assert!(reason.contains("Chart not found"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn overall_ready_reconciling_true_beats_ready_unknown() {
        // Reconciling=True takes precedence — the reconciler is in
        // motion, not failed.
        let mut s = ConditionSet::new();
        s.set(Condition::new(
            READY,
            ConditionStatus::Unknown,
            "",
            "no status yet",
            t(0),
        ));
        s.set(reconciling_true());
        assert!(s.overall_ready().is_in_progress());
    }

    #[test]
    fn overall_ready_reconciling_true_beats_ready_false() {
        // Even when Ready=False, Reconciling=True takes precedence —
        // a re-run is in flight and may correct the failure.
        let mut s = ConditionSet::new();
        s.set(ready_false());
        s.set(reconciling_true());
        match s.overall_ready() {
            ReadyState::InProgress { .. } => {}
            other => panic!("expected InProgress, got {other:?}"),
        }
    }

    #[test]
    fn overall_ready_ready_unknown_alone_is_unknown() {
        let mut s = ConditionSet::new();
        s.set(Condition::new(
            READY,
            ConditionStatus::Unknown,
            "",
            "",
            t(0),
        ));
        assert!(s.overall_ready().is_unknown());
    }

    // ── ConditionSet serde ─────────────────────────────────────────

    #[test]
    fn condition_set_serializes_as_array() {
        let mut s = ConditionSet::new();
        s.set(ready_true());
        s.set(reconciling_true());

        let json = serde_json::to_string(&s).unwrap();
        // Should be a JSON array, not an object (matches K8s
        // status.conditions wire format).
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
    }

    #[test]
    fn condition_set_round_trip() {
        let mut s = ConditionSet::new();
        s.set(ready_true().with_observed_generation(3));
        s.set(reconciling_true());

        let json = serde_json::to_string(&s).unwrap();
        let back: ConditionSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn condition_set_serializes_deterministically_across_insert_order() {
        let mut a = ConditionSet::new();
        a.set(ready_true());
        a.set(reconciling_true());

        let mut b = ConditionSet::new();
        b.set(reconciling_true());
        b.set(ready_true());

        let ja = serde_json::to_string(&a).unwrap();
        let jb = serde_json::to_string(&b).unwrap();
        assert_eq!(ja, jb, "set serialization must be insert-order-independent");
    }

    // ── condition_reason_message helper ────────────────────────────

    #[test]
    fn reason_message_formats() {
        // both populated → "reason: message"
        let c = Condition::new("X", ConditionStatus::True, "Ok", "all good", t(0));
        assert_eq!(condition_reason_message(&c), "Ok: all good");

        // message empty → reason only
        let c = Condition::new("X", ConditionStatus::True, "Ok", "", t(0));
        assert_eq!(condition_reason_message(&c), "Ok");

        // reason empty → message only
        let c = Condition::new("X", ConditionStatus::True, "", "msg", t(0));
        assert_eq!(condition_reason_message(&c), "msg");
    }

    // ── ConditionSet sort invariant ────────────────────────────────

    #[test]
    fn binary_search_works_after_arbitrary_inserts() {
        let mut s = ConditionSet::new();
        for name in ["Mango", "Apple", "Zebra", "Banana", "Kiwi"] {
            s.set(Condition::new(name, ConditionStatus::True, "", "", t(0)));
        }
        // get() relies on binary search; verify it works.
        assert!(s.get("Apple").is_some());
        assert!(s.get("Mango").is_some());
        assert!(s.get("Zebra").is_some());
        assert!(s.get("Nope").is_none());
    }
}
