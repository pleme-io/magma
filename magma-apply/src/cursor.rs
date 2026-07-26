//! Resumable apply position — the typed state that makes plan length
//! irrelevant.
//!
//! # The problem this exists to remove
//!
//! Before this module, an apply was all-or-nothing: [`crate::engine::run_plan_with_providers`]
//! walked every change in one call, and a caller that ran out of wall clock
//! (the operator's `PANGEA_TIMEOUT`) surfaced a *terminal error* —
//! "Reconciliation timeout after 600 seconds" — having thrown away whatever
//! it had done. Convergence therefore depended on the whole plan fitting
//! inside one window, so a big enough workspace could never converge at all.
//! Raising the deadline only buys one growth cycle: it is a hand-set static
//! over `(prologue + paced_rpc_count / rate)`, and every term on the right
//! grows as the workspace does.
//!
//! # The shape of the fix
//!
//! A cycle does **bounded** work and **durably records** it. Running out of
//! quantum stops being an error and becomes a modelled transition — a
//! [`CycleOutcome::Yielded`] carrying an [`ApplyCursor`] that says exactly
//! where the apply got to. N cycles then converge for any N, because each one
//! starts from the frontier the last one left. This is what makes plan length
//! irrelevant; executing waves concurrently (a later stage) only changes how
//! *fast* it converges, never *whether*.
//!
//! # Why the invariants land where they do
//!
//! * **No "stopped, position unknown".** [`CycleOutcome`] has three arms and
//!   every non-completed one carries a cursor. There is no inhabitant of the
//!   type that represents an unfinished apply without a resumable position,
//!   so that state is *truly unrepresentable* — not checked for.
//! * **No silent zero-progress yield.** [`CycleOutcome::Yielded`] carries a
//!   [`Progress`], which cannot be constructed empty. A cycle that advanced
//!   nothing therefore *cannot* be reported as a yield; it must be
//!   [`CycleOutcome::Stalled`], a distinct arm that escalates. This is the
//!   seal on the real failure mode of naive chunking: a fixed prologue that
//!   exceeds the quantum, retrying forever with epsilon progress. Whether a
//!   stall *occurs* is an empirical fact about a live workspace and stays
//!   only-mitigated — but a stall masquerading as progress is impossible.
//! * **No rollback.** [`ApplyCursor`] exposes only additive mutators. There
//!   is no removal method and no `&mut` accessor to its collections, so
//!   un-completing has no code path in-crate. Across the serde boundary the
//!   same claim is weaker but still structural: a duplicate entry is rejected
//!   at parse time (see [`CursorError`]), so the tier there is
//!   *parse-time-rejected*, not truly-unrepresentable. Both halves are stated
//!   because they are genuinely different guarantees.
//! * **No resume against the wrong plan.** A cursor is bound to the
//!   [`PlanId`] it was created for, and [`PlanId`] is already a BLAKE3 hash
//!   of `(changes, state_serial, state_lineage)` — magma had the content
//!   address; this module just uses it. The only way to hand a cursor to the
//!   engine is [`ApplyCursor::resume`], which returns `None` on mismatch, so
//!   there is no expressible program that resumes one plan's progress into a
//!   different plan.
//!
//! What is deliberately *not* claimed: that a resumed apply can never
//! duplicate a create against the real cloud. Cloud I/O is not
//! transactional — a create can commit provider-side in the instant between
//! the RPC returning and the checkpoint committing. No type removes that.
//! The honest claim is at-least-once with typed adopt-on-conflict (see
//! `import_prepass::import_on_conflict`), and what chunking buys is that the
//! exposure window shrinks from a whole cycle to a single node.

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::time::Duration;

use magma_types::{PlanId, Plan, ResourceAddress};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ApplyOutcome;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CursorError {
    /// A persisted cursor listed the same address twice. Rejected at the
    /// parse boundary so a corrupted or hand-edited cursor cannot smuggle a
    /// non-monotone `completed` set into the engine.
    #[error("cursor lists a completed address more than once: {address}")]
    DuplicateCompleted { address: String },
    /// Same, for a cached data-source read.
    #[error("cursor lists a data-source result more than once: {address}")]
    DuplicateDataResult { address: String },
}

// ── Quantum ────────────────────────────────────────────────────────

/// How much wall clock one apply cycle may spend before it yields.
///
/// A zero quantum would mean "yield before doing anything", i.e. a guaranteed
/// stall — so it is unconstructible. The inner field is private and
/// [`Quantum::new`] is the only constructor.
///
/// Note this is a *scheduling quantum*, not a deadline in the old sense:
/// exceeding it is the normal, expected outcome for a large plan, not a
/// failure. There is no such thing as an "infeasible" quantum — a small one
/// simply yields more often.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Quantum(Duration);

impl Quantum {
    /// Build a quantum. Returns `None` for a zero duration.
    pub fn new(d: Duration) -> Option<Self> {
        if d.is_zero() { None } else { Some(Self(d)) }
    }

    /// Convenience for whole seconds. `None` when `secs == 0`.
    pub fn from_secs(secs: u64) -> Option<Self> {
        Self::new(Duration::from_secs(secs))
    }

    pub fn as_duration(self) -> Duration {
        self.0
    }

    pub fn as_millis(self) -> u64 {
        u64::try_from(self.0.as_millis()).unwrap_or(u64::MAX)
    }
}

// ── Progress ───────────────────────────────────────────────────────

/// The set of addresses a cycle *newly* recorded into its cursor — the
/// witness that a yield actually advanced.
///
/// "Advanced" deliberately includes a newly-cached deferred data-source read,
/// not just an applied mutation. A workspace whose prologue is dominated by
/// paced data reads makes real, durable progress each cycle by caching them,
/// and reporting that as a stall would be wrong in exactly the direction that
/// hides a working system.
///
/// Cannot be constructed empty — that is what forces a zero-progress cycle
/// into [`CycleOutcome::Stalled`] instead of letting it pose as a yield.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<ResourceAddress>", into = "Vec<ResourceAddress>")]
pub struct Progress(Vec<ResourceAddress>);

impl Progress {
    /// The only constructor. `None` for an empty vec.
    pub fn new(addrs: Vec<ResourceAddress>) -> Option<Self> {
        if addrs.is_empty() { None } else { Some(Self(addrs)) }
    }

    pub fn as_slice(&self) -> &[ResourceAddress] {
        &self.0
    }

    /// Non-zero by construction.
    pub fn len(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.0.len()).unwrap_or(NonZeroUsize::MIN)
    }

    /// Always false — present only so clippy's `len_without_is_empty` does
    /// not push us toward an `is_empty` that could never return `true`.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Parse-boundary rejection of an empty progress witness.
impl TryFrom<Vec<ResourceAddress>> for Progress {
    type Error = &'static str;
    fn try_from(v: Vec<ResourceAddress>) -> Result<Self, Self::Error> {
        Self::new(v).ok_or("progress witness must be non-empty")
    }
}

impl From<Progress> for Vec<ResourceAddress> {
    fn from(p: Progress) -> Self {
        p.0
    }
}

// ── ApplyCursor ────────────────────────────────────────────────────

/// One cached deferred data-source read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataResult {
    pub address: ResourceAddress,
    pub value: serde_json::Value,
}

/// Serde shape for [`ApplyCursor`]. Kept separate so the real type can
/// validate on the way in rather than deriving a permissive round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApplyCursorWire {
    plan_id: PlanId,
    completed: Vec<ResourceAddress>,
    #[serde(default)]
    data_results: Vec<DataResult>,
}

/// Where an apply got to — the resumable position.
///
/// Append-only: `complete` and `record_data` are the only mutators and both
/// add. There is deliberately no `remove`, no `clear`, and no `&mut` view of
/// either collection, so within this crate a cursor cannot go backwards.
///
/// Ordering is insertion order, which is deterministic (waves are
/// deterministic, and cycles concatenate), so the serialized form is stable —
/// which matters once a later stage content-addresses this alongside the
/// state row.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "ApplyCursorWire", into = "ApplyCursorWire")]
pub struct ApplyCursor {
    plan_id: PlanId,
    completed: Vec<ResourceAddress>,
    completed_set: HashSet<ResourceAddress>,
    data_results: Vec<DataResult>,
    data_set: HashSet<ResourceAddress>,
}

impl ApplyCursor {
    /// A fresh cursor for `plan_id` — nothing done yet.
    pub fn empty(plan_id: PlanId) -> Self {
        Self {
            plan_id,
            completed: Vec::new(),
            completed_set: HashSet::new(),
            data_results: Vec::new(),
            data_set: HashSet::new(),
        }
    }

    pub fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    /// Addresses applied so far, in completion order.
    pub fn completed(&self) -> &[ResourceAddress] {
        &self.completed
    }

    pub fn len(&self) -> usize {
        self.completed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.completed.is_empty() && self.data_results.is_empty()
    }

    pub fn contains(&self, addr: &ResourceAddress) -> bool {
        self.completed_set.contains(addr)
    }

    /// A previously-cached deferred data-source read, if this cursor has one.
    ///
    /// Consulting this is what stops a resumed cycle re-paying the paced
    /// read prologue: those reads cost one rate-limiter token each and are
    /// *not* persisted in `State`, so without the cache every cycle would
    /// re-run all of them before reaching any new mutation.
    pub fn data_result(&self, addr: &ResourceAddress) -> Option<&serde_json::Value> {
        if !self.data_set.contains(addr) {
            return None;
        }
        self.data_results
            .iter()
            .find(|d| &d.address == addr)
            .map(|d| &d.value)
    }

    pub fn data_results(&self) -> &[DataResult] {
        &self.data_results
    }

    /// Record an applied address. Idempotent; returns `true` if this call
    /// actually advanced the cursor.
    pub fn complete(&mut self, addr: ResourceAddress) -> bool {
        if !self.completed_set.insert(addr.clone()) {
            return false;
        }
        self.completed.push(addr);
        true
    }

    /// Cache a deferred data-source read. Idempotent; returns `true` if this
    /// call actually advanced the cursor.
    pub fn record_data(&mut self, addr: ResourceAddress, value: serde_json::Value) -> bool {
        if !self.data_set.insert(addr.clone()) {
            return false;
        }
        self.data_results.push(DataResult {
            address: addr,
            value,
        });
        true
    }

    /// Mint the token that lets the engine resume from this cursor.
    ///
    /// Returns `None` when the cursor belongs to a different plan. Because
    /// [`Resume`] has no other constructor, "resumed a cursor against a plan
    /// it was not computed for" has no expressible program — it is not
    /// guarded against at runtime, it simply cannot be written.
    ///
    /// Note that [`PlanId`] hashes `state_serial`, and applying bumps the
    /// serial — so a re-plan *after* partial progress necessarily yields a
    /// different id and correctly invalidates the cursor. The caller's job is
    /// to avoid re-planning while a valid cursor exists, not to work around
    /// this check.
    pub fn resume<'a>(&'a self, plan: &Plan) -> Option<Resume<'a>> {
        if self.plan_id == plan.id {
            Some(Resume { cursor: self })
        } else {
            None
        }
    }
}

/// Proof that a cursor matches the plan being applied. Constructible only via
/// [`ApplyCursor::resume`].
#[derive(Debug, Clone, Copy)]
pub struct Resume<'a> {
    cursor: &'a ApplyCursor,
}

impl<'a> Resume<'a> {
    pub fn cursor(self) -> &'a ApplyCursor {
        self.cursor
    }
}

impl TryFrom<ApplyCursorWire> for ApplyCursor {
    type Error = CursorError;

    fn try_from(w: ApplyCursorWire) -> Result<Self, Self::Error> {
        let mut completed_set = HashSet::with_capacity(w.completed.len());
        for a in &w.completed {
            if !completed_set.insert(a.clone()) {
                return Err(CursorError::DuplicateCompleted {
                    address: describe(a),
                });
            }
        }
        let mut data_set = HashSet::with_capacity(w.data_results.len());
        for d in &w.data_results {
            if !data_set.insert(d.address.clone()) {
                return Err(CursorError::DuplicateDataResult {
                    address: describe(&d.address),
                });
            }
        }
        Ok(Self {
            plan_id: w.plan_id,
            completed: w.completed,
            completed_set,
            data_results: w.data_results,
            data_set,
        })
    }
}

impl From<ApplyCursor> for ApplyCursorWire {
    fn from(c: ApplyCursor) -> Self {
        Self {
            plan_id: c.plan_id,
            completed: c.completed,
            data_results: c.data_results,
        }
    }
}

/// Human-readable `type.name` for an address, for error text only.
fn describe(a: &ResourceAddress) -> String {
    let mut s = String::with_capacity(a.type_id.0.len() + a.name.len() + 1);
    s.push_str(&a.type_id.0);
    s.push('.');
    s.push_str(&a.name);
    s
}

// ── CycleStats ─────────────────────────────────────────────────────

/// Per-cycle telemetry.
///
/// This lives on the cycle rather than on `AppliedChange` on purpose: it
/// describes *this run*, not the change, and putting it here keeps the change
/// type — constructed in 30 places across 13 crates — untouched.
///
/// `prologue_ms` is the load-bearing number. It is the fixed cost a cycle pays
/// before it can apply anything (seeding the resolution map, resolving
/// deferred data-source reads, building the graph). Chunked resumption
/// converges only while `prologue < quantum` with room for at least one node,
/// so this is the quantity a derived quantum must be sized against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleStats {
    /// Fixed setup cost before the first mutation could be attempted.
    pub prologue_ms: u64,
    /// Total wall clock for the cycle.
    pub elapsed_ms: u64,
    /// The quantum in force, if any.
    pub quantum_ms: Option<u64>,
    /// Real (non-NoOp, non-data) changes this cycle attempted.
    pub nodes_attempted: usize,
    /// Real changes this cycle applied successfully.
    pub nodes_completed: usize,
    /// Real changes still outstanding when the cycle ended.
    pub nodes_remaining: usize,
    /// Dependency waves entered this cycle.
    pub waves_entered: usize,
    /// Deferred data-source reads served from the cursor instead of re-read.
    pub data_reads_cached: usize,
    /// Deferred data-source reads attempted via RPC this cycle. Counts
    /// attempts, not successes — each one spends a rate-limiter token either
    /// way, and this exists to measure what the prologue actually costs.
    pub data_reads_performed: usize,
}

// ── CycleOutcome ───────────────────────────────────────────────────

/// What one apply cycle did.
///
/// The arms are the whole point. Every non-`Completed` arm carries a cursor,
/// so an unfinished apply *always* knows where it stopped; and `Yielded`
/// carries a non-empty [`Progress`], so a cycle that advanced nothing cannot
/// be reported as a yield.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CycleOutcome {
    /// Every real change in the plan is done. Terminal for this plan.
    Completed {
        outcome: ApplyOutcome,
        stats: CycleStats,
    },
    /// Ran out of quantum having advanced. Re-run with `cursor` to continue.
    /// This is a normal state, not an error.
    Yielded {
        partial: ApplyOutcome,
        cursor: ApplyCursor,
        progress: Progress,
        stats: CycleStats,
    },
    /// Ran out of quantum having advanced *nothing*. The quantum cannot cover
    /// this cycle's fixed prologue, so retrying unchanged will not converge —
    /// this needs a bigger quantum or a smaller prologue, and is meant to
    /// escalate rather than silently loop.
    Stalled {
        partial: ApplyOutcome,
        cursor: ApplyCursor,
        stats: CycleStats,
    },
}

impl CycleOutcome {
    /// The receipt for this cycle, whichever arm it took.
    pub fn outcome(&self) -> &ApplyOutcome {
        match self {
            CycleOutcome::Completed { outcome, .. } => outcome,
            CycleOutcome::Yielded { partial, .. } => partial,
            CycleOutcome::Stalled { partial, .. } => partial,
        }
    }

    pub fn into_outcome(self) -> ApplyOutcome {
        match self {
            CycleOutcome::Completed { outcome, .. } => outcome,
            CycleOutcome::Yielded { partial, .. } => partial,
            CycleOutcome::Stalled { partial, .. } => partial,
        }
    }

    /// The resumable position, absent only when the plan is finished.
    pub fn cursor(&self) -> Option<&ApplyCursor> {
        match self {
            CycleOutcome::Completed { .. } => None,
            CycleOutcome::Yielded { cursor, .. } | CycleOutcome::Stalled { cursor, .. } => {
                Some(cursor)
            }
        }
    }

    pub fn stats(&self) -> &CycleStats {
        match self {
            CycleOutcome::Completed { stats, .. }
            | CycleOutcome::Yielded { stats, .. }
            | CycleOutcome::Stalled { stats, .. } => stats,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, CycleOutcome::Completed { .. })
    }

    /// True when the caller should schedule another cycle.
    pub fn needs_another_cycle(&self) -> bool {
        !self.is_complete()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_types::{ModulePath, ResourceKind, ResourceTypeId};

    fn addr(name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::default(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("github_repository".to_string()),
            name: name.to_string(),
            key: None,
        }
    }

    fn plan_id(b: u8) -> PlanId {
        PlanId([b; 32])
    }

    #[test]
    fn quantum_rejects_zero() {
        assert!(Quantum::new(Duration::ZERO).is_none());
        assert!(Quantum::from_secs(0).is_none());
        assert!(Quantum::from_secs(1).is_some());
    }

    #[test]
    fn progress_cannot_be_empty() {
        assert!(Progress::new(vec![]).is_none());
        let p = Progress::new(vec![addr("a")]).expect("non-empty");
        assert_eq!(p.len().get(), 1);
    }

    #[test]
    fn progress_rejects_empty_at_the_parse_boundary() {
        let err = serde_json::from_str::<Progress>("[]");
        assert!(err.is_err(), "empty progress must not deserialize");
    }

    #[test]
    fn cursor_is_append_only_and_idempotent() {
        let mut c = ApplyCursor::empty(plan_id(1));
        assert!(c.complete(addr("a")));
        assert!(!c.complete(addr("a")), "re-completing must not advance");
        assert!(c.complete(addr("b")));
        assert_eq!(c.len(), 2);
        assert!(c.contains(&addr("a")));
        assert!(!c.contains(&addr("z")));
    }

    #[test]
    fn cursor_round_trips_through_serde() {
        let mut c = ApplyCursor::empty(plan_id(7));
        c.complete(addr("a"));
        c.complete(addr("b"));
        c.record_data(addr("d1"), serde_json::json!({"id": "x"}));

        let json = serde_json::to_string(&c).expect("serialize");
        let back: ApplyCursor = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.plan_id(), plan_id(7));
        assert_eq!(back.completed(), c.completed());
        assert_eq!(
            back.data_result(&addr("d1")),
            Some(&serde_json::json!({"id": "x"}))
        );
    }

    #[test]
    fn cursor_rejects_duplicate_completed_at_parse_time() {
        // A hand-edited or corrupted cursor must not be able to smuggle a
        // non-monotone completed set past the boundary.
        let pid = serde_json::to_value(plan_id(0)).expect("plan id serializes");
        let wire = serde_json::json!({
            "plan_id": pid,
            "completed": [addr("a"), addr("a")],
            "data_results": [],
        });
        let err = serde_json::from_value::<ApplyCursor>(wire).unwrap_err();
        assert!(
            err.to_string().contains("more than once"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resume_token_only_mints_for_the_matching_plan() {
        let c = ApplyCursor::empty(plan_id(1));
        let mut plan = magma_types::Plan {
            id: plan_id(1),
            created_at: chrono::Utc::now(),
            config_root: std::path::PathBuf::new(),
            variables: Default::default(),
            resource_changes: vec![],
            output_changes: vec![],
        };
        assert!(c.resume(&plan).is_some(), "matching plan must resume");
        plan.id = plan_id(2);
        assert!(
            c.resume(&plan).is_none(),
            "a cursor must not resume into a different plan"
        );
    }

    #[test]
    fn data_result_cache_is_a_hit_only_for_recorded_addresses() {
        let mut c = ApplyCursor::empty(plan_id(1));
        assert!(c.data_result(&addr("d")).is_none());
        assert!(c.record_data(addr("d"), serde_json::json!(1)));
        assert_eq!(c.data_result(&addr("d")), Some(&serde_json::json!(1)));
        assert!(!c.record_data(addr("d"), serde_json::json!(2)));
        assert_eq!(
            c.data_result(&addr("d")),
            Some(&serde_json::json!(1)),
            "re-recording must not overwrite"
        );
    }
}
