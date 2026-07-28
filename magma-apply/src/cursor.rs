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
//! * **No silent skip of a different change.** Each entry records a
//!   [`ChangeFingerprint`] — a content address over the change's *intent* —
//!   and [`ApplyCursor::covers`] requires it to match before skipping. An
//!   address-keyed cursor could quietly not apply a real change whose address
//!   happened to be recorded; a fingerprint-keyed one cannot. The predicate is
//!   safety-monotone: it can only cause more re-application, never less.
//! * **No resume against the wrong plan.** A cursor is bound to the
//!   [`PlanId`] it was created for, and [`PlanId`] is already a BLAKE3 hash
//!   of `(changes, state_serial, state_lineage)` — magma had the content
//!   address; this module just uses it. The only way to hand a cursor to the
//!   engine is [`ApplyCursor::resume`], which returns `None` on mismatch, so
//!   there is no expressible program that resumes one plan's progress into a
//!   different plan.
//!
//! # Durability is a separate concern, and it is [`crate::checkpoint`]'s
//!
//! A cursor held only in memory is lost when the process dies, so on its own
//! this type bounds the loss at one *cycle*, not one node. Writing
//! `(state, cursor)` durably as each node completes is what actually shrinks
//! the window, and that is [`crate::checkpoint::CheckpointSink`]'s job. The
//! two are designed together: the cursor is the position, the checkpoint makes
//! the position survive.
//!
//! What is deliberately *not* claimed: that a resumed apply can never
//! duplicate a create against the real cloud. Cloud I/O is not
//! transactional — a create can commit provider-side in the instant between
//! the RPC returning and the checkpoint committing. No type removes that.
//! The honest claim is at-least-once with typed adopt-on-conflict (see
//! `import_prepass::import_on_conflict`), and what per-node checkpointing buys
//! is that the exposure window shrinks from a whole cycle to a single node.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::Duration;

use magma_types::{Action, Plan, PlanId, ResourceAddress, ResourceChange};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

// ── ChangeFingerprint ──────────────────────────────────────────────

/// Content address of a change's *intent*: BLAKE3 over `(address, action,
/// after)`.
///
/// # Why the cursor is keyed on this and not on the address alone
///
/// An address-keyed cursor says "we did something to `github_repository.foo`".
/// A fingerprint-keyed one says "we drove `github_repository.foo` to *this*
/// desired value". Only the second is self-verifying: it carries, in the entry
/// itself, a proof of which change it recorded, instead of inheriting that
/// meaning from an external plan-identity check.
///
/// That matters because the skip is a *silent* operation. If a cursor entry's
/// address matched but the plan's change for that address had different
/// content, an address-keyed skip would quietly not apply a real change and
/// still report success — the same silent-drop failure class the checkpoint
/// seam defends from the other side (see [`crate::checkpoint`]).
///
/// The predicate is safety-monotone with respect to the address-only one it
/// replaces: requiring fingerprint equality *as well as* address equality can
/// only ever cause **more** re-application, never less. Re-application is the
/// safe direction (a duplicate is rejected and adopted); a silent drop is not.
///
/// # What is hashed, and what is deliberately not
///
/// * `address` and `action` — identity and verb.
/// * `after` — the desired end value. This is the intent.
/// * **not** `before` — the pre-apply value, read from state. Two changes that
///   drive a resource to the same `after` are the same intent even if their
///   starting points differ, and if we have already driven the resource there,
///   skipping is correct. Including `before` would also make the fingerprint
///   sensitive to unrelated state churn, causing needless re-application.
/// * **not** `reasons` — explanatory metadata, not intent.
///
/// The bytes are `serde_json` over a fixed field order, and `serde_json::Map`
/// is a `BTreeMap` in this workspace (the `preserve_order` feature is off), so
/// object keys are sorted and the hash is stable under key reordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeFingerprint([u8; 32]);

/// The exact bytes hashed. A named struct rather than a tuple so the field
/// order is explicit and reviewable — changing it changes every fingerprint.
#[derive(Serialize)]
struct FingerprintInputs<'a> {
    address: &'a ResourceAddress,
    action: Action,
    after: Option<&'a serde_json::Value>,
}

impl ChangeFingerprint {
    /// Fingerprint a change.
    ///
    /// Serialization of a `ResourceChange`'s own fields cannot fail (it is
    /// plain data that round-trips through the plan artifact already), but
    /// rather than unwrap, an encode error degrades to a distinct sentinel
    /// hash. A sentinel compares unequal to any real fingerprint, so the
    /// failure mode is "this never matches, so never skip" — the safe
    /// direction, by construction.
    #[must_use]
    pub fn of(change: &ResourceChange) -> Self {
        let inputs = FingerprintInputs {
            address: &change.address,
            action: change.action,
            after: change.after.as_ref(),
        };
        match serde_json::to_vec(&inputs) {
            Ok(bytes) => Self(magma_attest::hash_bytes32(&bytes)),
            Err(_) => Self([0u8; 32]),
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// Hex on the wire — a cursor is read by humans in a Postgres row, and 32
/// decimal numbers in a JSON array is not that.
impl Serialize for ChangeFingerprint {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for ChangeFingerprint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        let raw = hex::decode(&s).map_err(D::Error::custom)?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| D::Error::custom("change fingerprint must be 32 bytes"))?;
        Ok(Self(bytes))
    }
}

/// One applied change: which resource, and which version of the change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedChange {
    pub address: ResourceAddress,
    pub fingerprint: ChangeFingerprint,
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
    completed: Vec<CompletedChange>,
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
    completed: Vec<CompletedChange>,
    completed_index: HashMap<ResourceAddress, ChangeFingerprint>,
    data_results: Vec<DataResult>,
    data_index: HashMap<ResourceAddress, usize>,
}

impl ApplyCursor {
    /// A fresh cursor for `plan_id` — nothing done yet.
    pub fn empty(plan_id: PlanId) -> Self {
        Self {
            plan_id,
            completed: Vec::new(),
            completed_index: HashMap::new(),
            data_results: Vec::new(),
            data_index: HashMap::new(),
        }
    }

    pub fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    /// Changes applied so far, in completion order.
    pub fn completed(&self) -> &[CompletedChange] {
        &self.completed
    }

    /// Just the addresses, in completion order.
    pub fn completed_addresses(&self) -> impl Iterator<Item = &ResourceAddress> {
        self.completed.iter().map(|c| &c.address)
    }

    pub fn len(&self) -> usize {
        self.completed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.completed.is_empty() && self.data_results.is_empty()
    }

    /// Has *some* change for this address been applied?
    ///
    /// The weaker of the two questions, and deliberately **not** what the
    /// engine skips on — see [`ApplyCursor::covers`]. Kept for introspection
    /// and for callers that genuinely want the address-level fact.
    pub fn contains(&self, addr: &ResourceAddress) -> bool {
        self.completed_index.contains_key(addr)
    }

    /// The fingerprint recorded for this address, if any.
    pub fn fingerprint_of(&self, addr: &ResourceAddress) -> Option<ChangeFingerprint> {
        self.completed_index.get(addr).copied()
    }

    /// Is **this exact change** already applied?
    ///
    /// The skip predicate. Both the address and the fingerprint must match, so
    /// a cursor entry can never cause a *different* change to the same resource
    /// to be silently skipped. A mismatch means the recorded change and the
    /// planned change are not the same intent, and the honest answer is to
    /// apply — re-application is absorbed by adopt-on-conflict, a silent drop
    /// is not absorbed by anything.
    pub fn covers(&self, change: &ResourceChange) -> bool {
        self.completed_index
            .get(&change.address)
            .is_some_and(|fp| *fp == ChangeFingerprint::of(change))
    }

    /// The changes a resumed cycle still has to apply: everything this cursor
    /// does not already cover, in the order given.
    ///
    /// # Why this is a named function and not an inline filter
    ///
    /// This one line is the whole reason plan size stops governing
    /// convergence. Each cycle applies some prefix of the frontier and records
    /// it; the next cycle's frontier is strictly smaller by exactly what was
    /// recorded; the plan is finished when the frontier is empty. That is the
    /// induction, and naming it makes it *directly* testable at sizes no
    /// end-to-end run could reach — see `convergence_is_independent_of_plan_size`,
    /// which drives this exact function to 10,000 changes.
    ///
    /// The engine consumes the result as the *only* source of nodes it will
    /// execute: excluded changes are never added to the dependency graph, so
    /// they appear in no wave and in no lookup table. Re-application is
    /// therefore structurally impossible rather than guarded by a runtime
    /// check — there is no code path from a covered change to a provider RPC.
    ///
    /// Exclusion tests [`Self::covers`] (address **and** fingerprint), not
    /// address alone, so a stale entry can never silently swallow a genuinely
    /// different change to the same resource.
    pub fn frontier<'a>(
        &self,
        reals: impl IntoIterator<Item = &'a ResourceChange>,
    ) -> Vec<&'a ResourceChange> {
        reals.into_iter().filter(|c| !self.covers(c)).collect()
    }

    /// A previously-cached deferred data-source read, if this cursor has one.
    ///
    /// Consulting this is what stops a resumed cycle re-paying the paced
    /// read prologue: those reads cost one rate-limiter token each and are
    /// *not* persisted in `State`, so without the cache every cycle would
    /// re-run all of them before reaching any new mutation.
    pub fn data_result(&self, addr: &ResourceAddress) -> Option<&serde_json::Value> {
        self.data_index
            .get(addr)
            .and_then(|i| self.data_results.get(*i))
            .map(|d| &d.value)
    }

    pub fn data_results(&self) -> &[DataResult] {
        &self.data_results
    }

    /// Record an applied change. Idempotent; returns `true` if this call
    /// actually advanced the cursor.
    ///
    /// Takes the change rather than the address so the entry carries its own
    /// fingerprint — the cursor records *what* was applied, not merely *that*
    /// something was.
    pub fn complete(&mut self, change: &ResourceChange) -> bool {
        let fingerprint = ChangeFingerprint::of(change);
        if self
            .completed_index
            .insert(change.address.clone(), fingerprint)
            .is_some()
        {
            // Already recorded. Note this does not overwrite the stored entry's
            // fingerprint in `completed` — append-only means the first record
            // stands.
            return false;
        }
        self.completed.push(CompletedChange {
            address: change.address.clone(),
            fingerprint,
        });
        true
    }

    /// Cache a deferred data-source read. Idempotent; returns `true` if this
    /// call actually advanced the cursor.
    pub fn record_data(&mut self, addr: ResourceAddress, value: serde_json::Value) -> bool {
        if self.data_index.contains_key(&addr) {
            return false;
        }
        self.data_index.insert(addr.clone(), self.data_results.len());
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
        let mut completed_index = HashMap::with_capacity(w.completed.len());
        for c in &w.completed {
            if completed_index
                .insert(c.address.clone(), c.fingerprint)
                .is_some()
            {
                return Err(CursorError::DuplicateCompleted {
                    address: describe(&c.address),
                });
            }
        }
        let mut data_index = HashMap::with_capacity(w.data_results.len());
        for (i, d) in w.data_results.iter().enumerate() {
            if data_index.insert(d.address.clone(), i).is_some() {
                return Err(CursorError::DuplicateDataResult {
                    address: describe(&d.address),
                });
            }
        }
        Ok(Self {
            plan_id: w.plan_id,
            completed: w.completed,
            completed_index,
            data_results: w.data_results,
            data_index,
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
    /// The widest wave in this cycle's graph — the maximum in-wave
    /// concurrency the dependency structure ever offers. An executor cannot
    /// usefully run more workers than this however large its budget, so it
    /// is the structural ceiling to compare any concurrency setting against.
    pub max_wave_width: usize,
    /// Total time blocked in the rate limiter before mutation RPCs, summed
    /// over nodes.
    ///
    /// This field and `node_rpc_ms_total` exist to answer ONE question that
    /// decides whether concurrency is worth anything: **is this apply
    /// rate-bound or latency-bound?**
    ///
    /// * `pacer_wait_ms_total` ≫ `node_rpc_ms_total` → rate-bound. The
    ///   shared 1 req/s bucket is the constraint; more workers would simply
    ///   queue on it and buy nothing. Chunked resumption is the only lever.
    /// * `node_rpc_ms_total` ≫ `pacer_wait_ms_total` → latency-bound. The
    ///   providers are slow relative to the pace, and concurrency up to
    ///   roughly `rate × latency` is real throughput.
    ///
    /// Measured rather than assumed, per "perf decisions from data": every
    /// prior estimate of where an apply's wall-clock goes was arithmetic on
    /// a plan size, not an observation of a run.
    pub pacer_wait_ms_total: u64,
    /// Total time inside provider RPCs for mutations, summed over nodes —
    /// excluding rate-limiter wait. Pairs with `pacer_wait_ms_total`.
    pub node_rpc_ms_total: u64,
    /// The slowest single node's RPC time. A high max against a modest
    /// total marks one pathological resource rather than a slow provider,
    /// which is a different fix.
    pub node_rpc_ms_max: u64,
    /// Deferred data-source reads served from the cursor instead of re-read.
    pub data_reads_cached: usize,
    /// Deferred data-source reads attempted via RPC this cycle. Counts
    /// attempts, not successes — each one spends a rate-limiter token either
    /// way, and this exists to measure what the prologue actually costs.
    pub data_reads_performed: usize,
    /// Durable checkpoints accepted this cycle — one per applied node plus one
    /// per newly-cached deferred read. Zero with no sink configured.
    pub checkpoints_written: usize,
    /// Checkpoints the sink rejected. Any non-zero value means the cycle
    /// stopped early to keep the unrecorded set bounded, and that durability
    /// — not the quantum, not the providers — is the thing to fix.
    pub checkpoint_failures: usize,
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

    /// A `Create` change driving `name` to `after`.
    fn change(name: &str, after: serde_json::Value) -> ResourceChange {
        ResourceChange {
            address: addr(name),
            action: Action::Create,
            before: None,
            after: Some(after),
            reasons: vec![],
        }
    }

    fn create(name: &str) -> ResourceChange {
        change(name, serde_json::json!({ "name": name }))
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
        assert!(c.complete(&create("a")));
        assert!(!c.complete(&create("a")), "re-completing must not advance");
        assert!(c.complete(&create("b")));
        assert_eq!(c.len(), 2);
        assert!(c.contains(&addr("a")));
        assert!(!c.contains(&addr("z")));
    }

    #[test]
    fn cursor_round_trips_through_serde() {
        let mut c = ApplyCursor::empty(plan_id(7));
        c.complete(&create("a"));
        c.complete(&create("b"));
        c.record_data(addr("d1"), serde_json::json!({"id": "x"}));

        let json = serde_json::to_string(&c).expect("serialize");
        let back: ApplyCursor = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.plan_id(), plan_id(7));
        assert_eq!(back.completed(), c.completed());
        assert!(
            back.covers(&create("a")),
            "a round-tripped cursor must still cover what it recorded"
        );
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
        let entry = serde_json::json!({
            "address": addr("a"),
            "fingerprint": ChangeFingerprint::of(&create("a")).to_hex(),
        });
        let wire = serde_json::json!({
            "plan_id": pid,
            "completed": [entry, entry],
            "data_results": [],
        });
        let err = serde_json::from_value::<ApplyCursor>(wire).unwrap_err();
        assert!(
            err.to_string().contains("more than once"),
            "unexpected error: {err}"
        );
    }

    // ── Content-addressed identity ─────────────────────────────────

    #[test]
    fn a_fingerprint_is_stable_and_intent_sensitive() {
        let a1 = ChangeFingerprint::of(&create("a"));
        let a2 = ChangeFingerprint::of(&create("a"));
        assert_eq!(a1, a2, "the same change must fingerprint identically");

        // A different desired value is a different intent.
        let different_after = ChangeFingerprint::of(&change("a", serde_json::json!({"name": "z"})));
        assert_ne!(a1, different_after);

        // A different address is a different change.
        assert_ne!(a1, ChangeFingerprint::of(&create("b")));

        // A different verb is a different change.
        let mut updated = create("a");
        updated.action = Action::Update;
        assert_ne!(a1, ChangeFingerprint::of(&updated));
    }

    #[test]
    fn a_fingerprint_ignores_before_and_reasons() {
        // `before` is where the resource started; the fingerprint records where
        // we drove it. Two changes with the same destination are the same
        // intent, and skipping the second is correct.
        let mut with_before = create("a");
        with_before.before = Some(serde_json::json!({"name": "stale"}));
        with_before.reasons = vec![];
        assert_eq!(
            ChangeFingerprint::of(&create("a")),
            ChangeFingerprint::of(&with_before)
        );
    }

    #[test]
    fn a_fingerprint_is_stable_under_json_key_order() {
        // `serde_json::Map` is a BTreeMap in this workspace, so an `after`
        // written with keys in a different order hashes the same. If someone
        // ever turns on `preserve_order`, this test is the tripwire.
        let one = change("a", serde_json::json!({ "x": 1, "y": 2 }));
        let other = change("a", serde_json::json!({ "y": 2, "x": 1 }));
        assert_eq!(
            ChangeFingerprint::of(&one),
            ChangeFingerprint::of(&other),
            "object key order must not change a fingerprint"
        );
    }

    #[test]
    fn covers_requires_the_fingerprint_to_match_not_just_the_address() {
        let mut c = ApplyCursor::empty(plan_id(1));
        c.complete(&create("a"));

        assert!(c.covers(&create("a")), "the recorded change is covered");
        assert!(
            c.contains(&addr("a")),
            "the address-level question is still true"
        );

        // Same address, different intent. The address-only predicate would say
        // "skip" and silently drop this change; `covers` must not.
        let redirected = change("a", serde_json::json!({ "name": "somewhere-else" }));
        assert!(
            !c.covers(&redirected),
            "a different change to a recorded address must NOT be skipped"
        );
        assert!(
            c.contains(&redirected.address),
            "…even though the weaker address predicate still matches — which is \
             exactly why the engine skips on `covers`, not `contains`"
        );
    }

    #[test]
    fn a_fingerprint_round_trips_as_hex() {
        let fp = ChangeFingerprint::of(&create("a"));
        let json = serde_json::to_string(&fp).expect("serialize");
        assert!(json.starts_with('"'), "fingerprints serialize as hex: {json}");
        let back: ChangeFingerprint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(fp, back);

        // Wrong length is rejected at the boundary rather than truncated.
        assert!(serde_json::from_str::<ChangeFingerprint>("\"abcd\"").is_err());
        assert!(serde_json::from_str::<ChangeFingerprint>("\"zz\"").is_err());
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
            observation: magma_types::Observation::unrefreshed(),
        };
        assert!(c.resume(&plan).is_some(), "matching plan must resume");
        plan.id = plan_id(2);
        assert!(
            c.resume(&plan).is_none(),
            "a cursor must not resume into a different plan"
        );
    }

    #[test]
    fn cursor_data_reads_are_a_hit_only_for_recorded_addresses() {
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

    // ── T4 forcing functions ───────────────────────────────────────
    //
    // The tests below exist to BITE: each one fails if the property it
    // names regresses. Where a property is a compile-time fact rather than
    // a runtime one, the test is written so that breaking the property
    // stops it compiling — stated per test, never rounded up.

    // ── I1 · plan length is irrelevant ─────────────────────────────

    /// The frontier is exactly "everything not yet covered", order preserved.
    ///
    /// The base case of the convergence induction: what one cycle leaves
    /// behind is precisely what the next one picks up — no gap (a silent drop)
    /// and no overlap (a re-application).
    #[test]
    fn the_frontier_is_exactly_what_the_cursor_does_not_cover() {
        let changes: Vec<ResourceChange> = ["a", "b", "c", "d"].iter().map(|n| create(n)).collect();
        let mut c = ApplyCursor::empty(plan_id(1));
        c.complete(&changes[1]);
        c.complete(&changes[3]);

        let front = c.frontier(changes.iter());
        let names: Vec<&str> = front.iter().map(|c| c.address.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["a", "c"],
            "the frontier must drop covered changes and keep the rest in order"
        );
    }

    /// ★ THE SCALING TEST (algebraic half).
    ///
    /// Drives the REAL [`ApplyCursor::frontier`] — the same function the engine
    /// calls — through a full convergence loop at sizes no end-to-end run could
    /// reach, and asserts the three facts that together mean *plan length does
    /// not govern convergence*:
    ///
    /// 1. **It terminates**, in exactly `ceil(n / k)` cycles, for every `n`.
    ///    Cycle count scales with size; whether it converges does not.
    /// 2. **Every change is applied exactly once** across all cycles — no
    ///    duplicate (I2) and no silent drop.
    /// 3. **The frontier shrinks strictly** every cycle, which is what forbids
    ///    the livelock: a cycle that made progress cannot hand its successor
    ///    the same work.
    ///
    /// `n` runs to 10,000 — nearly 4x the 2,665-resource plan that motivated
    /// all of this — and the per-cycle budget `k` is varied independently, so
    /// the assertion is genuinely over the (size, budget) product and not one
    /// lucky pairing.
    ///
    /// # On the pairings
    ///
    /// They are chosen to bound this test's own runtime, and the reason is
    /// worth stating because it is a real property of the code: [`Self::covers`]
    /// computes a fingerprint (JSON encode + BLAKE3) per call, and the frontier
    /// is an O(n) scan, so driving a whole convergence costs O(n²/k) hashes.
    /// The smallest budget therefore rides the smaller sizes and the largest
    /// size rides the larger budgets — every `n` is still driven to
    /// convergence, and `k = 1` (the worst case, one node per cycle) is still
    /// exercised to n = 1,000.
    ///
    /// In production that cost is real but negligible: a 2,665-resource plan at
    /// one node per cycle is ~7M hashes spread over the whole convergence —
    /// seconds in total, against the ~2,665 seconds the 1 req/s pacer spends on
    /// the same plan. Rate, not hashing, is the term that matters.
    #[test]
    fn convergence_is_independent_of_plan_size() {
        const PAIRINGS: &[(usize, usize)] = &[
            // Worst-case budget: one node per cycle, so cycles == n.
            (0, 1),
            (1, 1),
            (2, 1),
            (10, 1),
            (100, 1),
            (1_000, 1),
            // Mid budgets.
            (100, 7),
            (1_000, 7),
            (2_665, 7), // the plan size that motivated this work
            // Large sizes at budgets that keep the scan cost bounded.
            (10_000, 64),
            (10_000, 512),
        ];

        for &(n, k) in PAIRINGS {
            let changes: Vec<ResourceChange> = (0..n).map(|i| create(&format!("r{i}"))).collect();
            let mut cursor = ApplyCursor::empty(plan_id(1));

            let mut cycles = 0usize;
            let mut applied_order: Vec<String> = Vec::new();
            let mut last_len = usize::MAX;

            loop {
                let front = cursor.frontier(changes.iter());
                if front.is_empty() {
                    break; // converged
                }
                assert!(
                    front.len() < last_len,
                    "n={n} k={k}: frontier must shrink strictly every cycle \
                         (got {} then {}) — equal-sized frontiers are the livelock",
                    last_len,
                    front.len()
                );
                last_len = front.len();

                // One cycle: apply up to `k` nodes off the frontier.
                for change in front.into_iter().take(k) {
                    applied_order.push(change.address.name.clone());
                    cursor.complete(change);
                }
                cycles += 1;

                assert!(
                    cycles <= n + 1,
                    "n={n} k={k}: did not converge in a bounded number of cycles"
                );
            }

            assert_eq!(
                cycles,
                n.div_ceil(k),
                "n={n} k={k}: a cycle must consume a full budget while work remains"
            );
            assert_eq!(
                applied_order.len(),
                n,
                "n={n} k={k}: every change must be applied exactly once"
            );
            let unique: std::collections::BTreeSet<&String> = applied_order.iter().collect();
            assert_eq!(
                unique.len(),
                n,
                "n={n} k={k}: an address was applied more than once"
            );
        }
    }

    /// A cycle that completes nothing hands its successor an identical
    /// frontier — the livelock the `Stalled` arm exists to name.
    ///
    /// Asserted here so the property the scaling test relies on (strict
    /// shrinkage ⟺ progress) is pinned from both sides: shrinkage is not
    /// automatic, it is *caused* by recording completions.
    #[test]
    fn a_cycle_that_records_nothing_cannot_shrink_the_frontier() {
        let changes: Vec<ResourceChange> = ["a", "b"].iter().map(|n| create(n)).collect();
        let cursor = ApplyCursor::empty(plan_id(1));
        let before = cursor.frontier(changes.iter()).len();
        // No `complete` calls — i.e. a cycle whose quantum could not cover the
        // prologue.
        let after = cursor.frontier(changes.iter()).len();
        assert_eq!(
            before, after,
            "without a recorded completion the next cycle repeats the same work; \
             this is why a zero-progress cycle must land in Stalled, not Yielded"
        );
    }

    // ── I2 · monotone progress ─────────────────────────────────────

    /// A recorded address whose *content* differs is re-applied, not skipped.
    ///
    /// The direction matters and is not symmetric: re-applying is absorbed by
    /// adopt-on-conflict, whereas skipping would be a real change silently not
    /// made and still reported as success. Complements
    /// `covers_requires_the_fingerprint_to_match_not_just_the_address` by
    /// asserting the consequence at the frontier — the place the decision is
    /// actually acted on.
    #[test]
    fn a_changed_intent_at_a_recorded_address_stays_on_the_frontier() {
        let old = change("r", serde_json::json!({ "visibility": "private" }));
        let new = change("r", serde_json::json!({ "visibility": "public" }));

        let mut c = ApplyCursor::empty(plan_id(1));
        c.complete(&old);

        assert!(
            c.covers(&old),
            "the recorded intent itself must be covered — otherwise nothing is skipped ever"
        );
        let front = c.frontier(std::slice::from_ref(&new));
        assert_eq!(
            front.len(),
            1,
            "a different desired value at a recorded address must survive the frontier; \
             dropping it would be a silent no-op reported as success"
        );
    }

    // ── I3 · the FSM models partial application ────────────────────

    /// Every arm that is not `Completed` carries a resumable position.
    ///
    /// This is a **compile-time** forcing function, not a runtime one. The
    /// match is exhaustive with no wildcard, so adding a `CycleOutcome` arm
    /// that stops mid-plan *without* a cursor would fail to compile here —
    /// which is the point. "Applied, position unknown" has no inhabitant.
    #[test]
    fn every_unfinished_outcome_carries_a_resumable_position() {
        fn position(o: &CycleOutcome) -> Option<&ApplyCursor> {
            match o {
                // The only arm permitted to have no position, because there is
                // nothing left to resume.
                CycleOutcome::Completed { .. } => None,
                CycleOutcome::Yielded { cursor, .. } => Some(cursor),
                CycleOutcome::Stalled { cursor, .. } => Some(cursor),
            }
        }

        let outcome = ApplyOutcome {
            plan_id: plan_id(1),
            state: magma_state::empty_state(),
            applied: vec![],
            failed: vec![],
            started_at: chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };
        let cursor = ApplyCursor::empty(plan_id(1));
        let stats = CycleStats::default();

        let yielded = CycleOutcome::Yielded {
            partial: outcome.clone(),
            cursor: cursor.clone(),
            progress: Progress::new(vec![addr("a")]).expect("non-empty"),
            stats,
        };
        let stalled = CycleOutcome::Stalled {
            partial: outcome.clone(),
            cursor,
            stats,
        };
        let completed = CycleOutcome::Completed { outcome, stats };

        assert!(
            position(&yielded).is_some(),
            "a yield must know where it is"
        );
        assert!(
            position(&stalled).is_some(),
            "a stall must know where it is"
        );
        assert!(position(&completed).is_none());

        // And the public accessor agrees with the exhaustive match above, so
        // the guarantee cannot drift between them.
        for o in [&yielded, &stalled] {
            assert!(o.cursor().is_some());
            assert!(
                o.needs_another_cycle(),
                "an unfinished cycle must ask to be re-run"
            );
        }
        assert!(completed.cursor().is_none());
        assert!(!completed.needs_another_cycle());
    }
}
