//! Durable per-node checkpointing — what makes bounded cycles *safe* rather
//! than an infinite retry loop.
//!
//! # The gap this closes
//!
//! [`crate::cursor`] made an unfinished apply carry a resumable position, so a
//! cycle that runs out of quantum yields instead of failing. But that cursor
//! was only handed back when the cycle *returned*. A process killed
//! mid-cycle — a spot reclaim, an OOM, a node roll, exactly the environment
//! this executor runs in — lost the whole cycle's record, and every node it had
//! already applied became a re-application candidate.
//!
//! So the exposure window was still a whole cycle. This module shrinks it to
//! one node by writing `(state, cursor)` durably as each node completes.
//!
//! # The correctness argument, stated precisely
//!
//! The defence against re-creating a resource across a crash is **not** the
//! cursor — it is the durably-checkpointed [`State`]. The planner NoOps
//! anything state already records, so a resource whose state landed is never
//! *planned* again, let alone applied. The cursor's job is narrower: skip
//! re-attempts *within* the plan currently being applied, so a resumed cycle
//! does not spend paced RPCs re-walking ground it covered.
//!
//! That split is why the two must be written together, and why the asymmetry
//! matters:
//!
//! * **cursor ahead of state** — the cursor claims a node is done while state
//!   has no record of it. The resumed cycle *skips* it, so the resource is
//!   never created. That is a **silent drop of a real change**: the apply
//!   reports success having quietly not done the work. This is the dangerous
//!   direction.
//! * **state ahead of cursor** — the node is re-attempted within the same
//!   plan. The provider rejects the duplicate as already-exists and the
//!   reactive adopt path (`importPolicy.autoOnConflict`, live on the
//!   `pleme-io-opensource` workspace today) absorbs it into state. Wasteful,
//!   not wrong.
//!
//! [`CheckpointSink`] therefore exposes exactly one method, and it takes
//! **both**. There is no method that writes a cursor alone, so "cursor ahead
//! of state" has no code path *at this seam* — it is not a discipline the
//! caller must remember, it is a shape the trait does not admit.
//!
//! # What is NOT claimed
//!
//! That the two land atomically in the *store* is the implementation's
//! promise, not this trait's. The seam makes the wrong call unwritable; it
//! cannot make a sloppy implementation transactional. The intended
//! implementation is pangea-operator's already-proven single-`Transaction`
//! upsert (`ArtifactStore::put_apply_result`, state row + artifact in one
//! Postgres transaction) extended with the cursor blob — so this is an
//! extension of a proven atomic write, not a new persistence layer.
//!
//! Nor does any of this make duplicate creates impossible. Cloud I/O is not
//! transactional: a create can commit provider-side in the instant between the
//! RPC returning and the checkpoint committing. Per-node checkpointing shrinks
//! that window to one node and hands the residue to adopt-on-conflict — and
//! adopt-on-conflict only fires for resources the provider *rejects* as
//! duplicates. A type the provider will happily create twice yields an orphan,
//! and no amount of checkpointing changes that. It is a C5 ceiling
//! (non-transactional cloud I/O), not debt.

use async_trait::async_trait;
use magma_types::State;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::cursor::ApplyCursor;

/// A checkpoint could not be made durable.
///
/// Deliberately opaque: the engine's reaction to a failed checkpoint does not
/// depend on *why* it failed. It stops applying, because continuing would grow
/// the set of nodes whose work is not durably recorded — which is precisely the
/// quantity this module exists to bound.
#[derive(Debug, Error)]
#[error("checkpoint: {0}")]
pub struct CheckpointError(pub String);

impl CheckpointError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Durable sink for apply progress.
///
/// One method, taking both halves, on purpose — see the module docs. An
/// implementation MUST make the two writes atomic; the trait's shape removes
/// the caller's ability to get the *ordering* wrong, and the implementation
/// owns the *atomicity*.
///
/// Implementations should be idempotent (upsert), because the engine may
/// checkpoint the same cursor twice if a cycle ends immediately after a node.
#[async_trait]
pub trait CheckpointSink: Send + Sync {
    /// Durably record that `cursor` is the position reached against `state`.
    ///
    /// Called after every node the cycle applies and after every deferred
    /// data-source read it newly caches. Both are durable advances worth
    /// keeping: a read costs a rate-limiter token, so losing one is a second of
    /// prologue the next cycle has to re-pay.
    async fn checkpoint(&self, state: &State, cursor: &ApplyCursor) -> Result<(), CheckpointError>;
}

/// Discards checkpoints.
///
/// The default when no sink is supplied, and what keeps every pre-existing
/// caller's behaviour byte-identical: an apply with no sink writes nothing
/// mid-cycle and returns exactly what it returned before this module existed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullCheckpointSink;

#[async_trait]
impl CheckpointSink for NullCheckpointSink {
    async fn checkpoint(
        &self,
        _state: &State,
        _cursor: &ApplyCursor,
    ) -> Result<(), CheckpointError> {
        Ok(())
    }
}

/// Keeps the most recent checkpoint in memory, plus a count.
///
/// This is the mockable `Environment` for the checkpoint seam (per the org's
/// TYPED-SPEC + INTERPRETER triplet rule): it lets the engine's durability
/// behaviour be proven with no database, no filesystem and no network. It is
/// also a legitimate runtime choice for a single-cycle unbounded apply, where
/// nothing outlives the process anyway.
#[derive(Debug, Default)]
pub struct MemoryCheckpointSink {
    last: Mutex<Option<(State, ApplyCursor)>>,
    writes: std::sync::atomic::AtomicUsize,
}

impl MemoryCheckpointSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many checkpoints have been accepted.
    pub fn writes(&self) -> usize {
        self.writes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The most recently recorded `(state, cursor)` pair, if any.
    pub async fn last(&self) -> Option<(State, ApplyCursor)> {
        self.last.lock().await.clone()
    }
}

#[async_trait]
impl CheckpointSink for MemoryCheckpointSink {
    async fn checkpoint(&self, state: &State, cursor: &ApplyCursor) -> Result<(), CheckpointError> {
        *self.last.lock().await = Some((state.clone(), cursor.clone()));
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::ApplyCursor;
    use magma_types::PlanId;

    fn empty_state() -> State {
        magma_state::empty_state()
    }

    #[tokio::test]
    async fn the_null_sink_accepts_everything_and_keeps_nothing() {
        let sink = NullCheckpointSink;
        let c = ApplyCursor::empty(PlanId([1; 32]));
        assert!(sink.checkpoint(&empty_state(), &c).await.is_ok());
    }

    #[tokio::test]
    async fn the_memory_sink_records_the_latest_pair_and_counts_writes() {
        let sink = MemoryCheckpointSink::new();
        assert_eq!(sink.writes(), 0);
        assert!(sink.last().await.is_none());

        let c = ApplyCursor::empty(PlanId([2; 32]));
        sink.checkpoint(&empty_state(), &c).await.expect("accepted");
        sink.checkpoint(&empty_state(), &c).await.expect("accepted");

        assert_eq!(sink.writes(), 2);
        let (_, got) = sink.last().await.expect("a pair was recorded");
        assert_eq!(got.plan_id(), PlanId([2; 32]));
    }

    /// The seam's whole point, expressed as a compile-time fact rather than a
    /// runtime assertion: a sink is handed both halves in one call, so there is
    /// no way to write a cursor without the state it corresponds to. If a
    /// future refactor split this into two methods, this test would stop
    /// compiling — which is the intent.
    #[tokio::test]
    async fn a_sink_can_only_be_handed_both_halves_together() {
        struct BothOrNothing;

        #[async_trait]
        impl CheckpointSink for BothOrNothing {
            async fn checkpoint(
                &self,
                state: &State,
                cursor: &ApplyCursor,
            ) -> Result<(), CheckpointError> {
                // Both are in scope, always. There is no arm of this trait
                // that sees one without the other.
                let _ = (state.serial, cursor.len());
                Ok(())
            }
        }

        let c = ApplyCursor::empty(PlanId([3; 32]));
        assert!(BothOrNothing.checkpoint(&empty_state(), &c).await.is_ok());
    }
}
