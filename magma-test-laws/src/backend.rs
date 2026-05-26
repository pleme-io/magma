//! Reusable trait-law helpers for `magma_backend::Backend` impls.
//!
//! Every Backend in the substrate (LocalBackend, InMemoryBackend,
//! S3, GCS, Postgres, etc.) must obey the universal Backend laws.
//! These helpers turn each law into a one-line test:
//!
//! ```no_run
//! # use magma_test_laws::backend::*;
//! # use magma_backend::InMemoryBackend;
//! #[tokio::test]
//! async fn inmemory_backend_obeys_all_laws() {
//!     let b = InMemoryBackend::new();
//!     assert_write_read_round_trip(&b).await;
//!     assert_read_idempotent(&b).await;
//!     assert_lock_unlock_round_trip(&b).await;
//!     assert_serial_monotonic(&b).await;
//! }
//! ```
//!
//! Gated behind `backend-laws` feature. Per
//! `theory/CONVERGENCE-SUBSTRATE.md` §V.4 (durable state).

use magma_backend::{Backend, LockId};
use magma_state::empty_state;
use magma_types::State;

// ── Law 1: write-then-read returns the written state ──────────────

/// After `write_state(s)`, the next `read_state()` returns a State
/// equal to `s` (modulo serial+lineage which are durable identity).
pub async fn assert_write_read_round_trip<B: Backend>(b: &B) {
    let mut s = empty_state();
    s.serial = 42;
    b.write_state(&s).await.expect("write_state failed");
    let read = b.read_state().await.expect("read_state failed");
    assert_eq!(
        read.serial, s.serial,
        "Backend law violated: write-then-read did not preserve serial",
    );
    assert_eq!(
        read.lineage, s.lineage,
        "Backend law violated: write-then-read did not preserve lineage",
    );
    assert_eq!(
        read.resources.len(),
        s.resources.len(),
        "Backend law violated: write-then-read did not preserve resources",
    );
}

// ── Law 2: read is referentially transparent ──────────────────────

/// Two consecutive `read_state()` calls (no intervening write)
/// return equal States. This is the durable equivalent of
/// `Reconciler.read_state` idempotency.
pub async fn assert_read_idempotent<B: Backend>(b: &B) {
    let s1 = b.read_state().await.expect("read #1 failed");
    let s2 = b.read_state().await.expect("read #2 failed");
    assert_eq!(
        s1.lineage, s2.lineage,
        "Backend law violated: read_state is not referentially transparent (lineage diverged)",
    );
    assert_eq!(
        s1.serial, s2.serial,
        "Backend law violated: read_state is not referentially transparent (serial diverged)",
    );
}

// ── Law 3: lock-then-unlock is a round trip ───────────────────────

/// `lock()` produces an id; `unlock(id)` succeeds without error.
pub async fn assert_lock_unlock_round_trip<B: Backend>(b: &B) {
    let id = b.lock().await.expect("lock failed");
    b.unlock(&id)
        .await
        .expect("unlock with correct id failed — round trip broken");
}

// ── Law 4: unlock with wrong id is detectable ─────────────────────

/// Calling `unlock(bogus)` either errors loudly or, for memory
/// backends with no cross-process exclusion, succeeds silently.
/// This helper only requires that the call NOT PANIC — different
/// backends have different concurrency semantics.
pub async fn assert_unlock_does_not_panic<B: Backend>(b: &B) {
    let bogus = LockId("not-the-real-id".into());
    let _ = b.unlock(&bogus).await; // result intentionally ignored
}

// ── Law 5: serial monotonically increases under repeated writes ──

/// Two writes with increasing serial values are durably preserved
/// in order — a second read sees the second serial.
pub async fn assert_serial_monotonic<B: Backend>(b: &B) {
    let mut s = empty_state();
    s.serial = 1;
    b.write_state(&s).await.expect("write #1 failed");
    let r1 = b.read_state().await.expect("read #1 failed");
    assert_eq!(r1.serial, 1);

    let mut s2 = r1.clone();
    s2.serial = 2;
    b.write_state(&s2).await.expect("write #2 failed");
    let r2 = b.read_state().await.expect("read #2 failed");
    assert_eq!(
        r2.serial, 2,
        "Backend law violated: serial did not advance after second write",
    );
}

// ── Composite: assert all laws back-to-back ───────────────────────

/// Run every Backend law against `b`. Convenience for impls that
/// don't need bespoke per-law setup. Panics on the first violation
/// with a clear message naming the broken law.
pub async fn assert_all_laws<B: Backend>(b: &B) {
    assert_read_idempotent(b).await;
    assert_write_read_round_trip(b).await;
    assert_lock_unlock_round_trip(b).await;
    assert_unlock_does_not_panic(b).await;
    assert_serial_monotonic(b).await;
}

// ── Optional: round-trip a State through serde for backends that
// persist via JSON. Useful for catching JSON-vs-binary divergence.

/// Round-trip an in-memory State through `serde_json::to_value` +
/// `from_value` and assert equality. Doesn't touch the backend at
/// all — pure type-shape test. Useful in a `#[test]` next to the
/// other law calls.
pub fn assert_state_serde_round_trip() {
    let s = empty_state();
    let v = serde_json::to_value(&s).expect("to_value failed");
    let back: State = serde_json::from_value(v).expect("from_value failed");
    assert_eq!(s.lineage, back.lineage);
    assert_eq!(s.serial, back.serial);
}
