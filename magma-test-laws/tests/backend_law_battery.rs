//! Integration test: every Backend impl in the substrate obeys the
//! universal Backend laws.
//!
//! Same pattern as `concrete_reconcilers_obey_laws.rs` — one test
//! per impl, each calling `assert_all_laws`. A failure means a
//! Backend drifted away from the contract.

#![cfg(feature = "backend-laws")]

use magma_backend::{InMemoryBackend, LocalBackend};
use magma_test_laws::backend::*;

// ── InMemoryBackend ────────────────────────────────────────────────

#[tokio::test]
async fn inmemory_backend_obeys_all_laws() {
    let b = InMemoryBackend::new();
    assert_all_laws(&b).await;
}

// ── LocalBackend ───────────────────────────────────────────────────

#[tokio::test]
async fn local_backend_obeys_all_laws() {
    let dir = tempfile::tempdir().unwrap();
    let b = LocalBackend::new(dir.path().to_path_buf());
    assert_all_laws(&b).await;
}

// ── Per-law convenience test (proves helpers work in isolation) ────

#[tokio::test]
async fn law_helpers_can_be_used_independently_on_inmemory() {
    let b = InMemoryBackend::new();
    assert_read_idempotent(&b).await;
    assert_write_read_round_trip(&b).await;
    assert_lock_unlock_round_trip(&b).await;
    assert_unlock_does_not_panic(&b).await;
    assert_serial_monotonic(&b).await;
}

#[test]
fn state_serde_round_trips() {
    assert_state_serde_round_trip();
}
