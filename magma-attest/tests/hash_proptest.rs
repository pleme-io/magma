//! Property-based proofs for `magma_attest::hash_plan_inputs`.
//!
//! The function is small (4-line BLAKE3 wrapper) but it's the
//! attestation entry point — every tameshi receipt + bundle hash
//! flows through it. Lock the basic shape invariants.

use magma_attest::hash_plan_inputs;
use proptest::prelude::*;

// ── Property 1: deterministic over arbitrary bytes ─────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn hash_is_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let a = hash_plan_inputs(&bytes);
        let b = hash_plan_inputs(&bytes);
        prop_assert_eq!(a.0, b.0);
    }
}

// ── Property 2: output is always 32 bytes (BLAKE3 hash length) ────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn hash_output_is_32_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let h = hash_plan_inputs(&bytes);
        prop_assert_eq!(h.0.len(), 32);
    }
}

// ── Property 3: different inputs yield different outputs ───────────
//
// Sample two non-equal byte sequences + assert hashes differ. This
// is collision-resistance under BLAKE3 — guaranteed for distinct
// inputs of this size class.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn hash_diverges_for_distinct_inputs(
        a in proptest::collection::vec(any::<u8>(), 1..256),
        b in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(a != b);
        let ha = hash_plan_inputs(&a);
        let hb = hash_plan_inputs(&b);
        prop_assert_ne!(ha.0, hb.0);
    }
}

// ── Property 4: empty input doesn't panic + produces 32-byte hash ──

#[test]
fn empty_input_yields_well_formed_hash() {
    let h = hash_plan_inputs(b"");
    assert_eq!(h.0.len(), 32);
    // BLAKE3 of empty string is well-known; verify it's not zeros.
    assert_ne!(h.0, [0u8; 32]);
}

// ── Property 5: single-byte changes detectable ─────────────────────
//
// Avalanche property: flipping one bit anywhere in the input
// produces a hash that differs in many positions. We assert at
// least 1 byte differs (the strict avalanche criterion is stronger
// but this is the contract magma-attest depends on).

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn single_byte_flip_changes_hash(
        bytes in proptest::collection::vec(any::<u8>(), 1..128),
        flip_idx in 0usize..128usize,
    ) {
        let mut mutated = bytes.clone();
        let i = flip_idx % mutated.len();
        mutated[i] = mutated[i].wrapping_add(1);
        let ha = hash_plan_inputs(&bytes);
        let hb = hash_plan_inputs(&mutated);
        prop_assert_ne!(ha.0, hb.0);
    }
}
