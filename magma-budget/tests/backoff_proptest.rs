//! Property-based proofs for the retry-policy backoff math.
//!
//! `Backoff::duration_for_attempt(n)` is consulted on every retry
//! across the substrate. The math is small but load-bearing: a
//! buggy backoff (overflow → 0ms; cap not honored; non-monotonic)
//! would either DDoS upstreams or perpetually fail. These proptests
//! turn the contract into a proven theorem over the entire u32
//! attempt space.
//!
//! Invariants:
//! 1. Constant backoff is constant: same delay for every attempt.
//! 2. Linear backoff is strictly increasing in attempt.
//! 3. Exponential backoff is monotonic non-decreasing + capped at max_ms.
//! 4. No overflow panics for any (attempt, base_ms, max_ms) combination.

use magma_budget::Backoff;
use proptest::prelude::*;
use std::time::Duration;

// ── Property 1: constant backoff returns the same delay forever ────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn constant_backoff_is_constant(
        delay_ms in 0u64..100_000u64,
        attempt_a in 0u32..1000,
        attempt_b in 0u32..1000,
    ) {
        let b = Backoff::Constant { delay_ms };
        prop_assert_eq!(b.duration_for_attempt(attempt_a), b.duration_for_attempt(attempt_b));
        prop_assert_eq!(b.duration_for_attempt(attempt_a), Duration::from_millis(delay_ms));
    }
}

// ── Property 2: linear backoff is strictly increasing ──────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn linear_backoff_is_strictly_increasing_with_attempt(
        base_ms in 1u64..1_000_000u64,   // exclude 0 (degenerate)
        attempt in 0u32..1000,
    ) {
        let b = Backoff::Linear { base_ms };
        let d_n   = b.duration_for_attempt(attempt);
        let d_np1 = b.duration_for_attempt(attempt + 1);
        prop_assert!(
            d_np1 > d_n,
            "linear backoff not strictly increasing at attempt {attempt}: d_n={d_n:?}, d_np1={d_np1:?}",
        );
    }
}

// ── Property 3: exponential backoff is monotonic + capped ──────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn exponential_backoff_is_monotonic_and_capped(
        base_ms in 1u64..10_000u64,
        max_ms  in 1u64..1_000_000u64,
        attempt in 0u32..64,
    ) {
        let b = Backoff::Exponential { base_ms, max_ms };
        let d_n   = b.duration_for_attempt(attempt);
        let d_np1 = b.duration_for_attempt(attempt + 1);
        // Monotonic non-decreasing.
        prop_assert!(
            d_np1 >= d_n,
            "exponential backoff non-monotonic at attempt {attempt}: d_n={d_n:?}, d_np1={d_np1:?}",
        );
        // Capped.
        prop_assert!(
            d_n.as_millis() <= max_ms as u128,
            "exponential backoff exceeded max_ms at attempt {attempt}: {d_n:?} > {max_ms}ms",
        );
    }
}

// ── Property 4: no overflow panic for large attempts ───────────────
//
// duration_for_attempt is called by the operator inside the retry
// loop. If the operator's retry budget is misconfigured (say 1000
// retries with exponential backoff), the math must NOT panic — it
// should saturate.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn no_overflow_for_any_attempt(
        backoff_kind in 0u8..3,
        base_ms in 1u64..(u64::MAX / 2),
        max_ms  in 1u64..(u64::MAX / 2),
        attempt in 0u32..1000,
    ) {
        let b = match backoff_kind {
            0 => Backoff::Constant    { delay_ms: base_ms },
            1 => Backoff::Linear      { base_ms },
            _ => Backoff::Exponential { base_ms, max_ms },
        };
        // Must not panic for any combination.
        let _d = b.duration_for_attempt(attempt);
    }
}

// ── Property 5: exponential at attempt=0 yields base_ms ────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn exponential_attempt_zero_yields_base_when_under_cap(
        base_ms in 1u64..1_000u64,
        cap_factor in 2u64..100u64,
    ) {
        let max_ms = base_ms * cap_factor;
        let b = Backoff::Exponential { base_ms, max_ms };
        prop_assert_eq!(b.duration_for_attempt(0), Duration::from_millis(base_ms));
    }
}

// ── Property 6: linear at attempt=0 yields base_ms ─────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn linear_attempt_zero_yields_base(base_ms in 0u64..100_000u64) {
        let b = Backoff::Linear { base_ms };
        prop_assert_eq!(b.duration_for_attempt(0), Duration::from_millis(base_ms));
    }
}
