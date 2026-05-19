//! Property-based proofs for `magma-spec` plan comparison + what-if.
//!
//! Properties:
//! 1. `compare_plans(a, a)` is identical.
//! 2. compare counts are consistent: only_in_before + in_both + diverged
//!    == a.changes.len(); same for after side.
//! 3. compare is "swap-symmetric": compare(a,b) and compare(b,a) swap
//!    only_in_before ↔ only_in_after; in_both + diverged identical.
//! 4. StateMutation::apply round-trips: SetKey(k,v) then RemoveKey(k)
//!    yields original-minus-k.
//! 5. Replace mutation produces exact target.
//! 6. compare_plans preserves PlanIds (no swap).

use std::collections::HashSet;

use magma_spec::{compare_plans, StateMutation};
use magma_test_laws::strategies::arb_plan;
use proptest::prelude::*;
use serde_json::{json, Value};

// ── Property 1: comparing a plan with itself is identical ─────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn compare_with_self_is_identical(plan in arb_plan()) {
        let cmp = compare_plans(&plan, &plan);
        prop_assert!(cmp.is_identical(), "self-compare not identical: {cmp:?}");
        prop_assert_eq!(cmp.in_both.len(), plan.changes.len());
        prop_assert_eq!(cmp.only_in_before.len(), 0);
        prop_assert_eq!(cmp.only_in_after.len(),  0);
        prop_assert_eq!(cmp.diverged.len(), 0);
    }
}

// ── Property 2: counts sum to input lengths ────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn compare_counts_sum_to_input_sizes(a in arb_plan(), b in arb_plan()) {
        let cmp = compare_plans(&a, &b);
        let (only_before, only_after, diverged, in_both) = cmp.counts();
        // Every Change in `a` is accounted for in exactly one of
        // only_in_before, in_both, diverged.
        let a_addrs: HashSet<&str> = a.changes.iter().map(|c| c.address.as_str()).collect();
        let b_addrs: HashSet<&str> = b.changes.iter().map(|c| c.address.as_str()).collect();
        // a-side sum equals a-side address count.
        prop_assert_eq!(only_before + in_both + diverged, a_addrs.len());
        prop_assert_eq!(only_after  + in_both + diverged, b_addrs.len());
    }
}

// ── Property 3: swap-symmetric ─────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn compare_is_swap_symmetric(a in arb_plan(), b in arb_plan()) {
        let ab = compare_plans(&a, &b);
        let ba = compare_plans(&b, &a);
        // Swap only_in_before with only_in_after.
        prop_assert_eq!(ab.only_in_before.len(), ba.only_in_after.len());
        prop_assert_eq!(ab.only_in_after.len(),  ba.only_in_before.len());
        // in_both + diverged sizes invariant under swap.
        prop_assert_eq!(ab.in_both.len(),  ba.in_both.len());
        prop_assert_eq!(ab.diverged.len(), ba.diverged.len());
    }
}

// ── Property 4: SetKey then RemoveKey round-trips ──────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn set_then_remove_yields_minus_key(
        k in "[a-z][a-z0-9_]{0,5}",
        v in (0i64..1000).prop_map(|n| json!(n)),
    ) {
        let initial = json!({"existing": 1});
        let after_set = StateMutation::SetKey(k.clone(), v).apply(&initial);
        let after_remove = StateMutation::RemoveKey(k).apply(&after_set);
        // After set+remove of the same key, state equals original.
        prop_assert_eq!(after_remove, initial);
    }
}

// ── Property 5: Replace is exact ───────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn replace_mutation_is_exact(target in (0i64..1000).prop_map(|n| json!({"only": n}))) {
        let any_initial: Value = json!({"x": 1, "y": "hello"});
        let result = StateMutation::Replace(target.clone()).apply(&any_initial);
        prop_assert_eq!(result, target);
    }
}

// ── Property 6: compare preserves plan IDs ─────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn compare_preserves_plan_ids(a in arb_plan(), b in arb_plan()) {
        let cmp = compare_plans(&a, &b);
        prop_assert_eq!(&cmp.before, &a.id);
        prop_assert_eq!(&cmp.after,  &b.id);
    }
}
