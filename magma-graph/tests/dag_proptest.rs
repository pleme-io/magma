//! Property-based proofs for `ResourceGraph` DAG operations.
//!
//! Properties:
//! 1. `add` is idempotent — repeat adds yield the same node count.
//! 2. `waves` union equals every node added (no losses).
//! 3. Every edge `from → to` has from-wave-idx < to-wave-idx.
//! 4. Intra-wave nodes are pairwise independent (no edge between them).
//! 5. Cycles always produce `GraphError::CycleDetected`.
//! 6. Empty graph has empty waves.

use std::collections::{HashMap, HashSet};

use magma_graph::ResourceGraph;
use magma_types::{InstanceKey, ModulePath, ResourceAddress, ResourceKind, ResourceTypeId};
use proptest::prelude::*;

fn arb_address() -> impl Strategy<Value = ResourceAddress> {
    (
        "[a-z][a-z0-9_]{0,7}", // type
        "[a-z][a-z0-9_]{0,7}", // name
    )
        .prop_map(|(t, n)| ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId(t),
            name: n,
            key: None::<InstanceKey>,
        })
}

fn arb_unique_addresses(min: usize, max: usize) -> impl Strategy<Value = Vec<ResourceAddress>> {
    proptest::collection::vec(arb_address(), min..=max).prop_map(|mut v| {
        let mut seen = HashSet::new();
        v.retain(|a| seen.insert((a.type_id.0.clone(), a.name.clone())));
        v
    })
}

// Edge generator that produces a strict upper-triangular set on a
// sorted node list — guaranteed acyclic by construction.
fn arb_dag(
    addrs: Vec<ResourceAddress>,
) -> impl Strategy<Value = (Vec<ResourceAddress>, Vec<(usize, usize)>)> {
    let n = addrs.len();
    if n < 2 {
        return Just((addrs, vec![])).boxed();
    }
    let edge_strategy = proptest::collection::vec(
        (0..(n - 1)).prop_flat_map(move |lo| ((lo + 1)..n).prop_map(move |hi| (lo, hi))),
        0..=(n * 2),
    );
    edge_strategy
        .prop_map(move |edges| (addrs.clone(), edges))
        .boxed()
}

// ── Property 1: add is idempotent ─────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn add_is_idempotent(addr in arb_address(), repeats in 1usize..=5usize) {
        let mut g = ResourceGraph::new();
        for _ in 0..repeats {
            g.add(addr.clone());
        }
        prop_assert_eq!(g.len(), 1);
    }
}

// ── Property 2: waves union equals input ──────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn waves_union_equals_input_addresses(
        spec in arb_unique_addresses(1, 6).prop_flat_map(arb_dag),
    ) {
        let (addrs, edges) = spec;
        let mut g = ResourceGraph::new();
        for a in &addrs {
            g.add(a.clone());
        }
        for (lo, hi) in edges {
            g.depend(addrs[hi].clone(), addrs[lo].clone());
        }
        let waves = g.waves().unwrap();
        // `.flat_map(Wave::iter)` rather than `.flatten()`: `Wave` is not
        // `IntoIterator` precisely so that collapsing the decomposition is
        // always an explicit, greppable act. See `magma_graph::Waves`.
        let flat: HashSet<_> = waves.iter().flat_map(magma_graph::Wave::iter).collect();
        let want: HashSet<_> = addrs.iter().collect();
        prop_assert_eq!(flat, want);
    }
}

// ── Property 3: every edge has lower-wave from + higher-wave to ───

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn edges_respect_wave_ordering(
        spec in arb_unique_addresses(2, 6).prop_flat_map(arb_dag),
    ) {
        let (addrs, edges) = spec;
        if addrs.len() < 2 { return Ok(()); }
        let mut g = ResourceGraph::new();
        for a in &addrs {
            g.add(a.clone());
        }
        for &(lo, hi) in &edges {
            g.depend(addrs[hi].clone(), addrs[lo].clone());
        }
        let waves = g.waves().unwrap();
        let wave_idx: HashMap<ResourceAddress, usize> = waves
            .iter()
            .enumerate()
            .flat_map(|(i, w)| w.iter().map(move |a| (a.clone(), i)))
            .collect();
        for (lo, hi) in &edges {
            let from = &addrs[*lo];
            let to   = &addrs[*hi];
            prop_assert!(
                wave_idx[from] < wave_idx[to],
                "edge {from:?} → {to:?} not respected by wave order: from-wave={}, to-wave={}",
                wave_idx[from], wave_idx[to],
            );
        }
    }
}

// ── Property 4: cycles are always detected ────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn cycles_always_detected(
        addrs in arb_unique_addresses(2, 5),
    ) {
        let mut g = ResourceGraph::new();
        for a in &addrs {
            g.add(a.clone());
        }
        // Build a strict cycle: addrs[0] → addrs[1] → ... → addrs[n-1] → addrs[0]
        let n = addrs.len();
        for i in 0..n {
            let j = (i + 1) % n;
            g.depend(addrs[j].clone(), addrs[i].clone());
        }
        // detect_cycle returns Some(_) and waves returns Err.
        prop_assert!(g.detect_cycle().is_some(), "cycle not detected");
        prop_assert!(g.waves().is_err(), "waves() on cyclic graph did not error");
    }
}

// ── Property 5: empty graph has empty waves ────────────────────────

#[test]
fn empty_graph_has_empty_waves() {
    let g = ResourceGraph::new();
    assert!(g.is_empty());
    assert_eq!(g.len(), 0);
    let waves = g.waves().unwrap();
    assert_eq!(waves.len(), 0);
}
