//! ★ The scaling forcing function, end to end against a REAL provider.
//!
//! # What this file exists to prove
//!
//! That **plan length does not govern whether an apply converges**. A plan too
//! large to finish inside one scheduling quantum is a normal, modelled state:
//! the cycle yields with its position durably recorded, the next cycle resumes
//! at the frontier, and N cycles converge for any N.
//!
//! `magma-apply`'s unit tests prove the *algebra* of that (see
//! `cursor::tests::convergence_is_independent_of_plan_size`, which drives the
//! real frontier function to 10,000 changes). This file proves the **whole
//! machine**: real `Plugin::spawn`, real gRPC, real `ApplyResourceChange`, real
//! `State` writes, real cursor round-trips — driven in a loop until
//! `CycleOutcome::Completed`.
//!
//! # Why `terraform-provider-random`
//!
//! `random_id` applies with no credentials and no external API, so a plan of N
//! of them is a genuine multi-resource provider apply that touches no cloud and
//! consumes nobody's real rate limit. It is the only way to exercise the
//! convergence loop against something that actually *succeeds* — the in-crate
//! unit tests drive an unreachable provider, where every change fails and so
//! nothing is ever recorded as complete.
//!
//! The engine's own rate limiter IS configured here, but as a *test
//! instrument* rather than as the invariant under test — see
//! [`drive_to_convergence`] for why that is what makes these tests
//! deterministic. I5 has its own tests in `engine::tests`.
//!
//! Skips gracefully when the provider binary is absent, matching
//! `real_provider_apply.rs`, so a clean checkout never fails on it.
//!
//! # What that means for CI — stated plainly, not rounded up
//!
//! CI runs `cargo test --workspace` on a runner that has no
//! `terraform-provider-random` on disk, so **these tests skip there**. They are
//! a local/developer proof that the whole machine converges, NOT a gate that
//! blocks a merge. The half of I1 that genuinely gates CI is the algebraic one
//! in `cursor::tests::convergence_is_independent_of_plan_size`, which needs no
//! provider and therefore always runs.
//!
//! Point `MAGMA_TEST_WORKSPACE` at a directory that has run `tofu init` with
//! the `random` provider to turn these into a real gate.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use magma_apply::cursor::{ApplyCursor, CycleOutcome, Quantum};
use magma_apply::engine::{ApplyContext, run_plan_with_providers_resumable};
use magma_types::{
    Action, ModulePath, Plan, PlanId, ResourceAddress, ResourceChange, ResourceKind,
    ResourceTypeId, State,
};

/// A workspace that has run `init` and thus has a `random` provider on disk.
fn workspace() -> PathBuf {
    std::env::var("MAGMA_TEST_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(
                "/Users/drzzln/code/github/pleme-io/pangea-gems/pangea/test_infrastructure",
            )
        })
}

fn have_provider(ws: &PathBuf) -> bool {
    magma_providers::locate_provider(ws, "random").is_ok()
}

fn addr(name: &str) -> ResourceAddress {
    ResourceAddress {
        module: ModulePath::root(),
        kind: ResourceKind::Managed,
        type_id: ResourceTypeId("random_id".to_string()),
        name: name.to_string(),
        key: None,
    }
}

/// A plan of `n` independent `random_id` creates.
///
/// Independent on purpose: with no inter-resource references the dependency
/// graph is one wide wave, so the ONLY thing that can bound work per cycle is
/// the quantum. That isolates what is under test — if convergence needed
/// several cycles here, it is because the quantum cut the cycle short, not
/// because the graph forced a sequence.
fn plan_of(n: usize) -> Plan {
    Plan {
        id: PlanId([7u8; 32]),
        created_at: chrono::Utc::now(),
        config_root: PathBuf::new(),
        variables: HashMap::new(),
        resource_changes: (0..n)
            .map(|i| ResourceChange {
                address: addr(&format!("r{i}")),
                action: Action::Create,
                before: None,
                after: Some(serde_json::json!({ "byte_length": 4 })),
                reasons: Vec::new(),
            })
            .collect(),
        output_changes: Vec::new(),
        observation: magma_types::Observation::unrefreshed(),
    }
}

fn empty_state() -> State {
    State {
        version: 4,
        terraform_version: "1.9.0".to_string(),
        serial: 0,
        lineage: uuid::Uuid::nil(),
        outputs: HashMap::new(),
        resources: Vec::new(),
    }
}

/// What one full drive-to-convergence produced.
struct Convergence {
    cycles: usize,
    /// Every address reported applied, across all cycles, WITH duplicates kept
    /// — the raw evidence for the exactly-once assertion.
    applied: Vec<String>,
    yielded_at_least_once: bool,
    state: State,
}

/// One mutation per 100ms. See [`drive_to_convergence`] for why this is here.
const PACE_RPH: f64 = 36_000.0;
/// Comfortably above the fixed prologue, comfortably below one node's cost.
const QUANTUM_MS: u64 = 50;

/// Drive cycles until the plan completes, exactly as an operator's reconcile
/// loop would: re-enter with the previous cycle's cursor, never re-plan.
///
/// # Why this configures a pacer rather than turning it off
///
/// The first version of this test used an unpaced context and a 1ms quantum,
/// reasoning that a provider round-trip would obviously overrun it. It was
/// flaky in the worst way — it *passed* in a full-suite run and *failed* on the
/// next invocation — because `terraform-provider-random` is fast enough locally
/// that a whole cycle's fixed prologue also lands at ~1ms. The quantum was
/// racing the prologue, so the test was measuring the machine rather than the
/// property, and a lost race surfaces as `Stalled`.
///
/// Configuring the pacer fixes that at the root instead of by widening a
/// tolerance: it makes per-node cost a *controlled* quantity (~100ms) rather
/// than a machine-speed-dependent one. The quantum then sits ~50x above the
/// prologue and ~2x below a single node, so both margins come from a mechanism
/// the test owns.
///
/// `max_cycles` is a harness guard, not part of the contract — if it is ever
/// hit, the property under test has failed.
async fn drive_to_convergence(
    plan: &Plan,
    quantum: Option<Quantum>,
    max_cycles: usize,
) -> Convergence {
    // Built ONCE, outside the loop, so every cycle draws on the same token
    // bucket — which is also how the real engine is configured.
    let ctx = ApplyContext::new(workspace()).with_pace_rph(PACE_RPH);

    let mut state = empty_state();
    let mut cursor: Option<ApplyCursor> = None;
    let mut applied: Vec<String> = Vec::new();
    let mut cycles = 0usize;
    let mut yielded_at_least_once = false;

    loop {
        assert!(
            cycles < max_cycles,
            "did not converge within {max_cycles} cycles — plan size is governing \
             convergence, which is exactly what must not happen"
        );

        let resume = cursor.as_ref().and_then(|c| c.resume(plan));
        let outcome =
            run_plan_with_providers_resumable(plan, &mut state, &ctx, resume, quantum, None).await;
        cycles += 1;

        for a in &outcome.outcome().applied {
            applied.push(a.address.name.clone());
        }
        assert!(
            outcome.outcome().failed.is_empty(),
            "cycle {cycles} had provider failures: {:?}",
            outcome.outcome().failed
        );

        match outcome {
            CycleOutcome::Completed { .. } => {
                return Convergence {
                    cycles,
                    applied,
                    yielded_at_least_once,
                    state,
                };
            }
            CycleOutcome::Yielded {
                cursor: c,
                progress,
                ..
            } => {
                // A yield must be a real advance — the type says so, and this
                // re-states it where a regression would actually show up.
                assert!(!progress.as_slice().is_empty());
                yielded_at_least_once = true;
                cursor = Some(c);
            }
            CycleOutcome::Stalled { stats, .. } => {
                panic!(
                    "cycle {cycles} stalled: the quantum ({:?}ms) could not cover the \
                     fixed prologue ({}ms). That is a livelock, not a yield.",
                    stats.quantum_ms, stats.prologue_ms
                );
            }
        }
    }
}

/// ★ A plan that cannot finish in one quantum still converges.
///
/// The headline property. The quantum is half of what a single paced mutation
/// costs, so every cycle applies one or two resources and yields — and the loop
/// still reaches `Completed`, with every resource applied exactly once.
///
/// Before chunked resumption this shape had no successful outcome at all: the
/// apply was all-or-nothing, so a plan bigger than the window failed forever and
/// discarded its work each time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plan_too_large_for_one_quantum_converges_across_cycles() {
    let ws = workspace();
    if !have_provider(&ws) {
        eprintln!(
            "SKIP scaling_convergence: no `random` provider under {}",
            ws.display()
        );
        return;
    }

    const N: usize = 6;
    let plan = plan_of(N);
    let quantum = Quantum::new(Duration::from_millis(QUANTUM_MS)).expect("non-zero");

    let got = drive_to_convergence(&plan, Some(quantum), N * 4 + 8).await;

    assert!(
        got.yielded_at_least_once,
        "a {QUANTUM_MS}ms quantum over {N} paced mutations must yield at least \
         once; if it completed in one cycle this test is no longer exercising \
         resumption"
    );
    assert!(
        got.cycles > 1,
        "expected multiple cycles, got {}",
        got.cycles
    );

    // Exactly-once, the I2 half — asserted end to end rather than algebraically.
    let unique: HashSet<&String> = got.applied.iter().collect();
    assert_eq!(
        got.applied.len(),
        N,
        "every resource applied exactly once across {} cycles; got {:?}",
        got.cycles,
        got.applied
    );
    assert_eq!(
        unique.len(),
        N,
        "an address was applied twice: {:?}",
        got.applied
    );

    // And the cloud-side truth: N resources, each carrying provider-computed
    // attributes, i.e. the provider really ran for each one.
    assert_eq!(
        got.state.resources.len(),
        N,
        "all {N} resources are in state"
    );
    for r in &got.state.resources {
        let hex = r.instances[0]
            .attributes
            .get("hex")
            .and_then(|v| v.as_str());
        assert!(
            hex.is_some_and(|h| h.len() == 8),
            "byte_length=4 → 8 hex chars, provider-computed: {:?}",
            r.instances[0].attributes
        );
    }
}

/// ★ Convergence does not depend on plan size.
///
/// The same quantum against plans of increasing size. Every one converges; the
/// only thing that grows is the cycle count. That is the whole claim — "a
/// 2,665-resource plan and a 26,650-resource plan both converge" — measured
/// here at the sizes an end-to-end provider test can afford, and proven
/// algebraically to 10,000 in `cursor::tests`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn convergence_holds_across_plan_sizes() {
    let ws = workspace();
    if !have_provider(&ws) {
        eprintln!(
            "SKIP scaling_convergence: no `random` provider under {}",
            ws.display()
        );
        return;
    }

    let quantum = Quantum::new(Duration::from_millis(QUANTUM_MS)).expect("non-zero");
    let mut previous_cycles = 0usize;

    for n in [1usize, 3, 9] {
        let plan = plan_of(n);
        let got = drive_to_convergence(&plan, Some(quantum), n * 4 + 8).await;

        assert_eq!(
            got.applied.len(),
            n,
            "n={n}: every change applied exactly once, got {:?}",
            got.applied
        );
        assert_eq!(
            got.state.resources.len(),
            n,
            "n={n}: all resources in state"
        );
        assert!(
            got.cycles >= previous_cycles,
            "n={n}: a larger plan should not need FEWER cycles ({} vs {})",
            got.cycles,
            previous_cycles
        );
        previous_cycles = got.cycles;
    }
}

/// With no quantum the engine runs to completion in one cycle — the
/// pre-resumption behaviour, unchanged.
///
/// The negative control for the two tests above: it shows their multi-cycle
/// behaviour is caused by the quantum and not by something incidental, and it
/// pins the promise that adding resumption did not change the default path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbounded_cycle_still_completes_in_one_pass() {
    let ws = workspace();
    if !have_provider(&ws) {
        eprintln!(
            "SKIP scaling_convergence: no `random` provider under {}",
            ws.display()
        );
        return;
    }

    const N: usize = 4;
    let plan = plan_of(N);
    let got = drive_to_convergence(&plan, None, 3).await;

    assert_eq!(
        got.cycles, 1,
        "no quantum ⇒ no yield point ⇒ exactly one cycle"
    );
    assert!(!got.yielded_at_least_once);
    assert_eq!(got.applied.len(), N);
    assert_eq!(got.state.resources.len(), N);
}
