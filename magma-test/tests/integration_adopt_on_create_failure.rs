//! Integration laws for **adopt-on-create-failure** — the gate that decides
//! whether a resource which already exists on the provider gets adopted into
//! state or re-planned as a create forever.
//!
//! ## What changed, and why a new law battery exists for it
//!
//! Adoption used to be gated on `is_already_exists(&msg)`: a substring match
//! over the provider's own prose (`"already exists"`, `"422"`, `"409"`). That
//! oracle is a guess about a string. The gate is now the **provider's own
//! answer** — `ImportResourceState` returning a non-null state — which is a
//! fact about the world.
//!
//! The difference is not cosmetic, and the pleme-io-opensource wedge is the
//! proof: its stuck child creates did not fail with 422. They failed with
//! **404**, because the create was posted to a URL built from a parent name
//! that had been guessed from a naming convention instead of resolved from
//! state. Under the string oracle those resources were never even *considered*
//! for adoption, so every cycle re-planned ~50 creates against resources that
//! had existed on GitHub the whole time.
//!
//! Four laws:
//!
//!   1. a create that fails with a diagnostic that says nothing about
//!      already-existing is STILL adopted when the provider can import it;
//!   2. a create that fails and is genuinely absent stays a hard failure, and
//!      reports the ORIGINAL apply error (never the import's);
//!   3. adoption writes IDENTITY, not an import stub — the adopted state is
//!      immediately usable by dependents;
//!   4. **the wedge itself**: a resource that exists on the provider is not
//!      planned as a create on the next cycle. Laws 1–3 are about a single
//!      apply; law 4 is about the LOOP, which is where the operator's symptom
//!      actually lived (`failed=50`, same 50 addresses, every cycle, forever).
//!
//! ## Tier-honesty about law 4 — one cycle, not zero
//!
//! Adoption happens at APPLY time. The plan that is running when the conflict
//! is discovered still contains the create; only the NEXT plan is clean. Law 4
//! therefore pins convergence-by-controller (Viggy), **not** a plan-time
//! guarantee, and its assertions say so. Making the very first plan create-free
//! would need plan → adopt → replan, and `magma-apply` receives a plan, it does
//! not compute one — that loop belongs to `pangea-operator`'s import prepass.

use std::fs;
use std::path::PathBuf;

use magma_apply::engine::{ApplyContext, run_plan_with_providers};
use magma_config::Config;
use magma_types::{
    Action, ChangeReason, ModulePath, Plan, PlanId, ResourceAddress, ResourceChange, ResourceKind,
    ResourceTypeId, State,
};

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

/// A workspace whose `.terraform/providers/` holds only the mock binary,
/// named so `magma_providers::locate_provider(_, "mock")` finds it.
fn workspace_with_mock_provider() -> tempfile::TempDir {
    let td = tempfile::tempdir().expect("tempdir");
    let providers_dir = td.path().join(".terraform").join("providers");
    fs::create_dir_all(&providers_dir).expect("mkdir providers dir");
    let dest = providers_dir.join("terraform-provider-mock");
    fs::copy(mock_provider_binary(), &dest).expect("copy mock_provider binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms).expect("chmod +x");
    }
    td
}

fn create_of(name: &str) -> ResourceChange {
    ResourceChange {
        address: ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("mock_resource".to_string()),
            name: "under_test".to_string(),
            key: None,
        },
        action: Action::Create,
        before: None,
        // `mock_resource` is name-keyed, so the derived import id IS this
        // name — the same relationship `github_repository` has.
        after: Some(serde_json::json!({ "name": name })),
        reasons: vec![ChangeReason::AttributeDrift],
    }
}

fn plan_of(change: ResourceChange) -> Plan {
    Plan {
        id: PlanId([0u8; 32]),
        created_at: chrono::Utc::now(),
        config_root: PathBuf::new(),
        variables: Default::default(),
        resource_changes: vec![change],
        output_changes: Vec::new(),
        observation: magma_types::Observation::unrefreshed(),
    }
}

fn empty() -> State {
    State {
        version: 4,
        terraform_version: "1.9.0".to_string(),
        serial: 0,
        lineage: uuid::Uuid::nil(),
        outputs: Default::default(),
        resources: Vec::new(),
    }
}

// ── Law 1: the diagnostic is not the oracle ───────────────────────────────

/// The load-bearing law. `boom-adoptable` fails its create with a bare
/// **404**, a message containing none of `already exists` / `422` / `409`.
/// The provider can nonetheless import it, so it must be adopted.
///
/// RED RUN (performed, required — a gate never observed to fail may be
/// checking nothing): with the gate reverted to
/// `if change.action == Action::Create && is_already_exists(&msg)` this test
/// fails with `applied 0 / failed 1`, reason `404 Not Found`. That is the
/// live pleme-io-opensource symptom, reproduced offline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_that_fails_without_saying_already_exists_is_still_adopted() {
    let ws = workspace_with_mock_provider();
    let mut state = empty();
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();

    let outcome = run_plan_with_providers(&plan_of(create_of("boom-adoptable")), &mut state, &ctx)
        .await;

    assert!(
        outcome.failed.is_empty(),
        "a create whose failure diagnostic never mentions already-existing must \
         still be adopted when the provider can import it — the string oracle \
         is what left ~50 pleme-io-opensource children stuck: {:?}",
        outcome.failed
    );
    assert_eq!(outcome.applied.len(), 1, "the resource was adopted");
    assert_eq!(
        state.resources.len(),
        1,
        "adoption must land in state — that is what stops the NEXT plan from \
         proposing the same create"
    );
}

// ── Law 2: a genuine absence is still a genuine failure ───────────────────

/// Adoption must not swallow real failures. `missing-boom` fails its create
/// AND cannot be imported (the provider answers "resource not found"), so the
/// change stays failed — and the reported reason is the CREATE's error, not
/// the import's, because the create is what the operator asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_that_fails_and_is_genuinely_absent_stays_a_failure() {
    let ws = workspace_with_mock_provider();
    let mut state = empty();
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();

    let outcome =
        run_plan_with_providers(&plan_of(create_of("missing-boom")), &mut state, &ctx).await;

    assert_eq!(
        outcome.failed.len(),
        1,
        "an un-importable failed create is a real failure: {:?}",
        outcome.applied
    );
    assert!(
        outcome.applied.is_empty() && state.resources.is_empty(),
        "nothing may be written to state for a resource that does not exist"
    );
    let reason = &outcome.failed[0].reason;
    assert!(
        reason.contains("404"),
        "the ORIGINAL apply diagnostic must survive; reporting the import's \
         error instead would hide why the create failed: {reason}"
    );
}

// ── Law 3: adoption writes identity, not a stub ───────────────────────────

/// An adopted resource must carry its identity immediately. The mock models a
/// real provider's two-step import (`ImportResourceState` → stub,
/// `ReadResource` → hydrated), so a single-step adoption would land
/// `name: null` here — an address that exists in state while its identity does
/// not, which is the shape that makes every dependent's
/// `${…node_id}` / `${…name}` reference resolve to nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_adopted_resource_is_never_identity_less() {
    let ws = workspace_with_mock_provider();
    let mut state = empty();
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();

    let _ = run_plan_with_providers(&plan_of(create_of("boom-adoptable")), &mut state, &ctx).await;

    let attrs = &state.resources[0].instances[0].attributes;
    assert_eq!(
        attrs.get("name").and_then(|v| v.as_str()),
        Some("boom-adoptable"),
        "adopted state must carry identity: {attrs:?}"
    );
    assert!(
        attrs
            .get("imported_by")
            .is_some_and(|v| !v.is_null()),
        "the confirming ReadResource must have run — a bare import stub \
         leaves every computed attribute null: {attrs:?}"
    );
}

// ── Law 4: THE WEDGE — an existing resource stops being planned as a create ─

/// The address every cycle of the pleme-io-opensource template was stuck on.
const WEDGED: &str = "boom-adoptable";

/// The config the operator declares. `boom-adoptable` is the fixture's stand-in
/// for "this already exists on the provider": its create fails (with a bare
/// 404, saying nothing about already-existing) while `ImportResourceState`
/// answers for it — precisely the shape of a `github_issue_label` whose repo's
/// labels GitHub created at repo birth.
fn cfg_declaring_the_wedged_resource() -> Config {
    Config::from_json(serde_json::json!({
        "resource": { "mock_resource": { "under_test": { "name": WEDGED } } }
    }))
    .expect("config parses")
}

fn creates_of(plan: &Plan, addr_name: &str) -> usize {
    plan.resource_changes
        .iter()
        .filter(|c| c.action == Action::Create && c.address.name == addr_name)
        .count()
}

/// **The regression test for the reported defect.**
///
/// The operator's symptom was never a single failed apply — it was a loop that
/// could not leave it: `failed=50`, the same 50 addresses, every cycle,
/// indefinitely, because a resource that already existed on the provider was
/// re-planned as a create forever. This exercises the whole cycle boundary:
///
///   cycle 1: plan (create) → apply (create fails 404, provider CAN import it,
///            so it is adopted into state)
///   cycle 2: plan the SAME config against the state cycle 1 produced
///
/// and pins the property the loop was missing: **no create for that address on
/// cycle 2.** State is the only thing carrying the fact forward, which is why
/// this is the test that would have caught the defect and none of laws 1–3
/// would have — they all end at the apply boundary.
///
/// RED RUN (performed, required — a gate never observed to fail may be checking
/// nothing): with the adoption gate reverted to
/// `if change.action == Action::Create && is_already_exists(&msg)`, cycle 1
/// fails instead of adopting, state stays empty, and cycle 2 re-plans the exact
/// same create — the assertion below fires with `cycle 2 re-planned 1 create(s)`,
/// which IS the live wedge, reproduced offline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resource_that_exists_on_the_provider_is_not_planned_as_a_create_next_cycle() {
    let ws = workspace_with_mock_provider();
    let cfg = cfg_declaring_the_wedged_resource();
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();
    let mut state = empty();

    // ── cycle 1 ───────────────────────────────────────────────────────────
    let plan1 = magma_plan::plan(&cfg, &state).expect("cycle 1 plan");
    assert_eq!(
        creates_of(&plan1, "under_test"),
        1,
        "the fixture must actually start wedged — an empty state plans the \
         create that the provider will then refuse: {:?}",
        plan1.resource_changes
    );

    let outcome = run_plan_with_providers(&plan1, &mut state, &ctx).await;

    // ── cycle 2: the same config, against the state cycle 1 produced ──────
    //
    // Asserted BEFORE the per-cycle assertions below, deliberately: the wedge
    // is the property that was reported, so it must be the property that fires.
    // A red run that stops at "cycle 1 failed" proves an apply broke; a red run
    // that stops here proves the LOOP cannot leave the create — which is the
    // operator's actual symptom.
    let plan2 = magma_plan::plan(&cfg, &state).expect("cycle 2 plan");
    assert_eq!(
        creates_of(&plan2, "under_test"),
        0,
        "THE WEDGE: a resource that exists on the provider was re-planned as a \
         create. This is the pleme-io-opensource failure exactly — 50 addresses \
         re-proposed as creates every cycle against resources that had been on \
         GitHub the whole time. cycle 1 failures were {:?}; cycle 2 re-planned \
         {} create(s): {:?}",
        outcome.failed,
        creates_of(&plan2, "under_test"),
        plan2.resource_changes
    );

    // Why cycle 2 is clean, spelled out so a future regression cannot be
    // "explained" by some other mechanism: cycle 1 adopted, and the adoption
    // landed in STATE.
    assert!(
        outcome.failed.is_empty(),
        "cycle 1 must adopt rather than fail: {:?}",
        outcome.failed
    );
    assert_eq!(
        state.resources.len(),
        1,
        "adoption must be recorded in STATE — state is the only thing that \
         carries the fact into the next cycle"
    );

    // Stronger than the assertion above, and the real convergence claim: the
    // cycle is a fixpoint, not merely create-free. A leftover Update would
    // mean the loop still churns on an address it has nothing to do to.
    assert!(
        plan2
            .resource_changes
            .iter()
            .all(|c| c.action == Action::NoOp),
        "cycle 2 must be a fixpoint: {:?}",
        plan2.resource_changes
    );
}

/// Sanity: the fixture is not accidentally passing because the mock never
/// fails. A name WITHOUT the sentinel applies normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fixture_only_fails_on_the_sentinel() {
    let ws = workspace_with_mock_provider();
    let mut state = empty();
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();
    let outcome = run_plan_with_providers(&plan_of(create_of("ordinary")), &mut state, &ctx).await;
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    assert_eq!(outcome.applied.len(), 1);
}

// ── Law 5: an import that finds the WRONG resource is refused ─────────────

/// A successful `ImportResourceState` answers *"something exists under this
/// id"*. It never answers *"this is the resource you planned"* — and nothing
/// else on the adoption path compares the two.
///
/// That gap is the price of widening the gate from "the diagnostic said
/// conflict" to "any failed create tries an import": every transient failure
/// now reaches the importer, and a derived id that is syntactically valid but
/// names a DIFFERENT real resource gets adopted under the planned address.
/// The next cycle then diffs config against that stranger and, if the provider
/// says `requires_replace`, routes it to `apply_replace` — a destroy of a live
/// resource nobody planned to touch. (`PROTECTED_RESOURCE_TYPES` in
/// pangea-operator's executor policy names no `github_*` type, so nothing
/// downstream catches it either.)
///
/// `boom-wrong` fails its create and the mock's importer returns a real state
/// belonging to `someone-elses-resource`. The adoption must be refused and the
/// ORIGINAL create error reported.
///
/// RED RUN (performed): with the `verify_identity` block removed from
/// `apply_one_inner`'s adopt arm this test fails with `failed 0 / applied 1`
/// and `state.resources[0].attributes.name == "someone-elses-resource"` —
/// i.e. magma silently takes ownership of a resource it was never asked to
/// touch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_import_that_returns_a_different_resource_is_refused() {
    let ws = workspace_with_mock_provider();
    let mut state = empty();
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();

    let outcome = run_plan_with_providers(&plan_of(create_of("boom-wrong")), &mut state, &ctx).await;

    assert!(
        state.resources.is_empty(),
        "magma must never take ownership of a resource it did not plan; state \
         holds: {:?}",
        state
            .resources
            .iter()
            .map(|r| r.instances[0].attributes.get("name").cloned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        outcome.failed.len(),
        1,
        "a refused adoption is a real failure, not a silent success: {:?}",
        outcome.applied
    );
    assert!(
        outcome.failed[0].reason.contains("404"),
        "the ORIGINAL create diagnostic must survive the refusal: {}",
        outcome.failed[0].reason
    );
}

// ── Law 6: a confirming read that says ABSENT is a refusal, not a stub ────

/// The import protocol's step 2 exists to answer a question step 1 cannot:
/// for a passthrough importer (`ImportStatePassthroughContext`, which
/// `github_repository` uses) `ImportResourceState` makes **no API call at
/// all** and will hand back a stub for any string. `ReadResource` returning a
/// cty-null `new_state` is the provider affirmatively saying the resource is
/// not there.
///
/// Treating that as a failed read and falling back to the stub is the worst
/// reachable outcome of the whole adoption path — strictly worse than the
/// re-create loop it replaces. The stub is persisted, its identity backfilled
/// from the import id so it looks healthy, the resource drops out of every
/// future plan, and it is **never created**. Silently.
///
/// `boom-vanished` fails its create, imports "successfully", and its
/// confirming read answers absent.
///
/// RED RUN (performed): with `import_and_confirm`'s `Ok(None)` arm folded back
/// into the catch-all `_ => imp_dv`, this test fails with `applied 1` and a
/// state entry for a resource that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_import_the_confirming_read_refutes_is_not_persisted() {
    let ws = workspace_with_mock_provider();
    let mut state = empty();
    let ctx = ApplyContext::new(ws.path().to_path_buf()).without_pacer();

    let outcome =
        run_plan_with_providers(&plan_of(create_of("boom-vanished")), &mut state, &ctx).await;

    assert!(
        state.resources.is_empty(),
        "a resource the provider says is absent must NEVER be written to \
         state — it would then never be created: {:?}",
        state.resources
    );
    assert_eq!(
        outcome.failed.len(),
        1,
        "the create genuinely failed and could not be adopted: {:?}",
        outcome.applied
    );
}
