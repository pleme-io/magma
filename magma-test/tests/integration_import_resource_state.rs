//! Integration law battery for magma's resource-import capability.
//!
//! These tests drive the REAL client → prepass → absorb flow end-to-end
//! over a gRPC channel against the `mock_provider` binary (whose
//! `ImportResourceState` is implemented to return a canned imported
//! state). This closes the keystone gap: magma can now ADOPT a
//! pre-existing cloud/SaaS resource into state instead of re-planning
//! it as a create (which 422s "already exists") — the failure class
//! that wedged the rio pangea-operator (cloudflare-pleme +
//! pleme-io-opensource).
//!
//! Four laws, each over the real wire path:
//!
//!   1. explicit-id import absorbs a pre-existing resource;
//!   2. autoOnConflict converts an already-exists create into an import;
//!   3. import is idempotent (re-running absorbs nothing new, no RPC);
//!   4. a failed import is a typed per-resource FailedImport, not a panic.

use std::path::PathBuf;
use std::time::Duration;

use magma_apply::import_prepass::{
    ImportEnvironment, PluginImportEnvironment, import_on_conflict, run_explicit_prepass,
};
use magma_plugin::{Plugin, PluginSpec};
use magma_state::empty_state;
use magma_types::{ImportDirectives, ModulePath, ResourceAddress, ResourceKind, ResourceTypeId};

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

/// Spawn the mock provider, dial it (plain h2c), return a
/// `PluginImportEnvironment` ready to drive the real
/// `ImportResourceState` RPC. The `Plugin` is returned alongside so the
/// caller keeps the subprocess alive for the test's duration.
async fn spawn_import_env() -> (Plugin, PluginImportEnvironment) {
    let spec = PluginSpec {
        binary: mock_provider_binary(),
        kill_grace: Duration::from_secs(1),
        secure: false, // mock_provider runs plain h2c
        ..PluginSpec::default()
    };
    let mut plugin = Plugin::spawn(spec).await.expect("spawn mock provider");
    let channel = plugin.dial().await.expect("dial gRPC").clone();
    (plugin, PluginImportEnvironment::new(channel))
}

fn addr(type_id: &str, name: &str) -> ResourceAddress {
    ResourceAddress {
        module: ModulePath::root(),
        kind: ResourceKind::Managed,
        type_id: ResourceTypeId(type_id.into()),
        name: name.into(),
        key: None,
    }
}

// ── Law 1: explicit-id import absorbs a pre-existing resource ──────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_id_import_absorbs_through_real_rpc() {
    let (_plugin, env) = spawn_import_env().await;

    // Operator's spec.importHints: adopt a pre-existing cloudflare zone
    // by its zone id, and a github_repository by its name.
    let directives = ImportDirectives::default()
        .with_explicit("cloudflare_zone.quero_cloud", "abc123zoneid")
        .with_explicit("github_repository.galho", "galho");

    let mut state = empty_state();
    let outcome = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("prepass structural ok");

    // Both absorbed through the REAL ImportResourceState RPC.
    assert_eq!(
        outcome.newly_absorbed(),
        2,
        "both hinted resources absorbed: {outcome:?}",
    );
    assert!(outcome.all_succeeded(), "no failures: {outcome:?}");
    assert_eq!(state.resources.len(), 2);

    // The mock echoes the id into the absorbed attributes — proves the
    // DynamicValue round-tripped through the wire + decode path.
    let zone = state
        .resources
        .iter()
        .find(|r| r.address.type_id.0 == "cloudflare_zone")
        .expect("zone absorbed");
    assert_eq!(zone.address.name, "quero_cloud");
    assert_eq!(zone.instances[0].attributes["id"], "abc123zoneid");

    let repo = state
        .resources
        .iter()
        .find(|r| r.address.type_id.0 == "github_repository")
        .expect("repo absorbed");
    assert_eq!(repo.instances[0].attributes["id"], "galho");
}

// ── Law 2: autoOnConflict converts already-exists create → import ──

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auto_on_conflict_converts_create_into_import() {
    let (_plugin, env) = spawn_import_env().await;

    // Simulate the apply loop: a create for github_repository.galho was
    // rejected by the provider as already-exists. With
    // importPolicy.autoOnConflict, we retry as an import using the
    // resource's natural id (github_repository's id == the repo name).
    let mut state = empty_state();
    let target = addr("github_repository", "galho");
    let natural_id = "galho"; // derived from planned `after` attrs

    let absorbed = import_on_conflict(&env, &target, natural_id, &mut state)
        .await
        .expect("import-on-conflict succeeds against real RPC");

    assert!(absorbed, "the already-exists create became an import");
    assert_eq!(state.resources.len(), 1);
    assert_eq!(state.resources[0].address, target);
    assert_eq!(state.resources[0].instances[0].attributes["name"], "galho");
}

// ── Law 3: import is idempotent (re-run absorbs nothing, no RPC) ───

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_is_idempotent_over_real_rpc() {
    let (_plugin, env) = spawn_import_env().await;

    let directives =
        ImportDirectives::default().with_explicit("cloudflare_dns_record.api", "z1/rec1");

    let mut state = empty_state();

    // First prepass absorbs.
    let first = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("first prepass");
    assert_eq!(first.newly_absorbed(), 1);
    assert_eq!(state.resources.len(), 1);

    // Second prepass over the same state: the resource is already
    // present, so it's a NoOp — the receipt records it as not-absorbed
    // and no duplicate lands in state.
    let second = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("second prepass");
    assert_eq!(second.newly_absorbed(), 0, "idempotent: nothing new");
    assert_eq!(second.imported.len(), 1);
    assert!(!second.imported[0].absorbed);
    assert_eq!(state.resources.len(), 1, "no duplicate resource");
}

// ── Law 4: failed import is a typed per-resource FailedImport ──────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_import_is_typed_failure_not_panic() {
    let (_plugin, env) = spawn_import_env().await;

    // The mock returns an ERROR diagnostic for the sentinel id
    // "missing" — exactly what a real provider does for a bad import id.
    let directives = ImportDirectives::default()
        .with_explicit("cloudflare_zone.good", "realzoneid")
        .with_explicit("cloudflare_zone.bad", "missing");

    let mut state = empty_state();
    let outcome = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("prepass structurally ok even with a failing import");

    // The good one absorbed; the bad one is a typed FailedImport.
    assert_eq!(outcome.newly_absorbed(), 1);
    assert_eq!(outcome.failed.len(), 1, "exactly one failure: {outcome:?}");
    assert_eq!(outcome.failed[0].address, "cloudflare_zone.bad");
    assert!(
        outcome.failed[0].reason.contains("resource not found"),
        "failure reason carries the provider diagnostic: {:?}",
        outcome.failed[0].reason,
    );
    assert!(!outcome.all_succeeded());

    // Only the good resource landed; the failed one stays un-absorbed
    // (plan will re-propose it as Create — never a hard abort).
    assert_eq!(state.resources.len(), 1);
    assert_eq!(state.resources[0].address.name, "good");
}

// ── Bonus: the raw client surface returns typed ImportedInstance ───

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_import_client_returns_typed_instances() {
    let (_plugin, env) = spawn_import_env().await;
    // Drive the ImportEnvironment surface directly (the same call the
    // prepass makes) and assert the decoded typed shape.
    let instances = env
        .import_resource_state("aws_iam_role", "cluster-role-id")
        .await
        .expect("import RPC ok");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].type_name, "aws_iam_role");
    assert_eq!(instances[0].attributes["id"], "cluster-role-id");
    assert_eq!(instances[0].attributes["imported_by"], "mock_provider");
}
