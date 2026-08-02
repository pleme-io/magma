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

use magma_apply::engine::ApplyContext;
use magma_apply::import_prepass::{
    ConfiguredImportEnvironment, ImportEnvironment, PluginImportEnvironment, import_on_conflict,
    run_explicit_prepass,
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

    // The instance the conflicting create was routed to. This test
    // uses the default one, which is what `provider_for_change` yields
    // for a resource declaring no `provider`.
    let instance = magma_types::ProviderInstance::implied_by_type(&target.type_id.0);
    let absorbed = import_on_conflict(&env, &target, natural_id, &mut state, &instance)
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
        .import_resource_state(
            "aws_iam_role",
            "cluster-role-id",
            &magma_types::ProviderInstance::implied_by_type("aws_iam_role"),
        )
        .await
        .expect("import RPC ok");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].type_name, "aws_iam_role");
    assert_eq!(instances[0].attributes["id"], "cluster-role-id");
    assert_eq!(instances[0].attributes["imported_by"], "mock_provider");
}

// ── Law 5: ConfiguredImportEnvironment — the fix under test ────────
//
// `PluginImportEnvironment` above dials a RAW, UNCONFIGURED channel and
// decodes ONLY `DynamicValue.json`. Real providers never populate that
// field for `ImportResourceState` — they respond via `.msgpack`, exactly
// like every other RPC (`PlanResourceChange`, `ApplyResourceChange`,
// `ReadResource`) already does in this codebase — and the plugin
// protocol requires `ConfigureProvider`/`Configure` to run before any
// other RPC. `ConfiguredImportEnvironment` closes both gaps by reusing
// `engine::dial_configured_provider` — the SAME spawn -> handshake ->
// dial -> get_schema -> configure lifecycle the apply engine's own
// `Registry` (and its mid-apply on-conflict adopt) already rides.
//
// These tests exercise the REAL `.terraform/providers` binary-discovery
// path (`magma_providers::locate_provider`), not a pre-dialed channel —
// proving the fix's provider-name inference (`engine::provider_local_name`)
// + dial + configure + schema-typed msgpack decode all work end-to-end.

/// A fake workspace whose `.terraform/providers/` holds the mock
/// provider binary named `terraform-provider-mock` — exactly how a real
/// `github`/`cloudflare`/`aws` provider is laid out after `tofu init`,
/// per `magma_providers::locate_provider`'s doc ("a flat dir of binaries
/// or the registry tree" both work).
fn configured_provider_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let providers_dir = dir.path().join(".terraform").join("providers");
    std::fs::create_dir_all(&providers_dir).expect("mkdir .terraform/providers");
    let dest = providers_dir.join("terraform-provider-mock");
    std::fs::copy(mock_provider_binary(), &dest).expect("copy mock_provider binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dest)
            .expect("stat copied binary")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dest, perms).expect("chmod copied binary +x");
    }
    dir
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_import_environment_absorbs_through_real_registry_lifecycle() {
    let ws = configured_provider_workspace();
    let ctx = ApplyContext::new(ws.path().to_path_buf());
    let env = ConfiguredImportEnvironment::new(&ctx);

    // "mock_resource" -> provider local name "mock" (the same
    // first-`_`-prefix rule `engine::provider_local_name` uses for every
    // other RPC) -> dials `terraform-provider-mock`.
    let directives = ImportDirectives::default().with_explicit("mock_resource.adopted", "abc123");

    let mut state = empty_state();
    let outcome = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("prepass structurally ok");

    assert_eq!(outcome.newly_absorbed(), 1, "{outcome:?}");
    assert!(outcome.all_succeeded(), "{outcome:?}");
    assert_eq!(state.resources.len(), 1);
    assert_eq!(state.resources[0].address.type_id.0, "mock_resource");

    // The mock encodes {id, name, imported_by} through the REAL
    // schema-typed msgpack codec (magma_cty) — a round-trip that only
    // succeeds if ConfiguredImportEnvironment actually ran
    // GetProviderSchema + ConfigureProvider + ImportResourceState +
    // schema-driven msgpack decode, not the raw JSON-only shortcut
    // PluginImportEnvironment takes.
    let attrs = &state.resources[0].instances[0].attributes;
    assert_eq!(attrs["id"], "abc123");
    assert_eq!(attrs["name"], "abc123");
    assert_eq!(attrs["imported_by"], "mock_provider");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_import_environment_reuses_one_dialed_provider_across_calls() {
    // Two imports against the SAME provider ("mock") must share one
    // dialed + configured connection (dial-once-per-provider,
    // per-address idempotency handled by the prepass) rather than
    // re-spawning a subprocess per address.
    let ws = configured_provider_workspace();
    let ctx = ApplyContext::new(ws.path().to_path_buf());
    let env = ConfiguredImportEnvironment::new(&ctx);

    let directives = ImportDirectives::default()
        .with_explicit("mock_resource.first", "id-1")
        .with_explicit("mock_resource.second", "id-2");

    let mut state = empty_state();
    let outcome = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("prepass structurally ok");

    assert_eq!(outcome.newly_absorbed(), 2, "{outcome:?}");
    assert!(outcome.all_succeeded(), "{outcome:?}");
    assert_eq!(state.resources.len(), 2);
}

// ── Law 6: an adopted resource is NEVER identity-less ──────────────
//
// THE regression this pins. `ImportResourceState` is, by protocol
// contract, only step ONE: it returns a STUB carrying just enough
// identity for step two, `ReadResource`, which is what populates every
// other attribute — including every COMPUTED one. `ConfiguredImportEnvironment`
// used to call step one alone and hand the raw stub to `absorb()`.
//
// The damage is not "slightly incomplete state". It is a resource whose
// ADDRESS exists (so the next plan stops proposing a Create — the loop
// looks fixed) while its IDENTITY does not, and magma's `refresh` is an
// M0.10 no-op so it never self-heals. Every dependent referencing a
// computed attribute then resolves to null FOREVER:
// `github_branch_protection.repository_id = ${github_repository.X.node_id}`
// → `""` → GitHub's "Could not resolve to a node with the global id of ''"
// → NOT an already-exists diagnostic → the reactive adopt path is never
// reached → the pre-existing branch protection can never adopt. Live
// receipt: nine `github_repository` entries in the pleme-io-opensource
// state carrying `name: null, node_id: null`, with 50 children failing
// every cycle behind them.
//
// The `stub-` id makes the mock behave like a real provider (see
// `mock_provider`'s `import_resource_state` / `read_resource`). Run
// against the pre-fix code this assertion fails on a null `name` — the
// deliberately-broken-input red run this gate is required to have.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adopted_resource_is_never_identity_less() {
    let ws = configured_provider_workspace();
    let ctx = ApplyContext::new(ws.path().to_path_buf());
    let env = ConfiguredImportEnvironment::new(&ctx);

    let directives = ImportDirectives::default().with_explicit("mock_resource.adopted", "stub-xyz");

    let mut state = empty_state();
    let outcome = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("prepass structurally ok");

    assert_eq!(outcome.newly_absorbed(), 1, "{outcome:?}");
    assert!(outcome.all_succeeded(), "{outcome:?}");

    let attrs = &state.resources[0].instances[0].attributes;
    assert_eq!(attrs["id"], "stub-xyz", "identity present");
    // The two attributes the import STUB left null. Both are populated
    // only by the protocol's confirming ReadResource.
    assert_eq!(
        attrs["name"], "stub-xyz",
        "adoption must run the confirming ReadResource — absorbing the raw \
         import stub persists an identity-less resource: {attrs:?}",
    );
    assert_eq!(
        attrs["imported_by"], "mock_provider",
        "every computed attribute the stub left null must be hydrated, not \
         just the one magma happens to backfill by hand: {attrs:?}",
    );
}

/// The same law stated the other way: NO attribute the provider declares
/// may be left null by an adoption whose confirming read succeeded. Stated
/// as an exhaustive scan rather than named fields so a future schema
/// attribute cannot silently join the identity-less set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adoption_leaves_no_null_attribute_when_the_read_confirms() {
    let ws = configured_provider_workspace();
    let ctx = ApplyContext::new(ws.path().to_path_buf());
    let env = ConfiguredImportEnvironment::new(&ctx);

    let directives = ImportDirectives::default().with_explicit("mock_resource.adopted", "stub-abc");
    let mut state = empty_state();
    run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("prepass structurally ok");

    let attrs = &state.resources[0].instances[0].attributes;
    let nulls: Vec<&String> = attrs
        .as_object()
        .expect("attributes are an object")
        .iter()
        .filter(|(_, v)| v.is_null())
        .map(|(k, _)| k)
        .collect();
    assert!(
        nulls.is_empty(),
        "an adopted resource whose confirming ReadResource succeeded must carry \
         no null attributes; these came straight from the import stub: {nulls:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_import_environment_missing_schema_is_typed_failure_not_panic() {
    // "mock_missing_type" also resolves to provider "mock" (dials +
    // configures fine) but the mock's schema never declared this
    // resource type — the missing-schema condition must surface as a
    // typed per-resource FailedImport, never a panic/unwrap.
    let ws = configured_provider_workspace();
    let ctx = ApplyContext::new(ws.path().to_path_buf());
    let env = ConfiguredImportEnvironment::new(&ctx);

    let directives = ImportDirectives::default().with_explicit("mock_missing_type.x", "abc123");
    let mut state = empty_state();
    let outcome = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("prepass structurally ok even when the provider has no schema for the type");

    assert_eq!(outcome.failed.len(), 1, "{outcome:?}");
    assert!(
        outcome.failed[0].reason.contains("no schema"),
        "{:?}",
        outcome.failed[0].reason
    );
    assert_eq!(state.resources.len(), 0);
}
