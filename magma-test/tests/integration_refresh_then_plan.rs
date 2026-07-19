//! End-to-end proof of `magma_apply::engine::refresh_then_plan`'s
//! load-bearing fix, over the REAL wire path against the `mock_provider`
//! binary (real `Plugin::spawn` → real `ReadResource` RPC → real decode).
//!
//! Before this fix, every magma entry point (`magma plan`, `magma apply`,
//! `magma_plan` over MCP, …) diffed config against whatever `state`
//! happened to be on disk, with NO call to the provider in between —
//! `magma-apply::engine::{refresh_state, refresh_named}` existed, were
//! tested, and had exactly zero non-test callers anywhere in the
//! workspace. A resource deleted out-of-band (in the cloud console,
//! outside magma) therefore showed as `NoOp` — invisible drift — instead
//! of the `Create` it actually needs.
//!
//! `resource_is_recreated_after_refresh_detects_out_of_band_deletion`
//! reproduces exactly that failure mode against a real (mocked) provider
//! and proves the fix closes it: the SAME state/config pair that plans
//! `NoOp` via the bare `magma_plan::plan` call now plans `Create` once
//! routed through `refresh_then_plan`, because refresh's real
//! `ReadResource` RPC discovers the resource is gone and drops it from
//! state before the plan diff runs.
//!
//! `refresh_leaves_a_still_present_resource_as_noop` is the companion
//! false-positive guard: refresh must not manufacture drift for a
//! resource the provider confirms is still there unchanged.

use std::path::{Path, PathBuf};

use magma_apply::engine::{ApplyContext, refresh_then_plan};
use magma_config::Config;
use magma_types::{
    Action, InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind,
    ResourceTypeId, State, StateInstance, StateResource,
};

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

/// Build a workspace dir whose `.terraform/providers` tree contains a copy
/// of `mock_provider`, named + laid out so
/// `magma_providers::locate_provider(workspace, "mock")` finds it —
/// exactly the tree `tofu init` / `terraform init` produces, so
/// `refresh_then_plan`'s `ApplyContext` can spawn + dial it for real.
fn workspace_with_mock_provider() -> tempfile::TempDir {
    let td = tempfile::tempdir().expect("tempdir");
    let dir = td
        .path()
        .join(".terraform/providers/registry.terraform.io/mock/mock/1.0.0/local");
    std::fs::create_dir_all(&dir).expect("mkdir provider dir");
    let dest = dir.join("terraform-provider-mock");
    std::fs::copy(mock_provider_binary(), &dest).expect("copy mock_provider binary");
    // `fs::copy` carries over the source's executable bit on Unix; assert
    // it rather than silently spawning a non-executable file later.
    assert_executable(&dest);
    td
}

#[cfg(unix)]
fn assert_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(p).expect("metadata").permissions().mode();
    assert!(mode & 0o111 != 0, "{p:?} must be executable, mode={mode:o}");
}
#[cfg(not(unix))]
fn assert_executable(_p: &Path) {}

fn cfg_declaring_keep_me() -> Config {
    Config::from_json(serde_json::json!({
        "resource": {
            "mock_resource": {
                "keep_me": { "id": "gone", "name": "keep_me", "imported_by": "" }
            }
        }
    }))
    .expect("config parses")
}

fn state_with_keep_me(id: &str) -> State {
    State {
        version: 4,
        terraform_version: "1.9.0".into(),
        serial: 1,
        lineage: Default::default(),
        outputs: Default::default(),
        resources: vec![StateResource {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId("mock_resource".into()),
                name: "keep_me".into(),
                key: None,
            },
            provider: ProviderReference {
                source: "local/mock".into(),
                name: "mock".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: serde_json::json!({
                    "id": id, "name": "keep_me", "imported_by": ""
                }),
                sensitive_attribute_paths: Vec::new(),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        }],
    }
}

/// THE fix, proven end-to-end: a resource deleted out-of-band (the mock's
/// `id == "gone"` sentinel — see `mock_provider.rs`'s `read_resource`) is
/// `NoOp` under the OLD (pre-fix) direct `magma_plan::plan` call, and
/// `Create` once routed through `refresh_then_plan`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_is_recreated_after_refresh_detects_out_of_band_deletion() {
    let ws = workspace_with_mock_provider();
    let cfg = cfg_declaring_keep_me();
    let mut state = state_with_keep_me("gone");

    // Baseline — reproduces the bug: without a refresh step, config and
    // the (stale, phantom) recorded state agree, so the resource that was
    // ACTUALLY deleted out-of-band is invisible.
    let stale_plan = magma_plan::plan(&cfg, &state).expect("stale plan");
    assert_eq!(
        stale_plan.resource_changes[0].action,
        Action::NoOp,
        "the bug this fix closes: an out-of-band deletion is invisible \
         without a refresh step",
    );

    // The fix: refresh_then_plan's real ReadResource RPC (over a genuinely
    // spawned + dialed mock provider) discovers the resource is gone and
    // drops it from state BEFORE the plan diff runs.
    let ctx = ApplyContext::new(ws.path().to_path_buf());
    let (plan, report) = refresh_then_plan(&cfg, &mut state, Some(&ctx))
        .await
        .expect("refresh_then_plan");
    let report = report.expect("refresh ran (ctx = Some)");

    assert_eq!(report.dropped_instances, 1, "the phantom instance was dropped");
    assert_eq!(report.dropped_resources, 1, "its whole resource was dropped");
    assert_eq!(report.refreshed, 0);
    assert!(state.resources.is_empty(), "state no longer records the deleted resource");
    assert_eq!(
        plan.resource_changes[0].action,
        Action::Create,
        "the SAME config now correctly plans a Create — drift is caught",
    );
}

/// False-positive guard: a resource the provider confirms is STILL there,
/// unchanged, must stay `NoOp` after refresh — refresh must never
/// manufacture drift.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_leaves_a_still_present_resource_as_noop() {
    let ws = workspace_with_mock_provider();
    let cfg = Config::from_json(serde_json::json!({
        "resource": {
            "mock_resource": {
                "keep_me": { "id": "still-here", "name": "keep_me", "imported_by": "" }
            }
        }
    }))
    .expect("config parses");
    let mut state = state_with_keep_me("still-here");

    let ctx = ApplyContext::new(ws.path().to_path_buf());
    let (plan, report) = refresh_then_plan(&cfg, &mut state, Some(&ctx))
        .await
        .expect("refresh_then_plan");
    let report = report.expect("refresh ran (ctx = Some)");

    assert_eq!(report.dropped_instances, 0);
    assert_eq!(report.dropped_resources, 0);
    assert_eq!(report.refreshed, 1, "the real ReadResource RPC ran and confirmed it");
    assert_eq!(state.resources.len(), 1);
    assert_eq!(
        plan.resource_changes[0].action,
        Action::NoOp,
        "unchanged real-world state — no manufactured drift",
    );
}
