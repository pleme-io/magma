use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use magma_apply::engine::{ApplyContext, refresh_state};
use magma_apply::guard::{ProgressBeacon, RpcDeadlines, RpcGuard};
use magma_plugin::provider::UnresponsiveCause;
use magma_state::empty_state;
use magma_types::{
    InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind, ResourceTypeId,
    State, StateInstance, StateResource,
};

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let providers = dir.path().join(".terraform").join("providers");
    std::fs::create_dir_all(&providers).expect("mkdir providers");
    let dest = providers.join("terraform-provider-mock");
    std::fs::copy(mock_provider_binary(), &dest).expect("copy mock provider");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dest).expect("stat").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dest, perms).expect("chmod");
    }
    dir
}

fn row(name: &str, id: &str) -> StateResource {
    StateResource {
        address: ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("mock_resource".into()),
            name: name.into(),
            key: None,
        },
        provider: ProviderReference {
            source: "mock/mock".into(),
            name: "mock".into(),
            alias: None,
        },
        instances: vec![StateInstance {
            index_key: None,
            schema_version: 1,
            attributes: serde_json::json!({ "id": id, "name": name }),
            sensitive_attribute_paths: Vec::new(),
            private: vec![],
            dependencies: vec![],
            status: InstanceStatus::Ready,
        }],
    }
}

fn state(rows: Vec<StateResource>) -> State {
    let mut s = empty_state();
    s.resources = rows;
    s
}

fn guarded(ws: &tempfile::TempDir, read: Duration) -> (ApplyContext, Arc<RpcGuard>) {
    let guard = Arc::new(RpcGuard::new(
        RpcDeadlines {
            dial: Duration::from_secs(30),
            read,
            mutate: Duration::from_secs(60),
        },
        Arc::new(ProgressBeacon::new()),
    ));
    let ctx = ApplyContext::new(ws.path().to_path_buf())
        .without_pacer()
        .with_rpc_guard(Arc::clone(&guard));
    (ctx, guard)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_process_that_exits_mid_read_is_seen_at_once_and_replaced() {
    let ws = workspace();
    let (ctx, guard) = guarded(&ws, Duration::from_secs(600));
    let mut st = state(vec![row("dies", "exit-mid-rpc"), row("after", "res-after")]);
    let started = Instant::now();
    let report = refresh_state(&mut st, &ctx).await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(30),
        "a dead provider must not cost the 600s read deadline: {took:?}"
    );
    assert_eq!(report.kept_on_error, 1, "{report:?}");
    assert_eq!(
        report.refreshed, 1,
        "the replacement process served the next row: {report:?}"
    );
    assert_eq!(st.resources.len(), 2);
    let faults = guard.beacon.faults();
    assert_eq!(faults.len(), 1, "{faults:?}");
    assert!(
        matches!(faults[0].cause, UnresponsiveCause::Exited { .. }),
        "{faults:?}"
    );
    assert_eq!(faults[0].subject.as_deref(), Some("mock_resource.dies"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_process_that_hangs_mid_read_is_killed_at_the_deadline_and_replaced() {
    let ws = workspace();
    let (ctx, guard) = guarded(&ws, Duration::from_secs(2));
    let mut st = state(vec![
        row("hangs", "hang-mid-rpc"),
        row("after", "res-after"),
    ]);
    let started = Instant::now();
    let report = refresh_state(&mut st, &ctx).await;
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(30),
        "{took:?}"
    );
    assert_eq!(report.kept_on_error, 1, "{report:?}");
    assert_eq!(report.refreshed, 1, "{report:?}");
    let faults = guard.beacon.faults();
    assert_eq!(faults.len(), 1, "{faults:?}");
    assert!(
        matches!(faults[0].cause, UnresponsiveCause::DeadlineExceeded { .. }),
        "{faults:?}"
    );
}
