//! `run_plan_via_providers` end-to-end against the real null provider.
//!
//! Proves the apply ENGINE (not just the registry) drives a real
//! provider to materialize a resource: an all-Create plan goes through
//! run_plan_via_providers → ProviderRegistry → Configure/Plan/Apply →
//! the provider-filled state is written into `State`. This is the exact
//! path `executor:magma` will take (the operator pre-seeds the registry
//! with the correct provider sources + configs).
//!
//! Skips when the vendored null provider binary is absent.

use std::collections::HashMap;
use std::path::PathBuf;

use magma_apply::run_plan_via_providers;
use magma_providers::ProviderRegistry;
use magma_types::{
    Action, ModulePath, Plan, PlanId, ResourceAddress, ResourceChange, ResourceKind,
    ResourceTypeId, State,
};

fn null_fixture() -> Option<PathBuf> {
    for c in [
        "../magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
        "magma-test/fixtures/providers/terraform-provider-null_v3.2.4_x5",
    ] {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p.canonicalize().unwrap_or(p));
        }
    }
    None
}

fn empty_state() -> State {
    State {
        version: 4,
        terraform_version: "1.7.0".into(),
        serial: 0,
        lineage: uuid::Uuid::nil(),
        outputs: HashMap::new(),
        resources: Vec::new(),
    }
}

fn create_change(type_name: &str, name: &str, after: serde_json::Value) -> ResourceChange {
    ResourceChange {
        address: ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId(type_name.into()),
            name: name.into(),
            key: None,
        },
        action: Action::Create,
        before: None,
        after: Some(after),
        reasons: Vec::new(),
    }
}

fn plan_with(changes: Vec<ResourceChange>) -> Plan {
    Plan {
        id: PlanId([0u8; 32]),
        created_at: chrono::Utc::now(),
        config_root: PathBuf::from("/tmp/magma-test"),
        variables: HashMap::new(),
        resource_changes: changes,
        output_changes: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_plan_via_providers_creates_null_resource() {
    let Some(binary) = null_fixture() else {
        eprintln!("skip: null provider fixture missing");
        return;
    };

    let registry = ProviderRegistry::from_default_cache();
    // Pre-seed under the source default_provider_for(null_resource) yields
    // ("hashicorp/null"), so the in-engine connect("hashicorp/null") hits
    // this cached connection rather than the (empty) plugin cache.
    registry
        .connect_binary("hashicorp/null", binary)
        .await
        .expect("pre-seed null provider");

    let mut state = empty_state();
    let plan = plan_with(vec![create_change(
        "null_resource",
        "demo",
        serde_json::json!({ "triggers": { "via": "run_plan_via_providers" }, "id": null }),
    )]);

    let provider_configs = HashMap::new(); // null needs no provider config
    let outcome = run_plan_via_providers(&plan, &mut state, &registry, &provider_configs)
        .await
        .expect("run_plan_via_providers");

    eprintln!(
        "applied={} failed={} resources={}",
        outcome.applied.len(),
        outcome.failed.len(),
        state.resources.len()
    );
    assert!(
        outcome.failed.is_empty(),
        "no failures expected, got: {:?}",
        outcome.failed
    );
    assert_eq!(outcome.applied.len(), 1, "one resource applied");
    assert_eq!(state.resources.len(), 1, "one resource in state");

    // The provider materialized the resource: state carries the
    // computed `id` it filled (not the null we sent).
    let attrs = &state.resources[0].instances[0].attributes;
    eprintln!("materialized state attributes: {attrs}");
    assert!(
        attrs.get("id").map(|v| !v.is_null()).unwrap_or(false),
        "provider-filled computed `id` expected, got: {attrs}",
    );
    assert_eq!(state.serial, 1, "serial bumped after a real apply");
}
