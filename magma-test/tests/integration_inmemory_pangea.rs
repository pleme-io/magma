//! In-memory Pangea pipeline — the §II.9 demonstration.
//!
//! Drives a Pangea-rendered Terraform JSON workspace through magma's
//! typed core *entirely in memory*: no `tempfile`, no intermediate
//! disk writes, no shell-outs. Pure typed-value flow through Rust:
//!
//!     Pangea-rendered JSON  (str or serde_json::Value)
//!         → magma_config::Config
//!             → magma_plan::plan(config, state)
//!                 → magma_types::Plan
//!
//! This is the M0 proof of §II.9 (in-memory pipelines + shigoto
//! work-graph): when Pangea Ruby evaluates in-process, the rendered
//! architecture never touches disk on its way to magma's planner.
//!
//! Two paths exercised:
//!
//! 1. **Pure-JSON in-memory** (this file's primary tests) — caller
//!    constructs a `serde_json::Value` directly (or parses an inline
//!    string), feeds it to `Config::from_json`, plans against state.
//!    No filesystem ops. Demonstrates the lib-as-Rust-API interface
//!    (`theory/MAGMA.md` §II.8 interface 4).
//!
//! 2. **Disk-shape discovery + in-memory load** — `WorkspaceShape::discover`
//!    against a fixture dir, then `TerraformJsonLoader::load` to bring
//!    the rendered JSON into memory. After load, the rest of the
//!    pipeline runs disk-free. Demonstrates the `magma-pangea`
//!    workspace-discovery path is compatible with the in-memory flow.

use std::collections::HashSet;
use std::path::PathBuf;

use magma_config::Config;
use magma_pangea::{ShapeKind, TerraformJsonLoader, WorkspaceLoader, WorkspaceShape};
use magma_plan::plan as compute_plan;
use magma_state::empty_state;
use magma_types::{Action, ResourceAddress};
use serde_json::json;

// ── Path 1: pure-in-memory pipeline ────────────────────────────────

/// The canonical §II.9 demo: workspace JSON, planning, all in RAM.
/// Every value here is a Rust value; no file path is named, no
/// serde-to-tempfile-and-back ritual happens.
#[tokio::test]
async fn inmemory_pangea_pipeline_create() {
    // 1. Pangea-rendered architecture — in memory.
    let rendered = json!({
        "terraform": {
            "required_providers": {
                "aws":        { "source": "hashicorp/aws",        "version": "~> 5.0" },
                "cloudflare": { "source": "cloudflare/cloudflare" }
            }
        },
        "resource": {
            "aws_vpc": {
                "main": { "cidr_block": "10.0.0.0/16" }
            },
            "cloudflare_record": {
                "auth": { "name": "auth", "type": "CNAME", "value": "tunnel.example.com" }
            }
        }
    });

    // 2. Typed Config — no parsing of HCL anywhere; magma reads
    // Pangea-rendered JSON directly (§II.1).
    let cfg = Config::from_json(rendered).expect("parse rendered JSON");
    assert_eq!(cfg.resources.len(), 2);
    let provider_refs = cfg.provider_references();
    assert_eq!(provider_refs.len(), 2);

    // 3. Plan against fresh state.
    let state = empty_state();
    let plan = compute_plan(&cfg, &state).expect("plan");

    // 4. Assert: two Create actions, deterministic plan_id.
    assert_eq!(plan.resource_changes.len(), 2);
    assert!(
        plan.resource_changes
            .iter()
            .all(|c| c.action == Action::Create)
    );
    let addrs: HashSet<&str> = plan
        .resource_changes
        .iter()
        .map(|c| c.address.type_id.0.as_str())
        .collect();
    assert!(addrs.contains("aws_vpc"));
    assert!(addrs.contains("cloudflare_record"));

    // 5. Plan-id determinism — same inputs produce same hash.
    let plan2 = compute_plan(&cfg, &state).expect("plan2");
    assert_eq!(plan.id.0, plan2.id.0, "PlanId is deterministic across runs");
}

/// In-memory chaining demo: the typed Plan output from one workspace
/// directly feeds the input of another (no state file, no S3, no
/// terraform_remote_state data source) — per §II.9 cross-workspace
/// chaining without disk.
#[tokio::test]
async fn inmemory_pangea_cross_workspace_chain() {
    // Workspace A (VPC) produces an output we'd traditionally fetch
    // via `data "terraform_remote_state"`. In magma's in-memory chain,
    // the output is a typed value handed to workspace B as input.
    let vpc_rendered = json!({
        "resource": {
            "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } }
        },
        "output": { "vpc_id": { "value": "vpc-typed-stub-id", "sensitive": false } }
    });
    let vpc_cfg = Config::from_json(vpc_rendered).expect("vpc cfg");
    assert!(vpc_cfg.outputs.contains_key("vpc_id"));

    // Workspace B (subnet) — would normally reference
    // `data.terraform_remote_state.vpc.outputs.vpc_id`. In magma's
    // in-memory chain, the value is injected as a typed Rust value
    // (here: a serde_json::Value extracted from the parent workspace).
    let vpc_id_value = vpc_cfg.outputs.get("vpc_id").unwrap().value.clone();
    let subnet_rendered = json!({
        "resource": {
            "aws_subnet": {
                "public_a": {
                    "vpc_id":     vpc_id_value,
                    "cidr_block": "10.0.1.0/24"
                }
            }
        }
    });
    let subnet_cfg = Config::from_json(subnet_rendered).expect("subnet cfg");
    assert_eq!(subnet_cfg.resources.len(), 1);
    let subnet_state = empty_state();
    let subnet_plan = compute_plan(&subnet_cfg, &subnet_state).expect("subnet plan");
    assert_eq!(subnet_plan.resource_changes.len(), 1);
    assert_eq!(subnet_plan.resource_changes[0].action, Action::Create);

    // Round-trip the cross-workspace reference. No state file written
    // anywhere; the chain happens entirely as typed Rust values.
    let after = subnet_plan.resource_changes[0].after.as_ref().unwrap();
    assert_eq!(after["vpc_id"].as_str(), Some("vpc-typed-stub-id"));
}

/// In-memory plan diff: simulate a partial apply by injecting a state
/// resource for one of the config resources, then re-planning — the
/// existing one becomes NoOp, the missing one becomes Create.
#[tokio::test]
async fn inmemory_plan_partial_state() {
    use magma_types::{
        InstanceStatus, ModulePath, ProviderReference, ResourceAddress as Addr, ResourceKind,
        ResourceTypeId, State, StateInstance, StateResource,
    };

    let rendered = json!({
        "resource": {
            "aws_vpc":    { "main": { "cidr_block": "10.0.0.0/16" } },
            "aws_subnet": { "public_a": { "cidr_block": "10.0.1.0/24" } }
        }
    });
    let cfg = Config::from_json(rendered).expect("cfg");

    // Simulate a state where the VPC was applied but the subnet wasn't.
    let mut state: State = empty_state();
    state.resources.push(StateResource {
        address: Addr {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId("aws_vpc".into()),
            name: "main".into(),
            key: None,
        },
        provider: ProviderReference {
            source: "hashicorp/aws".into(),
            name: "aws".into(),
            alias: None,
        },
        instances: vec![StateInstance {
            schema_version: 0,
            attributes: json!({ "cidr_block": "10.0.0.0/16", "id": "vpc-existing" }),
            private: vec![],
            dependencies: vec![],
            status: InstanceStatus::Ready,
        }],
    });

    let plan = compute_plan(&cfg, &state).expect("plan");
    assert_eq!(plan.resource_changes.len(), 2);

    let actions: HashSet<(String, Action)> = plan
        .resource_changes
        .iter()
        .map(|c| (c.address.type_id.0.clone(), c.action))
        .collect();
    assert!(actions.contains(&("aws_vpc".into(), Action::NoOp)));
    assert!(actions.contains(&("aws_subnet".into(), Action::Create)));
}

// ── Path 2: workspace discovery + in-memory load ──────────────────

fn fixture_pangea_dir() -> PathBuf {
    let manifest =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set in cargo test");
    PathBuf::from(manifest).join("fixtures/pangea")
}

/// Workspace discovery (from disk) → in-memory load → plan.
/// Demonstrates that the loader correctly bridges disk → memory.
#[tokio::test]
async fn inmemory_load_from_fixture_directory() {
    let fixture = fixture_pangea_dir();
    if !fixture.exists() {
        eprintln!("skip: fixtures/pangea/ not present");
        return;
    }

    let shape = WorkspaceShape::discover(&fixture).expect("discover");
    assert!(matches!(shape, WorkspaceShape::TerraformJson { .. }));

    let loaded = TerraformJsonLoader.load(shape).await.expect("load");
    assert_eq!(loaded.shape, ShapeKind::TerraformJson);

    let cfg = Config::from_json(loaded.rendered).expect("Config from loaded.rendered");
    assert!(cfg.resources.contains_key("aws_vpc"));
    assert!(cfg.resources.contains_key("aws_subnet"));
    let vpc = &cfg.resources["aws_vpc"]["main"];
    assert_eq!(vpc["cidr_block"].as_str(), Some("10.0.0.0/16"));

    // Plan it.
    let state = empty_state();
    let plan = compute_plan(&cfg, &state).expect("plan");
    // 1 aws_vpc.main + 2 aws_subnet.* = 3 resources.
    assert_eq!(plan.resource_changes.len(), 3);
}

/// Resource address enumeration — proves the typed Config exposes
/// every resource as a typed `ResourceAddress`, ready for graph
/// construction in `magma-graph`.
#[tokio::test]
async fn inmemory_resource_address_enumeration() {
    let rendered = json!({
        "resource": {
            "aws_vpc":            { "a": {}, "b": {} },
            "cloudflare_record":  { "x": {}, "y": {}, "z": {} }
        },
        "data": {
            "aws_caller_identity": { "current": {} }
        }
    });
    let cfg = Config::from_json(rendered).expect("cfg");
    let addrs: Vec<ResourceAddress> = cfg.resource_addresses().collect();
    assert_eq!(addrs.len(), 6); // 2 + 3 + 1

    let kinds: HashSet<String> = addrs.iter().map(|a| a.type_id.0.clone()).collect();
    assert!(kinds.contains("aws_vpc"));
    assert!(kinds.contains("cloudflare_record"));
    assert!(kinds.contains("aws_caller_identity"));
}
