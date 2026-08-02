//! Integration test: typical Pangea-rendered workspaces pass the
//! universal lifecycle laws.
//!
//! These mirror the kinds of Terraform JSON Pangea emits for real
//! workspaces under `pangea-architectures/workspaces/*` — a few
//! resources, a couple of outputs, no module nesting (modules are
//! flattened at render time).

#![cfg(feature = "workspace-laws")]

use magma_config::Config;
use magma_test_laws::workspace::*;
use serde_json::json;

fn cfg(v: serde_json::Value) -> Config {
    Config::from_json(v).expect("Config::from_json")
}

// ── Real-shape workspace ──────────────────────────────────────────

fn vpc_workspace() -> Config {
    cfg(json!({
        "terraform": {
            "required_providers": {
                "aws": { "source": "hashicorp/aws", "version": "~> 5.0" }
            }
        },
        "provider": { "aws": { "region": "us-east-1" } },
        "resource": {
            "aws_vpc": {
                "main": { "cidr_block": "10.0.0.0/16", "enable_dns_support": true }
            },
            "aws_subnet": {
                "web": { "vpc_id": "${aws_vpc.main.id}", "cidr_block": "10.0.1.0/24" }
            }
        }
    }))
}

fn cluster_workspace() -> Config {
    cfg(json!({
        "terraform": {
            "required_providers": {
                "aws": { "source": "hashicorp/aws" }
            }
        },
        "resource": {
            "aws_iam_role": {
                "cluster": { "name": "cluster-role" }
            },
            "aws_iam_policy": {
                "cluster": { "name": "cluster-policy", "policy": "{}" }
            },
            "aws_launch_template": {
                "cluster": { "name": "cluster-lt" }
            }
        }
    }))
}

fn dns_workspace() -> Config {
    cfg(json!({
        "terraform": {
            "required_providers": {
                "cloudflare": { "source": "cloudflare/cloudflare" }
            }
        },
        "resource": {
            "cloudflare_record": {
                "api":     { "zone_id": "z1", "name": "api",     "type": "A", "value": "1.1.1.1" },
                "grafana": { "zone_id": "z1", "name": "grafana", "type": "A", "value": "2.2.2.2" }
            }
        }
    }))
}

// ── Property 1: a real workspace passes all lifecycle laws ────────

#[test]
fn vpc_workspace_passes_all_laws() {
    assert_all_laws(&vpc_workspace());
}

#[test]
fn cluster_workspace_passes_all_laws() {
    assert_all_laws(&cluster_workspace());
}

#[test]
fn dns_workspace_passes_all_laws() {
    assert_all_laws(&dns_workspace());
}

// ── Property 2: empty workspace is vacuously valid ────────────────

#[test]
fn empty_workspace_passes() {
    assert_all_laws(&Config::default());
}

// ── Property 3: per-law isolation tests ───────────────────────────

#[test]
fn plan_is_deterministic_for_real_workspace() {
    assert_plan_deterministic(&vpc_workspace());
}

#[test]
fn apply_converges_for_real_workspace() {
    assert_apply_converges(&vpc_workspace());
}

#[test]
fn destroy_round_trip_for_real_workspace() {
    assert_destroy_round_trip(&vpc_workspace());
}

#[test]
fn apply_enumerates_all_changes_for_real_workspace() {
    assert_apply_enumerates_all_changes(&vpc_workspace());
}

#[test]
fn apply_bumps_serial_for_real_workspace() {
    assert_apply_bumps_serial(&vpc_workspace());
}

// ── Property: import absorbs externally-discovered resources ───────

// ── Property: the import prepass absorbs through an ImportEnvironment ─

/// A mock `ImportEnvironment` for the prepass law: returns a canned
/// state for any id except the sentinel `"missing"`, which it rejects
/// with an error (so the failure-isolation arm is exercised).
struct LawMockEnv;

#[async_trait::async_trait]
impl magma_apply::import_prepass::ImportEnvironment for LawMockEnv {
    async fn import_resource_state(
        &self,
        type_name: &str,
        id: &str,
        _provider: &magma_types::ProviderInstance,
    ) -> Result<Vec<magma_types::ImportedInstance>, String> {
        if id == "missing" {
            return Err("mock: resource not found".into());
        }
        Ok(vec![magma_types::ImportedInstance {
            type_name: type_name.to_string(),
            attributes: serde_json::json!({"id": id, "name": id}),
            private: vec![],
        }])
    }
}

#[tokio::test]
async fn import_prepass_absorbs_obeys_the_universal_law() {
    magma_test_laws::workspace::assert_import_prepass_absorbs(
        || LawMockEnv,
        ("cloudflare_zone.quero_cloud", "abc123zoneid"),
        ("cloudflare_zone.bad", "missing"),
    )
    .await;
}

#[test]
fn import_absorbs_a_preexisting_iam_role() {
    use magma_types::{
        InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind,
        ResourceTypeId, StateInstance, StateResource,
    };
    let cluster = cluster_workspace();
    assert_import_absorbs(&cluster, |state| {
        // Simulate `magma import aws_iam_role.cluster` finding a
        // pre-existing role with id "cluster-role-id".
        state.resources.push(StateResource {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId("aws_iam_role".into()),
                name: "cluster".into(),
                key: None,
            },
            provider: ProviderReference {
                source: "hashicorp/aws".into(),
                name: "aws".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: serde_json::json!({"name": "cluster-role", "id": "cluster-role-id"}),
                sensitive_attribute_paths: Vec::new(),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        });
    });
}
