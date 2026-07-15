//! magma-plan — plan algorithm: `Config × State → Plan`.
//!
//! The load-bearing semantics layer. Walks config + state, emits typed
//! `ResourceChange`s. M0 ships the structural diff (NoOp / Create /
//! Delete / Update-as-NoOp); the per-attribute update detection that
//! requires provider RPC (`PlanResourceChange`) lands in M0.x once
//! magma-protocol's gRPC bindings are wired.
//!
//! Per `theory/MAGMA.md` §X.1, OpenTofu has documented plan-diff
//! quirks. Magma matches bug-for-bug for M0–M2 — each documented
//! quirk is a `magma_known_quirk!` proptest case so regressions surface
//! immediately.

use std::collections::HashSet;

use chrono::Utc;
use magma_attest::hash_plan_inputs;
use magma_config::Config;
use magma_types::{Action, ChangeReason, Plan, ResourceAddress, ResourceChange, State};

mod compliance;
pub use compliance::{check_security_group_compliance, ComplianceViolation};

// ── Errors ─────────────────────────────────────────────────────────

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("config error: {0}")]
    Config(#[from] magma_config::ConfigError),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("compliance violation — refusing to plan:\n{}", .0.iter().map(|v| format!("  - {v}")).collect::<Vec<_>>().join("\n"))]
    Compliance(Vec<ComplianceViolation>),
}

// ── Plan ──────────────────────────────────────────────────────────

/// Compute a typed `Plan` from `config` against `state` — the M0
/// structural diff. No provider RPC yet; updates show as NoOp pending
/// the `PlanResourceChange` integration.
pub fn plan(config: &Config, state: &State) -> Result<Plan, PlanError> {
    // Compliance gate — default-on, unbypassable (every architecture's
    // Ruby DSL choice converges here). Refuse to compute a plan at all
    // if the config declares a world-open security-group ingress rule
    // outside the narrow default-allowed public ports. See compliance.rs.
    let violations = check_security_group_compliance(config);
    if !violations.is_empty() {
        return Err(PlanError::Compliance(violations));
    }

    let config_addrs: HashSet<ResourceAddress> = config.resource_addresses().collect();
    let state_addrs: HashSet<ResourceAddress> =
        state.resources.iter().map(|r| r.address.clone()).collect();

    let mut changes: Vec<ResourceChange> = Vec::new();

    // Create: in config, not in state.
    for addr in config_addrs.difference(&state_addrs) {
        let after = lookup_config_value(config, addr);
        changes.push(ResourceChange {
            address: addr.clone(),
            action: Action::Create,
            before: None,
            after,
            reasons: vec![ChangeReason::NewResource],
        });
    }

    // Delete: in state, not in config.
    for addr in state_addrs.difference(&config_addrs) {
        let before = lookup_state_value(state, addr);
        changes.push(ResourceChange {
            address: addr.clone(),
            action: Action::Delete,
            before,
            after: None,
            reasons: vec![ChangeReason::DeletedResource],
        });
    }

    // Update: in both. M0 stub — NoOp until provider RPC integration.
    for addr in config_addrs.intersection(&state_addrs) {
        let before = lookup_state_value(state, addr);
        let after = lookup_config_value(config, addr);
        changes.push(ResourceChange {
            address: addr.clone(),
            action: Action::NoOp, // TODO(M0.x): provider PlanResourceChange RPC.
            before,
            after,
            reasons: vec![],
        });
    }

    // Deterministic order — proptest needs stable plan output.
    changes.sort_by_key(|c| {
        (
            c.address.type_id.0.clone(),
            c.address.name.clone(),
            format!("{:?}", c.address.key),
        )
    });

    // Hash inputs for the typed PlanId.
    let canonical = serde_json::to_vec(&PlanInputs {
        changes: &changes,
        state_serial: state.serial,
        state_lineage: state.lineage,
    })?;
    let plan_id = hash_plan_inputs(&canonical);

    Ok(Plan {
        id: plan_id,
        created_at: Utc::now(),
        config_root: std::path::PathBuf::new(),
        variables: Default::default(),
        resource_changes: changes,
        output_changes: Vec::new(),
    })
}

fn lookup_config_value(config: &Config, addr: &ResourceAddress) -> Option<serde_json::Value> {
    config
        .resources
        .get(&addr.type_id.0)
        .and_then(|by_name| by_name.get(&addr.name))
        .cloned()
}

fn lookup_state_value(state: &State, addr: &ResourceAddress) -> Option<serde_json::Value> {
    state
        .resources
        .iter()
        .find(|r| r.address == *addr)
        .and_then(|r| r.instances.first())
        .map(|i| i.attributes.clone())
}

#[derive(serde::Serialize)]
struct PlanInputs<'a> {
    changes: &'a [ResourceChange],
    state_serial: u64,
    state_lineage: uuid::Uuid,
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_types::{InstanceStatus, ProviderReference, StateInstance, StateResource};
    use serde_json::json;

    fn empty_state() -> State {
        State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: uuid::Uuid::new_v4(),
            outputs: Default::default(),
            resources: Vec::new(),
        }
    }

    fn cfg_with_vpc() -> Config {
        let json_v = json!({
            "resource": {
                "aws_vpc": {
                    "main": { "cidr_block": "10.0.0.0/16" }
                }
            }
        });
        Config::from_json(json_v).unwrap()
    }

    #[test]
    fn plan_refuses_a_world_open_security_group_rule() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_security_group_rule": {
                    "grafana_nodeport": {
                        "type": "ingress",
                        "from_port": 32714,
                        "to_port": 32714,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                }
            }
        }))
        .unwrap();
        let st = empty_state();
        let err = plan(&cfg, &st).unwrap_err();
        assert!(matches!(err, PlanError::Compliance(_)));
    }

    #[test]
    fn empty_in_empty_out() {
        let cfg = Config::default();
        let st = empty_state();
        let p = plan(&cfg, &st).unwrap();
        assert!(p.resource_changes.is_empty());
    }

    #[test]
    fn one_resource_creates() {
        let cfg = cfg_with_vpc();
        let st = empty_state();
        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::Create);
        assert_eq!(p.resource_changes[0].address.type_id.0, "aws_vpc");
    }

    #[test]
    fn missing_in_config_deletes() {
        let cfg = Config::default();
        let mut st = empty_state();
        st.resources.push(StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: magma_types::ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId("aws_vpc".into()),
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
                attributes: json!({"id": "vpc-abc"}),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }],
        });
        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::Delete);
    }

    #[test]
    fn identical_yields_noop() {
        let cfg = cfg_with_vpc();
        let mut st = empty_state();
        st.resources.push(StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: magma_types::ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId("aws_vpc".into()),
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
                attributes: json!({"cidr_block": "10.0.0.0/16"}),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }],
        });
        let p = plan(&cfg, &st).unwrap();
        // For M0, "in-both" is a NoOp pending provider RPC.
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::NoOp);
    }

    #[test]
    fn plan_id_deterministic_for_same_inputs() {
        let cfg = cfg_with_vpc();
        let st = empty_state();
        let p1 = plan(&cfg, &st).unwrap();
        let p2 = plan(&cfg, &st).unwrap();
        // PlanId only depends on inputs + structural changes, not timestamp.
        assert_eq!(p1.id.0, p2.id.0);
    }
}
