//! magma-apply — apply engine.
//!
//! Drives provider RPC for each `ResourceChange` in a plan, updating
//! state per the provider's response. Parallelism + retries + budgets
//! come from `shigoto::Scheduler` (per `theory/MAGMA.md` §II.9).
//!
//! M0 ships the synchronous-per-wave engine; full
//! `shigoto::Scheduler`-driven parallelism + budget enforcement +
//! crash-resumption land alongside M1's broader shigoto integration.
//! The typed shape matches §II.9 — every apply operation surfaces as
//! a typed `ApplyChange` Job.

pub mod engine;
pub mod shigoto_jobs;

use chrono::Utc;
use magma_types::{
    Action, InstanceStatus, Plan, ProviderReference, ResourceAddress, ResourceChange, ResourceKind,
    ResourceTypeId, State, StateInstance, StateResource,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("apply failed for {address:?}: {reason}")]
    Failed {
        address: ResourceAddress,
        reason: String,
    },
    #[error("missing provider for resource {0:?}")]
    MissingProvider(ResourceAddress),
    #[error("state update conflict: {0}")]
    StateConflict(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

// ── ApplyOutcome ───────────────────────────────────────────────────

/// The output of `run_plan` — typed receipt summarizing what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyOutcome {
    pub plan_id: magma_types::PlanId,
    pub state: State,
    pub applied: Vec<AppliedChange>,
    pub failed: Vec<FailedChange>,
    pub started_at: chrono::DateTime<Utc>,
    pub finished_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedChange {
    pub address: ResourceAddress,
    pub action: Action,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedChange {
    pub address: ResourceAddress,
    pub action: Action,
    pub reason: String,
}

// ── Apply engine (M0 — structural; provider RPC integration in M0.x) ──

/// Apply a `Plan` against `state`, mutating state in place per each
/// `ResourceChange`. M0 implementation is the structural diff:
/// Create produces a fresh `StateInstance` with the planned attributes;
/// Delete removes the resource from state; NoOp is a passthrough.
/// Update / Replace / Forget paths land alongside the provider-RPC
/// integration (M0.x) once `PlanResourceChange` + `ApplyResourceChange`
/// gRPC calls flow through the spawned `Plugin`.
///
/// This is the typed in-memory `apply` step in the §II.9 work-graph;
/// downstream consumers (chains, MCP `magma_apply`, CLI `magma apply`)
/// invoke this function directly with typed values.
pub fn run_plan(plan: &Plan, state: &mut State) -> Result<ApplyOutcome, ApplyError> {
    let started_at = Utc::now();
    let mut applied = Vec::new();
    let mut failed = Vec::new();

    for change in &plan.resource_changes {
        match apply_one(change, state) {
            Ok(a) => applied.push(a),
            Err(e) => failed.push(FailedChange {
                address: change.address.clone(),
                action: change.action,
                reason: e.to_string(),
            }),
        }
    }

    // Bump state serial when anything changed.
    if !applied.is_empty() {
        state.serial = state.serial.saturating_add(1);
    }

    Ok(ApplyOutcome {
        plan_id: plan.id,
        state: state.clone(),
        applied,
        failed,
        started_at,
        finished_at: Utc::now(),
    })
}

fn apply_one(change: &ResourceChange, state: &mut State) -> Result<AppliedChange, ApplyError> {
    match change.action {
        Action::NoOp => Ok(AppliedChange {
            address: change.address.clone(),
            action: Action::NoOp,
            before: change.before.clone(),
            after: change.after.clone(),
        }),

        Action::Create | Action::Read => {
            let attributes = change
                .after
                .clone()
                .unwrap_or(serde_json::Value::Object(Default::default()));
            insert_resource(state, &change.address, attributes);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: None,
                after: change.after.clone(),
            })
        }

        Action::Delete | Action::Forget => {
            remove_resource(state, &change.address);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: None,
            })
        }

        Action::Update => {
            // M0: Update is treated as upsert against state. Real
            // attribute-level update via provider RPC lands in M0.x.
            let attributes = change
                .after
                .clone()
                .unwrap_or(serde_json::Value::Object(Default::default()));
            remove_resource(state, &change.address);
            insert_resource(state, &change.address, attributes);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: Action::Update,
                before: change.before.clone(),
                after: change.after.clone(),
            })
        }

        Action::Replace | Action::CreateThenDelete | Action::DeleteThenCreate => {
            // Delete-then-create variant: drop the prior instance, insert
            // the new one. M0 ignores ordering; the provider would in
            // practice care about resource dependencies.
            remove_resource(state, &change.address);
            let attributes = change
                .after
                .clone()
                .unwrap_or(serde_json::Value::Object(Default::default()));
            insert_resource(state, &change.address, attributes);
            Ok(AppliedChange {
                address: change.address.clone(),
                action: change.action,
                before: change.before.clone(),
                after: change.after.clone(),
            })
        }
    }
}

pub(crate) fn insert_resource(
    state: &mut State,
    address: &ResourceAddress,
    attributes: serde_json::Value,
) {
    // Remove any existing then push the fresh instance.
    state.resources.retain(|r| r.address != *address);
    state.resources.push(StateResource {
        address: address.clone(),
        provider: default_provider_for(address),
        instances: vec![StateInstance {
            schema_version: 0,
            attributes,
            private: Vec::new(),
            dependencies: Vec::new(),
            status: InstanceStatus::Ready,
        }],
    });
}

pub(crate) fn remove_resource(state: &mut State, address: &ResourceAddress) {
    state.resources.retain(|r| r.address != *address);
}

pub(crate) fn default_provider_for(address: &ResourceAddress) -> ProviderReference {
    // Heuristic: resource type `aws_*` → hashicorp/aws, etc. M0.x replaces
    // this with a typed provider lookup from `magma-providers`.
    let type_name = &address.type_id.0;
    let (namespace, name) = type_name
        .split_once('_')
        .map(|(prefix, _)| match prefix {
            "aws" => ("hashicorp", "aws"),
            "google" | "gcp" => ("hashicorp", "google"),
            "azurerm" => ("hashicorp", "azurerm"),
            "cloudflare" => ("cloudflare", "cloudflare"),
            "datadog" => ("datadog", "datadog"),
            "kubernetes" => ("hashicorp", "kubernetes"),
            "helm" => ("hashicorp", "helm"),
            "null" => ("hashicorp", "null"),
            "random" => ("hashicorp", "random"),
            "tls" => ("hashicorp", "tls"),
            "local" => ("hashicorp", "local"),
            "external" => ("hashicorp", "external"),
            "archive" => ("hashicorp", "archive"),
            "akeyless" => ("akeyless-community", "akeyless"),
            "hcloud" => ("hetznercloud", "hcloud"),
            "splunk" => ("splunk", "splunk"),
            _ => ("hashicorp", prefix),
        })
        .unwrap_or(("hashicorp", "null"));
    let _ = type_name; // address is already destructured
    let _ = address.kind;
    ProviderReference {
        source: format!("{namespace}/{name}"),
        name: name.into(),
        alias: None,
    }
}

// silence unused warnings on ResourceKind / ResourceTypeId until M0.x
// wires the provider lookup through a real registry.
const _: fn(ResourceKind, ResourceTypeId) = |_, _| {};

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use magma_types::{
        ChangeReason, ModulePath, PlanId, ResourceAddress, ResourceKind, ResourceTypeId,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn fresh_state() -> State {
        State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: Uuid::new_v4(),
            outputs: HashMap::new(),
            resources: Vec::new(),
        }
    }

    fn addr(type_name: &str, name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId(type_name.into()),
            name: name.into(),
            key: None,
        }
    }

    fn plan_with(changes: Vec<ResourceChange>) -> Plan {
        Plan {
            id: PlanId([0u8; 32]),
            created_at: Utc::now(),
            config_root: PathBuf::new(),
            variables: HashMap::new(),
            resource_changes: changes,
            output_changes: Vec::new(),
        }
    }

    #[test]
    fn apply_create_adds_to_state() {
        let mut state = fresh_state();
        let p = plan_with(vec![ResourceChange {
            address: addr("aws_vpc", "main"),
            action: Action::Create,
            before: None,
            after: Some(json!({ "cidr_block": "10.0.0.0/16" })),
            reasons: vec![ChangeReason::NewResource],
        }]);

        let outcome = run_plan(&p, &mut state).unwrap();
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.failed.len(), 0);
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.type_id.0, "aws_vpc");
        assert_eq!(state.serial, 1);
    }

    #[test]
    fn apply_delete_removes_from_state() {
        let mut state = fresh_state();
        state.resources.push(StateResource {
            address: addr("aws_vpc", "main"),
            provider: default_provider_for(&addr("aws_vpc", "main")),
            instances: vec![StateInstance {
                schema_version: 0,
                attributes: json!({ "id": "vpc-x" }),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        });

        let p = plan_with(vec![ResourceChange {
            address: addr("aws_vpc", "main"),
            action: Action::Delete,
            before: Some(json!({ "id": "vpc-x" })),
            after: None,
            reasons: vec![ChangeReason::DeletedResource],
        }]);

        let outcome = run_plan(&p, &mut state).unwrap();
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(state.resources.len(), 0);
    }

    #[test]
    fn provider_inferred_for_known_prefixes() {
        let r = default_provider_for(&addr("aws_vpc", "x"));
        assert_eq!(r.source, "hashicorp/aws");
        let r = default_provider_for(&addr("cloudflare_record", "x"));
        assert_eq!(r.source, "cloudflare/cloudflare");
        let r = default_provider_for(&addr("akeyless_dfc_key", "x"));
        assert_eq!(r.source, "akeyless-community/akeyless");
    }
}
