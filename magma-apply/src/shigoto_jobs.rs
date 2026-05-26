//! shigoto Job wrappers for magma operations.
//!
//! Per `theory/MAGMA.md` §II.9, every magma operation surfaces as a
//! typed `shigoto::Job`. This module provides the typed wrappers:
//!
//! - `PlanJob` — wraps `magma_plan::plan(Config, State) -> Plan`
//! - `ApplyChangeJob` — wraps a single `ResourceChange` application
//! - `ApplyPlanJob` — wraps the full `run_plan(Plan, &mut State)`
//!
//! The scheduler integration (driving a `shigoto::Dag<ApplyChangeJob>`
//! via `shigoto::Scheduler`) lands alongside M1's broader shigoto
//! integration. The typed shape is in place now so consumers can
//! schedule directly via shigoto without rewriting wrappers later.

use std::sync::Arc;

use magma_config::Config;
use magma_types::{Plan, ResourceChange, State};
use shigoto::{Job, JobId, JobKindId, JobScope, JobSubject};

use crate::{ApplyError, ApplyOutcome};

/// `Plan` operation: produces a typed `Plan` from `Config × State`.
pub struct PlanJob {
    pub workspace_name: String,
    pub config: Arc<Config>,
    pub state: Arc<State>,
}

#[derive(Debug, thiserror::Error)]
#[error("plan job error: {0}")]
pub struct PlanJobError(pub String);

#[async_trait::async_trait]
impl Job for PlanJob {
    type Output = Plan;
    type Error = PlanJobError;

    fn id(&self) -> JobId {
        JobId {
            scope: JobScope::Workspace(self.workspace_name.clone()),
            kind: self.kind(),
            subject: JobSubject::None,
        }
    }

    fn kind(&self) -> JobKindId {
        JobKindId::new("magma.plan")
    }

    async fn execute(&self) -> Result<Self::Output, Self::Error> {
        magma_plan::plan(&self.config, &self.state).map_err(|e| PlanJobError(e.to_string()))
    }
}

/// `ApplyChange` operation: applies one `ResourceChange`. The full
/// resource graph maps to a `shigoto::Dag<ApplyChangeJob>` with edges
/// per the resource dependency graph (per `magma_graph::ResourceGraph`).
pub struct ApplyChangeJob {
    pub workspace_name: String,
    pub change: ResourceChange,
    // M0 holds a snapshot of state at job creation; the apply mutates
    // a clone in execute(). Full multi-tenant state-mutation under
    // shigoto's Scheduler requires the typed StateRef + back-channel
    // commit pattern that lands in M1.
    pub state_snapshot: Arc<State>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyChangeJobError {
    #[error("apply: {0}")]
    Apply(#[from] ApplyError),
}

#[async_trait::async_trait]
impl Job for ApplyChangeJob {
    type Output = ApplyOutcome;
    type Error = ApplyChangeJobError;

    fn id(&self) -> JobId {
        JobId {
            scope: JobScope::Workspace(self.workspace_name.clone()),
            kind: self.kind(),
            subject: JobSubject::Pinned(format!(
                "{}.{}",
                self.change.address.type_id.0, self.change.address.name,
            )),
        }
    }

    fn kind(&self) -> JobKindId {
        JobKindId::new("magma.apply_change")
    }

    async fn execute(&self) -> Result<Self::Output, Self::Error> {
        // Apply just this one change against a fresh state clone.
        let mut state = (*self.state_snapshot).clone();
        let single_plan = Plan {
            id: magma_types::PlanId([0u8; 32]),
            created_at: chrono::Utc::now(),
            config_root: std::path::PathBuf::new(),
            variables: Default::default(),
            resource_changes: vec![self.change.clone()],
            output_changes: vec![],
        };
        let outcome = crate::run_plan(&single_plan, &mut state)?;
        Ok(outcome)
    }
}

/// `ApplyPlan` operation: wraps the full `run_plan` call as a single
/// shigoto Job. Used when the operator wants the whole plan as one
/// scheduler-tracked unit (rather than decomposing into per-change Jobs).
pub struct ApplyPlanJob {
    pub workspace_name: String,
    pub plan: Arc<Plan>,
    pub state_snapshot: Arc<State>,
}

#[async_trait::async_trait]
impl Job for ApplyPlanJob {
    type Output = ApplyOutcome;
    type Error = ApplyChangeJobError;

    fn id(&self) -> JobId {
        JobId {
            scope: JobScope::Workspace(self.workspace_name.clone()),
            kind: self.kind(),
            subject: JobSubject::Pinned(format!("plan-{}", hex::encode(self.plan.id.0))),
        }
    }

    fn kind(&self) -> JobKindId {
        JobKindId::new("magma.apply_plan")
    }

    async fn execute(&self) -> Result<Self::Output, Self::Error> {
        let mut state = (*self.state_snapshot).clone();
        Ok(crate::run_plan(&self.plan, &mut state)?)
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_types::{
        Action, ChangeReason, ModulePath, ResourceAddress, ResourceKind, ResourceTypeId,
    };
    use serde_json::json;

    fn empty_state() -> State {
        State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: uuid::Uuid::new_v4(),
            outputs: Default::default(),
            resources: vec![],
        }
    }

    #[tokio::test]
    async fn apply_change_job_runs() {
        let job = ApplyChangeJob {
            workspace_name: "test-ws".into(),
            change: ResourceChange {
                address: ResourceAddress {
                    module: ModulePath::root(),
                    kind: ResourceKind::Managed,
                    type_id: ResourceTypeId("aws_vpc".into()),
                    name: "main".into(),
                    key: None,
                },
                action: Action::Create,
                before: None,
                after: Some(json!({ "cidr_block": "10.0.0.0/16" })),
                reasons: vec![ChangeReason::NewResource],
            },
            state_snapshot: Arc::new(empty_state()),
        };
        assert_eq!(job.kind().0, "magma.apply_change");
        let outcome = job.execute().await.unwrap();
        assert_eq!(outcome.applied.len(), 1);
    }

    #[test]
    fn plan_job_kind_id() {
        let job = PlanJob {
            workspace_name: "test-ws".into(),
            config: Arc::new(Config::default()),
            state: Arc::new(empty_state()),
        };
        assert_eq!(job.kind().0, "magma.plan");
        assert!(matches!(job.id().scope, JobScope::Workspace(_)));
    }
}
