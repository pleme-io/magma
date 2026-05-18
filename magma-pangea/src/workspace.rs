//! `Workspace` — a typed reconcilable atom.
//!
//! Per [[project-workspaces-as-programmable-atoms]] / theory/MAGMA.md
//! §II.9, each Pangea workspace is a typed primitive with declared
//! input/output slots, a render function (inputs → Config), and a
//! reconcile method (state × config → ReconcileResult).
//!
//! Workspaces compose into `WorkspaceChain` DAGs (see [`crate::chain`])
//! that thread outputs to downstream inputs as typed Rust values —
//! no disk, no `data "terraform_remote_state"`, no JSON serialization
//! across workspace boundaries.

use std::collections::HashMap;

use async_trait::async_trait;
use magma_config::Config;
use magma_types::{Plan, State};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("input slot {0:?} missing or malformed")]
    InputMissing(String),
    #[error("output slot {0:?} not produced by workspace")]
    OutputMissing(String),
    #[error("config error: {0}")]
    Config(#[from] magma_config::ConfigError),
    #[error("plan error: {0}")]
    Plan(String),
    #[error("invalid chain: {0}")]
    InvalidChain(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ── ReconcileResult ────────────────────────────────────────────────

/// The output of reconciling a single workspace — the typed values
/// downstream consumers (chains, tests, callers) interact with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileResult {
    pub workspace_name: String,
    pub plan:           Plan,
    pub new_state:      State,
    pub outputs:        HashMap<String, serde_json::Value>,
}

// ── Workspace trait ───────────────────────────────────────────────

/// A typed reconcilable atom.
///
/// Each impl declares its typed `input_slots` + `output_slots`, then
/// implements `render` (build a `Config` from inputs) and `reconcile`
/// (plan + populate outputs).
///
/// For M0, `reconcile` performs the structural plan (Create / Delete /
/// NoOp) via `magma_plan::plan`; the provider-RPC apply step lands in
/// M0.x once the gRPC mTLS layer is pinned.
#[async_trait]
pub trait Workspace: Send + Sync {
    fn name(&self) -> &str;
    fn input_slots(&self) -> Vec<String>;
    fn output_slots(&self) -> Vec<String>;

    /// Render this workspace's `Config` from typed inputs. Pure
    /// (no side effects); called by `reconcile` and standalone for
    /// dry-run / synth flows.
    fn render(
        &self,
        inputs: &HashMap<String, serde_json::Value>,
    ) -> Result<Config, WorkspaceError>;

    /// Reconcile against current state. Returns the typed plan +
    /// (post-apply) state + extracted outputs.
    async fn reconcile(
        &self,
        inputs: &HashMap<String, serde_json::Value>,
        current_state: State,
    ) -> Result<ReconcileResult, WorkspaceError>;
}

// ── InlineWorkspace — closure-built for tests + dynamic flows ─────

type RenderFn = Box<
    dyn Fn(
            &HashMap<String, serde_json::Value>,
        ) -> Result<Config, WorkspaceError>
        + Send
        + Sync,
>;

type OutputFn = Box<
    dyn Fn(
            &Config,
            &State,
        ) -> HashMap<String, serde_json::Value>
        + Send
        + Sync,
>;

/// A `Workspace` built from closures. Used heavily in tests + for
/// dynamically-constructed flows (tatara-lisp `(defmagma-workspace …)`
/// compiles to InlineWorkspace instances at runtime in M0.x).
pub struct InlineWorkspace {
    name:         String,
    input_slots:  Vec<String>,
    output_slots: Vec<String>,
    render_fn:    RenderFn,
    output_fn:    OutputFn,
}

impl InlineWorkspace {
    pub fn new<R, O>(
        name: impl Into<String>,
        input_slots: Vec<String>,
        output_slots: Vec<String>,
        render: R,
        outputs: O,
    ) -> Self
    where
        R: Fn(&HashMap<String, serde_json::Value>) -> Result<Config, WorkspaceError>
            + Send
            + Sync
            + 'static,
        O: Fn(&Config, &State) -> HashMap<String, serde_json::Value>
            + Send
            + Sync
            + 'static,
    {
        Self {
            name: name.into(),
            input_slots,
            output_slots,
            render_fn: Box::new(render),
            output_fn: Box::new(outputs),
        }
    }
}

#[async_trait]
impl Workspace for InlineWorkspace {
    fn name(&self) -> &str { &self.name }
    fn input_slots(&self) -> Vec<String> { self.input_slots.clone() }
    fn output_slots(&self) -> Vec<String> { self.output_slots.clone() }

    fn render(
        &self,
        inputs: &HashMap<String, serde_json::Value>,
    ) -> Result<Config, WorkspaceError> {
        (self.render_fn)(inputs)
    }

    async fn reconcile(
        &self,
        inputs: &HashMap<String, serde_json::Value>,
        current_state: State,
    ) -> Result<ReconcileResult, WorkspaceError> {
        let cfg = self.render(inputs)?;
        let plan = magma_plan::plan(&cfg, &current_state)
            .map_err(|e| WorkspaceError::Plan(e.to_string()))?;
        // M0: state is unchanged (plan-only). M0.x wires provider RPC
        // through `magma_apply` to mutate `current_state` per the plan.
        let new_state = current_state;
        let outputs = (self.output_fn)(&cfg, &new_state);
        Ok(ReconcileResult {
            workspace_name: self.name.clone(),
            plan,
            new_state,
            outputs,
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_state::empty_state;
    use magma_types::Action;
    use serde_json::json;

    #[tokio::test]
    async fn inline_workspace_reconciles() {
        let ws = InlineWorkspace::new(
            "demo",
            vec!["x".into()],
            vec!["y".into()],
            |inputs| {
                let x = inputs.get("x").and_then(|v| v.as_str()).unwrap_or("default");
                Config::from_json(json!({
                    "resource": { "aws_vpc": { "main": { "cidr_block": x } } }
                }))
                .map_err(WorkspaceError::Config)
            },
            |_cfg, _state| {
                HashMap::from([("y".to_string(), json!("y-value"))])
            },
        );
        let mut inputs = HashMap::new();
        inputs.insert("x".into(), json!("10.0.0.0/16"));
        let result = ws.reconcile(&inputs, empty_state()).await.unwrap();
        assert_eq!(result.workspace_name, "demo");
        assert_eq!(result.plan.resource_changes.len(), 1);
        assert_eq!(result.plan.resource_changes[0].action, Action::Create);
        assert_eq!(result.outputs.get("y"), Some(&json!("y-value")));
    }

    #[tokio::test]
    async fn workspace_idempotent_re_reconcile() {
        let ws = InlineWorkspace::new(
            "idem", vec![], vec![],
            |_| Config::from_json(json!({ "resource": { "aws_vpc": { "main": {} } } }))
                .map_err(WorkspaceError::Config),
            |_, _| HashMap::new(),
        );
        // empty_state() generates a new lineage uuid each call, which
        // legitimately changes the PlanId hash. For an idempotency
        // test we hold the state fixed across both runs.
        let fixed = empty_state();
        let r1 = ws.reconcile(&HashMap::new(), fixed.clone()).await.unwrap();
        let r2 = ws.reconcile(&HashMap::new(), fixed).await.unwrap();
        // Same inputs + same state → same PlanId.
        assert_eq!(r1.plan.id.0, r2.plan.id.0);
    }
}
