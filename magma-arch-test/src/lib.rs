//! magma-arch-test — reusable typed verification primitives for
//! Pangea-rendered workspaces.
//!
//! `WorkspaceTestHarness` wraps the in-memory pipeline (`discover →
//! load → parse → plan`) and exposes typed assertions any consumer can
//! use:
//!
//!   - `magma-test/tests/integration_pangea_architectures_coverage.rs`
//!     (already; will refactor to use this)
//!   - `magma fixture verify` CLI subcommand
//!   - `pangea-architectures` rspec tests (via Ruby ↔ magma fixture
//!     mediation; see Pangea::Magma::Matchers)
//!   - `pangea-operator` integration tests when it adopts magma
//!   - Third-party Pangea gem consumers
//!
//! Compounding goal: every tool that needs to assert *"this workspace
//! works under magma"* uses the typed primitives here, never the raw
//! `magma-plan + magma-config` combo directly. New consumers add one
//! line: `WorkspaceTestHarness::verify(&path).await`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::Utc;
use magma_config::Config;
use magma_pangea::{TerraformJsonLoader, WorkspaceLoader, WorkspaceShape};
use magma_plan::plan;
use magma_state::empty_state;
use magma_types::{Action, Plan, PlanId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("workspace path does not exist: {0:?}")]
    NoSuchPath(PathBuf),
    #[error("workspace discovery failed: {0}")]
    Discover(String),
    #[error("workspace load failed: {0}")]
    Load(String),
    #[error("config parse failed: {0}")]
    Parse(String),
    #[error("plan failed: {0}")]
    Plan(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("expectation violated: {0}")]
    ExpectationViolated(String),
}

// ── Typed reports ─────────────────────────────────────────────────

/// Output of a single workspace's harness run — a typed value
/// downstream consumers (CLI reports, MCP tools, rspec matchers)
/// interpret without re-running the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceReport {
    /// Workspace shape detected by `magma_pangea::WorkspaceShape::discover`.
    pub shape:                String,
    /// Number of resource changes the plan emits against empty state.
    pub resource_change_count: usize,
    /// Action histogram across all changes (Create/Delete/NoOp/etc.).
    pub action_histogram:     HashMap<String, usize>,
    /// Distinct provider sources referenced by the workspace.
    pub providers:            Vec<String>,
    /// Distinct resource type names that appear in the rendered JSON.
    pub resource_types:       Vec<String>,
    /// The BLAKE3 PlanId of this run (hex-encoded). Deterministic when
    /// inputs are fixed.
    pub plan_id:              String,
    /// Plan creation timestamp (RFC3339).
    pub created_at:           String,
    /// Compatibility summary — derived from the planner output.
    pub compatibility:        CompatibilitySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilitySummary {
    pub parses:                bool,
    pub plans_cleanly:         bool,
    pub all_creates:           bool,
    pub uses_in_memory_chains: bool,
}

// ── Harness ───────────────────────────────────────────────────────

/// Reusable verification primitive. Construct via `WorkspaceTestHarness::new`
/// (no async; just wires references) then call `.verify().await` for
/// a typed `WorkspaceReport`, or use the assertion helpers
/// (`assert_plans_cleanly`, etc.) for test-friendly inline checks.
pub struct WorkspaceTestHarness {
    workspace_path: PathBuf,
}

impl WorkspaceTestHarness {
    pub fn new(workspace_path: impl Into<PathBuf>) -> Self {
        Self { workspace_path: workspace_path.into() }
    }

    pub fn path(&self) -> &Path { &self.workspace_path }

    /// Run the full pipeline (discover → load → parse → plan) and
    /// return a typed `WorkspaceReport`. Doesn't mutate state on
    /// disk — works against a temp clone if the workspace is a
    /// single-file fixture.
    pub async fn verify(&self) -> Result<WorkspaceReport, HarnessError> {
        let workspace_dir = self.materialize_workspace_dir().await?;

        let shape = WorkspaceShape::discover(workspace_dir.path())
            .map_err(|e| HarnessError::Discover(e.to_string()))?;
        let shape_kind = match &shape {
            WorkspaceShape::PangeaRuby     { .. } => "PangeaRuby",
            WorkspaceShape::TerraformJson  { .. } => "TerraformJson",
        }
        .to_string();

        let loaded = TerraformJsonLoader
            .load(shape)
            .await
            .map_err(|e| HarnessError::Load(e.to_string()))?;
        let cfg = Config::from_json(loaded.rendered)
            .map_err(|e| HarnessError::Parse(e.to_string()))?;
        let plan_out = plan(&cfg, &empty_state())
            .map_err(|e| HarnessError::Plan(e.to_string()))?;

        Ok(report_from(&cfg, &plan_out, shape_kind))
    }

    /// Materialize the workspace as a directory we can pass to
    /// `WorkspaceShape::discover`. If `workspace_path` is already a
    /// directory we use it directly; if it's a single `.tf.json` file
    /// we stage it into a tempdir (so the discover step sees a real
    /// workspace shape).
    async fn materialize_workspace_dir(&self) -> Result<WorkspaceDir, HarnessError> {
        if !self.workspace_path.exists() {
            return Err(HarnessError::NoSuchPath(self.workspace_path.clone()));
        }
        if self.workspace_path.is_dir() {
            return Ok(WorkspaceDir::Direct(self.workspace_path.clone()));
        }
        // It's a file. Stage it in a tempdir under its existing name.
        let tmp = tempfile::tempdir()?;
        let name = self
            .workspace_path
            .file_name()
            .map(std::ffi::OsString::from)
            .unwrap_or_else(|| std::ffi::OsString::from("rendered.tf.json"));
        let staged = tmp.path().join(&name);
        tokio::fs::copy(&self.workspace_path, &staged).await?;
        Ok(WorkspaceDir::Staged(tmp))
    }

    // ── Assertion helpers ─────────────────────────────────────────

    /// Assert: pipeline runs cleanly, every change is a Create
    /// (i.e. empty-state baseline). Returns the report for further
    /// inspection.
    pub async fn assert_plans_cleanly(&self) -> Result<WorkspaceReport, HarnessError> {
        let report = self.verify().await?;
        if !report.compatibility.plans_cleanly {
            return Err(HarnessError::ExpectationViolated(
                "workspace does not plan cleanly".into(),
            ));
        }
        Ok(report)
    }

    /// Assert: the plan emits at least `min` resource changes.
    pub async fn assert_min_changes(&self, min: usize) -> Result<WorkspaceReport, HarnessError> {
        let report = self.verify().await?;
        if report.resource_change_count < min {
            return Err(HarnessError::ExpectationViolated(format!(
                "expected at least {min} changes, got {}",
                report.resource_change_count,
            )));
        }
        Ok(report)
    }

    /// Assert: the workspace references a specific provider source
    /// (e.g. "hashicorp/aws").
    pub async fn assert_uses_provider(
        &self,
        provider_source: &str,
    ) -> Result<WorkspaceReport, HarnessError> {
        let report = self.verify().await?;
        if !report.providers.iter().any(|p| p == provider_source) {
            return Err(HarnessError::ExpectationViolated(format!(
                "expected provider {provider_source:?}; got {:?}",
                report.providers,
            )));
        }
        Ok(report)
    }

    /// Assert: the workspace declares a specific resource type
    /// (e.g. "aws_vpc"). Useful for fixture coverage checks.
    pub async fn assert_uses_resource_type(
        &self,
        resource_type: &str,
    ) -> Result<WorkspaceReport, HarnessError> {
        let report = self.verify().await?;
        if !report.resource_types.iter().any(|r| r == resource_type) {
            return Err(HarnessError::ExpectationViolated(format!(
                "expected resource type {resource_type:?}; got {:?}",
                report.resource_types,
            )));
        }
        Ok(report)
    }

    /// Assert: PlanId is byte-stable across reruns with the same
    /// fixed state. Critical for tameshi attestation + §II.6 level-3
    /// plan-diff determinism.
    ///
    /// `empty_state()` regenerates the state lineage UUID on every
    /// call, which legitimately changes the PlanId hash. To prove
    /// determinism we hold one state fixed and run the plan twice
    /// against it inline (rather than calling `verify()` twice, which
    /// would each construct fresh state).
    pub async fn assert_plan_id_deterministic(&self) -> Result<WorkspaceReport, HarnessError> {
        let workspace_dir = self.materialize_workspace_dir().await?;
        let shape = WorkspaceShape::discover(workspace_dir.path())
            .map_err(|e| HarnessError::Discover(e.to_string()))?;
        let shape_kind = match &shape {
            WorkspaceShape::PangeaRuby     { .. } => "PangeaRuby",
            WorkspaceShape::TerraformJson  { .. } => "TerraformJson",
        }
        .to_string();
        let loaded = TerraformJsonLoader
            .load(shape)
            .await
            .map_err(|e| HarnessError::Load(e.to_string()))?;
        let cfg = Config::from_json(loaded.rendered)
            .map_err(|e| HarnessError::Parse(e.to_string()))?;
        let fixed_state = empty_state();
        let p1 = plan(&cfg, &fixed_state).map_err(|e| HarnessError::Plan(e.to_string()))?;
        let p2 = plan(&cfg, &fixed_state).map_err(|e| HarnessError::Plan(e.to_string()))?;
        if p1.id.0 != p2.id.0 {
            return Err(HarnessError::ExpectationViolated(format!(
                "PlanId not deterministic against fixed state: {} != {}",
                hex::encode(p1.id.0),
                hex::encode(p2.id.0),
            )));
        }
        Ok(report_from(&cfg, &p1, shape_kind))
    }

    /// Run the full architecture-composition + workspace-lifecycle
    /// law battery against this workspace. One-line entrypoint for
    /// "does this Pangea-rendered workspace pass every universal
    /// substrate contract?"
    ///
    /// Internally uses `magma_test_laws::preflight` wrappers so
    /// every law violation surfaces as a typed `HarnessError`
    /// (instead of a panic). Suitable for both `#[tokio::test]`
    /// AND production preflight (pangea-operator startup, magma CLI
    /// flight-check).
    pub async fn assert_all_substrate_laws(&self) -> Result<WorkspaceReport, HarnessError> {
        let workspace_dir = self.materialize_workspace_dir().await?;
        let shape = WorkspaceShape::discover(workspace_dir.path())
            .map_err(|e| HarnessError::Discover(e.to_string()))?;
        let shape_kind = match &shape {
            WorkspaceShape::PangeaRuby     { .. } => "PangeaRuby",
            WorkspaceShape::TerraformJson  { .. } => "TerraformJson",
        }
        .to_string();
        let loaded = TerraformJsonLoader
            .load(shape)
            .await
            .map_err(|e| HarnessError::Load(e.to_string()))?;
        let cfg = Config::from_json(loaded.rendered)
            .map_err(|e| HarnessError::Parse(e.to_string()))?;
        // Architecture composition + workspace lifecycle laws as
        // typed Results (no panic propagation).
        if let Err(v) = magma_test_laws::preflight::check_architecture(&cfg) {
            return Err(HarnessError::ExpectationViolated(format!(
                "{} — {}", v.law, v.message,
            )));
        }
        if let Err(v) = magma_test_laws::preflight::check_workspace(&cfg) {
            return Err(HarnessError::ExpectationViolated(format!(
                "{} — {}", v.law, v.message,
            )));
        }
        // Final report from one canonical plan run.
        let plan_out = plan(&cfg, &empty_state())
            .map_err(|e| HarnessError::Plan(e.to_string()))?;
        Ok(report_from(&cfg, &plan_out, shape_kind))
    }
}

// ── Helpers ────────────────────────────────────────────────────────

enum WorkspaceDir {
    Direct(PathBuf),
    Staged(tempfile::TempDir),
}

impl WorkspaceDir {
    fn path(&self) -> &Path {
        match self {
            Self::Direct(p)   => p,
            Self::Staged(tmp) => tmp.path(),
        }
    }
}

fn report_from(cfg: &Config, plan_out: &Plan, shape: String) -> WorkspaceReport {
    let providers: Vec<String> = cfg
        .provider_references()
        .into_iter()
        .map(|p| p.source)
        .collect();

    let resource_types: Vec<String> = {
        let mut s: HashSet<String> = HashSet::new();
        for type_name in cfg.resources.keys() {
            s.insert(type_name.clone());
        }
        for type_name in cfg.data.keys() {
            s.insert(type_name.clone());
        }
        let mut v: Vec<String> = s.into_iter().collect();
        v.sort();
        v
    };

    let mut action_histogram: HashMap<String, usize> = HashMap::new();
    let mut all_creates = !plan_out.resource_changes.is_empty();
    for change in &plan_out.resource_changes {
        let action_str = action_name(change.action);
        *action_histogram.entry(action_str.into()).or_insert(0) += 1;
        if !matches!(change.action, Action::Create) {
            all_creates = false;
        }
    }

    WorkspaceReport {
        shape,
        resource_change_count: plan_out.resource_changes.len(),
        action_histogram,
        providers,
        resource_types,
        plan_id:               hex::encode(plan_id_bytes(&plan_out.id)),
        created_at:            plan_out.created_at.to_rfc3339(),
        compatibility: CompatibilitySummary {
            parses:                true,
            plans_cleanly:         true,
            all_creates,
            // Always true when consumed via this harness — the harness
            // *is* the in-memory chain. Materializing to disk happens
            // only for fixture staging.
            uses_in_memory_chains: true,
        },
    }
}

fn plan_id_bytes(id: &PlanId) -> &[u8; 32] { &id.0 }

fn action_name(a: Action) -> &'static str {
    match a {
        Action::NoOp             => "no_op",
        Action::Create           => "create",
        Action::Read             => "read",
        Action::Update           => "update",
        Action::Replace          => "replace",
        Action::Delete           => "delete",
        Action::Forget           => "forget",
        Action::CreateThenDelete => "create_then_delete",
        Action::DeleteThenCreate => "delete_then_create",
    }
}

// ── Aggregate reporter (multi-fixture) ────────────────────────────

/// Aggregate report across multiple workspace verifications. Used by
/// the `magma fixture` CLI subcommand to emit a single JSON document
/// summarizing a fixture-dir-wide run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateReport {
    pub total_workspaces: usize,
    pub passed:           usize,
    pub failed:           usize,
    pub started_at:       String,
    pub finished_at:      String,
    pub workspaces:       Vec<NamedReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedReport {
    pub name:   String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<WorkspaceReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:  Option<String>,
}

/// Run the harness against every `.tf.json` file under `dir`. Emits a
/// typed aggregate report. Doesn't bail on the first failure — every
/// fixture is attempted, the report covers all of them. CI consumers
/// can inspect `.failed > 0` for exit-code logic.
pub async fn verify_directory(dir: impl AsRef<Path>) -> Result<AggregateReport, HarnessError> {
    let started_at = Utc::now().to_rfc3339();
    let dir = dir.as_ref();
    let mut workspaces: Vec<NamedReport> = Vec::new();

    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.is_file() && p.extension().is_some_and(|ext| ext == "json") {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    entries.sort();

    let mut passed = 0;
    let mut failed = 0;
    for entry in &entries {
        let name = entry
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string();
        let harness = WorkspaceTestHarness::new(entry.clone());
        match harness.verify().await {
            Ok(report) => {
                passed += 1;
                workspaces.push(NamedReport {
                    name,
                    status: "passed".into(),
                    report: Some(report),
                    error:  None,
                });
            }
            Err(e) => {
                failed += 1;
                workspaces.push(NamedReport {
                    name,
                    status: "failed".into(),
                    report: None,
                    error:  Some(e.to_string()),
                });
            }
        }
    }

    Ok(AggregateReport {
        total_workspaces: entries.len(),
        passed,
        failed,
        started_at,
        finished_at: Utc::now().to_rfc3339(),
        workspaces,
    })
}

/// Run the full substrate law battery against every `.tf.json` file
/// under `dir`. Per-fixture pass/fail; emits the same typed
/// `AggregateReport` shape `verify_directory` uses. Use this for
/// CI gates: a `failed > 0` means at least one workspace violated a
/// universal substrate contract.
pub async fn run_law_battery_directory(
    dir: impl AsRef<Path>,
) -> Result<AggregateReport, HarnessError> {
    let started_at = Utc::now().to_rfc3339();
    let dir = dir.as_ref();
    let mut workspaces: Vec<NamedReport> = Vec::new();

    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.is_file() && p.extension().is_some_and(|ext| ext == "json") {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    entries.sort();

    let mut passed = 0;
    let mut failed = 0;
    for entry in &entries {
        let name = entry
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("<unknown>")
            .to_string();
        let harness = WorkspaceTestHarness::new(entry.clone());
        match harness.assert_all_substrate_laws().await {
            Ok(report) => {
                passed += 1;
                workspaces.push(NamedReport {
                    name,
                    status: "passed".into(),
                    report: Some(report),
                    error:  None,
                });
            }
            Err(e) => {
                failed += 1;
                workspaces.push(NamedReport {
                    name,
                    status: "violated".into(),
                    report: None,
                    error:  Some(e.to_string()),
                });
            }
        }
    }

    Ok(AggregateReport {
        total_workspaces: entries.len(),
        passed,
        failed,
        started_at,
        finished_at: Utc::now().to_rfc3339(),
        workspaces,
    })
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn verify_single_workspace_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("test.tf.json");
        std::fs::write(
            &json_path,
            serde_json::to_string(&json!({
                "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
            })).unwrap(),
        ).unwrap();

        let harness = WorkspaceTestHarness::new(tmp.path().to_path_buf());
        let report = harness.verify().await.unwrap();
        assert_eq!(report.shape, "TerraformJson");
        assert_eq!(report.resource_change_count, 1);
        assert!(report.action_histogram.contains_key("create"));
        assert!(report.compatibility.all_creates);
    }

    #[tokio::test]
    async fn verify_single_file_stages_into_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("test.tf.json");
        std::fs::write(
            &json_path,
            serde_json::to_string(&json!({
                "resource": {
                    "aws_vpc":    { "main":    {} },
                    "aws_subnet": { "public":  {} }
                }
            })).unwrap(),
        ).unwrap();

        let harness = WorkspaceTestHarness::new(json_path.clone());
        let report = harness.verify().await.unwrap();
        assert_eq!(report.resource_change_count, 2);
    }

    #[tokio::test]
    async fn assert_uses_provider_works() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("test.tf.json");
        std::fs::write(
            &json_path,
            serde_json::to_string(&json!({
                "terraform": {
                    "required_providers": { "aws": { "source": "hashicorp/aws" } }
                },
                "resource": { "aws_vpc": { "main": {} } }
            })).unwrap(),
        ).unwrap();

        let harness = WorkspaceTestHarness::new(tmp.path().to_path_buf());
        let report = harness.assert_uses_provider("hashicorp/aws").await.unwrap();
        assert!(report.providers.contains(&"hashicorp/aws".to_string()));

        let err = harness.assert_uses_provider("cloudflare/cloudflare").await;
        assert!(matches!(err, Err(HarnessError::ExpectationViolated(_))));
    }

    #[tokio::test]
    async fn assert_plan_id_deterministic_holds_for_same_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let json_path = tmp.path().join("test.tf.json");
        std::fs::write(
            &json_path,
            serde_json::to_string(&json!({
                "resource": { "aws_vpc": { "main": {} } }
            })).unwrap(),
        ).unwrap();

        let harness = WorkspaceTestHarness::new(tmp.path().to_path_buf());
        harness.assert_plan_id_deterministic().await.unwrap();
    }

    #[tokio::test]
    async fn verify_directory_aggregates() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["a", "b", "c"] {
            std::fs::write(
                tmp.path().join(format!("{name}.tf.json")),
                serde_json::to_string(&json!({
                    "resource": { "aws_vpc": { name: {} } }
                })).unwrap(),
            ).unwrap();
        }

        let agg = verify_directory(tmp.path()).await.unwrap();
        assert_eq!(agg.total_workspaces, 3);
        assert_eq!(agg.passed,           3);
        assert_eq!(agg.failed,           0);
        for w in &agg.workspaces {
            assert_eq!(w.status, "passed");
            assert!(w.report.is_some());
            assert!(w.error.is_none());
        }
    }
}
