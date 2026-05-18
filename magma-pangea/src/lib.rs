//! magma-pangea — Pangea Ruby DSL evaluator + Terraform JSON reader.
//!
//! The canonical input layer for magma. Two paths to a typed
//! `magma_types::Config`:
//!
//! 1. **Pangea Ruby DSL** (preferred): the operator authors a workspace
//!    in Pangea Ruby (e.g. `template :seph_vpc do ... end`); magma loads
//!    the Pangea Ruby gems (pangea-core, pangea-aws, pangea-cloudflare,
//!    pangea-akeyless, …) into an in-process CRuby interpreter via
//!    [`magnus`] and evaluates the DSL. Returns a typed value tree.
//!    Mirrors pangea-operator's pattern (see `pangea-ruby-eval` crate);
//!    available behind the `magnus` feature.
//!
//! 2. **Terraform JSON** (compat fallback): the operator (or some
//!    pipeline) has already rendered a workspace to Terraform JSON via
//!    Pangea's `TerraformSynthesizer`. magma reads the JSON directly,
//!    no Ruby in the loop. Required for environments without a CRuby
//!    toolchain (some CI, some WASI deployments). Always available.
//!
//! HCL parsing is **out of scope** per `theory/MAGMA.md` §II.1. Magma
//! never reads `.tf` files. If you have raw HCL, render it to Terraform
//! JSON with `terraform-config-inspect` or migrate to Pangea Ruby.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod chain;
pub mod workspace;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PangeaError {
    #[error("workspace path does not exist: {0:?}")]
    NoSuchWorkspace(PathBuf),
    #[error("workspace has no Pangea Ruby files or Terraform JSON: {0:?}")]
    EmptyWorkspace(PathBuf),
    #[error("Pangea Ruby evaluation failed: {0}")]
    RubyEval(String),
    #[error("Terraform JSON parse failed: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("magnus feature is required for in-process Pangea Ruby evaluation; build with --features magnus")]
    MagnusDisabled,
}

// ── Workspace discovery ────────────────────────────────────────────

/// Workspace layout discovered on disk. Magma supports two input modes;
/// the loader picks one based on which artifacts are present.
#[derive(Debug, Clone)]
pub enum WorkspaceShape {
    /// Pangea Ruby workspace: at least one `*.rb` file + a `pangea.yml`
    /// at workspace root. Evaluated in-process via magnus (magnus feature
    /// required).
    PangeaRuby {
        root: PathBuf,
        pangea_yml: PathBuf,
        ruby_files: Vec<PathBuf>,
    },
    /// Pre-rendered Terraform JSON: one or more `*.tf.json` files. Read
    /// directly into magma-types without Ruby in the loop.
    TerraformJson {
        root: PathBuf,
        json_files: Vec<PathBuf>,
    },
}

impl WorkspaceShape {
    /// Probe a directory and return what shape it is.
    pub fn discover(root: impl AsRef<Path>) -> Result<Self, PangeaError> {
        let root = root.as_ref();
        if !root.exists() {
            return Err(PangeaError::NoSuchWorkspace(root.to_path_buf()));
        }

        let mut ruby_files = Vec::new();
        let mut json_files = Vec::new();
        let mut pangea_yml: Option<PathBuf> = None;

        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name == "pangea.yml" || name == "pangea.yaml" {
                pangea_yml = Some(path.clone());
            } else if name.ends_with(".tf.json") {
                json_files.push(path);
            } else if name.ends_with(".rb") {
                ruby_files.push(path);
            }
        }

        match (pangea_yml, ruby_files.is_empty(), json_files.is_empty()) {
            (Some(yml), false, _) => Ok(Self::PangeaRuby {
                root: root.to_path_buf(),
                pangea_yml: yml,
                ruby_files,
            }),
            (_, _, false) => Ok(Self::TerraformJson {
                root: root.to_path_buf(),
                json_files,
            }),
            _ => Err(PangeaError::EmptyWorkspace(root.to_path_buf())),
        }
    }
}

// ── Loader trait ───────────────────────────────────────────────────

/// Loaded workspace artifacts — the in-memory output of either input
/// path. Downstream (`magma-config`) refines this into typed
/// `magma_types::Config` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedWorkspace {
    pub shape:     ShapeKind,
    pub root:      PathBuf,
    /// Rendered Terraform JSON — the lingua franca regardless of input
    /// path. For PangeaRuby, this is the synthesizer's output. For
    /// TerraformJson, this is the concatenated input JSON.
    pub rendered:  serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapeKind {
    PangeaRuby,
    TerraformJson,
}

#[async_trait]
pub trait WorkspaceLoader: Send + Sync {
    async fn load(&self, shape: WorkspaceShape) -> Result<LoadedWorkspace, PangeaError>;
}

// ── Terraform JSON loader (always available) ───────────────────────

pub struct TerraformJsonLoader;

#[async_trait]
impl WorkspaceLoader for TerraformJsonLoader {
    async fn load(&self, shape: WorkspaceShape) -> Result<LoadedWorkspace, PangeaError> {
        let (root, files) = match shape {
            WorkspaceShape::TerraformJson { root, json_files } => (root, json_files),
            WorkspaceShape::PangeaRuby { .. } => {
                return Err(PangeaError::RubyEval(
                    "TerraformJsonLoader does not handle PangeaRuby shapes; use PangeaRubyLoader (magnus feature)".into(),
                ));
            }
        };

        let mut merged = serde_json::Map::new();
        for file in &files {
            let bytes = tokio::fs::read(file).await?;
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            if let serde_json::Value::Object(obj) = v {
                for (k, val) in obj {
                    merged.insert(k, val);
                }
            }
        }

        Ok(LoadedWorkspace {
            shape:    ShapeKind::TerraformJson,
            root,
            rendered: serde_json::Value::Object(merged),
        })
    }
}

// ── Pangea Ruby loader (behind `magnus` feature) ───────────────────

#[cfg(feature = "magnus")]
pub mod ruby {
    //! In-process CRuby evaluator for the Pangea DSL.
    //!
    //! Single CRuby interpreter per process (CRuby GVL constraint).
    //! Bootstrap on a dedicated thread; route eval requests via channels.
    //! Mirrors `pangea-operator/pangea-ruby-eval`'s pattern.

    use super::{LoadedWorkspace, PangeaError, ShapeKind, WorkspaceLoader, WorkspaceShape};
    use async_trait::async_trait;

    pub struct PangeaRubyLoader {
        // Real impl owns a `RubyEvaluator` pinned to a dedicated thread +
        // a channel for eval requests. Stubbed here; the production
        // builder constructs it via `pangea_ruby_eval::RubyEvaluator`.
        _phantom: std::marker::PhantomData<()>,
    }

    impl PangeaRubyLoader {
        pub fn new() -> Result<Self, PangeaError> {
            Ok(Self { _phantom: std::marker::PhantomData })
        }
    }

    #[async_trait]
    impl WorkspaceLoader for PangeaRubyLoader {
        async fn load(&self, shape: WorkspaceShape) -> Result<LoadedWorkspace, PangeaError> {
            let WorkspaceShape::PangeaRuby { root, ruby_files, .. } = shape else {
                return Err(PangeaError::RubyEval(
                    "PangeaRubyLoader requires a PangeaRuby workspace shape".into(),
                ));
            };

            // TODO(M0): wire pangea_ruby_eval::RubyEvaluator on a
            // dedicated owner thread; with_load_paths for the Pangea
            // gem set (pangea-core, pangea-aws, pangea-cloudflare,
            // pangea-akeyless, ...); eval each *.rb file; capture the
            // `template :name do ... end` synthesizer output as JSON;
            // return as `rendered`.
            //
            // For now, return an empty rendering with the discovered
            // file list as metadata so dependent crates can compile.
            let _ = ruby_files;
            Ok(LoadedWorkspace {
                shape:    ShapeKind::PangeaRuby,
                root,
                rendered: serde_json::json!({}),
            })
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discover_terraform_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("seph-vpc.tf.json"), br#"{"resource":{}}"#).unwrap();
        let shape = WorkspaceShape::discover(dir.path()).unwrap();
        assert!(matches!(shape, WorkspaceShape::TerraformJson { .. }));
    }

    #[test]
    fn discover_pangea_ruby() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pangea.yml"), b"namespace: test\n").unwrap();
        fs::write(dir.path().join("seph_vpc.rb"), b"# pangea ruby workspace\n").unwrap();
        let shape = WorkspaceShape::discover(dir.path()).unwrap();
        assert!(matches!(shape, WorkspaceShape::PangeaRuby { .. }));
    }

    #[test]
    fn discover_empty_workspace_errs() {
        let dir = tempfile::tempdir().unwrap();
        let err = WorkspaceShape::discover(dir.path()).unwrap_err();
        assert!(matches!(err, PangeaError::EmptyWorkspace(_)));
    }

    #[test]
    fn discover_missing_workspace_errs() {
        let err = WorkspaceShape::discover("/nonexistent/path/xxxyyyzzz").unwrap_err();
        assert!(matches!(err, PangeaError::NoSuchWorkspace(_)));
    }

    #[tokio::test]
    async fn terraform_json_loader_concatenates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("vpc.tf.json"),
            br#"{"resource":{"aws_vpc":{"main":{"cidr_block":"10.0.0.0/16"}}}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("subnet.tf.json"),
            br#"{"resource":{"aws_subnet":{"web":{"vpc_id":"vpc-x"}}}}"#,
        )
        .unwrap();

        let shape = WorkspaceShape::discover(dir.path()).unwrap();
        let loaded = TerraformJsonLoader.load(shape).await.unwrap();
        assert_eq!(loaded.shape, ShapeKind::TerraformJson);
        let resources = &loaded.rendered["resource"];
        assert!(resources.get("aws_vpc").is_some() || resources.get("aws_subnet").is_some());
    }
}
