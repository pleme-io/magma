//! magma-repo — typed Pangea repository primitive.
//!
//! Parses a directory shaped like `pangea-architectures` into a
//! typed `DiscoveredRepo` value the operator drives continuous
//! reconciliation against. Owns:
//!
//! * **`config`** — typed root `pangea.yml` (accounts, state
//!   backend, tags, namespaces).
//! * **`workspace`** — typed per-workspace `pangea.yml`
//!   (default_namespace, account override, state).
//! * **`discover`** — scans a directory + builds a typed
//!   `DiscoveredRepo`.
//! * **`attestation`** — BLAKE3 over the canonical discovered
//!   closure (commit-independent so two operators see identical
//!   hashes for identical content).
//!
//! Future: `source`, `watch`, `reconciler` modules (M1-M2 per
//! theory/PANGEA-REPOSITORY.md).
//!
//! M0 lands today: typed parse + discovery + attestation. The
//! Reconciler trait impl + Git watcher land in subsequent
//! milestones; the API surface is stable so consumers can wire
//! against it today.

#![deny(unsafe_code)]
#![allow(dead_code)] // M0 stub for future-milestone fields.

pub mod attestation;
pub mod config;
pub mod discover;
pub mod reconciler;
pub mod source;
pub mod workspace;

pub use reconciler::{PangeaRepoReconciler, RepoObservedState};
pub use source::{Source, SourceError};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("discovery: {0}")]
    Discovery(String),
    #[error("missing required file: {0}")]
    MissingFile(String),
}

pub type Result<T> = std::result::Result<T, RepoError>;

/// One discovered workspace, the typed result of scanning a
/// `workspaces/<name>/` subdirectory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredWorkspace {
    /// Workspace name (the `<name>` in `workspaces/<name>/`).
    pub name: String,
    /// Absolute path to the workspace directory.
    pub dir: PathBuf,
    /// Typed parse of the workspace's `pangea.yml`.
    pub config: workspace::WorkspaceConfig,
    /// Path to the Ruby template file (if exactly one `.rb` lives
    /// in the workspace dir + matches `default_namespace`-ish).
    pub template: Option<PathBuf>,
}

/// Result of scanning a Pangea-shaped directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredRepo {
    /// Absolute path to the repo root.
    pub root: PathBuf,
    /// Typed root `pangea.yml`.
    pub root_config: config::RootConfig,
    /// Sorted list of discovered workspaces (alphabetical by name
    /// for deterministic iteration).
    pub workspaces: Vec<DiscoveredWorkspace>,
    /// BLAKE3 hex hash over the canonical typed closure
    /// (root config + every workspace's name + config).
    pub repo_attestation: String,
}

/// Public entry: scan a directory shaped like pangea-architectures
/// + return a typed `DiscoveredRepo`. Reads `pangea.yml` at the
/// root + `workspaces/*/pangea.yml` for every subdirectory.
pub fn discover(root: impl Into<PathBuf>) -> Result<DiscoveredRepo> {
    discover::discover(root.into())
}
