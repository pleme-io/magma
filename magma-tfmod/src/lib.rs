//! magma-tfmod — Terraform module ingestion + Pangea primitive
//! generation.
//!
//! Downloads Terraform modules from:
//! * `registry.terraform.io` (Hashicorp's public registry)
//! * Terraform Cloud private registries
//! * Git URLs (github.com/...)
//! * Local paths
//!
//! Parses the module's `variables` + `outputs` (HCL2), and emits
//! a Pangea-shaped typed primitive: a `Pangea::Architectures::*`
//! Ruby module that wraps the TF module call.
//!
//! The compounding effect: every TF module ever published becomes
//! one ingestion call away from being a typed Pangea primitive
//! composable in Ruby DSL alongside hand-written architectures.
//!
//! Per [`theory/MAGMA-AS-PLATFORM.md`](https://github.com/pleme-io/theory/blob/main/MAGMA-AS-PLATFORM.md) §IV.M9-M10.
//!
//! # Crate status
//!
//! M9 not yet started. This file is the typed API skeleton.

#![deny(unsafe_code)]
#![allow(dead_code)] // M9 stub.

pub mod registry;
pub mod parser;
pub mod codegen;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TfModError {
    #[error("registry: {0}")]
    Registry(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("codegen: {0}")]
    Codegen(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TfModError>;

/// Typed Terraform module reference. Source-locked + version-pinned.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ModuleSource {
    /// Public TF registry: `terraform-aws-modules/vpc/aws`.
    Registry { namespace: String, name: String, provider: String, version: String },
    /// Terraform Cloud private registry.
    TerraformCloud { org: String, name: String, provider: String, version: String },
    /// Git URL with ref pinning.
    Git { url: String, reference: String },
    /// Path on disk.
    Path { dir: std::path::PathBuf },
}

/// Typed module schema after HCL2 parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSchema {
    pub source:    ModuleSource,
    pub variables: Vec<Variable>,
    pub outputs:   Vec<Output>,
    /// Required providers declared in `terraform.required_providers`.
    pub required_providers: Vec<RequiredProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name:        String,
    pub type_expr:   Option<String>, // HCL2 type expr as string for now
    pub default:     Option<serde_json::Value>,
    pub description: Option<String>,
    #[serde(default)]
    pub required:    bool,
    #[serde(default)]
    pub sensitive:   bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
    pub name:        String,
    pub description: Option<String>,
    #[serde(default)]
    pub sensitive:   bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredProvider {
    pub local_name: String,
    pub source:     String,
    pub version:    Option<String>,
}

/// Public entry point: download + parse + emit Pangea Ruby code
/// for a Terraform module.
pub async fn ingest(_source: ModuleSource) -> Result<String> {
    Err(TfModError::Registry(
        "M9 not yet started — see theory/MAGMA-AS-PLATFORM.md".into(),
    ))
}
