//! magma-types — the typed primitive surface for the magma IaC executor.
//!
//! Every consumer crate codes against the types defined here. State, plans,
//! provider schemas, the resource graph, attestation receipts — all
//! ground in this crate. Per `theory/MAGMA.md` §III.
//!
//! Wire formats (Terraform JSON, terraform.tfstate v4, tfplugin5/6 protobuf)
//! are serializations of these typed values. Internal flow is typed
//! end-to-end; JSON appears only at the wire boundary.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ── Identity ───────────────────────────────────────────────────────

/// Identifier for a workspace member crate that produces a typed resource.
/// Provider-scoped. Currently owns its string; M0 follow-up swaps to an
/// interned `&'static str` via `lasso` or similar once the lookup tables
/// are large enough to matter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceTypeId(pub String);

/// Module path within a configuration: `root` or `a.b.c`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ModulePath(pub Vec<String>);

impl ModulePath {
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }
}

/// The kind of resource a `ResourceAddress` identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Managed,
    Data,
    Output,
    Local,
    Variable,
}

/// Instance key for `count` / `for_each`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InstanceKey {
    Index(u64),
    Key(String),
}

/// Canonical resource identity. Round-trips byte-equal through OpenTofu's
/// state-file format (`"aws_vpc.foo[\"bar\"]"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceAddress {
    pub module: ModulePath,
    pub kind: ResourceKind,
    pub type_id: ResourceTypeId,
    pub name: String,
    pub key: Option<InstanceKey>,
}

/// Reference to a provider — namespace + name + alias.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderReference {
    pub source: String,        // e.g. "hashicorp/aws"
    pub name: String,          // e.g. "aws"
    pub alias: Option<String>, // e.g. "us-east-2"
}

// ── Schema (provider-reported) ─────────────────────────────────────

/// Provider schema; the typed shape every resource attribute conforms to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSchema {
    pub provider: Block,
    pub resource_schemas: HashMap<String, Block>,
    pub data_source_schemas: HashMap<String, Block>,
    pub functions: HashMap<String, FunctionSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub version: u64,
    pub attributes: HashMap<String, Attribute>,
    pub nested_blocks: HashMap<String, NestedBlock>,
    pub description: Option<String>,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub type_repr: String, // cty type-string serialization
    pub description: Option<String>,
    pub required: bool,
    pub optional: bool,
    pub computed: bool,
    pub sensitive: bool,
    pub write_only: bool,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedBlock {
    pub block: Block,
    pub nesting: NestingMode,
    pub min_items: u64,
    pub max_items: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestingMode {
    Single,
    List,
    Set,
    Map,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub parameters: Vec<FunctionParameter>,
    pub variadic: Option<FunctionParameter>,
    pub return_type: String,
    pub summary: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionParameter {
    pub name: String,
    pub type_repr: String,
    pub description: Option<String>,
    pub nullable: bool,
}

// ── Plan ───────────────────────────────────────────────────────────

/// BLAKE3 hash of (config + prior state + variables + computed plan).
/// Two plans with the same `PlanId` are bit-equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub [u8; 32]);

/// The output of `magma plan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: PlanId,
    pub created_at: DateTime<Utc>,
    pub config_root: PathBuf,
    pub variables: HashMap<String, serde_json::Value>,
    pub resource_changes: Vec<ResourceChange>,
    pub output_changes: Vec<OutputChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceChange {
    pub address: ResourceAddress,
    pub action: Action,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub reasons: Vec<ChangeReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputChange {
    pub name: String,
    pub action: Action,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
    pub sensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    NoOp,
    Create,
    Read,
    Update,
    Replace,
    Delete,
    Forget,
    CreateThenDelete,
    DeleteThenCreate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeReason {
    NewResource,
    DeletedResource,
    AttributeDrift,
    RequiresReplace,
    ReplaceTriggeredBy(ResourceAddress),
    Tainted,
    ReplacedByCli,
}

// ── State ──────────────────────────────────────────────────────────

/// In-memory state; serializes to `terraform.tfstate` (schema v4) byte-equal
/// with OpenTofu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub version: u64,
    pub terraform_version: String,
    pub serial: u64,
    pub lineage: Uuid,
    pub outputs: HashMap<String, OutputValue>,
    pub resources: Vec<StateResource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateResource {
    pub address: ResourceAddress,
    pub provider: ProviderReference,
    pub instances: Vec<StateInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateInstance {
    pub schema_version: u64,
    pub attributes: serde_json::Value,
    pub private: Vec<u8>,
    pub dependencies: Vec<ResourceAddress>,
    pub status: InstanceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    Ready,
    Tainted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputValue {
    pub value: serde_json::Value,
    pub sensitive: bool,
}

// ── Diagnostics ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub summary: String,
    pub detail: Option<String>,
    pub address: Option<ResourceAddress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MagmaTypesError {
    #[error("invalid resource address: {0}")]
    InvalidAddress(String),
    #[error("schema validation failed: {0}")]
    SchemaViolation(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
