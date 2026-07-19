//! magma-fixtures — shared test fixture builders.
//!
//! Every magma crate's tests need a Pangea-shaped `.tf.json` or a
//! magma-typed `State` somewhere. Before this crate, those builders
//! were copy-pasted across 7+ files; now there's one canonical
//! surface. Per Pillar 12.
//!
//! # Usage
//!
//! ```no_run
//! use magma_fixtures::{TfJsonBuilder, StateBuilder};
//!
//! # async fn ex() -> std::io::Result<()> {
//! // Build a Pangea-shaped workspace directory
//! let workspace = TfJsonBuilder::new()
//!     .resource("aws_vpc", "net", serde_json::json!({"cidr_block": "10.0.0.0/16"}))
//!     .output("vpc_id", serde_json::json!("vpc-test"))
//!     .render_to_tempdir()?;
//!
//! // Build a magma-typed State + write it to disk
//! let (path, _tmp) = StateBuilder::new()
//!     .resource("aws_iam_role", "alpha", serde_json::json!({"name": "alpha"}))
//!     .write_tempfile().await?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;

use magma_state::write_state;
use magma_types::{
    InstanceStatus, ModulePath, ProviderReference, ResourceAddress, ResourceKind, ResourceTypeId,
    State, StateInstance, StateResource,
};
use serde_json::{Map, Value, json};

// ── Pangea-shaped .tf.json builder ────────────────────────────────

/// A builder for Pangea-rendered Terraform JSON. The shape every
/// `magma flow` / `magma plan` consumer reads. Produces a JSON
/// object with `provider`, `resource`, and (optionally) `output`
/// blocks.
#[derive(Debug, Default, Clone)]
pub struct TfJsonBuilder {
    provider: Map<String, Value>,
    resources: Vec<(String, String, Value)>,
    outputs: Vec<(String, Value)>,
}

impl TfJsonBuilder {
    /// New empty builder; AWS provider at us-east-1 is the default.
    #[must_use]
    pub fn new() -> Self {
        let mut me = Self::default();
        me.provider
            .insert("aws".into(), json!({ "region": "us-east-1" }));
        me
    }

    /// Drop the default AWS provider and start with an empty set.
    #[must_use]
    pub fn no_default_provider(mut self) -> Self {
        self.provider.clear();
        self
    }

    /// Add or override a provider entry.
    #[must_use]
    pub fn provider(mut self, name: &str, config: Value) -> Self {
        self.provider.insert(name.into(), config);
        self
    }

    /// Add a resource block: `{ "resource": { "<type>": { "<name>": <attrs> } } }`.
    #[must_use]
    pub fn resource(mut self, type_id: &str, name: &str, attributes: Value) -> Self {
        self.resources
            .push((type_id.into(), name.into(), attributes));
        self
    }

    /// Add an output: `{ "output": { "<name>": { "value": <value> } } }`.
    #[must_use]
    pub fn output(mut self, name: &str, value: Value) -> Self {
        self.outputs.push((name.into(), value));
        self
    }

    /// Render to a JSON value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut top = Map::new();
        top.insert("provider".into(), Value::Object(self.provider.clone()));

        let mut resource_map: Map<String, Value> = Map::new();
        for (ty, name, attrs) in &self.resources {
            let entry = resource_map
                .entry(ty.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            entry
                .as_object_mut()
                .unwrap()
                .insert(name.clone(), attrs.clone());
        }
        top.insert("resource".into(), Value::Object(resource_map));

        if !self.outputs.is_empty() {
            let mut output_map = Map::new();
            for (name, val) in &self.outputs {
                output_map.insert(name.clone(), json!({ "value": val }));
            }
            top.insert("output".into(), Value::Object(output_map));
        }

        Value::Object(top)
    }

    /// Render to a pretty-printed JSON string.
    #[must_use]
    pub fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_value()).expect("infallible")
    }

    /// Render to a tempdir's `main.tf.json`. Returns the tempdir's
    /// path (the caller can place the returned `TempDir` somewhere
    /// to keep the dir alive).
    pub fn render_to_tempdir(&self) -> std::io::Result<TfJsonWorkspace> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("main.tf.json");
        std::fs::write(&path, self.to_pretty_json())?;
        Ok(TfJsonWorkspace { _tmp: tmp, path })
    }

    /// Render to `dir/main.tf.json` (used when the caller already
    /// owns a tempdir, e.g. for multi-workspace flows).
    pub fn render_to_dir(&self, dir: impl Into<PathBuf>) -> std::io::Result<PathBuf> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("main.tf.json");
        std::fs::write(&path, self.to_pretty_json())?;
        Ok(path)
    }
}

/// Owned handle to a tempdir-backed `.tf.json` workspace. The
/// tempdir is cleaned up when `TfJsonWorkspace` is dropped, so
/// keep it alive for the duration of the test.
pub struct TfJsonWorkspace {
    _tmp: tempfile::TempDir,
    pub path: PathBuf,
}

impl TfJsonWorkspace {
    /// Directory containing `main.tf.json`.
    #[must_use]
    pub fn dir(&self) -> PathBuf {
        self.path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(PathBuf::new)
    }
}

// ── magma-typed State builder ─────────────────────────────────────

/// A builder for magma-typed `State` values. Mirrors what each test
/// hand-constructs today: a State with N resources + a fresh
/// lineage. Use `write_tempfile` to drop it to disk via the
/// canonical `magma_state::write_state` path (round-trips byte-equal
/// through serde).
#[derive(Debug, Clone)]
pub struct StateBuilder {
    terraform_version: String,
    serial: u64,
    lineage: uuid::Uuid,
    resources: Vec<StateResource>,
}

impl Default for StateBuilder {
    fn default() -> Self {
        Self {
            terraform_version: "1.7.0".into(),
            serial: 1,
            lineage: uuid::Uuid::new_v4(),
            resources: Vec::new(),
        }
    }
}

impl StateBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Force a specific lineage UUID (useful for migration/round-trip
    /// tests that need a stable value).
    #[must_use]
    pub fn lineage(mut self, uuid: uuid::Uuid) -> Self {
        self.lineage = uuid;
        self
    }

    /// Force a specific serial.
    #[must_use]
    pub fn serial(mut self, serial: u64) -> Self {
        self.serial = serial;
        self
    }

    /// Add an aws-provider managed resource. Default provider is
    /// `hashicorp/aws`; use `resource_with_provider` for others.
    #[must_use]
    pub fn resource(self, type_id: &str, name: &str, attributes: Value) -> Self {
        self.resource_with_provider(type_id, name, attributes, "hashicorp/aws", "aws")
    }

    /// Add a managed resource with an explicit provider.
    #[must_use]
    pub fn resource_with_provider(
        mut self,
        type_id: &str,
        name: &str,
        attributes: Value,
        provider_source: &str,
        provider_name: &str,
    ) -> Self {
        self.resources.push(StateResource {
            address: ResourceAddress {
                module: ModulePath::default(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId(type_id.into()),
                name: name.into(),
                key: None,
            },
            provider: ProviderReference {
                source: provider_source.into(),
                name: provider_name.into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes,
                sensitive_attribute_paths: Vec::new(),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        });
        self
    }

    /// Build the typed `State` value.
    #[must_use]
    pub fn build(self) -> State {
        State {
            version: 4,
            terraform_version: self.terraform_version,
            serial: self.serial,
            lineage: self.lineage,
            outputs: Default::default(),
            resources: self.resources,
        }
    }

    /// Write to a `terraform.tfstate` inside a tempdir. Returns
    /// `(path, tempdir)` — keep the tempdir alive for the duration
    /// of the test.
    pub async fn write_tempfile(self) -> std::io::Result<(PathBuf, tempfile::TempDir)> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("terraform.tfstate");
        let state = self.build();
        write_state(&path, &state).await.map_err(io_err)?;
        Ok((path, tmp))
    }

    /// Write to a specific path. Caller owns the directory and is
    /// responsible for cleanup.
    pub async fn write_to(self, path: impl Into<PathBuf>) -> std::io::Result<PathBuf> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_state(&path, &self.build()).await.map_err(io_err)?;
        Ok(path)
    }
}

fn io_err(e: magma_state::StateError) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

// ── Tests for the fixtures themselves ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tf_json_default_emits_provider_and_resource() {
        let v = TfJsonBuilder::new()
            .resource("aws_vpc", "net", json!({ "cidr_block": "10.0.0.0/16" }))
            .output("vpc_id", json!("vpc-x"))
            .to_value();
        assert_eq!(v["provider"]["aws"]["region"], "us-east-1");
        assert_eq!(v["resource"]["aws_vpc"]["net"]["cidr_block"], "10.0.0.0/16");
        assert_eq!(v["output"]["vpc_id"]["value"], "vpc-x");
    }

    #[test]
    fn tf_json_multiple_resources_of_same_type_share_key() {
        let v = TfJsonBuilder::new()
            .resource("aws_iam_role", "a", json!({"name": "a"}))
            .resource("aws_iam_role", "b", json!({"name": "b"}))
            .to_value();
        let roles = &v["resource"]["aws_iam_role"];
        assert!(roles["a"].is_object());
        assert!(roles["b"].is_object());
    }

    #[test]
    fn tf_json_renders_to_tempdir() {
        let ws = TfJsonBuilder::new()
            .resource("aws_iam_role", "r", json!({"name": "r"}))
            .render_to_tempdir()
            .unwrap();
        assert!(ws.path.exists());
        assert!(ws.dir().exists());
        let read = std::fs::read_to_string(&ws.path).unwrap();
        assert!(read.contains("\"aws_iam_role\""));
    }

    #[tokio::test]
    async fn state_builder_round_trips_through_disk() {
        let (path, _tmp) = StateBuilder::new()
            .resource("aws_iam_role", "alpha", json!({"name":"alpha"}))
            .write_tempfile()
            .await
            .unwrap();
        let state = magma_state::read_state(&path).await.unwrap();
        assert_eq!(state.resources.len(), 1);
        assert_eq!(state.resources[0].address.name, "alpha");
    }

    #[tokio::test]
    async fn state_builder_lineage_is_stable_when_set() {
        let want = uuid::Uuid::nil();
        let (path, _tmp) = StateBuilder::new()
            .lineage(want)
            .resource("aws_iam_role", "x", json!({}))
            .write_tempfile()
            .await
            .unwrap();
        let state = magma_state::read_state(&path).await.unwrap();
        assert_eq!(state.lineage, want);
    }
}
