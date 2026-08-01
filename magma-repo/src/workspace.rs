//! Per-workspace `pangea.yml` typed shape.
//!
//! Pangea-architectures workspaces ship a `pangea.yml` per
//! workspace dir with:
//!
//! * `default_namespace` — the workspace's primary state slot
//! * `account` — AWS account override (lookup vs root-level
//!   accounts map)
//! * `tags` — workspace-specific tag overrides
//! * `namespaces` — per-namespace state config
//! * `depends_on` — typed cross-workspace dep order (used by
//!   PangeaRepoReconciler to order plan/apply)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    RepoError, Result,
    config::{NamespaceConfig, StateBackend},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    /// Default namespace this workspace activates. Must exist in
    /// `namespaces`.
    #[serde(default)]
    pub default_namespace: String,

    /// Account override (lookup key into root `accounts:` map).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,

    #[serde(default)]
    pub tags: BTreeMap<String, String>,

    #[serde(default)]
    pub namespaces: BTreeMap<String, NamespaceConfig>,

    /// Optional state backend override (workspace can pin a
    /// different bucket / region / key than root defaults).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateBackend>,

    /// Names of other workspaces this one depends on. Reconciler
    /// orders plan/apply so deps come first.
    #[serde(default)]
    pub depends_on: Vec<String>,

    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_yaml_ng::Value>,
}

/// Parse a workspace `pangea.yml` text into a typed
/// `WorkspaceConfig`.
pub fn parse(source: &str) -> Result<WorkspaceConfig> {
    serde_yaml_ng::from_str::<WorkspaceConfig>(source).map_err(RepoError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEPH_VPC: &str = r#"
default_namespace: seph-vpc

account: example-development

tags:
  Purpose: seph-vpc
  Cluster: seph
  InfraProject: seph-stack
  InfraLayer: vpc

namespaces:
  seph-vpc:
    description: Seph zero-trust VPC (SecureVpc Layer 1)
    state:
      type: s3
      key: pangea/seph-vpc
"#;

    #[test]
    fn parses_seph_vpc_workspace() {
        let cfg = parse(SEPH_VPC).unwrap();
        assert_eq!(cfg.default_namespace, "seph-vpc");
        assert_eq!(cfg.account.as_deref(), Some("example-development"));
        assert_eq!(cfg.tags.get("Cluster").map(String::as_str), Some("seph"));
        let ns = cfg.namespaces.get("seph-vpc").unwrap();
        assert!(ns.state.is_some());
    }

    #[test]
    fn parses_depends_on_list() {
        let src = r#"
default_namespace: cluster
depends_on:
  - seph-vpc
  - cluster-iam
"#;
        let cfg = parse(src).unwrap();
        assert_eq!(cfg.depends_on, vec!["seph-vpc", "cluster-iam"]);
    }

    #[test]
    fn empty_workspace_yields_default_config() {
        let cfg = parse("{}").unwrap();
        assert!(cfg.default_namespace.is_empty());
        assert!(cfg.account.is_none());
        assert!(cfg.depends_on.is_empty());
    }
}
