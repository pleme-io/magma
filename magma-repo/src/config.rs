//! Typed root `pangea.yml` shape. Mirrors what
//! `pangea-architectures/pangea.yml` declares.
//!
//! Fields we capture:
//!
//! * `tags` — workspace-default tag map
//! * `accounts` — AWS account registry (name → details)
//! * `sso` — SSO configuration
//! * `state` — S3 state backend defaults
//! * `cascade` — fleet cascade default depth
//! * `namespaces` — shared namespace patterns
//!
//! Unknown fields are preserved in the catch-all `_extra` map so
//! Pangea can grow new directives without breaking magma-repo
//! parsing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{RepoError, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootConfig {
    #[serde(default)]
    pub tags: BTreeMap<String, String>,

    #[serde(default)]
    pub accounts: BTreeMap<String, AccountConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso: Option<SsoConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateBackend>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cascade: Option<CascadeConfig>,

    #[serde(default)]
    pub namespaces: BTreeMap<String, NamespaceConfig>,

    /// Forward-compatible catch-all for unknown root fields.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    /// AWS account id (string, preserves leading zeros).
    pub account_id: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    pub start_url: String,
    pub region: String,
}

/// Typed state-backend default (root) or override (workspace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateBackend {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3Backend>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Backend {
    pub bucket: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamodb_table: Option<String>,
    #[serde(default)]
    pub encrypt: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_profile: Option<String>,
    /// State key (workspace-side override; absent at root level).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeConfig {
    pub default_depth: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamespaceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<NamespaceState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NamespaceState {
    /// `state: { type: local, path: "terraform.tfstate" }`
    /// `state: { type: local }` (path defaulted by tofu)
    Local {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// `state: { type: s3, key: "pangea/seph-vpc" }`
    S3 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
    /// Fallback for backend types we haven't typed yet — preserve
    /// the raw map so forward compatibility doesn't break parse.
    #[serde(other)]
    Other,
}

/// Parse root `pangea.yml` text into a typed `RootConfig`.
pub fn parse(source: &str) -> Result<RootConfig> {
    serde_yaml_ng::from_str::<RootConfig>(source).map_err(RepoError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
tags:
  ManagedBy: pangea
  Team: platform

accounts:
  # Generic fixture values. This test asserts the PARSER, so nothing here
  # needs to name a real estate — and naming one is how a private repo
  # becomes unpublishable. 123456789012 is AWS's documentation-reserved
  # account id; the previous fixture carried a real one belonging to the
  # HOST account this tool operates in, which is a host-facing disclosure
  # the moment this repo goes public.
  example-development:
    account_id: "123456789012"
    region: us-east-1
    role: AdministratorAccess

sso:
  start_url: https://example.awsapps.com/start
  region: us-east-2

state:
  s3:
    bucket: example-terraform-state
    region: us-east-1
    dynamodb_table: example-terraform-locks
    encrypt: true

cascade:
  default_depth: 0
"#;

    #[test]
    fn parses_minimal_root_config() {
        let cfg = parse(MINIMAL).unwrap();
        assert_eq!(
            cfg.tags.get("ManagedBy").map(String::as_str),
            Some("pangea")
        );
        assert_eq!(
            cfg.accounts.get("example-development").unwrap().account_id,
            "123456789012"
        );
        assert!(cfg.sso.is_some());
        assert_eq!(
            cfg.state.as_ref().unwrap().s3.as_ref().unwrap().bucket,
            "example-terraform-state"
        );
        assert_eq!(cfg.cascade.as_ref().unwrap().default_depth, 0);
    }

    #[test]
    fn empty_yaml_yields_empty_config() {
        let cfg = parse("{}").unwrap();
        assert!(cfg.tags.is_empty());
        assert!(cfg.accounts.is_empty());
        assert!(cfg.state.is_none());
    }

    #[test]
    fn unknown_fields_round_trip_via_extra() {
        let src = "custom_field: yes\nanother: 42\ntags: {}\n";
        let cfg = parse(src).unwrap();
        // The extra map captures fields the typed struct doesn't name.
        assert!(cfg.extra.contains_key("custom_field"));
        assert!(cfg.extra.contains_key("another"));
    }
}
