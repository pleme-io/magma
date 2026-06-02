//! Typed provider-RPC wrappers — the tfplugin6 `Provider` service over a
//! dialed [`Channel`], speaking [`magma_cty`] values.
//!
//! This is the layer that lets `magma-apply` stop being a structural
//! no-op and actually create resources (magma#2). [`Plugin::dial`] hands
//! back a gRPC `Channel`; [`ProviderConn`] wraps the generated tfplugin6
//! client and exposes the four RPCs the apply engine needs:
//!
//! - [`ProviderConn::get_schema`] — resource type → implied [`CtyType`]
//!   (via [`crate::schema`]).
//! - [`ProviderConn::configure`] — provider credentials / settings.
//! - [`ProviderConn::plan_resource_change`] — provider-proposed new state.
//! - [`ProviderConn::apply_resource_change`] — create/update/delete; the
//!   returned `DynamicValue` is the resource's new state.
//!
//! Every value crosses as a [`magma_cty::DynamicValue`]; provider
//! diagnostics with `Error` severity become a typed [`ProviderError`].

use std::collections::BTreeMap;

use magma_cty::{CtyType, DynamicValue};
use magma_protocol::tfplugin6;
use magma_protocol::tfplugin6::provider_client::ProviderClient;
use tonic::transport::Channel;

use crate::schema::{self, SchemaError};

/// A connected provider — the tfplugin6 client over a dialed channel.
pub struct ProviderConn {
    client: ProviderClient<Channel>,
}

/// A provider's schema, reduced to the implied cty types the apply codec
/// needs: the provider-config type + each managed resource's type.
#[derive(Debug, Clone)]
pub struct ProviderSchema {
    pub provider_config: CtyType,
    pub resources: BTreeMap<String, CtyType>,
}

impl ProviderSchema {
    /// The implied type of a managed resource, or `None` if the provider
    /// doesn't define it.
    pub fn resource(&self, type_name: &str) -> Option<&CtyType> {
        self.resources.get(type_name)
    }
}

/// A single provider diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Unknown,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider RPC transport: {0}")]
    Transport(String),
    #[error("provider returned {} error diagnostic(s): {}", .0.len(), fmt_diags(.0))]
    Diagnostics(Vec<Diag>),
    #[error("provider returned no new_state from apply")]
    NoNewState,
    #[error("schema: {0}")]
    Schema(#[from] SchemaError),
}

fn fmt_diags(diags: &[Diag]) -> String {
    diags
        .iter()
        .map(|d| format!("{}: {}", d.summary, d.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

impl ProviderConn {
    /// Wrap a dialed channel (`Plugin::dial`).
    pub fn new(channel: Channel) -> Self {
        Self {
            client: ProviderClient::new(channel),
        }
    }

    /// `GetProviderSchema` → the provider-config + per-resource implied types.
    pub async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
        let resp = self
            .client
            .get_provider_schema(tfplugin6::get_provider_schema::Request::default())
            .await
            .map_err(|s| ProviderError::Transport(s.to_string()))?
            .into_inner();
        diagnostics_into_result(&resp.diagnostics)?;

        let provider_config = match resp.provider.and_then(|s| s.block) {
            Some(b) => schema::block_implied_type(&b)?,
            None => CtyType::Object(BTreeMap::new()),
        };
        let mut resources = BTreeMap::new();
        for (name, sch) in resp.resource_schemas {
            if let Some(b) = sch.block {
                resources.insert(name, schema::block_implied_type(&b)?);
            }
        }
        Ok(ProviderSchema {
            provider_config,
            resources,
        })
    }

    /// `ConfigureProvider` — provider credentials / settings (the
    /// provider-config-typed `DynamicValue`).
    pub async fn configure(
        &mut self,
        config: &DynamicValue,
        terraform_version: &str,
    ) -> Result<(), ProviderError> {
        let resp = self
            .client
            .configure_provider(tfplugin6::configure_provider::Request {
                terraform_version: terraform_version.to_string(),
                config: Some(to_pb(config)),
                ..Default::default()
            })
            .await
            .map_err(|s| ProviderError::Transport(s.to_string()))?
            .into_inner();
        diagnostics_into_result(&resp.diagnostics)
    }

    /// `PlanResourceChange` — the provider's proposed new state for a
    /// change. The apply engine feeds this into `apply_resource_change`.
    pub async fn plan_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        proposed_new_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        let resp = self
            .client
            .plan_resource_change(tfplugin6::plan_resource_change::Request {
                type_name: type_name.to_string(),
                prior_state: Some(to_pb(prior_state)),
                proposed_new_state: Some(to_pb(proposed_new_state)),
                config: Some(to_pb(config)),
                ..Default::default()
            })
            .await
            .map_err(|s| ProviderError::Transport(s.to_string()))?
            .into_inner();
        diagnostics_into_result(&resp.diagnostics)?;
        resp.planned_state
            .map(from_pb)
            .ok_or(ProviderError::NoNewState)
    }

    /// `ApplyResourceChange` — execute the change against the real
    /// infrastructure. Returns the resource's new state.
    pub async fn apply_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        planned_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        let resp = self
            .client
            .apply_resource_change(tfplugin6::apply_resource_change::Request {
                type_name: type_name.to_string(),
                prior_state: Some(to_pb(prior_state)),
                planned_state: Some(to_pb(planned_state)),
                config: Some(to_pb(config)),
                ..Default::default()
            })
            .await
            .map_err(|s| ProviderError::Transport(s.to_string()))?
            .into_inner();
        diagnostics_into_result(&resp.diagnostics)?;
        resp.new_state.map(from_pb).ok_or(ProviderError::NoNewState)
    }
}

fn to_pb(dv: &DynamicValue) -> tfplugin6::DynamicValue {
    tfplugin6::DynamicValue {
        msgpack: dv.msgpack.clone(),
        json: Vec::new(),
    }
}

fn from_pb(dv: tfplugin6::DynamicValue) -> DynamicValue {
    DynamicValue {
        msgpack: dv.msgpack,
    }
}

/// Convert a provider's diagnostics into a typed result: any `Error`
/// diagnostic fails; warnings are returned-but-not-fatal (the caller
/// logs them). This is the single chokepoint that turns provider errors
/// into typed `ProviderError::Diagnostics` instead of silent success.
fn diagnostics_into_result(diags: &[tfplugin6::Diagnostic]) -> Result<(), ProviderError> {
    let errors: Vec<Diag> = diags
        .iter()
        .map(parse_diag)
        .filter(|d| d.severity == Severity::Error)
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ProviderError::Diagnostics(errors))
    }
}

fn parse_diag(d: &tfplugin6::Diagnostic) -> Diag {
    let severity = match tfplugin6::diagnostic::Severity::try_from(d.severity) {
        Ok(tfplugin6::diagnostic::Severity::Error) => Severity::Error,
        Ok(tfplugin6::diagnostic::Severity::Warning) => Severity::Warning,
        _ => Severity::Unknown,
    };
    Diag {
        severity,
        summary: d.summary.clone(),
        detail: d.detail.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(severity: i32, summary: &str) -> tfplugin6::Diagnostic {
        tfplugin6::Diagnostic {
            severity,
            summary: summary.into(),
            detail: String::new(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_diagnostics_is_ok() {
        assert!(diagnostics_into_result(&[]).is_ok());
    }

    #[test]
    fn warning_only_is_ok() {
        let diags = vec![diag(
            tfplugin6::diagnostic::Severity::Warning as i32,
            "heads up",
        )];
        assert!(diagnostics_into_result(&diags).is_ok());
    }

    #[test]
    fn any_error_diagnostic_fails() {
        let diags = vec![
            diag(tfplugin6::diagnostic::Severity::Warning as i32, "warn"),
            diag(tfplugin6::diagnostic::Severity::Error as i32, "boom"),
        ];
        match diagnostics_into_result(&diags) {
            Err(ProviderError::Diagnostics(errs)) => {
                assert_eq!(errs.len(), 1, "only error-severity diags are fatal");
                assert_eq!(errs[0].summary, "boom");
            }
            other => panic!("expected Diagnostics error, got {other:?}"),
        }
    }

    #[test]
    fn dynamic_value_pb_roundtrip() {
        let dv = DynamicValue {
            msgpack: vec![0xc0, 0x01, 0x02],
        };
        let pb = to_pb(&dv);
        assert_eq!(pb.msgpack, dv.msgpack);
        assert!(pb.json.is_empty());
        assert_eq!(from_pb(pb), dv);
    }
}
