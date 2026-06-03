//! Typed provider-RPC wrappers — the tfplugin5/6 `Provider` service over
//! a dialed [`Channel`], speaking [`magma_cty`] values.
//!
//! This is the layer that lets `magma-apply` stop being a structural
//! no-op and actually create resources (magma#2). [`Plugin::dial`] hands
//! back a gRPC `Channel` + the negotiated protocol; [`ProviderConn`]
//! wraps the matching generated client and exposes the four RPCs the
//! apply engine needs:
//!
//! - [`ProviderConn::get_schema`] — resource type → implied [`CtyType`].
//! - [`ProviderConn::configure`] — provider credentials / settings.
//! - [`ProviderConn::plan_resource_change`] — provider-proposed new state.
//! - [`ProviderConn::apply_resource_change`] — create/update/delete; the
//!   returned `DynamicValue` is the resource's new state.
//!
//! **Both protocols are dispatched.** SDKv2 providers (github — galho's
//! target — aws, …) speak tfplugin5; framework providers speak tfplugin6.
//! `ProviderConn::new` selects the client from the handshake's negotiated
//! `PluginProtocol`. The schema parser is shared (v5 schemas convert to
//! v6 via [`crate::schema::block5_implied_type`]); error-severity
//! diagnostics (severity `1` in both protocols) become a typed
//! [`ProviderError`].

use std::collections::BTreeMap;

use magma_cty::{CtyType, DynamicValue};
use magma_protocol::{PluginProtocol, tfplugin5, tfplugin6};

use crate::H2Channel;
use crate::schema::{self, SchemaError};

type Client5 = tfplugin5::provider_client::ProviderClient<H2Channel>;
type Client6 = tfplugin6::provider_client::ProviderClient<H2Channel>;

enum Client {
    V5(Client5),
    V6(Client6),
}

/// A connected provider — the protocol-matched client over a dialed channel.
pub struct ProviderConn {
    client: Client,
}

/// A provider's schema reduced to the implied cty types the apply codec
/// needs: the provider-config type + each managed resource's type.
#[derive(Debug, Clone)]
pub struct ProviderSchema {
    pub provider_config: CtyType,
    pub resources: BTreeMap<String, CtyType>,
}

impl ProviderSchema {
    pub fn resource(&self, type_name: &str) -> Option<&CtyType> {
        self.resources.get(type_name)
    }
}

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

/// Is this provider error worth retrying with backoff? True for transient
/// conditions — chiefly provider-side RATE LIMITING (github/cloud secondary
/// rate limits surface as error diagnostics or transport errors) and
/// transient transport faults. The tfplugin Diagnostic carries no status
/// code, so detection is text-pattern matching on the diagnostic + transport
/// strings. Permanent errors (bad config, schema, auth-denied) return false
/// so they fail fast instead of looping.
#[must_use]
pub fn is_retryable(e: &ProviderError) -> bool {
    const TRANSIENT: &[&str] = &[
        "rate limit",
        "secondary rate",
        "too many request",
        "abuse",
        "quota",
        "try again",
        "retry",
        "429",
        "503",
        "resource_exhausted",
        "unavailable",
        "timeout",
        "timed out",
        "connection reset",
        "broken pipe",
        "tls",
        "transport",
        "h2 protocol",
        "eof",
    ];
    let hit = |s: &str| {
        let l = s.to_ascii_lowercase();
        TRANSIENT.iter().any(|p| l.contains(p))
    };
    match e {
        ProviderError::Transport(s) => hit(s),
        ProviderError::Diagnostics(diags) => diags
            .iter()
            .any(|d| hit(&d.summary) || hit(&d.detail)),
        ProviderError::NoNewState | ProviderError::Schema(_) => false,
    }
}

fn fmt_diags(diags: &[Diag]) -> String {
    diags
        .iter()
        .map(|d| format!("{}: {}", d.summary, d.detail))
        .collect::<Vec<_>>()
        .join("; ")
}

impl ProviderConn {
    /// Wrap a dialed channel, selecting the client by the handshake's
    /// negotiated protocol (`Plugin::handshake().app_protocol`).
    pub fn new(channel: H2Channel, protocol: PluginProtocol) -> Self {
        let client = match protocol {
            PluginProtocol::V5 => {
                Client::V5(Client5::new(channel).max_decoding_message_size(256 * 1024 * 1024))
            }
            PluginProtocol::V6 => {
                Client::V6(Client6::new(channel).max_decoding_message_size(256 * 1024 * 1024))
            }
        };
        Self { client }
    }

    /// `GetProviderSchema` (v6) / `GetSchema` (v5) → provider-config +
    /// per-resource implied types.
    pub async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .get_provider_schema(tfplugin6::get_provider_schema::Request::default())
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))?;
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
            Client::V5(c) => {
                let resp = c
                    .get_schema(tfplugin5::get_provider_schema::Request::default())
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))?;
                let provider_config = match resp.provider.and_then(|s| s.block) {
                    Some(b) => schema::block5_implied_type(&b)?,
                    None => CtyType::Object(BTreeMap::new()),
                };
                let mut resources = BTreeMap::new();
                for (name, sch) in resp.resource_schemas {
                    if let Some(b) = sch.block {
                        resources.insert(name, schema::block5_implied_type(&b)?);
                    }
                }
                Ok(ProviderSchema {
                    provider_config,
                    resources,
                })
            }
        }
    }

    /// `ConfigureProvider` (v6) / `Configure` (v5) — provider creds/settings.
    pub async fn configure(
        &mut self,
        config: &DynamicValue,
        terraform_version: &str,
    ) -> Result<(), ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .configure_provider(tfplugin6::configure_provider::Request {
                        terraform_version: terraform_version.to_string(),
                        config: Some(to_pb6(config)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))
            }
            Client::V5(c) => {
                let resp = c
                    .configure(tfplugin5::configure::Request {
                        terraform_version: terraform_version.to_string(),
                        config: Some(to_pb5(config)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))
            }
        }
    }

    /// `PlanResourceChange` — the provider's proposed new state.
    pub async fn plan_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        proposed_new_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .plan_resource_change(tfplugin6::plan_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(to_pb6(prior_state)),
                        proposed_new_state: Some(to_pb6(proposed_new_state)),
                        config: Some(to_pb6(config)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))?;
                resp.planned_state
                    .map(from_pb6)
                    .ok_or(ProviderError::NoNewState)
            }
            Client::V5(c) => {
                let resp = c
                    .plan_resource_change(tfplugin5::plan_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(to_pb5(prior_state)),
                        proposed_new_state: Some(to_pb5(proposed_new_state)),
                        config: Some(to_pb5(config)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))?;
                resp.planned_state
                    .map(from_pb5)
                    .ok_or(ProviderError::NoNewState)
            }
        }
    }

    /// `ApplyResourceChange` — execute the change. Returns the new state.
    pub async fn apply_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        planned_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .apply_resource_change(tfplugin6::apply_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(to_pb6(prior_state)),
                        planned_state: Some(to_pb6(planned_state)),
                        config: Some(to_pb6(config)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))?;
                resp.new_state
                    .map(from_pb6)
                    .ok_or(ProviderError::NoNewState)
            }
            Client::V5(c) => {
                let resp = c
                    .apply_resource_change(tfplugin5::apply_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(to_pb5(prior_state)),
                        planned_state: Some(to_pb5(planned_state)),
                        config: Some(to_pb5(config)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))?;
                resp.new_state
                    .map(from_pb5)
                    .ok_or(ProviderError::NoNewState)
            }
        }
    }

    /// `ReadResource` — read the resource's ACTUAL current state from the
    /// provider (the refresh primitive). Returns `Ok(None)` when the provider
    /// reports the resource no longer exists (`new_state` is cty-null), so
    /// callers drop stale / phantom entries from state; `Ok(Some(dv))` with
    /// the refreshed wire state when it still exists.
    pub async fn read_resource(
        &mut self,
        type_name: &str,
        current_state: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .read_resource(tfplugin6::read_resource::Request {
                        type_name: type_name.to_string(),
                        current_state: Some(to_pb6(current_state)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))?;
                Ok(resp.new_state.map(from_pb6).filter(|d| !d.is_null()))
            }
            Client::V5(c) => {
                let resp = c
                    .read_resource(tfplugin5::read_resource::Request {
                        type_name: type_name.to_string(),
                        current_state: Some(to_pb5(current_state)),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))?;
                Ok(resp.new_state.map(from_pb5).filter(|d| !d.is_null()))
            }
        }
    }
}

fn transport(s: tonic::Status) -> ProviderError {
    ProviderError::Transport(s.to_string())
}

fn to_pb6(dv: &DynamicValue) -> tfplugin6::DynamicValue {
    tfplugin6::DynamicValue {
        msgpack: dv.msgpack.clone(),
        json: Vec::new(),
    }
}
fn from_pb6(dv: tfplugin6::DynamicValue) -> DynamicValue {
    DynamicValue {
        msgpack: dv.msgpack,
    }
}
fn to_pb5(dv: &DynamicValue) -> tfplugin5::DynamicValue {
    tfplugin5::DynamicValue {
        msgpack: dv.msgpack.clone(),
        json: Vec::new(),
    }
}
fn from_pb5(dv: tfplugin5::DynamicValue) -> DynamicValue {
    DynamicValue {
        msgpack: dv.msgpack,
    }
}

/// Extract `(severity, summary, detail)` from a tfplugin6 diagnostic.
fn diag6(d: &tfplugin6::Diagnostic) -> (i32, String, String) {
    (d.severity, d.summary.clone(), d.detail.clone())
}
/// Same for tfplugin5 (identical message shape).
fn diag5(d: &tfplugin5::Diagnostic) -> (i32, String, String) {
    (d.severity, d.summary.clone(), d.detail.clone())
}

/// Fail on any `Error`-severity diagnostic (severity `1` in both
/// tfplugin5 + tfplugin6); warnings (`2`) are non-fatal. The single
/// chokepoint that turns provider errors into typed failures rather than
/// silent success.
fn check_diags(diags: impl Iterator<Item = (i32, String, String)>) -> Result<(), ProviderError> {
    let errors: Vec<Diag> = diags
        .filter(|(sev, _, _)| *sev == 1)
        .map(|(_, summary, detail)| Diag {
            severity: Severity::Error,
            summary,
            detail,
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ProviderError::Diagnostics(errors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_diagnostics_is_ok() {
        assert!(check_diags(std::iter::empty()).is_ok());
    }

    #[test]
    fn warning_only_is_ok() {
        let diags = vec![(2, "heads up".to_string(), String::new())];
        assert!(check_diags(diags.into_iter()).is_ok());
    }

    #[test]
    fn any_error_diagnostic_fails() {
        let diags = vec![
            (2, "warn".to_string(), String::new()),
            (1, "boom".to_string(), "bad".to_string()),
        ];
        match check_diags(diags.into_iter()) {
            Err(ProviderError::Diagnostics(errs)) => {
                assert_eq!(errs.len(), 1, "only error-severity diags are fatal");
                assert_eq!(errs[0].summary, "boom");
            }
            other => panic!("expected Diagnostics error, got {other:?}"),
        }
    }

    #[test]
    fn dynamic_value_pb_roundtrip_both_protocols() {
        let dv = DynamicValue {
            msgpack: vec![0xc0, 0x01, 0x02],
        };
        assert_eq!(from_pb6(to_pb6(&dv)), dv);
        assert_eq!(from_pb5(to_pb5(&dv)), dv);
        assert!(to_pb6(&dv).json.is_empty());
    }
}
