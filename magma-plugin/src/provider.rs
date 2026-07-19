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

/// The client capabilities magma announces on every protocol request that
/// carries a `ClientCapabilities` field (`ConfigureProvider`, `ReadResource`,
/// `PlanResourceChange`, `ImportResourceState`, `ReadDataSource`, …).
///
/// Modern providers built on terraform-plugin-framework v1.15+ read this
/// field; an ABSENT (`None`) `ClientCapabilities` drives some framework
/// data-source / resource paths into a nil dereference — the provider logs
/// "No announced client capabilities" then SIGSEGVs (observed live: cloudflare
/// 5.13.0 nil-deref in `server_readdatasource.go` on `cloudflare_accounts`).
/// We announce explicit capabilities so the field is always PRESENT. magma
/// does not yet implement provider response *deferral* or *write-only*
/// attributes, so both are `false` — present-and-false, never absent.
pub(crate) fn client_caps_v6() -> Option<tfplugin6::ClientCapabilities> {
    Some(tfplugin6::ClientCapabilities {
        deferral_allowed: false,
        write_only_attributes_allowed: false,
    })
}

fn client_caps_v5() -> Option<tfplugin5::ClientCapabilities> {
    Some(tfplugin5::ClientCapabilities {
        deferral_allowed: false,
        write_only_attributes_allowed: false,
    })
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
    /// Data-source implied types (`data.<type>`), needed to encode a
    /// ReadDataSource config + decode its result. Without these the apply
    /// engine cannot evaluate `${data.*}` references (the rio-drive leak).
    pub data_sources: BTreeMap<String, CtyType>,
}

impl ProviderSchema {
    pub fn resource(&self, type_name: &str) -> Option<&CtyType> {
        self.resources.get(type_name)
    }

    pub fn data_source(&self, type_name: &str) -> Option<&CtyType> {
        self.data_sources.get(type_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub severity: Severity,
    pub summary: String,
    pub detail: String,
}

/// The provider's full response to `PlanResourceChange`: the normalized
/// planned state PLUS the attribute paths the provider says force a
/// destroy+create instead of an in-place update ("requires replace").
///
/// Terraform core reads this exact signal — computed by the provider
/// inside this SAME RPC — to decide Update vs Replace; it is not
/// something the schema or config can determine on their own (a
/// provider's `ForceNew` decision can be dynamic, e.g. via
/// `CustomizeDiff`). Prior to this type existing, [`ProviderConn::plan_resource_change`]
/// returned only the bare planned [`DynamicValue`], silently discarding
/// `requires_replace` — the ONE authoritative signal a provider gives
/// for immutable/ForceNew attributes — before it ever reached
/// magma-apply's business logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    pub state: DynamicValue,
    /// Provider-reported attribute paths requiring replace, rendered as
    /// dotted diagnostic strings (`"instance_types"`, `"tags.name"`,
    /// `"rules[2].port"`). Empty ⇒ the provider says an in-place update
    /// is sufficient. Diagnostic-only shape: callers only need to know
    /// whether this is non-empty to trigger destroy+create orchestration
    /// (see `magma-apply::engine::apply_one`); the strings make
    /// `requires_replace` legible in logs/errors without threading a
    /// full typed attribute-path AST through every consumer.
    pub requires_replace: Vec<String>,
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
                let mut data_sources = BTreeMap::new();
                for (name, sch) in resp.data_source_schemas {
                    if let Some(b) = sch.block {
                        data_sources.insert(name, schema::block_implied_type(&b)?);
                    }
                }
                Ok(ProviderSchema {
                    provider_config,
                    resources,
                    data_sources,
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
                let mut data_sources = BTreeMap::new();
                for (name, sch) in resp.data_source_schemas {
                    if let Some(b) = sch.block {
                        data_sources.insert(name, schema::block5_implied_type(&b)?);
                    }
                }
                Ok(ProviderSchema {
                    provider_config,
                    resources,
                    data_sources,
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
                        client_capabilities: client_caps_v6(),
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
                        client_capabilities: client_caps_v5(),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))
            }
        }
    }

    /// `PlanResourceChange` — the provider's proposed new state PLUS
    /// which attribute paths (if any) force a destroy+create instead of
    /// an in-place update. See [`PlannedChange`]'s doc for why the
    /// latter matters: it is the ONLY authoritative source for that
    /// decision, and was silently discarded here before `PlannedChange`
    /// existed.
    pub async fn plan_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        proposed_new_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<PlannedChange, ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .plan_resource_change(tfplugin6::plan_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(to_pb6(prior_state)),
                        proposed_new_state: Some(to_pb6(proposed_new_state)),
                        config: Some(to_pb6(config)),
                        client_capabilities: client_caps_v6(),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))?;
                let requires_replace = resp
                    .requires_replace
                    .iter()
                    .map(attribute_path_to_string_v6)
                    .collect();
                let state = resp
                    .planned_state
                    .map(from_pb6)
                    .ok_or(ProviderError::NoNewState)?;
                Ok(PlannedChange {
                    state,
                    requires_replace,
                })
            }
            Client::V5(c) => {
                let resp = c
                    .plan_resource_change(tfplugin5::plan_resource_change::Request {
                        type_name: type_name.to_string(),
                        prior_state: Some(to_pb5(prior_state)),
                        proposed_new_state: Some(to_pb5(proposed_new_state)),
                        config: Some(to_pb5(config)),
                        client_capabilities: client_caps_v5(),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))?;
                let requires_replace = resp
                    .requires_replace
                    .iter()
                    .map(attribute_path_to_string_v5)
                    .collect();
                let state = resp
                    .planned_state
                    .map(from_pb5)
                    .ok_or(ProviderError::NoNewState)?;
                Ok(PlannedChange {
                    state,
                    requires_replace,
                })
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
                        client_capabilities: client_caps_v6(),
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
                        client_capabilities: client_caps_v5(),
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

    /// `ReadDataSource` — evaluate a `data` block by querying the provider,
    /// returning its result state. The apply engine reads data sources up front
    /// so `${data.<type>.<name>.<attr>}` references resolve; without it those
    /// strings leaked verbatim to managed-resource RPCs (the rio-drive
    /// Cloudflare 400). `Ok(None)` if the provider returned cty-null.
    pub async fn read_data_source(
        &mut self,
        type_name: &str,
        config: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .read_data_source(tfplugin6::read_data_source::Request {
                        type_name: type_name.to_string(),
                        config: Some(to_pb6(config)),
                        client_capabilities: client_caps_v6(),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))?;
                Ok(resp.state.map(from_pb6).filter(|d| !d.is_null()))
            }
            Client::V5(c) => {
                let resp = c
                    .read_data_source(tfplugin5::read_data_source::Request {
                        type_name: type_name.to_string(),
                        config: Some(to_pb5(config)),
                        client_capabilities: client_caps_v5(),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))?;
                Ok(resp.state.map(from_pb5).filter(|d| !d.is_null()))
            }
        }
    }

    /// `ImportResourceState` — adopt a resource that EXISTS in the cloud but
    /// is absent from magma's state, by its provider-native import id (e.g.
    /// the repo name for `github_repository`). Returns the imported wire state
    /// (`Ok(Some(dv))`) or `Ok(None)` if the provider imported nothing /
    /// returned cty-null. This is the read/import half of the protocol that
    /// powers import-on-create-conflict (422 already-exists → observe → adopt)
    /// + `magma import`. Mirrors apply/read's V5/V6 dispatch + msgpack decode.
    pub async fn import_resource_state(
        &mut self,
        type_name: &str,
        id: &str,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        match &mut self.client {
            Client::V6(c) => {
                let resp = c
                    .import_resource_state(tfplugin6::import_resource_state::Request {
                        type_name: type_name.to_string(),
                        id: id.to_string(),
                        client_capabilities: client_caps_v6(),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag6))?;
                Ok(resp
                    .imported_resources
                    .into_iter()
                    .next()
                    .and_then(|ir| ir.state)
                    .map(from_pb6)
                    .filter(|d| !d.is_null()))
            }
            Client::V5(c) => {
                let resp = c
                    .import_resource_state(tfplugin5::import_resource_state::Request {
                        type_name: type_name.to_string(),
                        id: id.to_string(),
                        client_capabilities: client_caps_v5(),
                        ..Default::default()
                    })
                    .await
                    .map_err(transport)?
                    .into_inner();
                check_diags(resp.diagnostics.iter().map(diag5))?;
                Ok(resp
                    .imported_resources
                    .into_iter()
                    .next()
                    .and_then(|ir| ir.state)
                    .map(from_pb5)
                    .filter(|d| !d.is_null()))
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

/// One `AttributePath.Step` reduced to its selector, independent of
/// which protocol's generated type it came from — lets
/// [`render_attribute_path`] be shared by both `_v5`/`_v6` renderers
/// below instead of duplicating the join logic.
enum PathStep {
    Attribute(String),
    ElementKeyString(String),
    ElementKeyInt(i64),
}

/// Render an attribute path as a dotted diagnostic string:
/// `steps = [Attribute("tags"), ElementKeyString("Name")]` → `"tags.Name"`;
/// `steps = [Attribute("rules"), ElementKeyInt(2), Attribute("port")]` →
/// `"rules[2].port"`. See [`PlannedChange::requires_replace`]'s doc for why
/// this diagnostic shape (not a typed AST) is what callers need.
fn render_attribute_path(steps: impl Iterator<Item = PathStep>) -> String {
    let mut out = String::new();
    for step in steps {
        match step {
            PathStep::Attribute(name) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&name);
            }
            PathStep::ElementKeyString(key) => {
                out.push('[');
                out.push_str(&key);
                out.push(']');
            }
            PathStep::ElementKeyInt(i) => {
                out.push('[');
                out.push_str(&i.to_string());
                out.push(']');
            }
        }
    }
    out
}

fn attribute_path_to_string_v6(path: &tfplugin6::AttributePath) -> String {
    render_attribute_path(path.steps.iter().map(|s| match &s.selector {
        Some(tfplugin6::attribute_path::step::Selector::AttributeName(n)) => {
            PathStep::Attribute(n.clone())
        }
        Some(tfplugin6::attribute_path::step::Selector::ElementKeyString(k)) => {
            PathStep::ElementKeyString(k.clone())
        }
        Some(tfplugin6::attribute_path::step::Selector::ElementKeyInt(i)) => {
            PathStep::ElementKeyInt(*i)
        }
        // A step with no selector set is malformed wire data — render as
        // an empty attribute segment rather than panicking or dropping
        // the step (which would silently shorten the reported path).
        None => PathStep::Attribute(String::new()),
    }))
}

fn attribute_path_to_string_v5(path: &tfplugin5::AttributePath) -> String {
    render_attribute_path(path.steps.iter().map(|s| match &s.selector {
        Some(tfplugin5::attribute_path::step::Selector::AttributeName(n)) => {
            PathStep::Attribute(n.clone())
        }
        Some(tfplugin5::attribute_path::step::Selector::ElementKeyString(k)) => {
            PathStep::ElementKeyString(k.clone())
        }
        Some(tfplugin5::attribute_path::step::Selector::ElementKeyInt(i)) => {
            PathStep::ElementKeyInt(*i)
        }
        None => PathStep::Attribute(String::new()),
    }))
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

    fn v6_attr_step(name: &str) -> tfplugin6::attribute_path::Step {
        tfplugin6::attribute_path::Step {
            selector: Some(tfplugin6::attribute_path::step::Selector::AttributeName(
                name.to_string(),
            )),
        }
    }

    fn v6_index_step(i: i64) -> tfplugin6::attribute_path::Step {
        tfplugin6::attribute_path::Step {
            selector: Some(tfplugin6::attribute_path::step::Selector::ElementKeyInt(i)),
        }
    }

    fn v6_key_step(k: &str) -> tfplugin6::attribute_path::Step {
        tfplugin6::attribute_path::Step {
            selector: Some(tfplugin6::attribute_path::step::Selector::ElementKeyString(
                k.to_string(),
            )),
        }
    }

    #[test]
    fn attribute_path_to_string_v6_single_attribute() {
        let path = tfplugin6::AttributePath {
            steps: vec![v6_attr_step("instance_types")],
        };
        assert_eq!(attribute_path_to_string_v6(&path), "instance_types");
    }

    #[test]
    fn attribute_path_to_string_v6_nested_key() {
        let path = tfplugin6::AttributePath {
            steps: vec![v6_attr_step("tags"), v6_key_step("Name")],
        };
        assert_eq!(attribute_path_to_string_v6(&path), "tags[Name]");
    }

    #[test]
    fn attribute_path_to_string_v6_indexed_then_attribute() {
        let path = tfplugin6::AttributePath {
            steps: vec![v6_attr_step("rules"), v6_index_step(2), v6_attr_step("port")],
        };
        assert_eq!(attribute_path_to_string_v6(&path), "rules[2].port");
    }

    fn v5_attr_step(name: &str) -> tfplugin5::attribute_path::Step {
        tfplugin5::attribute_path::Step {
            selector: Some(tfplugin5::attribute_path::step::Selector::AttributeName(
                name.to_string(),
            )),
        }
    }

    #[test]
    fn attribute_path_to_string_v5_matches_v6_shape() {
        let path = tfplugin5::AttributePath {
            steps: vec![v5_attr_step("ami")],
        };
        assert_eq!(attribute_path_to_string_v5(&path), "ami");
    }

    /// The `plan_resource_change`/`apply_resource_change` wire round-trip
    /// this crate exists to speak has one job for the requires-replace
    /// signal: never drop it. A `PlannedChange` with an empty vec must be
    /// distinguishable from one with paths in it — `requires_replace()`'s
    /// consumer (`magma-apply::engine::apply_one`) branches on exactly
    /// this emptiness check.
    #[test]
    fn planned_change_requires_replace_is_empty_iff_no_paths() {
        let no_replace = PlannedChange {
            state: DynamicValue { msgpack: vec![0xc0] },
            requires_replace: vec![],
        };
        let must_replace = PlannedChange {
            state: DynamicValue { msgpack: vec![0xc0] },
            requires_replace: vec!["instance_types".to_string()],
        };
        assert!(no_replace.requires_replace.is_empty());
        assert!(!must_replace.requires_replace.is_empty());
    }
}
