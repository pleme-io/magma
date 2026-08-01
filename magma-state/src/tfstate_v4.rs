//! `tfstate_v4` — the wire-format boundary for real `terraform.tfstate`
//! files (schema version 4), as produced by real OpenTofu and
//! Terraform CLI runs.
//!
//! `magma_types::State` / `StateResource` / `StateInstance` are
//! magma's INTERNAL typed model — nested, ergonomic, easy to build in
//! Rust (`address: ResourceAddress { module, kind, type_id, name, key
//! }`, `provider: ProviderReference { source, name, alias }`). They do
//! NOT match the real on-disk JSON shape byte-for-byte: real tfstate
//! resources are flat (`mode`/`type`/`name`/`provider: <string>`) and
//! `provider` is a single formatted string, not a sub-object. Plain
//! `serde_json::from_slice::<State>(real_tfstate_bytes)` fails outright
//! on any genuine pre-existing state file — required fields like
//! `address` don't exist in it, and real fields like `mode`/`type`/
//! `name`/`index_key` aren't recognized by the typed shape.
//!
//! This module is the typed translation boundary between the two,
//! analogous to the tfplugin5/6 protobuf ⇄ `DynamicValue` boundary in
//! `magma-cty`. [`decode`] / [`encode`] are the sole entry points;
//! `magma_state::read_state` / `write_state` and
//! `magma_backend::LocalBackend` both route through them, so any
//! consumer that reads/writes state through those surfaces gets a real,
//! adoptable state file rather than magma's internal shape.
//!
//! # Verified against real fixtures
//!
//! Confirmed empirically against bytes produced by an actual `tofu
//! apply` (OpenTofu 1.10.9) and `terraform apply` (HashiCorp Terraform
//! 1.14.0) run against local, cost-free `null_resource` /
//! `time_static` configurations — not reconstructed from memory of the
//! spec alone (see `magma-state/tests/tfstate_v4_fixtures.rs`, which
//! checks the raw bytes in verbatim):
//!
//!   * OpenTofu's default provider registry host is
//!     `registry.opentofu.org`, **not** `registry.terraform.io` — the
//!     provider-string converter this module supersedes
//!     (`magma-operator-backend`'s prior `tofu_state` module)
//!     hardcoded the Terraform-CLI host on write, which silently
//!     rewrote (corrupted) any OpenTofu-native provider reference on
//!     round-trip. This module preserves the registry host verbatim
//!     instead of assuming either vendor.
//!   * `sensitive_attributes` is **always** emitted, even `[]`;
//!     `private` and `dependencies` are omitted from the JSON entirely
//!     when empty.
//!   * `index_key` lives on the **instance**, not the resource — one
//!     `count`/`for_each` resource is ONE `resources[]` entry with
//!     multiple `instances[]`, each carrying its own `index_key`. It
//!     precedes `status`, which precedes `schema_version`, when
//!     present.
//!   * `module` (a resource declared inside a module) is the **first**
//!     field on the resource entry, e.g. `"module":"module.child"`.
//!   * `status` is omitted unless the instance is tainted
//!     (`"status":"tainted"`); there is no `"status":"ready"` on disk.
//!
//! # Deliberately out of scope (named, not silently dropped)
//!
//!   * **`count`/`for_each` config-side expansion.** Neither Pangea nor
//!     `magma-config`'s JSON reader expands `count`/`for_each` today
//!     (`Config::resource_addresses()` always emits `key: None`) — see
//!     `theory/MAGMA.md` §IX. This module still round-trips a
//!     multi-instance resource read from a real file correctly (the
//!     instances travel together under one `StateResource`), but
//!     `magma-plan`'s diff only compares the first instance against
//!     config until config-side expansion lands (see
//!     `magma_plan::lookup_state_value`, which now warns instead of
//!     silently dropping instances 2..N).
//!   * **Deposed objects** (`resources[].deposed`, the
//!     create-before-destroy in-flight-replace bookkeeping). Nothing in
//!     magma's apply engine implements deposed-object tracking yet
//!     (`grep -r deposed` is empty across the workspace); a state file
//!     with non-empty `deposed` entries loses them on a decode→encode
//!     round-trip. Named here so it's a visible gap, not a silent one.
//!   * **`check_results`** (from HCL `check` blocks). Magma has no HCL
//!     parser and neither Pangea nor `magma-config` can express a
//!     `check` block, so there is nothing in `magma_types::State` to
//!     round-trip it through. Read-and-discarded; always written back
//!     as `null` (tofu's own shape when no `check` blocks exist).
//!   * **`private`'s non-empty wire shape** (base64, standard
//!     alphabet) is implemented per OpenTofu's documented encoding
//!     (`internal/states/statefile`), not empirically verified against
//!     a live non-empty fixture — no provider available in this
//!     environment happened to populate it. The empty case (omitted
//!     field) *is* empirically verified.
//!   * **Byte-for-byte whitespace** is matched as a side effect of using
//!     compact (non-pretty) JSON here — the same choice OpenTofu/
//!     Terraform make — but is not the actual compatibility bar: JSON
//!     *value* equality is what `tofu show -json` (and every real
//!     consumer) cares about, not text equality against a differently
//!     indented file.
//!
//! Per `theory/MAGMA.md` §II.2 ("State file | JSON, schema version 4 |
//! OpenTofu `internal/states/statefile/`") and §II.6 (byte-exact test
//! corpus, level `StateRoundTrip`).

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use magma_types::{
    InstanceKey, InstanceStatus, ModulePath, OutputValue, ProviderReference, ResourceAddress,
    ResourceKind, ResourceTypeId, State, StateInstance, StateResource,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::StateError;

/// Default provider registry host magma qualifies a short-form
/// `source` (`"hashicorp/aws"`, the shape `magma-config` builds from a
/// `required_providers` block) with when writing a FRESH provider
/// reference to the wire format. Mirrors OpenTofu's own default
/// resolution — confirmed empirically: a `required_providers` block
/// declaring `source = "hashicorp/null"` resolves to
/// `registry.opentofu.org/hashicorp/null` under a real `tofu apply`,
/// not `registry.terraform.io`. A `source` that already contains a
/// `.` (i.e. is already registry-qualified — round-tripped verbatim
/// from a real state file) is left untouched.
const DEFAULT_REGISTRY_HOST: &str = "registry.opentofu.org";

// ── Wire structs — field-for-field AND field-order-for-field-order ──
//
// serde_json serializes struct fields in declaration order (not
// alphabetized), so the declaration order below IS the on-disk key
// order. Every order choice here is taken from a real fixture, not
// assumed — see the module doc.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateWire {
    version: u64,
    terraform_version: String,
    serial: u64,
    lineage: String,
    #[serde(default)]
    outputs: BTreeMap<String, OutputWire>,
    resources: Vec<ResourceWire>,
    /// From HCL `check` blocks. See module doc — read-and-discarded,
    /// always written back as `null`.
    #[serde(default)]
    check_results: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutputWire {
    value: Value,
    #[serde(rename = "type")]
    type_constraint: Value,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    mode: String,
    #[serde(rename = "type")]
    type_: String,
    name: String,
    provider: String,
    #[serde(default)]
    instances: Vec<InstanceWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstanceWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    index_key: Option<InstanceKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<InstanceStatus>,
    schema_version: u64,
    attributes: Value,
    #[serde(default)]
    sensitive_attributes: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<String>,
}

// ── Public entry points ──────────────────────────────────────────────

/// Decode real `terraform.tfstate` v4 bytes into magma's typed
/// `State`. The primary read boundary — this is what lets magma
/// correctly read a real, pre-existing, tofu/terraform-produced state
/// file instead of failing outright.
pub fn decode(bytes: &[u8]) -> Result<State, StateError> {
    let wire: StateWire = serde_json::from_slice(bytes)?;
    wire_to_typed(&wire)
}

/// Encode magma's typed `State` into real `terraform.tfstate` v4
/// bytes — compact JSON (no pretty-printing), matching tofu/
/// terraform's own on-disk shape for every field this module models.
pub fn encode(state: &State) -> Result<Vec<u8>, StateError> {
    let wire = typed_to_wire(state)?;
    Ok(serde_json::to_vec(&wire)?)
}

// ── wire → typed ──────────────────────────────────────────────────

fn wire_to_typed(wire: &StateWire) -> Result<State, StateError> {
    let lineage = Uuid::parse_str(&wire.lineage)
        .map_err(|_| StateError::InvalidLineage(wire.lineage.clone()))?;
    let mut outputs = std::collections::HashMap::with_capacity(wire.outputs.len());
    for (name, ov) in &wire.outputs {
        outputs.insert(
            name.clone(),
            OutputValue {
                value: ov.value.clone(),
                sensitive: ov.sensitive,
                type_constraint: Some(ov.type_constraint.clone()),
            },
        );
    }
    let resources = wire
        .resources
        .iter()
        .map(resource_wire_to_typed)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(State {
        version: wire.version,
        terraform_version: wire.terraform_version.clone(),
        serial: wire.serial,
        lineage,
        outputs,
        resources,
    })
}

fn resource_wire_to_typed(r: &ResourceWire) -> Result<StateResource, StateError> {
    let addr_for_errors = format!("{}.{}", r.type_, r.name);
    let kind = match r.mode.as_str() {
        "managed" => ResourceKind::Managed,
        "data" => ResourceKind::Data,
        other => {
            return Err(StateError::MalformedAddress(
                addr_for_errors,
                format!("unsupported resource mode {other:?} (expected \"managed\" or \"data\")"),
            ));
        }
    };
    let module = match &r.module {
        Some(m) => parse_module_path(m)?,
        None => ModulePath::root(),
    };
    let provider = parse_provider_reference(&r.provider)?;
    let instances = r
        .instances
        .iter()
        .map(instance_wire_to_typed)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StateResource {
        address: ResourceAddress {
            module,
            kind,
            type_id: ResourceTypeId(r.type_.clone()),
            name: r.name.clone(),
            // Real tfstate carries the instance key per-instance
            // (`instances[].index_key`), not on the resource entry —
            // see `StateInstance::index_key`.
            key: None,
        },
        provider,
        instances,
    })
}

fn instance_wire_to_typed(i: &InstanceWire) -> Result<StateInstance, StateError> {
    let private = match &i.private {
        Some(b64) => B64
            .decode(b64)
            .map_err(|e| StateError::MalformedPrivate(e.to_string()))?,
        None => Vec::new(),
    };
    let dependencies = i
        .dependencies
        .iter()
        .map(|s| parse_address_string(s))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StateInstance {
        index_key: i.index_key.clone(),
        schema_version: i.schema_version,
        attributes: i.attributes.clone(),
        sensitive_attribute_paths: i.sensitive_attributes.clone(),
        private,
        dependencies,
        status: i.status.unwrap_or(InstanceStatus::Ready),
    })
}

// ── typed → wire ──────────────────────────────────────────────────

fn typed_to_wire(state: &State) -> Result<StateWire, StateError> {
    let mut outputs = BTreeMap::new();
    for (name, ov) in &state.outputs {
        outputs.insert(
            name.clone(),
            OutputWire {
                value: ov.value.clone(),
                type_constraint: ov
                    .type_constraint
                    .clone()
                    .unwrap_or_else(|| infer_type_constraint(&ov.value)),
                sensitive: ov.sensitive,
            },
        );
    }
    let resources = state
        .resources
        .iter()
        .map(resource_typed_to_wire)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StateWire {
        version: state.version,
        terraform_version: state.terraform_version.clone(),
        serial: state.serial,
        lineage: state.lineage.to_string(),
        outputs,
        resources,
        // No HCL `check` blocks are representable in `magma_types::State`
        // today — see module doc.
        check_results: Value::Null,
    })
}

fn resource_typed_to_wire(r: &StateResource) -> Result<ResourceWire, StateError> {
    let mode = match r.address.kind {
        ResourceKind::Managed => "managed",
        ResourceKind::Data => "data",
        other => return Err(StateError::UnwritableResourceKind(other)),
    };
    Ok(ResourceWire {
        module: format_module_path(&r.address.module),
        mode: mode.to_string(),
        type_: r.address.type_id.0.clone(),
        name: r.address.name.clone(),
        provider: format_provider_reference(&r.provider),
        instances: r.instances.iter().map(instance_typed_to_wire).collect(),
    })
}

fn instance_typed_to_wire(i: &StateInstance) -> InstanceWire {
    InstanceWire {
        index_key: i.index_key.clone(),
        status: matches!(i.status, InstanceStatus::Tainted).then_some(InstanceStatus::Tainted),
        schema_version: i.schema_version,
        attributes: i.attributes.clone(),
        sensitive_attributes: i.sensitive_attribute_paths.clone(),
        private: (!i.private.is_empty()).then(|| B64.encode(&i.private)),
        dependencies: i.dependencies.iter().map(format_address_string).collect(),
    }
}

fn infer_type_constraint(v: &Value) -> Value {
    match v {
        Value::Null | Value::String(_) => Value::String("string".into()),
        Value::Bool(_) => Value::String("bool".into()),
        Value::Number(_) => Value::String("number".into()),
        Value::Array(_) => serde_json::json!(["list", "string"]),
        Value::Object(_) => serde_json::json!(["object", {}]),
    }
}

// ── Provider reference string ⇄ ProviderReference ────────────────
//
// Real form: `provider["registry.opentofu.org/hashicorp/null"]`, or
// with an alias: `provider["registry.opentofu.org/hashicorp/aws"].east`.

/// Parse tofu/terraform's serialized provider form —
/// `provider["registry.opentofu.org/hashicorp/null"]`, optionally
/// suffixed `.alias` — into a typed `ProviderReference`. `source`
/// carries the registry host verbatim (see [`format_provider_reference`]
/// and the module doc for why this must not be normalized to one
/// vendor's default).
pub fn parse_provider_reference(s: &str) -> Result<ProviderReference, StateError> {
    let malformed = || StateError::MalformedProvider(s.to_string());
    let after_open = s.strip_prefix("provider[\"").ok_or_else(malformed)?;
    let close = after_open.find("\"]").ok_or_else(malformed)?;
    let source = &after_open[..close];
    let after_close = &after_open[close + 2..];
    let alias = after_close.strip_prefix('.').map(str::to_string);
    let name = source.rsplit('/').next().ok_or_else(malformed)?.to_string();
    Ok(ProviderReference {
        source: source.to_string(),
        name,
        alias,
    })
}

/// Format a `ProviderReference` back into tofu/terraform's serialized
/// form. A `source` that's already registry-qualified (contains a
/// `.`) is preserved verbatim; a short form (`"hashicorp/aws"`, as
/// `magma-config` builds from a `required_providers` block) is
/// qualified with [`DEFAULT_REGISTRY_HOST`].
pub fn format_provider_reference(p: &ProviderReference) -> String {
    let qualified_source = if p.source.contains('.') {
        p.source.clone()
    } else {
        format!("{DEFAULT_REGISTRY_HOST}/{}", p.source)
    };
    let mut s = format!("provider[\"{qualified_source}\"]");
    if let Some(alias) = &p.alias {
        s.push('.');
        s.push_str(alias);
    }
    s
}

// ── Address string ⇄ ResourceAddress ──────────────────────────────
//
// Real forms: `aws_vpc.foo`, `aws_vpc.foo[0]`, `aws_vpc.foo["bar"]`,
// `data.aws_vpc.foo`, `module.child.aws_vpc.foo`. Used for
// `dependencies` entries and the resource-level `module` field.

/// Strip a run of `module.<name>.` segments from the front of a real
/// state address string. Shared by resource-level `module` field
/// parsing and full address-string parsing (`dependencies` entries).
fn take_module_prefix(s: &str) -> Result<(Vec<String>, &str), StateError> {
    let mut parts = Vec::new();
    let mut rest = s;
    while let Some(after_module) = rest.strip_prefix("module.") {
        let dot = after_module.find('.').ok_or_else(|| {
            StateError::MalformedAddress(
                s.to_string(),
                "truncated \"module.<name>\" segment".into(),
            )
        })?;
        parts.push(after_module[..dot].to_string());
        rest = &after_module[dot + 1..];
    }
    Ok((parts, rest))
}

/// Parse the resource-level `module` field, e.g. `"module.child"` or
/// `"module.a.module.b"`. NOT the same grammar as [`take_module_prefix`]
/// (used for a full address string): here the LAST segment has no
/// trailing content to terminate against — the whole string IS the
/// module path — so this splits on every `.` rather than scanning for
/// a `module.` prefix followed by more content.
fn parse_module_path(s: &str) -> Result<ModulePath, StateError> {
    let tokens: Vec<&str> = s.split('.').collect();
    if tokens.is_empty() || tokens.len() % 2 != 0 {
        return Err(StateError::MalformedAddress(
            s.to_string(),
            "expected one or more \"module.<name>\" segments".into(),
        ));
    }
    let mut parts = Vec::with_capacity(tokens.len() / 2);
    let mut it = tokens.into_iter();
    while let (Some(keyword), Some(name)) = (it.next(), it.next()) {
        if keyword != "module" {
            return Err(StateError::MalformedAddress(
                s.to_string(),
                format!("expected \"module\" keyword, got {keyword:?}"),
            ));
        }
        parts.push(name.to_string());
    }
    Ok(ModulePath(parts))
}

fn format_module_path(m: &ModulePath) -> Option<String> {
    if m.0.is_empty() {
        None
    } else {
        Some(
            m.0.iter()
                .map(|p| format!("module.{p}"))
                .collect::<Vec<_>>()
                .join("."),
        )
    }
}

fn parse_address_string(s: &str) -> Result<ResourceAddress, StateError> {
    let (module_parts, rest) = take_module_prefix(s)?;
    let (kind, rest) = match rest.strip_prefix("data.") {
        Some(after_data) => (ResourceKind::Data, after_data),
        None => (ResourceKind::Managed, rest),
    };
    let dot = rest.find('.').ok_or_else(|| {
        StateError::MalformedAddress(s.to_string(), "missing \".\" between type and name".into())
    })?;
    let type_str = &rest[..dot];
    let after_type = &rest[dot + 1..];
    let (name, key) = match after_type.find('[') {
        Some(bracket) => {
            let name = &after_type[..bracket];
            let inner = after_type[bracket + 1..].strip_suffix(']').ok_or_else(|| {
                StateError::MalformedAddress(s.to_string(), "unterminated \"[\"".into())
            })?;
            (
                name.to_string(),
                Some(parse_instance_key_literal(inner, s)?),
            )
        }
        None => (after_type.to_string(), None),
    };
    Ok(ResourceAddress {
        module: ModulePath(module_parts),
        kind,
        type_id: ResourceTypeId(type_str.to_string()),
        name,
        key,
    })
}

/// Delegates to `ResourceAddress`'s `Display` — the single canonical
/// rendering, now living beside the type in `magma-types`.
///
/// It moved because this copy was PRIVATE to this module while every other
/// consumer needed the same answer, so they hand-rolled
/// `format!("{}.{}", type_id.0, name)` and silently dropped `kind`/`module`/
/// `key`. Keeping a thin wrapper (rather than deleting it) preserves this
/// module's `parse_address_string` ⇄ format round-trip tests, which are exactly
/// the proof that the moved `Display` still agrees with the parser.
fn format_address_string(a: &ResourceAddress) -> String {
    a.to_string()
}

fn parse_instance_key_literal(inner: &str, whole: &str) -> Result<InstanceKey, StateError> {
    if let Some(quoted) = inner.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Ok(InstanceKey::Key(unescape_key(quoted)))
    } else {
        inner.parse::<u64>().map(InstanceKey::Index).map_err(|_| {
            StateError::MalformedAddress(whole.to_string(), format!("invalid index key {inner:?}"))
        })
    }
}

fn unescape_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_reference_round_trips_opentofu_registry() {
        let s = "provider[\"registry.opentofu.org/hashicorp/null\"]";
        let p = parse_provider_reference(s).unwrap();
        assert_eq!(p.source, "registry.opentofu.org/hashicorp/null");
        assert_eq!(p.name, "null");
        assert_eq!(p.alias, None);
        assert_eq!(format_provider_reference(&p), s);
    }

    #[test]
    fn provider_reference_round_trips_terraform_registry() {
        // The registry host that a prior converter hardcoded
        // unconditionally on write — must NOT be silently rewritten
        // to `registry.opentofu.org` when the source data actually
        // says `registry.terraform.io`.
        let s = "provider[\"registry.terraform.io/hashicorp/aws\"]";
        let p = parse_provider_reference(s).unwrap();
        assert_eq!(format_provider_reference(&p), s);
    }

    #[test]
    fn provider_reference_round_trips_with_alias() {
        let s = "provider[\"registry.opentofu.org/hashicorp/aws\"].east";
        let p = parse_provider_reference(s).unwrap();
        assert_eq!(p.alias.as_deref(), Some("east"));
        assert_eq!(format_provider_reference(&p), s);
    }

    #[test]
    fn short_form_source_is_qualified_with_opentofu_default() {
        let p = ProviderReference {
            source: "hashicorp/null".into(),
            name: "null".into(),
            alias: None,
        };
        assert_eq!(
            format_provider_reference(&p),
            "provider[\"registry.opentofu.org/hashicorp/null\"]",
        );
    }

    #[test]
    fn address_string_round_trips_simple() {
        let a = parse_address_string("null_resource.base").unwrap();
        assert_eq!(a.type_id.0, "null_resource");
        assert_eq!(a.name, "base");
        assert_eq!(a.key, None);
        assert!(a.module.is_root());
        assert_eq!(format_address_string(&a), "null_resource.base");
    }

    #[test]
    fn address_string_round_trips_indexed() {
        let a = parse_address_string("null_resource.counted[1]").unwrap();
        assert_eq!(a.key, Some(InstanceKey::Index(1)));
        assert_eq!(format_address_string(&a), "null_resource.counted[1]");
    }

    #[test]
    fn address_string_round_trips_keyed() {
        let a = parse_address_string("null_resource.keyed[\"alpha\"]").unwrap();
        assert_eq!(a.key, Some(InstanceKey::Key("alpha".into())));
        assert_eq!(format_address_string(&a), "null_resource.keyed[\"alpha\"]");
    }

    #[test]
    fn address_string_round_trips_data_source() {
        let a = parse_address_string("data.aws_vpc.foo").unwrap();
        assert_eq!(a.kind, ResourceKind::Data);
        assert_eq!(format_address_string(&a), "data.aws_vpc.foo");
    }

    #[test]
    fn address_string_round_trips_module_prefixed() {
        let a = parse_address_string("module.child.null_resource.inner").unwrap();
        assert_eq!(a.module, ModulePath(vec!["child".into()]));
        assert_eq!(
            format_address_string(&a),
            "module.child.null_resource.inner",
        );
    }

    #[test]
    fn resource_level_module_field_round_trips() {
        // The standalone `module` field on a resource entry has no
        // trailing content to terminate against (unlike a full address
        // string) — `take_module_prefix`'s "there must be more after
        // the last segment" rule does NOT apply here. Caught by the
        // real-fixture round-trip test on `MODULE_OPENTOFU`.
        let m = parse_module_path("module.child").unwrap();
        assert_eq!(m, ModulePath(vec!["child".into()]));
        assert_eq!(format_module_path(&m).as_deref(), Some("module.child"));
    }

    #[test]
    fn resource_level_nested_module_field_round_trips() {
        let m = parse_module_path("module.a.module.b").unwrap();
        assert_eq!(m, ModulePath(vec!["a".into(), "b".into()]));
        assert_eq!(format_module_path(&m).as_deref(), Some("module.a.module.b"));
    }

    #[test]
    fn address_string_round_trips_nested_module() {
        let a = parse_address_string("module.a.module.b.aws_vpc.foo").unwrap();
        assert_eq!(a.module, ModulePath(vec!["a".into(), "b".into()]));
        assert_eq!(format_address_string(&a), "module.a.module.b.aws_vpc.foo");
    }

    #[test]
    fn address_string_key_escaping_round_trips() {
        let a = parse_address_string("null_resource.x[\"has \\\"quote\\\"\"]").unwrap();
        assert_eq!(a.key, Some(InstanceKey::Key("has \"quote\"".into())));
        assert_eq!(
            format_address_string(&a),
            "null_resource.x[\"has \\\"quote\\\"\"]",
        );
    }

    #[test]
    fn malformed_provider_reference_is_a_typed_error_not_a_panic() {
        let err = parse_provider_reference("not-a-provider-string").unwrap_err();
        assert!(matches!(err, StateError::MalformedProvider(_)));
    }

    #[test]
    fn malformed_address_string_is_a_typed_error_not_a_panic() {
        let err = parse_address_string("no-dot-here").unwrap_err();
        assert!(matches!(err, StateError::MalformedAddress(_, _)));
    }

    #[test]
    fn empty_private_is_omitted_nonempty_is_base64() {
        let ready = StateInstance {
            index_key: None,
            schema_version: 0,
            attributes: Value::Null,
            sensitive_attribute_paths: vec![],
            private: vec![],
            dependencies: vec![],
            status: InstanceStatus::Ready,
        };
        assert_eq!(instance_typed_to_wire(&ready).private, None);

        let with_private = StateInstance {
            private: vec![1, 2, 3],
            ..ready
        };
        let wire = instance_typed_to_wire(&with_private);
        assert_eq!(wire.private.as_deref(), Some("AQID"));
        let back = instance_wire_to_typed(&wire).unwrap();
        assert_eq!(back.private, vec![1, 2, 3]);
    }

    #[test]
    fn unwritable_resource_kind_is_a_typed_error_not_a_panic() {
        let r = StateResource {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Output,
                type_id: ResourceTypeId("x".into()),
                name: "y".into(),
                key: None,
            },
            provider: ProviderReference {
                source: "hashicorp/x".into(),
                name: "x".into(),
                alias: None,
            },
            instances: vec![],
        };
        let err = resource_typed_to_wire(&r).unwrap_err();
        assert!(matches!(err, StateError::UnwritableResourceKind(_)));
    }
}
