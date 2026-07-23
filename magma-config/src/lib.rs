//! magma-config — Terraform JSON → typed `magma_types::Config`
//! conversion + the small `${resource.attribute}` interpolation
//! resolver needed for Pangea-rendered JSON.
//!
//! Magma does **not** implement HCL. The full HCL2 expression language,
//! the ~150-function library, dynamic blocks, etc. are out of scope per
//! `theory/MAGMA.md` §II.1. Pangea Ruby evaluates all HCL-equivalent
//! expressions at render time; magma sees only flat resource definitions
//! plus the narrow `${aws_vpc.main.id}` style references that Terraform
//! resolves at apply time using state data.
//!
//! This crate owns:
//!
//! 1. **JSON → typed Config** — parses the rendered Terraform JSON
//!    surface (`resource`, `data`, `output`, `module`, `provider`, `terraform`
//!    top-level blocks) into typed magma-types values.
//! 2. **Interpolation resolver** — given a `${a.b.c}` string and a state
//!    map, resolves to a concrete value. The state map is built by
//!    `magma-state`; the resolver is called during plan/apply.

use std::collections::HashMap;

use magma_types::{ProviderReference, ResourceAddress, ResourceKind, ResourceTypeId, State};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("malformed Terraform JSON: {0}")]
    Malformed(String),
    #[error("unknown interpolation reference: {0:?}")]
    UnknownReference(String),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

// ── Top-level config (Pangea-rendered + tiny subset) ──────────────

/// The typed image of a Pangea-rendered Terraform JSON workspace.
/// Field renames preserve the Terraform JSON singular-form keys
/// (`resource`, `provider`, `output`, `module`) while exposing
/// idiomatic plural identifiers in Rust.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub terraform: TerraformBlock,
    #[serde(default, rename = "provider")]
    pub providers: HashMap<String, ProviderConfig>,
    /// `resource: { aws_vpc: { foo: { ... } } }`
    #[serde(default, rename = "resource")]
    pub resources: HashMap<String, HashMap<String, serde_json::Value>>,
    /// `data: { aws_caller_identity: { current: { ... } } }`
    #[serde(default)]
    pub data: HashMap<String, HashMap<String, serde_json::Value>>,
    #[serde(default, rename = "output")]
    pub outputs: HashMap<String, OutputDecl>,
    /// Module calls — we don't process module SOURCES (Pangea Ruby owns
    /// module expansion), but module BLOCKS in rendered JSON are still
    /// represented for graph + output tracking.
    #[serde(default, rename = "module")]
    pub modules: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TerraformBlock {
    #[serde(default)]
    pub required_providers: HashMap<String, RequiredProvider>,
    #[serde(default)]
    pub backend: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub required_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredProvider {
    pub source: String,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputDecl {
    pub value: serde_json::Value,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub description: Option<String>,
}

impl Config {
    /// Parse a rendered Terraform JSON `serde_json::Value` into a typed
    /// `Config`. Accepts the top-level shape that Pangea's renderer +
    /// `tofu show -json` both emit.
    pub fn from_json(v: serde_json::Value) -> Result<Self, ConfigError> {
        serde_json::from_value(v).map_err(ConfigError::from)
    }

    /// Iterate all `ResourceAddress`es declared by this config.
    pub fn resource_addresses(&self) -> impl Iterator<Item = ResourceAddress> + '_ {
        let managed = self.resources.iter().flat_map(|(type_name, by_name)| {
            by_name.keys().map(move |n| ResourceAddress {
                module: Default::default(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId(type_name.clone()),
                name: n.clone(),
                key: None,
            })
        });
        let data = self.data.iter().flat_map(|(type_name, by_name)| {
            by_name.keys().map(move |n| ResourceAddress {
                module: Default::default(),
                kind: ResourceKind::Data,
                type_id: ResourceTypeId(type_name.clone()),
                name: n.clone(),
                key: None,
            })
        });
        managed.chain(data)
    }

    /// Provider references declared by the `terraform.required_providers`
    /// block, joined with any `providers` configuration blocks.
    pub fn provider_references(&self) -> Vec<ProviderReference> {
        self.terraform
            .required_providers
            .iter()
            .map(|(name, rp)| ProviderReference {
                source: rp.source.clone(),
                name: name.clone(),
                alias: None,
            })
            .collect()
    }
}

// ── State resolution map ────────────────────────────────────────────

/// Build the `{type → {name → attributes}}` resolution map `resolve_reference`
/// / `resolve_config` navigate, from a typed `State`. Managed resources are
/// inserted directly under their `type_id` (`aws_vpc.main` →
/// `map["aws_vpc"]["main"]`); data resources are nested one level deeper
/// under a `data` head (`data.cloudflare_zones.z` →
/// `map["data"]["cloudflare_zones"]["z"]`), matching the reference grammar
/// (`${data.cloudflare_zones.z.result[0].id}` vs `${aws_vpc.main.id}`).
///
/// Mirrors `magma-apply::engine`'s apply-time `state_map` construction
/// (`sm_insert`/`sm_insert_data`) — this is the plan-time counterpart, so
/// `${type.name.attr}` references in a rendered config can be resolved
/// against already-applied state BEFORE a plan diffs `after` against
/// `before`, not only at apply time. Without this, any resource whose
/// config references another resource (`vpc_id = "${aws_vpc.main.id}"`)
/// is unconditionally reported as drifted: the literal, unresolved
/// reference string can never `serde_json::Value`-equal the concrete
/// value already recorded in state, regardless of whether anything
/// actually changed.
///
/// A resource with multiple `StateInstance`s (`count`/`for_each`, which
/// magma-config does not expand on the config side — see
/// `theory/MAGMA.md` §IX) contributes only its first instance, consistent
/// with the rest of the plan/apply pipeline's current single-instance
/// handling.
pub fn state_resolution_map(state: &State) -> HashMap<String, serde_json::Value> {
    let mut sm: HashMap<String, serde_json::Value> = HashMap::new();
    for r in &state.resources {
        let Some(inst) = r.instances.first() else {
            continue;
        };
        insert_into_resolution_map(&mut sm, &r.address, &inst.attributes);
    }
    sm
}

/// Insert one resource's attributes into an existing resolution map (as
/// built by `state_resolution_map`), keyed the same way. Lets a caller
/// GROW the map incrementally as resources are (re-)applied within the
/// same pass — e.g. `magma-apply`'s structural apply engines, which
/// resolve each resource's config against everything already applied
/// (including earlier resources in the SAME apply pass) before writing
/// its new state, mirroring real Terraform's create-then-resolve
/// ordering rather than persisting a literal `${...}` reference as if
/// it were a concrete attribute value.
pub fn insert_into_resolution_map(
    map: &mut HashMap<String, serde_json::Value>,
    address: &ResourceAddress,
    attributes: &serde_json::Value,
) {
    if address.kind == ResourceKind::Data {
        let data_head = map
            .entry("data".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(by_type) = data_head {
            let by_name = by_type
                .entry(address.type_id.0.clone())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            if let serde_json::Value::Object(by_name) = by_name {
                by_name.insert(address.name.clone(), attributes.clone());
            }
        }
    } else {
        let entry = map
            .entry(address.type_id.0.clone())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(by_name) = entry {
            by_name.insert(address.name.clone(), attributes.clone());
        }
    }
}

// ── Interpolation resolver ─────────────────────────────────────────

/// Resolve a `${aws_vpc.main.id}` style reference against a flat state
/// view. The reference grammar is intentionally narrow — only the subset
/// that appears in Pangea-rendered JSON.
///
/// Grammar:
///   reference := `${` path `}`
///   path      := segment (`.` segment)*
///   segment   := IDENT | IDENT `[` index `]`
///
/// Returns the concrete value (or an error if the reference can't be
/// resolved against `state`).
pub fn resolve_reference(
    reference: &str,
    state: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, ConfigError> {
    let inner = reference
        .trim_start_matches("${")
        .trim_end_matches('}')
        .trim();

    let mut parts = inner.split('.');
    let head = parts
        .next()
        .ok_or_else(|| ConfigError::Malformed(format!("empty reference: {reference:?}")))?;

    // The head segment may itself carry an index (rare, but uniform).
    let (head_key, head_idx) = parse_segment(head);
    let mut current = state
        .get(head_key)
        .cloned()
        .ok_or_else(|| ConfigError::UnknownReference(reference.to_string()))?;
    if let Some(i) = head_idx {
        current = index_into(&current, i, reference)?;
    }

    for part in parts {
        // Each segment is `IDENT` or `IDENT[index]` (the documented grammar).
        // The old impl only did `get(part)`, so it could not navigate the
        // `.result[0].id` shape Pangea's cloudflare_* data sources emit
        // (e.g. ${data.cloudflare_zones.X.result[0].id}) — the literal
        // string then leaked to the provider RPC. Parse the optional index.
        let (key, idx) = parse_segment(part);
        current = current
            .get(key)
            .cloned()
            .ok_or_else(|| ConfigError::UnknownReference(reference.to_string()))?;
        if let Some(i) = idx {
            current = index_into(&current, i, reference)?;
        }
    }

    Ok(current)
}

/// Split a path segment into its identifier and an optional `[index]`.
/// `"result[0]"` → `("result", Some(0))`; `"id"` → `("id", None)`.
/// A malformed/non-numeric index degrades to no-index (the subsequent
/// `get` then fails with a clean UnknownReference rather than panicking).
fn parse_segment(seg: &str) -> (&str, Option<usize>) {
    match seg.split_once('[') {
        Some((ident, rest)) => {
            let idx = rest.strip_suffix(']').and_then(|n| n.trim().parse::<usize>().ok());
            (ident, idx)
        }
        None => (seg, None),
    }
}

/// Index into a JSON array; error (never panic) if `value` is not an array
/// or the index is out of bounds.
fn index_into(
    value: &serde_json::Value,
    idx: usize,
    reference: &str,
) -> Result<serde_json::Value, ConfigError> {
    value
        .get(idx)
        .cloned()
        .ok_or_else(|| ConfigError::UnknownReference(reference.to_string()))
}

/// Recursively resolve every Terraform interpolation in a resource config
/// against `state`, returning the fully-concrete config to hand to a provider
/// RPC. This is the step magma was missing: the rendered config arrives with
/// literal `${...}` strings (e.g. account_id = "${data.cloudflare_accounts...}")
/// which the provider cannot accept (Cloudflare 400). Walk the JSON tree:
///   - a string that is EXACTLY one reference (`"${...}"`) → replaced by the
///     resolved value, preserving its JSON type (id stays a string, a count
///     stays a number, etc.);
///   - a string with an EMBEDDED reference (`"x-${...}-y"`) → each reference
///     substituted by its stringified resolved value;
///   - arrays/objects recurse; scalars pass through.
/// An unresolved reference is an error (surfaced, never silently leaked).
pub fn resolve_config(
    value: &serde_json::Value,
    state: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, ConfigError> {
    use serde_json::Value;
    match value {
        Value::String(s) => resolve_string(s, state),
        Value::Array(items) => {
            let resolved: Result<Vec<_>, _> =
                items.iter().map(|v| resolve_config(v, state)).collect();
            Ok(Value::Array(resolved?))
        }
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), resolve_config(v, state)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// `true` if the string contains a `${...}` interpolation. Escape-aware
/// (2026-07-23, same incident/fix family as `magma-test-laws::architecture`
/// and `magma-apply::engine`'s `collect_refs`/`substitute_refs`): a `$${`
/// HCL2-escaped literal must NOT count as an interpolation, or `resolve_string`
/// below tries to resolve the malformed extracted path from an escaped
/// GitHub Actions `${{ }}` expression as a real reference and fails the
/// whole config resolution (this function is shared by both `magma-plan`
/// and `magma-apply`, so the failure surfaces in either phase).
fn has_interpolation(s: &str) -> bool {
    contains_unescaped_dollar_brace(s)
}

/// `true` if `s` contains a genuine (non-`$$`-escaped) `${` anywhere.
fn contains_unescaped_dollar_brace(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 2 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'$' && bytes[i + 2] == b'{' {
            i += 3;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            return true;
        }
        i += 1;
    }
    false
}

/// `true` if the whole string is exactly one `${...}` reference (no surrounding
/// text), so the resolved value's JSON type is preserved. An escaped `$${...}`
/// never counts, even if it spans the whole string — it isn't a reference.
fn is_whole_reference(s: &str) -> bool {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("$$") {
        // The whole string opens with an escape ($${...) -- never a whole
        // reference, regardless of what follows.
        let _ = rest;
        return false;
    }
    t.starts_with("${") && t.ends_with('}') && !contains_unescaped_dollar_brace(&t[2..])
}

/// Escape-aware embedded-interpolation substitution. `$${`/`%%{` are HCL2's
/// own escapes for a literal `${`/`%{` and are rewritten to their unescaped
/// form (never resolved as a reference) — the same rule and rationale as
/// `magma-apply::engine::substitute_refs` (see that function's doc for the
/// full incident writeup: an escaped GitHub Actions `${{ }}` sequence left
/// un-rewritten would otherwise ship a syntactically broken workflow, or —
/// worse, here — fail this `Result`-returning function outright via `?` on
/// the malformed extracted "reference"). Slicing only happens immediately
/// adjacent to `$`/`%`/`{`/`}` (all single-byte ASCII), so every slice point
/// is a guaranteed UTF-8 char boundary regardless of surrounding content.
fn resolve_string(
    s: &str,
    state: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, ConfigError> {
    if !has_interpolation(s) {
        // No genuine interpolation. If the ONLY thing present is an escaped
        // literal, still unescape it before returning.
        return Ok(serde_json::Value::String(unescape_only(s)));
    }
    if is_whole_reference(s) {
        return resolve_reference(s.trim(), state);
    }
    // Embedded interpolation(s) inside a larger string → string substitution.
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut last_push = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 2 < bytes.len()
            && (bytes[i] == b'$' || bytes[i] == b'%')
            && bytes[i + 1] == bytes[i]
            && bytes[i + 2] == b'{'
        {
            out.push_str(&s[last_push..i]);
            out.push(bytes[i] as char); // '$' or '%' -- single-byte ASCII, safe
            out.push('{');
            i += 3;
            last_push = i;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let after = &s[i..];
            let end = after.find('}').ok_or_else(|| {
                ConfigError::Malformed(format!("unterminated interpolation: {s:?}"))
            })?;
            let reference = &after[..=end];
            let resolved = resolve_reference(reference, state)?;
            out.push_str(&s[last_push..i]);
            // Stringify the resolved value for embedding (strip quotes for strings).
            match resolved {
                serde_json::Value::String(v) => out.push_str(&v),
                other => out.push_str(&other.to_string()),
            }
            i += end + 1;
            last_push = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&s[last_push..]);
    Ok(serde_json::Value::String(out))
}

/// Rewrite any `$${`/`%%{` escape to its unescaped `${`/`%{` form, with no
/// reference resolution at all — the fast path for a string that
/// `has_interpolation` already determined carries no genuine `${...}`.
fn unescape_only(s: &str) -> String {
    if !s.contains("$${") && !s.contains("%%{") {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut last_push = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 2 < bytes.len() && (bytes[i] == b'$' || bytes[i] == b'%') && bytes[i + 1] == bytes[i] && bytes[i + 2] == b'{' {
            out.push_str(&s[last_push..i]);
            out.push(bytes[i] as char);
            out.push('{');
            i += 3;
            last_push = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&s[last_push..]);
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_minimal_terraform_json() {
        let v = json!({
            "terraform": {
                "required_providers": {
                    "aws": { "source": "hashicorp/aws", "version": "~> 5.0" }
                }
            },
            "resource": {
                "aws_vpc": {
                    "main": { "cidr_block": "10.0.0.0/16" }
                }
            }
        });
        let cfg = Config::from_json(v).unwrap();
        assert_eq!(cfg.terraform.required_providers.len(), 1);
        assert_eq!(cfg.resources.len(), 1);
        let addrs: Vec<_> = cfg.resource_addresses().collect();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].type_id.0, "aws_vpc");
        assert_eq!(addrs[0].name, "main");
    }

    #[test]
    fn provider_references_collected() {
        let v = json!({
            "terraform": {
                "required_providers": {
                    "aws":        { "source": "hashicorp/aws" },
                    "cloudflare": { "source": "cloudflare/cloudflare" }
                }
            }
        });
        let cfg = Config::from_json(v).unwrap();
        let refs = cfg.provider_references();
        assert_eq!(refs.len(), 2);
        assert!(refs.iter().any(|r| r.source == "hashicorp/aws"));
        assert!(refs.iter().any(|r| r.source == "cloudflare/cloudflare"));
    }

    #[test]
    fn resolve_simple_reference() {
        let mut state = HashMap::new();
        state.insert(
            "aws_vpc".to_string(),
            json!({ "main": { "id": "vpc-abc123" } }),
        );
        let resolved = resolve_reference("${aws_vpc.main.id}", &state).unwrap();
        assert_eq!(resolved, json!("vpc-abc123"));
    }

    #[test]
    fn resolve_unknown_reference_errs() {
        let state = HashMap::new();
        let err = resolve_reference("${aws_vpc.missing.id}", &state).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownReference(_)));
    }

    #[test]
    fn resolve_indexed_data_source_reference() {
        // The exact grammar the Pangea CloudflareTunnel architecture emits
        // (rio-drive): a data-source result navigated by list index. The old
        // impl could not parse `result[0]` and leaked the literal `${...}` to
        // the provider → Cloudflare 400.
        let mut state = HashMap::new();
        state.insert(
            "data".to_string(),
            json!({
                "cloudflare_zones": { "rio_drive_zone": { "result": [ { "id": "zone-abc" } ] } },
                "cloudflare_accounts": { "rio_drive_account": { "result": [ { "id": "acct-xyz" } ] } }
            }),
        );
        assert_eq!(
            resolve_reference("${data.cloudflare_zones.rio_drive_zone.result[0].id}", &state).unwrap(),
            json!("zone-abc"),
        );
        assert_eq!(
            resolve_reference("${data.cloudflare_accounts.rio_drive_account.result[0].id}", &state).unwrap(),
            json!("acct-xyz"),
        );
    }

    #[test]
    fn resolve_index_out_of_bounds_errs() {
        let mut state = HashMap::new();
        state.insert("data".to_string(), json!({ "x": { "y": { "result": [] } } }));
        let err = resolve_reference("${data.x.y.result[0].id}", &state).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownReference(_)));
    }

    #[test]
    fn resolve_managed_resource_id_reference() {
        // The tunnel-config references the tunnel's id (sibling managed
        // resource) — same path machinery, no index.
        let mut state = HashMap::new();
        state.insert(
            "cloudflare_zero_trust_tunnel_cloudflared".to_string(),
            json!({ "rio": { "id": "tunnel-123" } }),
        );
        assert_eq!(
            resolve_reference("${cloudflare_zero_trust_tunnel_cloudflared.rio.id}", &state).unwrap(),
            json!("tunnel-123"),
        );
    }

    #[test]
    fn state_resolution_map_nests_managed_and_data_resources() {
        use magma_types::{
            InstanceStatus, ModulePath, ProviderReference as PRef, StateInstance, StateResource,
        };

        let mk_addr = |kind: ResourceKind, type_id: &str, name: &str| ResourceAddress {
            module: ModulePath::root(),
            kind,
            type_id: ResourceTypeId(type_id.to_string()),
            name: name.to_string(),
            key: None,
        };
        let mk_instance = |attrs: serde_json::Value| StateInstance {
            index_key: None,
            schema_version: 0,
            attributes: attrs,
            sensitive_attribute_paths: Vec::new(),
            private: Vec::new(),
            dependencies: Vec::new(),
            status: InstanceStatus::Ready,
        };
        let provider = PRef {
            source: "hashicorp/aws".into(),
            name: "aws".into(),
            alias: None,
        };

        let state = State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: uuid::Uuid::new_v4(),
            outputs: Default::default(),
            resources: vec![
                StateResource {
                    address: mk_addr(ResourceKind::Managed, "aws_vpc", "main"),
                    provider: provider.clone(),
                    instances: vec![mk_instance(json!({ "id": "vpc-abc123" }))],
                },
                StateResource {
                    address: mk_addr(ResourceKind::Data, "cloudflare_zones", "z"),
                    provider: provider.clone(),
                    instances: vec![mk_instance(json!({ "result": [ { "id": "zone-abc" } ] }))],
                },
            ],
        };

        let sm = state_resolution_map(&state);
        assert_eq!(sm["aws_vpc"]["main"]["id"], json!("vpc-abc123"));
        assert_eq!(
            sm["data"]["cloudflare_zones"]["z"]["result"][0]["id"],
            json!("zone-abc")
        );

        // The map is exactly what resolve_reference/resolve_config expect —
        // both grammars must resolve directly against it.
        assert_eq!(
            resolve_reference("${aws_vpc.main.id}", &sm).unwrap(),
            json!("vpc-abc123")
        );
        assert_eq!(
            resolve_reference("${data.cloudflare_zones.z.result[0].id}", &sm).unwrap(),
            json!("zone-abc")
        );
    }

    #[test]
    fn resolve_config_walks_rio_drive_shaped_resource() {
        // A config shaped like the rio-drive CloudflareTunnel resources: a
        // whole-reference account_id/zone_id (must stay strings), a sibling
        // tunnel-id whole-reference, a nested ingress array (plain strings),
        // and an embedded interpolation in a hostname. resolve_config must
        // produce a fully-concrete config with zero `${...}` left.
        let mut state = HashMap::new();
        state.insert(
            "data".to_string(),
            json!({
                "cloudflare_accounts": { "a": { "result": [ { "id": "acct-xyz" } ] } },
                "cloudflare_zones": { "z": { "result": [ { "id": "zone-abc" } ] } }
            }),
        );
        state.insert(
            "cloudflare_zero_trust_tunnel_cloudflared".to_string(),
            json!({ "rio": { "id": "tun-1" } }),
        );
        let cfg = json!({
            "account_id": "${data.cloudflare_accounts.a.result[0].id}",
            "zone_id":    "${data.cloudflare_zones.z.result[0].id}",
            "tunnel_id":  "${cloudflare_zero_trust_tunnel_cloudflared.rio.id}",
            "name":       "tunnel-${cloudflare_zero_trust_tunnel_cloudflared.rio.id}-cfg",
            "ingress":    [ { "hostname": "drive.bristol.quero.cloud" } ]
        });
        let resolved = resolve_config(&cfg, &state).unwrap();
        assert_eq!(resolved["account_id"], json!("acct-xyz"));
        assert_eq!(resolved["zone_id"], json!("zone-abc"));
        assert_eq!(resolved["tunnel_id"], json!("tun-1"));
        assert_eq!(resolved["name"], json!("tunnel-tun-1-cfg")); // embedded substitution
        assert_eq!(resolved["ingress"][0]["hostname"], json!("drive.bristol.quero.cloud"));
        // No interpolation must survive anywhere.
        assert!(!resolved.to_string().contains("${"));
    }

    // ── Escape-aware has_interpolation / is_whole_reference / resolve_string
    // (2026-07-23 incident family — see magma-apply::engine's substitute_refs
    // for the full writeup) ─────────────────────────────────────────────

    #[test]
    fn has_interpolation_false_for_pure_escaped_literal() {
        assert!(!has_interpolation("$${{ secrets.BOT_PAT }}"));
        assert!(!has_interpolation("literal %%{if true}yes%%{endif}"));
    }

    #[test]
    fn has_interpolation_true_when_a_real_reference_sits_alongside_an_escape() {
        assert!(has_interpolation(
            "$${{ secrets.BOT_PAT }} and ${github_repository.izumi.id}"
        ));
    }

    #[test]
    fn resolve_string_unescapes_a_whole_string_escaped_literal_with_no_state_lookup() {
        // No `sm` entry that could possibly resolve `{aws_vpc.x.id}` --
        // if this were (wrongly) treated as a reference, this would error.
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let resolved = resolve_string("$${aws_vpc.x.id}", &sm).unwrap();
        assert_eq!(resolved, json!("${aws_vpc.x.id}"));
    }

    #[test]
    fn resolve_string_resolves_a_real_reference_next_to_an_escaped_github_actions_expr() {
        let mut sm: HashMap<String, serde_json::Value> = HashMap::new();
        sm.insert(
            "github_repository".to_string(),
            json!({ "izumi": { "id": "R_kgAizumi" } }),
        );
        let resolved = resolve_string(
            "$${{ secrets.BOT_PAT }} and ${github_repository.izumi.id}",
            &sm,
        )
        .unwrap();
        assert_eq!(resolved, json!("${{ secrets.BOT_PAT }} and R_kgAizumi"));
    }

    #[test]
    fn resolve_config_walks_a_github_repository_file_content_shaped_resource() {
        // The exact shape of the 2026-07-23 incident: a github_repository_file
        // whose `content` carries a real GitHub Actions workflow with a
        // correctly-HCL2-escaped secrets expression. resolve_config must
        // leave it as the correct, single-escaped, valid GHA syntax -- not
        // error, and not leave a stray extra `$`.
        let state: HashMap<String, serde_json::Value> = HashMap::new();
        let cfg = json!({
            "repository": "pangea-consul",
            "file": ".github/workflows/auto-bump.yml",
            "content": "name: auto-bump\njobs:\n  bump:\n    secrets:\n      BOT_PAT: $${{ secrets.BOT_PAT }}\n"
        });
        let resolved = resolve_config(&cfg, &state).unwrap();
        assert_eq!(
            resolved["content"],
            json!("name: auto-bump\njobs:\n  bump:\n    secrets:\n      BOT_PAT: ${{ secrets.BOT_PAT }}\n")
        );
    }

    #[test]
    fn resolve_string_does_not_corrupt_multi_byte_utf8_around_escaped_content() {
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let resolved =
            resolve_string("caf\u{e9} $${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}", &sm).unwrap();
        assert_eq!(resolved, json!("caf\u{e9} ${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}"));
    }
}
