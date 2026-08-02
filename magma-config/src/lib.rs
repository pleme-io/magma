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

use magma_types::{
    DependencyNode, ProviderInstance, ProviderInstanceError, ProviderReference, Resource,
    ResourceAddress, ResourceEdge, ResourceError, ResourceKind, ResourceMeta, ResourceTypeId,
    State,
};
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
    /// A `provider = …` meta-argument magma cannot honour. See
    /// [`magma_types::ProviderInstanceError`] — chiefly an alias, which
    /// magma refuses rather than silently resolving to the default
    /// provider instance.
    #[error("resource `{address}`: {source}")]
    ProviderMeta {
        address: String,
        #[source]
        source: ProviderInstanceError,
    },
    /// A meta-argument magma recognises but does not implement.
    /// Refused, never ignored — see [`split_resource_body`].
    #[error(
        "resource `{address}`: the `{key}` meta-argument is not implemented by magma. \
         {consequence} Refusing rather than applying a configuration whose declared \
         meaning magma cannot honour."
    )]
    UnimplementedMeta {
        address: String,
        key: &'static str,
        consequence: &'static str,
    },
    /// A meta-argument was present but not shaped the way Terraform
    /// defines it (`provider` must be a string, `depends_on` a list of
    /// address strings).
    #[error("resource `{address}`: malformed `{key}` meta-argument: {detail}")]
    MalformedMeta {
        address: String,
        key: &'static str,
        detail: String,
    },
    /// A typed [`Resource`] could not be built from a parsed block, or a
    /// caller handed [`Config::from_resources`] one that was already
    /// invalid.
    #[error(transparent)]
    Resource(#[from] ResourceError),
    /// [`Config::from_resources`] was handed an address the Terraform
    /// JSON container structurally cannot hold — see that method's doc.
    #[error(
        "resource `{address}`: {detail} \
         magma's Terraform JSON container cannot represent it, so accepting it here \
         would silently drop the part it cannot hold. Refusing instead."
    )]
    UnrepresentableAddress { address: String, detail: String },
    /// Two declared resources share one `(kind, type, name)` slot. In the
    /// JSON container the second would overwrite the first with no error.
    #[error(
        "duplicate resource address `{address}`: two declarations occupy one slot. \
         The Terraform JSON container is a map, so one would silently replace the other."
    )]
    DuplicateAddress { address: String },
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

    /// The raw declared body for one address — the managed table for a
    /// managed resource, the `data` table for a data source.
    ///
    /// Public and here rather than private in each consumer: `magma-plan`
    /// carried its own copy (`lookup_config_value`) and so did this
    /// crate's typed door, which is two chances for the kind-to-table
    /// mapping to disagree about where a data source lives.
    #[must_use]
    pub fn resource_body(&self, address: &ResourceAddress) -> Option<serde_json::Value> {
        let table = match address.kind {
            ResourceKind::Data => &self.data,
            _ => &self.resources,
        };
        table
            .get(&address.type_id.0)
            .and_then(|by_name| by_name.get(&address.name))
            .cloned()
    }

    /// Lower this config to typed [`Resource`] nodes — the SECOND door's
    /// currency, produced by the FIRST door.
    ///
    /// This is what makes the two doors one door. [`Config::from_json`]
    /// stays the shipped path and is not touched; this method reads it
    /// and hands back exactly the node type a Rust front end constructs
    /// directly. So there is no "JSON dialect" and "typed dialect" with
    /// their own semantics — there is one node type, and JSON is one way
    /// to arrive at it.
    ///
    /// Meta-arguments are split out per [`split_resource_body`], which
    /// means the same refusals apply: an aliased `provider`, a `count`,
    /// a `lifecycle` all stop here rather than being dropped.
    ///
    /// Order is deterministic — sorted by rendered address — because the
    /// underlying `HashMap` iteration order is not, and a dependency
    /// graph built from an unordered node list has unstable (though
    /// equally correct) wave contents.
    pub fn resources_typed(&self) -> Result<Vec<Resource>, ConfigError> {
        let mut out = Vec::new();
        for address in self.resource_addresses() {
            let label = address.to_string();
            let body = self.resource_body(&address);
            let (meta, attrs) = match body {
                Some(b) => split_resource_body(&label, &b)?,
                None => (ResourceMeta::default(), serde_json::Value::Null),
            };
            out.push(Resource::new(address, attrs)?.with_meta(meta));
        }
        out.sort_by_key(|r| r.address.to_string());
        Ok(out)
    }

    /// Raise typed [`Resource`] nodes into a `Config` — the second door.
    ///
    /// A front end in another dialect builds `Resource` values in Rust
    /// and gets a `Config` it can hand to `magma_plan::plan`, with no
    /// Terraform JSON text authored, parsed or emitted anywhere.
    ///
    /// **Fidelity is guaranteed by refusal, not by hope.** The container
    /// this fills is Terraform-JSON-shaped: `{type → {name → body}}`. It
    /// has nowhere to put a module path, an instance key, or a kind other
    /// than managed/data, and the `depends_on` strings it holds are
    /// re-parsed by [`split_resource_body`] on the way back out. So every
    /// address — the resource's own and each of its dependencies — is
    /// checked against what the container can actually hold, and anything
    /// it cannot is refused here. The round trip
    /// `from_resources(rs)?.resources_typed()? == rs` therefore holds for
    /// every input this accepts, which is the property a front end needs
    /// and the one a silent truncation would break.
    ///
    /// These refusals are magma's *documented* bounds surfacing at the
    /// boundary, not new limits: magma does not expand modules and does
    /// not implement `count`/`for_each` (so no instance keys), per
    /// `theory/MAGMA.md` §IX.
    pub fn from_resources(
        resources: impl IntoIterator<Item = Resource>,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        for r in resources {
            let slot = container_slot(&r.address)?;
            for dep in &r.meta.depends_on {
                // A dependency address survives only as a string that
                // `parse_depends_on_entry` must be able to read back.
                container_slot(dep)?;
            }
            let body = meta_into_body(&r)?;
            let by_name = match slot.0 {
                ResourceKind::Data => &mut config.data,
                _ => &mut config.resources,
            }
            .entry(slot.1)
            .or_default();
            if by_name.insert(slot.2, body).is_some() {
                return Err(ConfigError::DuplicateAddress {
                    address: r.address.to_string(),
                });
            }
        }
        Ok(config)
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

// ── Resource meta-arguments ─────────────────────────────────────────

/// The meta-argument catalog is CLOSED and lives on
/// [`magma_types::ResourceMeta`], not here. Two doors now enforce it —
/// this one (Terraform JSON) and `magma_types::Resource::new` (a Rust
/// front end) — and a second copy of the list is exactly how a key ends
/// up closed on one door and open on the other.
use magma_types::ResourceMeta as MetaCatalog;

/// Split a rendered resource block into its typed meta-arguments and the
/// provider attributes that remain.
///
/// **This is the boundary the two silently-wrong defects lived on.** A
/// resource block is one flat JSON object in which meta-arguments and
/// provider attributes are indistinguishable by shape. Downstream, both
/// were treated as attributes — and `magma_cty::from_json` walks the
/// provider SCHEMA rather than the JSON, so every meta-argument was
/// dropped on the floor with no error while still counting as
/// config-declared drift. `provider = "aws.us_east_2"` therefore applied
/// to the default account, and `depends_on` never became a graph edge.
///
/// The meta-argument set is **closed**: every key in it is removed from
/// the attributes here, so no meta-argument can reach a provider or a
/// drift comparison, whether or not magma implements its behaviour. The
/// two magma implements come back typed in [`ResourceMeta`]; the rest
/// are refused ([`ConfigError::UnimplementedMeta`]) because each is
/// silently wrong when ignored — "unsupported" and "quietly does
/// something else" are not the same failure, and only the first is
/// acceptable.
///
/// `address` is used only to name the resource in errors.
///
/// A block that is not a JSON object is returned unchanged with empty
/// meta — that shape is already handled (loudly) downstream and is not
/// this function's to reinterpret.
pub fn split_resource_body(
    address: &str,
    body: &serde_json::Value,
) -> Result<(ResourceMeta, serde_json::Value), ConfigError> {
    let Some(obj) = body.as_object() else {
        return Ok((ResourceMeta::default(), body.clone()));
    };

    let mut meta = ResourceMeta::default();
    let mut attrs = serde_json::Map::new();

    for (key, value) in obj {
        if let Some((k, consequence)) = MetaCatalog::UNIMPLEMENTED.iter().find(|(k, _)| k == key) {
            return Err(ConfigError::UnimplementedMeta {
                address: address.to_string(),
                key: k,
                consequence,
            });
        }
        match key.as_str() {
            "provider" => {
                let s = value.as_str().ok_or_else(|| ConfigError::MalformedMeta {
                    address: address.to_string(),
                    key: "provider",
                    detail: format!("expected a string, got {value}"),
                })?;
                meta.provider =
                    Some(ProviderInstance::try_from(s.to_string()).map_err(|source| {
                        ConfigError::ProviderMeta {
                            address: address.to_string(),
                            source,
                        }
                    })?);
            }
            "depends_on" => {
                let list = value.as_array().ok_or_else(|| ConfigError::MalformedMeta {
                    address: address.to_string(),
                    key: "depends_on",
                    detail: format!("expected a list of address strings, got {value}"),
                })?;
                for entry in list {
                    let s = entry.as_str().ok_or_else(|| ConfigError::MalformedMeta {
                        address: address.to_string(),
                        key: "depends_on",
                        detail: format!("expected an address string, got {entry}"),
                    })?;
                    meta.depends_on.push(parse_depends_on_entry(address, s)?);
                }
            }
            _ => {
                attrs.insert(key.clone(), value.clone());
            }
        }
    }

    debug_assert!(
        MetaCatalog::IMPLEMENTED
            .iter()
            .all(|k| !attrs.contains_key(*k)),
        "an implemented meta-argument leaked into the attributes",
    );
    Ok((meta, serde_json::Value::Object(attrs)))
}

/// Parse one `depends_on` entry — `aws_iam_role.x`, `data.aws_vpc.y`,
/// optionally index-suffixed — into a typed [`ResourceAddress`].
///
/// `module.<name>` is refused. magma does not expand module blocks
/// (`magma_config::Config::modules` is untyped JSON kept for graph and
/// output tracking only), so a module dependency has nothing to order
/// against; accepting it would drop the edge and reproduce the exact
/// defect this function exists to fix.
fn parse_depends_on_entry(address: &str, entry: &str) -> Result<ResourceAddress, ConfigError> {
    let malformed = |detail: String| ConfigError::MalformedMeta {
        address: address.to_string(),
        key: "depends_on",
        detail,
    };
    if entry.starts_with("module.") {
        return Err(malformed(format!(
            "`{entry}` depends on a module; magma does not expand module blocks, so this \
             ordering cannot be honoured — depend on the concrete resources instead"
        )));
    }
    let (kind, rest) = match entry.strip_prefix("data.") {
        Some(rest) => (ResourceKind::Data, rest),
        None => (ResourceKind::Managed, entry),
    };
    let mut segs = rest.split('.');
    let (Some(type_id), Some(name), None) = (segs.next(), segs.next(), segs.next()) else {
        return Err(malformed(format!(
            "`{entry}` is not a `[data.]<type>.<name>` resource address"
        )));
    };
    // `aws_instance.web[0]` targets the resource, matching how the
    // interpolation-derived edges in `magma_apply` key on `(type, name)`.
    let name = name.split('[').next().unwrap_or(name);
    if type_id.is_empty() || name.is_empty() {
        return Err(malformed(format!(
            "`{entry}` is not a `[data.]<type>.<name>` resource address"
        )));
    }
    Ok(ResourceAddress {
        module: Default::default(),
        kind,
        type_id: ResourceTypeId(type_id.to_string()),
        name: name.to_string(),
        key: None,
    })
}

/// The `(kind, type, name)` slot a `ResourceAddress` occupies in the
/// Terraform JSON container, or a refusal naming the part the container
/// cannot hold. See [`Config::from_resources`].
fn container_slot(
    address: &ResourceAddress,
) -> Result<(ResourceKind, String, String), ConfigError> {
    let refuse = |detail: &str| ConfigError::UnrepresentableAddress {
        address: address.to_string(),
        detail: detail.to_string(),
    };
    if !address.module.is_root() {
        return Err(refuse(
            "it is scoped to a module, and magma does not expand module blocks, so there is \
             no slot for it and no ordering to honour.",
        ));
    }
    if address.key.is_some() {
        return Err(refuse(
            "it carries an instance key, which only `count`/`for_each` produce — and magma \
             implements neither.",
        ));
    }
    match address.kind {
        ResourceKind::Managed | ResourceKind::Data => Ok((
            address.kind,
            address.type_id.0.clone(),
            address.name.clone(),
        )),
        other => Err(refuse(&{
            let mut s = String::from("it is a `");
            s.push_str(&other.to_string());
            s.push_str("`, and only managed resources and data sources have a resource slot.");
            s
        })),
    }
}

/// Fold a [`Resource`]'s typed meta back into one Terraform-JSON body,
/// so [`split_resource_body`] reads back exactly the meta it went in
/// with.
///
/// Every emitted value is a constructed `serde_json::Value` and every
/// address is rendered by [`ResourceAddress`]'s own `Display` — the two
/// sanctioned typed-emission surfaces. No syntax is `format!`ed.
fn meta_into_body(r: &Resource) -> Result<serde_json::Value, ConfigError> {
    if r.meta.is_empty() {
        return Ok(r.attributes().clone());
    }
    let serde_json::Value::Object(attrs) = r.attributes() else {
        return Err(ConfigError::Malformed(format!(
            "resource `{}` declares meta-arguments but its attributes are not a JSON object \
             ({}), so there is no block to carry them",
            r.address,
            kind_of(r.attributes()),
        )));
    };
    let mut body = attrs.clone();
    if let Some(p) = &r.meta.provider {
        body.insert(
            "provider".to_string(),
            serde_json::Value::String(p.name().to_string()),
        );
    }
    if !r.meta.depends_on.is_empty() {
        body.insert(
            "depends_on".to_string(),
            serde_json::Value::Array(
                r.meta
                    .depends_on
                    .iter()
                    .map(|d| serde_json::Value::String(d.to_string()))
                    .collect(),
            ),
        );
    }
    Ok(serde_json::Value::Object(body))
}

/// The JSON kind of a value, for a message that says what was found.
fn kind_of(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

// ── Dependency edges ────────────────────────────────────────────────

/// Derive the dependency edges among a set of nodes — the ONE
/// derivation, with both edge sources.
///
/// * **Interpolation** — a literal `${type.name.attr}` anywhere in the
///   node's body. This was for a long time the only source, and it is
///   why the missing one was invisible: the overwhelming majority of
///   real ordering IS expressed as a reference, so ordering appeared to
///   work.
/// * **`depends_on`** — ordering the author declared explicitly. The
///   meta-argument exists *precisely because* there is no interpolation
///   to infer the edge from — an author with a reference does not need
///   it — so the one case the interpolation scan structurally cannot see
///   is exactly the case it covers.
///
/// An edge is emitted only when its target is itself among `nodes`. A
/// dependency that is absent, already applied, or unchanged needs no
/// ordering: it is not being touched, so nothing can race it. A
/// self-edge is dropped.
///
/// Nodes are matched on `(type, name)`, deliberately ignoring kind and
/// module — the same key the interpolation grammar itself carries, since
/// `${aws_vpc.main.id}` names no kind and no module.
///
/// Edge order is the caller's node order, then interpolation edges in
/// body-walk order, then declared edges in declaration order. Callers
/// feed these straight into a graph, where duplicate edges are
/// significant to in-degree, so the order and the multiplicity are part
/// of the contract, not an accident.
#[must_use]
pub fn dependency_edges(nodes: &[DependencyNode<'_>]) -> Vec<ResourceEdge> {
    let by_key: HashMap<(&str, &str), &ResourceAddress> = nodes
        .iter()
        .map(|n| {
            (
                (n.address.type_id.0.as_str(), n.address.name.as_str()),
                n.address,
            )
        })
        .collect();

    let mut edges = Vec::new();
    for n in nodes {
        let self_key = (n.address.type_id.0.as_str(), n.address.name.as_str());
        let link = |dep_key: (&str, &str), edges: &mut Vec<ResourceEdge>| {
            if dep_key == self_key {
                return;
            }
            if let Some(dep) = by_key.get(&dep_key) {
                edges.push(ResourceEdge {
                    dependent: n.address.clone(),
                    dependency: (*dep).clone(),
                });
            }
        };
        if let Some(body) = n.body {
            for refstr in collect_refs(body) {
                if let Some((ty, name)) = ref_target(&refstr) {
                    link((ty.as_str(), name.as_str()), &mut edges);
                }
            }
        }
        for dep in n.depends_on {
            link((dep.type_id.0.as_str(), dep.name.as_str()), &mut edges);
        }
    }
    edges
}

// ── Interpolation reference extraction ──────────────────────────────
//
// Lives here, with the rest of the `${…}` family (`resolve_reference`,
// `resolve_config`, `has_interpolation`), and NOT in magma-apply where
// it grew. Edge derivation is now needed at config time by a front end
// that has no plan yet and no reason to depend on the apply engine; a
// second copy of an escape-aware scanner is how the 2026-07-23 escape
// incident managed to need fixing in three places.

/// Collect every `${…}` reference path (inner, no wrapper) found
/// anywhere in a config value.
///
/// Escape-aware: HCL2's own escaping convention doubles `$`/`%` before a
/// `{` (`$${`/`%%{`) to mean a literal `${`/`%{` that must NEVER be
/// treated as interpolation. A naive `s.find("${")` misreads a correctly
/// escaped value — e.g. `github_repository_file.content` carrying a
/// GitHub Actions `$${{ secrets.BOT_PAT }}` — as a real reference,
/// extracting the malformed path `{ secrets.BOT_PAT ` (the stray leading
/// brace is the leftover second `{` of the double-brace `${{ }}` GitHub
/// Actions syntax).
#[must_use]
pub fn collect_refs(v: &serde_json::Value) -> Vec<String> {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => scan_refs(s, out),
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

/// Byte-indexed, escape-aware `${…}` reference scan behind
/// [`collect_refs`]. Walks `s` left to right; at each position prefers
/// the 3-byte escape match (`$${`/`%%{`, consumed whole, never
/// re-examined — this is what stops the trailing brace of an escaped
/// `${{` from being mistaken for a fresh opener) over the 2-byte
/// reference-open match (`${`). Slicing only ever happens immediately
/// before/after one of `$`/`%`/`{`/`}` — all single-byte ASCII, so every
/// slice point is a guaranteed UTF-8 char boundary regardless of what
/// non-ASCII content surrounds it.
fn scan_refs(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 2 < bytes.len()
            && (bytes[i] == b'$' || bytes[i] == b'%')
            && bytes[i + 1] == bytes[i]
            && bytes[i + 2] == b'{'
        {
            i += 3;
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let after = &s[i + 2..];
            if let Some(end) = after.find('}') {
                out.push(after[..end].trim().to_string());
                i += 2 + end + 1;
                continue;
            }
            break;
        }
        i += 1;
    }
}

/// The `(type, name)` a reference path targets —
/// `github_repository.galho.node_id` → `("github_repository", "galho")`.
/// Returns `None` for `data.*` sources (resolved from existing state,
/// not ordered as apply dependencies) or malformed paths. Strips any
/// `[index]` from the name segment.
#[must_use]
pub fn ref_target(inner: &str) -> Option<(String, String)> {
    let segs: Vec<&str> = inner.split('.').collect();
    if segs.first() == Some(&"data") {
        return None;
    }
    if segs.len() >= 2 {
        let name = segs[1].split('[').next().unwrap_or(segs[1]);
        return Some((segs[0].to_string(), name.to_string()));
    }
    None
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
            let idx = rest
                .strip_suffix(']')
                .and_then(|n| n.trim().parse::<usize>().ok());
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
        if i + 2 < bytes.len()
            && (bytes[i] == b'$' || bytes[i] == b'%')
            && bytes[i + 1] == bytes[i]
            && bytes[i + 2] == b'{'
        {
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

    // ── Meta-argument split ────────────────────────────────────────
    //
    // Both defects this split fixes were SILENT. `magma_cty::from_json`
    // builds a value by walking the provider SCHEMA, so a meta-argument
    // left among the attributes is dropped with no error at all — and
    // meanwhile it still counts as a config-declared key for drift.
    // Nothing anywhere reported a problem.

    #[test]
    fn a_declared_provider_is_carried_as_meta_not_handed_to_the_provider() {
        let (meta, attrs) = split_resource_body(
            "aws_instance.web",
            &json!({ "provider": "aws", "ami": "ami-123" }),
        )
        .expect("a bare provider name is honourable");
        assert_eq!(
            meta.provider.as_ref().map(ProviderInstance::name),
            Some("aws")
        );
        // The attribute map handed to the provider must not contain it.
        assert_eq!(attrs, json!({ "ami": "ami-123" }));
    }

    /// THE wrong-account defect. Until this split existed, this body
    /// produced attributes still containing `provider`, which the cty
    /// encoder dropped — and the resource was applied through the
    /// default `aws` provider with no error at any layer.
    #[test]
    fn a_resource_pinned_to_an_aliased_provider_is_refused_not_silently_defaulted() {
        let err = split_resource_body(
            "aws_instance.web",
            &json!({ "provider": "aws.us_east_2", "ami": "ami-123" }),
        )
        .expect_err("magma cannot dial an aliased provider, so it must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("aws_instance.web"),
            "must name the resource: {msg}"
        );
        assert!(
            matches!(err, ConfigError::ProviderMeta { .. }),
            "must be the typed provider-meta refusal, got: {err}"
        );
    }

    #[test]
    fn a_declared_depends_on_becomes_typed_addresses_and_leaves_the_attributes() {
        let (meta, attrs) = split_resource_body(
            "aws_instance.web",
            &json!({
                "depends_on": ["aws_iam_role.exec", "data.aws_vpc.main", "aws_subnet.a[0]"],
                "ami": "ami-123",
            }),
        )
        .expect("depends_on is implemented");
        let got: Vec<String> = meta.depends_on.iter().map(ToString::to_string).collect();
        assert_eq!(
            got,
            vec!["aws_iam_role.exec", "data.aws_vpc.main", "aws_subnet.a"],
            "an index suffix targets the resource, matching how interpolation edges key",
        );
        assert_eq!(attrs, json!({ "ami": "ami-123" }));
    }

    #[test]
    fn a_depends_on_naming_a_module_is_refused_because_magma_cannot_order_against_one() {
        let err = split_resource_body(
            "aws_instance.web",
            &json!({ "depends_on": ["module.networking"] }),
        )
        .expect_err("magma does not expand modules, so it cannot honour the ordering");
        assert!(err.to_string().contains("module"), "got: {err}");
    }

    #[test]
    fn a_malformed_depends_on_is_refused_rather_than_ignored() {
        for body in [
            json!({ "depends_on": "aws_iam_role.exec" }), // not a list
            json!({ "depends_on": [42] }),                // not a string
            json!({ "depends_on": ["not_an_address"] }),  // no `.name`
            json!({ "depends_on": ["a.b.c"] }),           // too many segments
        ] {
            assert!(
                split_resource_body("aws_instance.web", &body).is_err(),
                "a depends_on magma cannot parse must never be silently dropped: {body}"
            );
        }
    }

    /// Every meta-argument leaves the attributes, whether or not magma
    /// implements it — that is what makes the two populations
    /// structurally distinct rather than distinguished case by case.
    /// The ones magma does NOT implement are refused, because each is
    /// silently wrong when ignored (a dropped `count` builds one
    /// resource where N were declared; a dropped `lifecycle` can
    /// destroy a `prevent_destroy` resource).
    #[test]
    fn a_recognised_but_unimplemented_meta_argument_is_refused_never_ignored() {
        for key in [
            "count",
            "for_each",
            "lifecycle",
            "provisioner",
            "connection",
        ] {
            let body = json!({ key: json!({}), "ami": "ami-123" });
            let Err(err) = split_resource_body("aws_instance.web", &body) else {
                panic!("`{key}` must be refused, not silently dropped from the attributes");
            };
            assert!(
                matches!(err, ConfigError::UnimplementedMeta { key: k, .. } if k == key),
                "`{key}` must be the typed unimplemented-meta refusal, got: {err}"
            );
            // The message must state what ignoring it would have done.
            assert!(
                err.to_string().contains("Ignoring it would"),
                "the refusal must name the consequence, got: {err}"
            );
        }
    }

    #[test]
    fn a_block_with_no_meta_arguments_passes_through_untouched() {
        let body = json!({ "ami": "ami-123", "tags": { "Name": "web" } });
        let (meta, attrs) =
            split_resource_body("aws_instance.web", &body).expect("no meta, no refusal");
        assert!(meta.is_empty());
        assert_eq!(attrs, body);
    }

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
            resolve_reference(
                "${data.cloudflare_zones.rio_drive_zone.result[0].id}",
                &state
            )
            .unwrap(),
            json!("zone-abc"),
        );
        assert_eq!(
            resolve_reference(
                "${data.cloudflare_accounts.rio_drive_account.result[0].id}",
                &state
            )
            .unwrap(),
            json!("acct-xyz"),
        );
    }

    #[test]
    fn resolve_index_out_of_bounds_errs() {
        let mut state = HashMap::new();
        state.insert(
            "data".to_string(),
            json!({ "x": { "y": { "result": [] } } }),
        );
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
            resolve_reference("${cloudflare_zero_trust_tunnel_cloudflared.rio.id}", &state)
                .unwrap(),
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
        assert_eq!(
            resolved["ingress"][0]["hostname"],
            json!("drive.bristol.quero.cloud")
        );
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
            json!(
                "name: auto-bump\njobs:\n  bump:\n    secrets:\n      BOT_PAT: ${{ secrets.BOT_PAT }}\n"
            )
        );
    }

    #[test]
    fn resolve_string_does_not_corrupt_multi_byte_utf8_around_escaped_content() {
        let sm: HashMap<String, serde_json::Value> = HashMap::new();
        let resolved =
            resolve_string("caf\u{e9} $${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}", &sm).unwrap();
        assert_eq!(
            resolved,
            json!("caf\u{e9} ${{ secrets.BOT_PAT }} \u{2764}\u{fe0f}")
        );
    }

    // ── The typed door ─────────────────────────────────────────────
    //
    // `Config::from_json` is the shipped path for every current consumer
    // (the CLI, the tlisp/lava path, magma-pangea). Everything below is a
    // SECOND door onto the same machine, so the tests come in pairs: what
    // the typed door does, and proof the JSON door is unchanged by it.

    use magma_types::{InstanceKey, ModulePath};

    fn managed(type_id: &str, name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind: ResourceKind::Managed,
            type_id: ResourceTypeId(type_id.to_string()),
            name: name.to_string(),
            key: None,
        }
    }

    /// The JSON door is READ, never rewritten: `resources_typed` is a
    /// projection. If it ever became a mutation, the raw map would lose
    /// the meta keys — and every existing consumer reads that raw map.
    #[test]
    fn lowering_to_typed_nodes_leaves_the_raw_json_container_byte_identical() {
        let raw = json!({
            "resource": {
                "aws_instance": {
                    "web": {
                        "ami": "ami-1",
                        "provider": "aws",
                        "depends_on": ["aws_iam_role.exec"]
                    }
                },
                "aws_iam_role": { "exec": { "name": "exec" } }
            }
        });
        let config = Config::from_json(raw.clone()).expect("parses");
        let before = serde_json::to_value(&config.resources).expect("serializes");

        let typed = config.resources_typed().expect("lowers");
        assert_eq!(typed.len(), 2);

        let after = serde_json::to_value(&config.resources).expect("serializes");
        assert_eq!(
            before, after,
            "resources_typed must be a read, not a rewrite"
        );
        // And the meta keys are still IN the raw block, exactly where
        // every existing consumer expects them.
        assert_eq!(
            config.resources["aws_instance"]["web"]["provider"],
            json!("aws")
        );
    }

    #[test]
    fn the_json_door_produces_typed_provider_and_depends_on() {
        let config = Config::from_json(json!({
            "resource": {
                "aws_instance": {
                    "web": {
                        "ami": "ami-1",
                        "provider": "aws",
                        "depends_on": ["aws_iam_role.exec"]
                    }
                }
            }
        }))
        .expect("parses");

        let typed = config.resources_typed().expect("lowers");
        let web = typed
            .iter()
            .find(|r| r.address == managed("aws_instance", "web"))
            .expect("present");
        assert_eq!(
            web.meta.provider.as_ref().map(ProviderInstance::name),
            Some("aws")
        );
        assert_eq!(web.meta.depends_on, vec![managed("aws_iam_role", "exec")]);
        // The meta keys are GONE from the attributes — that is the
        // invariant `Resource` holds structurally.
        assert_eq!(*web.attributes(), json!({ "ami": "ami-1" }));
    }

    /// The property a front end needs: what it declares is what magma
    /// plans. Anything the JSON container could not hold faithfully is
    /// refused by `from_resources`, so this round trip has no lossy
    /// inputs to fail on.
    #[test]
    fn typed_resources_round_trip_through_the_json_container_unchanged() {
        let mut declared = vec![
            Resource::new(managed("aws_iam_role", "exec"), json!({ "name": "exec" }))
                .expect("valid"),
            Resource::new(managed("aws_instance", "web"), json!({ "ami": "ami-1" }))
                .expect("valid")
                .with_provider(ProviderInstance::try_from("aws".to_string()).expect("bare"))
                .depending_on([managed("aws_iam_role", "exec")]),
            Resource::new(
                ResourceAddress {
                    kind: ResourceKind::Data,
                    ..managed("aws_ami", "latest")
                },
                json!({ "most_recent": true }),
            )
            .expect("valid"),
        ];
        declared.sort_by_key(|r| r.address.to_string());

        let config = Config::from_resources(declared.clone()).expect("representable");
        let back = config.resources_typed().expect("lowers");
        assert_eq!(back, declared);
    }

    /// The declared-only edge — the case interpolation structurally
    /// cannot see, because an author with a reference does not write
    /// `depends_on` at all.
    #[test]
    fn a_declared_dependency_becomes_an_edge_with_no_interpolation_anywhere() {
        let role = Resource::new(managed("aws_iam_role", "exec"), json!({ "name": "exec" }))
            .expect("valid");
        let web = Resource::new(managed("aws_instance", "web"), json!({ "ami": "ami-1" }))
            .expect("valid")
            .depending_on([managed("aws_iam_role", "exec")]);
        let nodes = [role.dependency_node(), web.dependency_node()];

        assert_eq!(
            dependency_edges(&nodes),
            vec![ResourceEdge {
                dependent: managed("aws_instance", "web"),
                dependency: managed("aws_iam_role", "exec"),
            }]
        );
    }

    #[test]
    fn an_interpolated_reference_still_becomes_an_edge() {
        let vpc = Resource::new(managed("aws_vpc", "main"), json!({ "cidr": "10.0.0.0/16" }))
            .expect("valid");
        let sub = Resource::new(
            managed("aws_subnet", "a"),
            json!({ "vpc_id": "${aws_vpc.main.id}" }),
        )
        .expect("valid");
        let nodes = [vpc.dependency_node(), sub.dependency_node()];

        assert_eq!(
            dependency_edges(&nodes),
            vec![ResourceEdge {
                dependent: managed("aws_subnet", "a"),
                dependency: managed("aws_vpc", "main"),
            }]
        );
    }

    #[test]
    fn an_edge_to_a_node_that_is_not_present_is_not_emitted() {
        let web = Resource::new(managed("aws_instance", "web"), json!({ "ami": "ami-1" }))
            .expect("valid")
            .depending_on([managed("aws_iam_role", "absent")]);
        assert_eq!(dependency_edges(&[web.dependency_node()]), vec![]);
    }

    // ── What the container cannot hold is REFUSED, never truncated ──

    #[test]
    fn a_module_scoped_resource_is_refused_rather_than_flattened_into_the_root() {
        let addr = ResourceAddress {
            module: ModulePath(vec!["net".to_string()]),
            ..managed("aws_vpc", "main")
        };
        let err = Config::from_resources([Resource::new(addr, json!({})).expect("valid")])
            .expect_err("a module-scoped address has no slot");
        assert!(
            matches!(err, ConfigError::UnrepresentableAddress { ref detail, .. }
                if detail.contains("module")),
            "expected a module refusal naming the reason, got: {err}"
        );
    }

    #[test]
    fn an_instance_keyed_resource_is_refused_because_magma_implements_no_count() {
        let addr = ResourceAddress {
            key: Some(InstanceKey::Index(0)),
            ..managed("aws_vpc", "main")
        };
        let err = Config::from_resources([Resource::new(addr, json!({})).expect("valid")])
            .expect_err("an instance key has no slot");
        assert!(
            matches!(err, ConfigError::UnrepresentableAddress { ref detail, .. }
                if detail.contains("count")),
            "expected an instance-key refusal, got: {err}"
        );
    }

    /// A dependency address is stored as a STRING and re-parsed on the
    /// way back out. `parse_depends_on_entry` refuses `module.…`, so
    /// accepting one here would drop the edge — the exact defect the
    /// declared-edge source exists to fix.
    #[test]
    fn a_module_scoped_dependency_is_refused_rather_than_silently_dropped() {
        let dep = ResourceAddress {
            module: ModulePath(vec!["net".to_string()]),
            ..managed("aws_vpc", "main")
        };
        let web = Resource::new(managed("aws_instance", "web"), json!({}))
            .expect("valid")
            .depending_on([dep]);
        let err = Config::from_resources([web]).expect_err("a module dependency cannot round-trip");
        assert!(matches!(err, ConfigError::UnrepresentableAddress { .. }));
    }

    #[test]
    fn two_resources_in_one_slot_are_refused_rather_than_one_overwriting_the_other() {
        let a = Resource::new(managed("aws_vpc", "main"), json!({ "cidr": "10.0.0.0/16" }))
            .expect("valid");
        let b = Resource::new(managed("aws_vpc", "main"), json!({ "cidr": "10.1.0.0/16" }))
            .expect("valid");
        let err = Config::from_resources([a, b]).expect_err("one slot, two declarations");
        assert!(matches!(err, ConfigError::DuplicateAddress { .. }), "{err}");
    }

    /// The unimplemented-meta refusal reaches the typed door too — it is
    /// the same closed catalog, enforced at both boundaries.
    #[test]
    fn the_typed_door_refuses_an_unimplemented_meta_argument_at_construction() {
        let err = Resource::new(managed("aws_instance", "web"), json!({ "count": 3 }))
            .expect_err("count is a meta-argument magma does not implement");
        assert!(
            matches!(err, ResourceError::MetaArgumentInAttributes { ref key, .. } if key == "count"),
            "{err}"
        );
    }
}
