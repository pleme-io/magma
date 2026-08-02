//! magma-types::reference — the typed reference value, its ONE renderer,
//! and the `${…}` recognizer that reads that rendering back.
//!
//! [`Resource`](crate::Resource) made a resource's *structure* typed:
//! address, provider routing and declared ordering stopped being strings
//! inside an untyped body. Its values did not follow. `vpc_id = <the id of
//! that vpc>` still had to be authored as the literal
//! `"${aws_vpc.main.id}"`, so the last thing a front end in another
//! dialect had to know how to spell was Terraform interpolation syntax —
//! and a typo in that spelling was a **silently missing dependency edge**,
//! which is an apply-order bug, not a parse error.
//!
//! [`Ref`] closes that. A reference is a typed value over a real
//! [`ResourceAddress`] and a typed attribute path, and exactly one surface
//! turns it into text: [`Ref::write_path`], reached through
//! `Display` (`${aws_vpc.main.id}`) and [`Ref::path`]
//! (`aws_vpc.main.id`). Per ★★ TYPED EMISSION there is no `format!()` of
//! Terraform syntax anywhere — the renderer is a `Display`-family
//! `write!()`, one of the three sanctioned emission surfaces.
//!
//! **The recognizer lives here too, and that is the point.**
//! [`collect_refs`] / [`ref_target`] are the inverse of the renderer: they
//! read `${…}` back out of a JSON body. They were in `magma-apply`, then
//! moved to `magma-config` beside the rest of the interpolation family.
//! They belong *here* now, because a renderer and its recognizer only mean
//! anything relative to each other — the property this module exists to
//! guarantee is that every constructible [`Ref`] renders to text the
//! scanner reads back as the same target. Keeping them in two crates would
//! make that property untestable in one place, which is how a round trip
//! quietly stops holding. `magma_config` re-exports both, so every
//! existing consumer path is unchanged.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ResourceAddress, ResourceKind};

// ── Attribute path ─────────────────────────────────────────────────

/// One step of a reference's attribute path — `.id`, or `[0]`.
///
/// Typed rather than a `String` because an index is *syntax*: `result[0]`
/// spelled as a path segment is a string carrying brackets, i.e. exactly
/// the text authoring this module exists to remove. As a step it renders
/// through the same writer as everything else.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttrStep {
    /// A named attribute — `.id`.
    Field(String),
    /// An element of a list attribute — `[0]`.
    Index(u64),
}

impl From<&str> for AttrStep {
    fn from(s: &str) -> Self {
        Self::Field(s.to_string())
    }
}

impl From<String> for AttrStep {
    fn from(s: String) -> Self {
        Self::Field(s)
    }
}

impl From<u64> for AttrStep {
    fn from(i: u64) -> Self {
        Self::Index(i)
    }
}

// ── The typed reference ────────────────────────────────────────────

/// Why a [`Ref`] could not be constructed.
///
/// Every variant is a shape whose *rendering* magma could not read back
/// as the reference it started as — so refusing here is what makes the
/// round trip a property of the type rather than a hope about its inputs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RefError {
    #[error(
        "reference target `{address}` is scoped to a module. The interpolation grammar has \
         no way to name a resource inside a module (`module.x.y` names a module OUTPUT), and \
         magma does not expand module blocks at all — so this reference would render to text \
         that resolves to nothing and orders against nothing."
    )]
    ModuleScoped { address: String },
    #[error(
        "reference target `{address}` carries an instance key. Only `count`/`for_each` \
         produce one and magma implements neither, so there is no keyed instance to \
         reference — see `theory/MAGMA.md` §IX."
    )]
    InstanceKeyed { address: String },
    #[error(
        "reference target `{address}` is a `{kind}`. Only managed resources and data sources \
         are referenceable: magma refuses `variable` and `locals` blocks outright, and an \
         `output` is not addressable from inside the configuration that declares it."
    )]
    NotAResource { address: String, kind: String },
    #[error(
        "reference target `{address}` has a {part} that is not an identifier (`{value}`). \
         A `.`, a bracket or a brace inside it would end the reference early when the \
         rendered `${{…}}` is read back, so the reference would silently name something else."
    )]
    MalformedTarget {
        address: String,
        part: &'static str,
        value: String,
    },
    #[error(
        "reference `{address}`: an attribute path cannot START with an index. `[0]` indexes \
         the step before it, and the step before the first one is the resource itself — an \
         instance key, which magma does not implement."
    )]
    LeadingIndex { address: String },
    #[error(
        "reference `{address}`: attribute path step `{field}` is not an identifier. A `.`, a \
         bracket or a brace inside a step would change where the rendered reference ends, so \
         the reference would name a different attribute than the one authored."
    )]
    MalformedField { address: String, field: String },
}

/// Serialization shadow for [`Ref`], so a persisted reference is
/// re-validated on the way back in. Same reason
/// [`ProviderInstance`](crate::ProviderInstance) takes this shape: plans
/// and declarations are written and re-read across reconcile cycles, so
/// deserialize is a real boundary, not a theoretical one.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefRepr {
    target: ResourceAddress,
    #[serde(default)]
    attr_path: Vec<AttrStep>,
}

/// A reference to another resource's attribute, as a typed value.
///
/// This is the value form of `${aws_vpc.main.id}`. It carries the
/// [`ResourceAddress`] it targets — the same typed identity the declared
/// resource carries, not a re-spelling of it — plus the attribute path
/// within that resource.
///
/// **What this buys, precisely.** A dependency edge derived from a
/// `Ref` is read off the value; an edge derived from a string is
/// recovered by scanning the body for `${…}`, parsing what is inside, and
/// hoping the author spelled the target the same way the target spells
/// itself. The failure modes are not comparable: a mistyped string is a
/// missing edge and therefore an apply-order bug that surfaces as a
/// provider error much later, while a `Ref` cannot be built without an
/// address value in hand, and one naming a resource this configuration
/// does not declare is refused by
/// [`Config::from_resources`](../../magma_config/struct.Config.html#method.from_resources)
/// with both ends named.
///
/// **Tier-honest.** The *state* of a `Ref` whose rendering the scanner
/// would misread is unrepresentable — the fields are private and
/// [`Ref::new`] is the only constructor, deserialize included. The
/// *value* is rejected at that boundary (a `Result::Err`), which is
/// parse-time-rejected, not truly-unrepresentable. And a `Ref` to a
/// well-formed address that simply is not declared anywhere is caught one
/// level up, at the config boundary — also parse-time-rejected. What is
/// *not* claimed: nothing here makes a wrong-but-well-formed address
/// unconstructible in isolation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "RefRepr", try_from = "RefRepr")]
pub struct Ref {
    /// Private: see the type doc — [`Ref::new`] is the only way in.
    target: ResourceAddress,
    attr_path: Vec<AttrStep>,
}

impl Ref {
    /// Reference `target`'s attribute at `path`.
    ///
    /// ```
    /// # use magma_types::{ModulePath, Ref, ResourceAddress, ResourceKind, ResourceTypeId};
    /// let vpc = ResourceAddress {
    ///     module: ModulePath::root(),
    ///     kind: ResourceKind::Managed,
    ///     type_id: ResourceTypeId("aws_vpc".into()),
    ///     name: "main".into(),
    ///     key: None,
    /// };
    /// let r = Ref::new(vpc, ["id"]).expect("referenceable");
    /// assert_eq!(r.to_string(), "${aws_vpc.main.id}");
    /// ```
    ///
    /// An empty path is allowed: `${aws_vpc.main}` references the whole
    /// resource object, which Terraform permits and which orders exactly
    /// the same way.
    pub fn new(
        target: ResourceAddress,
        path: impl IntoIterator<Item = impl Into<AttrStep>>,
    ) -> Result<Self, RefError> {
        let address = target.to_string();
        if !target.module.is_root() {
            return Err(RefError::ModuleScoped { address });
        }
        if target.key.is_some() {
            return Err(RefError::InstanceKeyed { address });
        }
        if !matches!(target.kind, ResourceKind::Managed | ResourceKind::Data) {
            return Err(RefError::NotAResource {
                kind: target.kind.to_string(),
                address,
            });
        }
        for (part, value) in [("type", &target.type_id.0), ("name", &target.name)] {
            if !is_identifier(value) {
                return Err(RefError::MalformedTarget {
                    address,
                    part,
                    value: value.clone(),
                });
            }
        }
        let attr_path: Vec<AttrStep> = path.into_iter().map(Into::into).collect();
        if matches!(attr_path.first(), Some(AttrStep::Index(_))) {
            return Err(RefError::LeadingIndex { address });
        }
        for step in &attr_path {
            if let AttrStep::Field(f) = step {
                if !is_identifier(f) {
                    return Err(RefError::MalformedField {
                        address,
                        field: f.clone(),
                    });
                }
            }
        }
        Ok(Self { target, attr_path })
    }

    /// The resource this reference targets.
    #[must_use]
    pub fn target(&self) -> &ResourceAddress {
        &self.target
    }

    /// The attribute path within that resource.
    #[must_use]
    pub fn attr_path(&self) -> &[AttrStep] {
        &self.attr_path
    }

    /// **The ONE renderer.** Writes the reference path — the text
    /// *inside* the braces, which is exactly what [`collect_refs`] yields
    /// for the rendered form. `Display` wraps this in `${…}` and
    /// [`Ref::path`] collects it into a `String`; nothing else in magma
    /// spells a reference.
    fn write_path(&self, out: &mut impl fmt::Write) -> fmt::Result {
        write!(out, "{}", self.target)?;
        for step in &self.attr_path {
            match step {
                AttrStep::Field(name) => write!(out, ".{name}")?,
                AttrStep::Index(i) => write!(out, "[{i}]")?,
            }
        }
        Ok(())
    }

    /// The reference path — `aws_vpc.main.id`, no `${…}` wrapper.
    ///
    /// This is the currency of the recognizer: `collect_refs` over a body
    /// containing this reference yields exactly this string. That
    /// equality is the compatibility contract between the typed door and
    /// the JSON door, and it is enforced — not merely tested — at every
    /// [`Resource`](crate::Resource) construction.
    #[must_use]
    pub fn path(&self) -> String {
        let mut s = String::new();
        self.write_path(&mut s)
            .expect("writing into a String cannot fail");
        s
    }

    /// The `(type, name)` this reference orders against, or `None` for a
    /// data source.
    ///
    /// **Must agree with [`ref_target`] on this reference's own
    /// [`path`](Ref::path), always.** That is what lets edge derivation
    /// read a typed reference structurally and a JSON body by scanning
    /// and get the same graph. Data sources return `None` in both: they
    /// are read up front from existing state, so they are not apply
    /// dependencies.
    #[must_use]
    pub fn edge_target(&self) -> Option<(&str, &str)> {
        match self.target.kind {
            ResourceKind::Data => None,
            _ => Some((self.target.type_id.0.as_str(), self.target.name.as_str())),
        }
    }
}

impl fmt::Display for Ref {
    /// The interpolation form — `${aws_vpc.main.id}` — the text that goes
    /// into a rendered configuration.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("${")?;
        self.write_path(f)?;
        f.write_str("}")
    }
}

impl From<Ref> for RefRepr {
    fn from(r: Ref) -> Self {
        Self {
            target: r.target,
            attr_path: r.attr_path,
        }
    }
}

impl TryFrom<RefRepr> for Ref {
    type Error = RefError;
    fn try_from(r: RefRepr) -> Result<Self, Self::Error> {
        Self::new(r.target, r.attr_path)
    }
}

/// Terraform identifier shape — what can appear as a type, a name or an
/// attribute step without changing where a rendered reference ends.
fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

// ── Typed attribute values ─────────────────────────────────────────

/// Why an [`AttrValue`] tree could not be lowered.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttrError {
    #[error(
        "literal interpolation `${{{found}}}` in a typed attribute value. Author it as a \
         `Ref` instead: a reference spelled as text is the one thing the typed door exists \
         to remove, because its target is recovered by scanning and re-parsing rather than \
         read off the value — so a typo in it is a missing dependency edge, not an error. \
         (An HCL-escaped `$${{…}}` is a literal, not a reference, and is accepted.)"
    )]
    LiteralInterpolation { found: String },
}

/// One part of an interpolated string — `"arn:${aws_x.y.id}/sub"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextPart {
    /// Literal text. May not itself contain an unescaped `${…}`.
    Literal(String),
    /// A typed reference, substituted in place.
    Ref(Ref),
}

impl From<&str> for TextPart {
    fn from(s: &str) -> Self {
        Self::Literal(s.to_string())
    }
}

impl From<String> for TextPart {
    fn from(s: String) -> Self {
        Self::Literal(s)
    }
}

impl From<Ref> for TextPart {
    fn from(r: Ref) -> Self {
        Self::Ref(r)
    }
}

/// A resource attribute value **as authored** — the typed tree a front
/// end builds, in which a reference is a [`Ref`] rather than a string.
///
/// **This is an authoring surface, lowered at construction — not a
/// storage format.** [`Resource`](crate::Resource) keeps holding a
/// `serde_json::Value`, because attribute values are cty data shaped by a
/// provider schema magma only learns at runtime; typing *those* would
/// mean a Rust type per resource type per provider version. What
/// `AttrValue` types is the one thing in a value that is magma's rather
/// than the provider's: a reference to another resource. Lowering renders
/// each [`Ref`] through the one renderer and hands back both the JSON
/// body and the references it contains, in the order a scan of that body
/// would find them.
///
/// The leaf case is deliberately strict: an [`AttrValue::Json`] carrying
/// a literal `${…}` is **refused**. Allowing it would let a body hold a
/// reference the typed side does not know about, which is precisely the
/// state that would make structural edge derivation wrong.
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    /// A literal JSON value — string, number, bool, null, or any nesting
    /// of them. Refused if it contains an unescaped `${…}`.
    Json(serde_json::Value),
    /// A typed reference occupying the whole slot: `vpc_id = ref`.
    Ref(Ref),
    /// A string assembled from literal text and references.
    Text(Vec<TextPart>),
    /// A list whose elements may themselves be references.
    List(Vec<AttrValue>),
    /// An object. Ordered, so that lowering visits keys in the same order
    /// a scan of the rendered body does.
    Map(BTreeMap<String, AttrValue>),
}

impl AttrValue {
    /// An object attribute — `{ name = …, tags = … }`.
    pub fn map<K: Into<String>, V: Into<Self>>(entries: impl IntoIterator<Item = (K, V)>) -> Self {
        Self::Map(
            entries
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }

    /// A list attribute.
    pub fn list<V: Into<Self>>(items: impl IntoIterator<Item = V>) -> Self {
        Self::List(items.into_iter().map(Into::into).collect())
    }

    /// A string built from literal text and references —
    /// `AttrValue::text([TextPart::from("arn:"), TextPart::from(r)])`.
    pub fn text<P: Into<TextPart>>(parts: impl IntoIterator<Item = P>) -> Self {
        Self::Text(parts.into_iter().map(Into::into).collect())
    }

    /// Lower to the rendered JSON body plus the references it contains.
    ///
    /// The reference list is in **body-walk order** — objects by key
    /// (they lower into a sorted map), lists in element order, text parts
    /// left to right — which is exactly the order [`collect_refs`] yields
    /// them from the result. That is not a coincidence to be maintained
    /// by hand: [`Resource::from_attrs`](crate::Resource::from_attrs)
    /// re-checks the two against each other, so a divergence is a
    /// construction error rather than a silently wrong graph.
    pub fn lower(self) -> Result<(serde_json::Value, Vec<Ref>), AttrError> {
        let mut refs = Vec::new();
        let body = self.lower_into(&mut refs)?;
        Ok((body, refs))
    }

    fn lower_into(self, refs: &mut Vec<Ref>) -> Result<serde_json::Value, AttrError> {
        match self {
            Self::Json(v) => match collect_refs(&v).into_iter().next() {
                Some(found) => Err(AttrError::LiteralInterpolation { found }),
                None => Ok(v),
            },
            Self::Ref(r) => {
                let rendered = r.to_string();
                refs.push(r);
                Ok(serde_json::Value::String(rendered))
            }
            Self::Text(parts) => {
                let mut s = String::new();
                for part in parts {
                    match part {
                        TextPart::Literal(lit) => {
                            let mut found = Vec::new();
                            scan_refs(&lit, &mut found);
                            if let Some(found) = found.into_iter().next() {
                                return Err(AttrError::LiteralInterpolation { found });
                            }
                            s.push_str(&lit);
                        }
                        TextPart::Ref(r) => {
                            use fmt::Write as _;
                            write!(s, "{r}").expect("writing into a String cannot fail");
                            refs.push(r);
                        }
                    }
                }
                Ok(serde_json::Value::String(s))
            }
            Self::List(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.lower_into(refs)?);
                }
                Ok(serde_json::Value::Array(out))
            }
            Self::Map(entries) => {
                let mut out = serde_json::Map::new();
                for (k, v) in entries {
                    let lowered = v.lower_into(refs)?;
                    out.insert(k, lowered);
                }
                Ok(serde_json::Value::Object(out))
            }
        }
    }
}

impl From<Ref> for AttrValue {
    fn from(r: Ref) -> Self {
        Self::Ref(r)
    }
}

impl From<serde_json::Value> for AttrValue {
    fn from(v: serde_json::Value) -> Self {
        Self::Json(v)
    }
}

impl From<&str> for AttrValue {
    fn from(s: &str) -> Self {
        Self::Json(serde_json::Value::String(s.to_string()))
    }
}

impl From<String> for AttrValue {
    fn from(s: String) -> Self {
        Self::Json(serde_json::Value::String(s))
    }
}

impl From<bool> for AttrValue {
    fn from(b: bool) -> Self {
        Self::Json(serde_json::Value::Bool(b))
    }
}

impl From<i64> for AttrValue {
    fn from(i: i64) -> Self {
        Self::Json(serde_json::Value::Number(i.into()))
    }
}

impl From<u64> for AttrValue {
    fn from(i: u64) -> Self {
        Self::Json(serde_json::Value::Number(i.into()))
    }
}

// ── Interpolation reference extraction (the recognizer) ─────────────
//
// The inverse of `Ref`'s renderer. It lived in magma-apply, then in
// magma-config beside the resolution family; it is here because the ONLY
// thing that makes either side correct is that the two agree, and an
// agreement enforced across a crate boundary is an agreement nobody
// checks. `magma_config` re-exports both functions, so no consumer path
// changed.

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
///
/// [`Ref::edge_target`] is the structural counterpart: for every
/// constructible [`Ref`], `ref_target(&r.path()) == r.edge_target()`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InstanceKey, ModulePath, ResourceTypeId};
    use serde_json::json;

    fn addr(kind: ResourceKind, type_id: &str, name: &str) -> ResourceAddress {
        ResourceAddress {
            module: ModulePath::root(),
            kind,
            type_id: ResourceTypeId(type_id.to_string()),
            name: name.to_string(),
            key: None,
        }
    }

    fn managed(type_id: &str, name: &str) -> ResourceAddress {
        addr(ResourceKind::Managed, type_id, name)
    }

    /// **The round trip.** A typed reference renders to exactly the text
    /// the scanner already recognises, and the scanner recovers exactly
    /// the target the reference knows structurally. Everything else in
    /// this change rests on this equality holding for every constructible
    /// `Ref`, so it is checked over the whole shape space at once.
    #[test]
    fn every_constructible_reference_renders_to_text_the_scanner_reads_back() {
        let cases = [
            Ref::new(managed("aws_vpc", "main"), ["id"]).expect("valid"),
            Ref::new(managed("aws_vpc", "main"), Vec::<AttrStep>::new()).expect("valid"),
            Ref::new(
                managed("aws_lb", "front"),
                [
                    AttrStep::Field("subnets".into()),
                    AttrStep::Index(0),
                    AttrStep::Field("arn".into()),
                ],
            )
            .expect("valid"),
            Ref::new(managed("github_repository", "galho"), ["node_id"]).expect("valid"),
            Ref::new(managed("aws_s3-bucket", "log_v2"), ["bucket", "id"]).expect("valid"),
            Ref::new(
                addr(ResourceKind::Data, "cloudflare_zones", "quero"),
                [
                    AttrStep::Field("result".into()),
                    AttrStep::Index(0),
                    AttrStep::Field("id".into()),
                ],
            )
            .expect("valid"),
        ];

        for r in cases {
            // Rendered into a body, the scanner yields the path back.
            let body = json!({ "attr": r.to_string() });
            assert_eq!(
                collect_refs(&body),
                vec![r.path()],
                "scanner did not read back `{r}`"
            );
            // And the recognizer's target agrees with the typed one.
            assert_eq!(
                ref_target(&r.path()),
                r.edge_target().map(|(t, n)| (t.to_string(), n.to_string())),
                "recognizer and structure disagree on `{r}`"
            );
        }
    }

    #[test]
    fn a_reference_renders_the_interpolation_form_and_the_bare_path() {
        let r = Ref::new(managed("aws_vpc", "main"), ["id"]).expect("valid");
        assert_eq!(r.to_string(), "${aws_vpc.main.id}");
        assert_eq!(r.path(), "aws_vpc.main.id");
    }

    #[test]
    fn an_index_step_renders_as_a_bracket_not_as_a_path_segment() {
        let r = Ref::new(
            addr(ResourceKind::Data, "cloudflare_zones", "quero"),
            [
                AttrStep::Field("result".into()),
                AttrStep::Index(0),
                AttrStep::Field("id".into()),
            ],
        )
        .expect("valid");
        assert_eq!(r.to_string(), "${data.cloudflare_zones.quero.result[0].id}");
    }

    /// A data reference orders nothing — it is read from existing state
    /// before the apply graph is walked. Both sides must say so.
    #[test]
    fn a_data_reference_is_not_an_ordering_edge_on_either_side() {
        let r = Ref::new(addr(ResourceKind::Data, "aws_ami", "latest"), ["id"]).expect("valid");
        assert_eq!(r.edge_target(), None);
        assert_eq!(ref_target(&r.path()), None);
    }

    // ── What cannot be a reference, and why ────────────────────────

    #[test]
    fn a_module_scoped_target_is_refused_because_it_would_render_to_nothing() {
        let target = ResourceAddress {
            module: ModulePath(vec!["net".to_string()]),
            ..managed("aws_vpc", "main")
        };
        assert!(matches!(
            Ref::new(target, ["id"]),
            Err(RefError::ModuleScoped { .. })
        ));
    }

    #[test]
    fn an_instance_keyed_target_is_refused_because_magma_implements_no_count() {
        let target = ResourceAddress {
            key: Some(InstanceKey::Index(0)),
            ..managed("aws_vpc", "main")
        };
        assert!(matches!(
            Ref::new(target, ["id"]),
            Err(RefError::InstanceKeyed { .. })
        ));
    }

    #[test]
    fn a_non_resource_target_is_refused() {
        for kind in [
            ResourceKind::Variable,
            ResourceKind::Local,
            ResourceKind::Output,
        ] {
            assert!(
                matches!(
                    Ref::new(addr(kind, "x", "y"), ["id"]),
                    Err(RefError::NotAResource { .. })
                ),
                "{kind} should not be referenceable"
            );
        }
    }

    /// The refusals that keep the round trip true: anything that would
    /// end the rendered `${…}` early, or move where it ends.
    #[test]
    fn a_target_or_step_that_would_break_the_rendering_is_refused() {
        assert!(matches!(
            Ref::new(managed("aws_vpc", "ma.in"), ["id"]),
            Err(RefError::MalformedTarget { part: "name", .. })
        ));
        assert!(matches!(
            Ref::new(managed("aws.vpc", "main"), ["id"]),
            Err(RefError::MalformedTarget { part: "type", .. })
        ));
        assert!(matches!(
            Ref::new(managed("aws_vpc", "main"), ["id}"]),
            Err(RefError::MalformedField { .. })
        ));
        assert!(matches!(
            Ref::new(managed("aws_vpc", "main"), [AttrStep::Index(0)]),
            Err(RefError::LeadingIndex { .. })
        ));
    }

    /// A `}` inside a field would end the rendered reference early — the
    /// scanner would read a SHORTER path and the round trip would break
    /// silently. This is the concrete reason the identifier check exists.
    #[test]
    fn a_brace_bearing_field_would_have_truncated_the_scanned_path() {
        // What the refusal prevents, demonstrated on raw text.
        let mut found = Vec::new();
        scan_refs("${aws_vpc.main.id}x}", &mut found);
        assert_eq!(found, vec!["aws_vpc.main.id".to_string()]);
    }

    #[test]
    fn a_persisted_reference_is_revalidated_on_the_way_back_in() {
        let bad = json!({
            "target": {
                "module": ["net"],
                "kind": "managed",
                "type_id": "aws_vpc",
                "name": "main",
                "key": null
            },
            "attr_path": [{ "field": "id" }]
        });
        assert!(serde_json::from_value::<Ref>(bad).is_err());

        let good = Ref::new(managed("aws_vpc", "main"), ["id"]).expect("valid");
        let round = serde_json::from_value::<Ref>(serde_json::to_value(&good).expect("serializes"))
            .expect("valid on the way back");
        assert_eq!(round, good);
    }

    // ── Typed attribute values ─────────────────────────────────────

    #[test]
    fn lowering_renders_references_and_reports_them_in_body_walk_order() {
        let vpc = Ref::new(managed("aws_vpc", "main"), ["id"]).expect("valid");
        let igw = Ref::new(managed("aws_internet_gateway", "gw"), ["id"]).expect("valid");
        let sg = Ref::new(managed("aws_security_group", "web"), ["id"]).expect("valid");

        let attrs = AttrValue::map([
            ("a_vpc", AttrValue::from(vpc.clone())),
            ("b_list", AttrValue::list([AttrValue::from(igw.clone())])),
            (
                "c_text",
                AttrValue::text([TextPart::from("sg-"), TextPart::from(sg.clone())]),
            ),
            ("d_plain", AttrValue::from("literal")),
        ]);

        let (body, refs) = attrs.lower().expect("lowers");
        assert_eq!(
            body,
            json!({
                "a_vpc": "${aws_vpc.main.id}",
                "b_list": ["${aws_internet_gateway.gw.id}"],
                "c_text": "sg-${aws_security_group.web.id}",
                "d_plain": "literal",
            })
        );
        assert_eq!(refs, vec![vpc, igw, sg]);
        // The ordering claim, checked rather than asserted in prose.
        assert_eq!(
            collect_refs(&body),
            refs.iter().map(Ref::path).collect::<Vec<_>>()
        );
    }

    /// The leaf refusal that makes structural edge derivation safe: a
    /// body cannot carry a reference the typed side does not know about.
    #[test]
    fn a_literal_interpolation_in_a_typed_value_is_refused() {
        let err = AttrValue::from("${aws_vpc.main.id}")
            .lower()
            .expect_err("a reference spelled as text");
        assert!(matches!(
            err,
            AttrError::LiteralInterpolation { ref found } if found == "aws_vpc.main.id"
        ));

        // Nested, too — the check walks the whole leaf value.
        assert!(
            AttrValue::from(json!({ "tags": { "vpc": "${aws_vpc.main.id}" } }))
                .lower()
                .is_err()
        );

        // And inside the literal half of an interpolated string.
        assert!(
            AttrValue::text([TextPart::from("${aws_vpc.main.id}")])
                .lower()
                .is_err()
        );
    }

    /// An HCL-escaped `$${…}` is a literal, not a reference. The typed
    /// door must not confuse the two — a GitHub Actions expression in a
    /// file body is the case that broke this family before.
    #[test]
    fn an_escaped_literal_is_not_a_reference_and_passes_through_the_typed_door() {
        let (body, refs) = AttrValue::from("$${{ secrets.BOT_PAT }}")
            .lower()
            .expect("an escaped literal is not a reference");
        assert_eq!(body, json!("$${{ secrets.BOT_PAT }}"));
        assert!(refs.is_empty());
    }
}
