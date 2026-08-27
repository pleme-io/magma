//! The `random` provider, natively — in-process Rust, no subprocess, no Go.
//!
//! ── ★ WHY THIS ONE FIRST ─────────────────────────────────────────────
//! Measured on the operator image (release r349, trivy artifact
//! 9648954592): `terraform-provider-random` contributed **36 of 190**
//! findings — the single largest contributor of any provider baked in,
//! ahead of aws (11). It is also the provider that makes **no network
//! calls whatsoever**: its entire job is to generate bytes and remember
//! them. 36 vulnerabilities to produce a random string.
//!
//! That combination is why it is first. It is not the easiest thing to
//! port; it is the best ratio of CVE surface removed to API surface
//! reimplemented, and it needs no credentials to exercise end-to-end.
//!
//! ── WHAT IS ACTUALLY IN USE, so the port is aimed ────────────────────
//! One live consumer across every architecture in the fleet
//! (`pangea-architectures/workspaces/camelot-eks-shaar-concentrator`):
//!
//! ```json
//! "random_password": { "…-webhook-creds-seed": { "length": 48, "special": false } }
//! ```
//!
//! So `random_password` is the correctness-critical type. The others are
//! implemented because a partial provider that silently ignores a type is
//! worse than one that refuses it — see `unsupported` below.
//!
//! ── ★ THE SCHEMA IS DELIBERATELY WIDER THAN WHAT WE USE ──────────────
//! Every attribute terraform-provider-random 3.x declares is declared
//! here, including ones nothing in the fleet reads (`bcrypt_hash`,
//! `number`). That is not padding: the schema is what STATE is decoded
//! against. A resource previously created by the Go provider has those
//! attributes in its stored JSON, and a narrower schema would fail to
//! decode it — turning a provider swap into a state migration. Declaring
//! the full set makes the swap a no-op for existing state.
//!
//! `bcrypt_hash` is declared and left NULL, which is a real divergence
//! and is named rather than hidden: the Go provider populates it with a
//! bcrypt of the result. Nothing in the fleet reads it, and it is
//! salted — so it is not comparable across implementations anyway and
//! could never be part of a byte-oracle. See `BCRYPT_HASH_IS_NULL`.

use std::collections::BTreeMap;

use magma_cty::{CtyType, CtyValue, DynamicValue};
use magma_provider_api::{PlannedChange, Provider, ProviderError, ProviderSchema};
use rand::Rng;
use rand::seq::SliceRandom;

/// The special characters terraform-provider-random uses when `special`
/// is true and `override_special` is unset. Copied from upstream rather
/// than invented — a different set silently produces passwords that a
/// downstream validator may reject.
const SPECIAL_DEFAULT: &str = "!@#$%&*()-_=+[]{}<>:?";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMERIC: &str = "0123456789";

/// Named so the divergence is greppable. See the module header.
const BCRYPT_HASH_IS_NULL: () = ();

/// The provider itself. Stateless: every resource is generated from its
/// config, and there is nothing to configure or connect to.
pub struct RandomProvider;

impl RandomProvider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandomProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// The attributes shared by `random_password` and `random_string`.
fn string_like_attrs(with_bcrypt: bool) -> BTreeMap<String, CtyType> {
    let mut a = BTreeMap::new();
    a.insert("length".into(), CtyType::Number);
    for b in [
        "special", "upper", "lower", "numeric", // `number` is upstream's DEPRECATED alias for
        // `numeric`. Declared because stored state may carry it.
        "number",
    ] {
        a.insert(b.into(), CtyType::Bool);
    }
    for n in ["min_numeric", "min_upper", "min_lower", "min_special"] {
        a.insert(n.into(), CtyType::Number);
    }
    a.insert("override_special".into(), CtyType::String);
    a.insert("keepers".into(), CtyType::Map(Box::new(CtyType::String)));
    a.insert("result".into(), CtyType::String);
    a.insert("id".into(), CtyType::String);
    if with_bcrypt {
        a.insert("bcrypt_hash".into(), CtyType::String);
    }
    a
}

fn random_id_attrs() -> BTreeMap<String, CtyType> {
    let mut a = BTreeMap::new();
    a.insert("byte_length".into(), CtyType::Number);
    a.insert("prefix".into(), CtyType::String);
    a.insert("keepers".into(), CtyType::Map(Box::new(CtyType::String)));
    for c in ["b64_url", "b64_std", "hex", "dec", "id"] {
        a.insert(c.into(), CtyType::String);
    }
    a
}

fn random_integer_attrs() -> BTreeMap<String, CtyType> {
    let mut a = BTreeMap::new();
    a.insert("min".into(), CtyType::Number);
    a.insert("max".into(), CtyType::Number);
    a.insert("seed".into(), CtyType::String);
    a.insert("keepers".into(), CtyType::Map(Box::new(CtyType::String)));
    a.insert("result".into(), CtyType::Number);
    a.insert("id".into(), CtyType::String);
    a
}

fn random_uuid_attrs() -> BTreeMap<String, CtyType> {
    let mut a = BTreeMap::new();
    a.insert("keepers".into(), CtyType::Map(Box::new(CtyType::String)));
    a.insert("result".into(), CtyType::String);
    a.insert("id".into(), CtyType::String);
    a
}

/// The resource types this provider serves, with their implied types.
#[must_use]
pub fn schema() -> ProviderSchema {
    let mut resources = BTreeMap::new();
    resources.insert(
        "random_password".to_string(),
        CtyType::Object(string_like_attrs(true)),
    );
    resources.insert(
        "random_string".to_string(),
        CtyType::Object(string_like_attrs(false)),
    );
    resources.insert("random_id".to_string(), CtyType::Object(random_id_attrs()));
    resources.insert(
        "random_integer".to_string(),
        CtyType::Object(random_integer_attrs()),
    );
    resources.insert(
        "random_uuid".to_string(),
        CtyType::Object(random_uuid_attrs()),
    );

    let mut resource_versions = BTreeMap::new();
    for k in resources.keys() {
        // Upstream random_password/random_string are schema version 1
        // (the 3.3 bcrypt migration); the rest are 0. Declaring the
        // version upstream declares is what keeps the engine from
        // demanding an UpgradeResourceState that never needed to happen.
        let v = i64::from(k == "random_password" || k == "random_string");
        resource_versions.insert(k.clone(), v);
    }

    ProviderSchema {
        provider_config: CtyType::Object(BTreeMap::new()),
        resources,
        data_sources: BTreeMap::new(),
        resource_versions,
    }
}

/// A type this provider does not serve.
///
/// ── ★ REFUSE, NEVER NO-OP ────────────────────────────────────────────
/// The dangerous failure for a partial provider is not "missing type" —
/// it is returning `Ok` with an empty state for a type it does not
/// understand. The engine would record a successful apply, write empty
/// state, and the resource would never exist while every status read
/// green. A typed error is loud and stops the apply.
fn unsupported(op: &str, type_name: &str) -> ProviderError {
    ProviderError::Transport(format!(
        "magma-provider-random: {op} for unsupported resource type {type_name:?} \
         (served: random_password, random_string, random_id, random_integer, random_uuid)"
    ))
}

fn obj<'a>(v: &'a CtyValue) -> Option<&'a BTreeMap<String, CtyValue>> {
    match v {
        CtyValue::Object(m) | CtyValue::Map(m) => Some(m),
        _ => None,
    }
}

fn get_bool(m: &BTreeMap<String, CtyValue>, k: &str, default: bool) -> bool {
    match m.get(k) {
        Some(CtyValue::Bool(b)) => *b,
        _ => default,
    }
}

fn get_i64(m: &BTreeMap<String, CtyValue>, k: &str, default: i64) -> i64 {
    match m.get(k) {
        Some(CtyValue::Number(n)) => n.as_i64().unwrap_or(default),
        _ => default,
    }
}

fn get_str<'a>(m: &'a BTreeMap<String, CtyValue>, k: &str) -> Option<&'a str> {
    match m.get(k) {
        Some(CtyValue::String(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn num(v: i64) -> CtyValue {
    CtyValue::Number(serde_json::Number::from(v))
}

/// Generate a string per upstream's algorithm: satisfy every declared
/// minimum first, fill the remainder from the union, then shuffle.
///
/// The shuffle is not cosmetic — without it the guaranteed characters sit
/// in a fixed order at the front, which is a real weakness in a generated
/// password and a visible difference from upstream output.
fn generate_string_like(m: &BTreeMap<String, CtyValue>) -> String {
    let length = get_i64(m, "length", 0).max(0);
    let special = get_bool(m, "special", true);
    let upper = get_bool(m, "upper", true);
    let lower = get_bool(m, "lower", true);
    // `number` is the deprecated alias; upstream honours it when set.
    let numeric = get_bool(m, "numeric", get_bool(m, "number", true));
    let specials = get_str(m, "override_special").unwrap_or(SPECIAL_DEFAULT);

    let mut rng = rand::thread_rng();
    let mut out: Vec<char> = Vec::new();
    let mut pool = String::new();

    let take = |set: &str, n: i64, out: &mut Vec<char>, rng: &mut rand::rngs::ThreadRng| {
        let chars: Vec<char> = set.chars().collect();
        if chars.is_empty() {
            return;
        }
        for _ in 0..n.max(0) {
            out.push(chars[rng.gen_range(0..chars.len())]);
        }
    };

    if lower {
        pool.push_str(LOWER);
        take(LOWER, get_i64(m, "min_lower", 0), &mut out, &mut rng);
    }
    if upper {
        pool.push_str(UPPER);
        take(UPPER, get_i64(m, "min_upper", 0), &mut out, &mut rng);
    }
    if numeric {
        pool.push_str(NUMERIC);
        take(NUMERIC, get_i64(m, "min_numeric", 0), &mut out, &mut rng);
    }
    if special {
        pool.push_str(specials);
        take(specials, get_i64(m, "min_special", 0), &mut out, &mut rng);
    }

    let pool: Vec<char> = pool.chars().collect();
    if pool.is_empty() {
        // Every character class disabled. Upstream errors; returning an
        // empty string would silently produce a zero-entropy credential,
        // which is the worst possible outcome, so the caller checks this.
        return String::new();
    }
    while (out.len() as i64) < length {
        out.push(pool[rng.gen_range(0..pool.len())]);
    }
    out.truncate(usize::try_from(length).unwrap_or(0));
    out.shuffle(&mut rng);
    out.into_iter().collect()
}

/// Fill in the attributes upstream marks Optional+Computed, so a plan
/// does not show a perpetual diff on defaults the config omitted.
fn apply_string_like_defaults(m: &mut BTreeMap<String, CtyValue>) {
    for (k, d) in [
        ("special", true),
        ("upper", true),
        ("lower", true),
        ("numeric", true),
    ] {
        if !matches!(m.get(k), Some(CtyValue::Bool(_))) {
            m.insert(k.to_string(), CtyValue::Bool(d));
        }
    }
    for k in ["min_numeric", "min_upper", "min_lower", "min_special"] {
        if !matches!(m.get(k), Some(CtyValue::Number(_))) {
            m.insert(k.to_string(), num(0));
        }
    }
}

/// Every argument of every `random_*` resource forces replacement —
/// there is no in-place update of a generated value, by construction.
/// Upstream declares all of them ForceNew for exactly this reason.
fn force_new_attrs(type_name: &str) -> &'static [&'static str] {
    match type_name {
        "random_password" | "random_string" => &[
            "length",
            "special",
            "upper",
            "lower",
            "numeric",
            "number",
            "min_numeric",
            "min_upper",
            "min_lower",
            "min_special",
            "override_special",
            "keepers",
        ],
        "random_id" => &["byte_length", "prefix", "keepers"],
        "random_integer" => &["min", "max", "seed", "keepers"],
        "random_uuid" => &["keepers"],
        _ => &[],
    }
}

/// The computed attributes, which a plan marks Unknown and an apply fills.
fn computed_attrs(type_name: &str) -> &'static [&'static str] {
    match type_name {
        "random_password" => &["result", "id", "bcrypt_hash"],
        "random_string" | "random_integer" | "random_uuid" => &["result", "id"],
        "random_id" => &["b64_url", "b64_std", "hex", "dec", "id"],
        _ => &[],
    }
}

/// The ONE computed attribute whose presence means "this resource has
/// been generated".
///
/// ── ★ WHY NOT "are all computed attributes known?" ───────────────────
/// That was the first implementation and it was wrong in a way the tests
/// caught: `bcrypt_hash` is LEGITIMATELY null (see the module header), so
/// "all computed attributes are non-null" is never true for
/// `random_password` — and the inverse check, "none is Unknown", was true
/// for a planned state whose `result` was merely NULL rather than
/// Unknown. Apply then returned early WITHOUT GENERATING and reported
/// success, writing a resource whose password was null.
///
/// That is exactly the silent no-op this provider refuses elsewhere, so
/// the predicate is now keyed on the one attribute that actually carries
/// the generated value.
fn primary_computed(type_name: &str) -> &'static str {
    match type_name {
        // random_id's `id` is derived from b64_url; `hex` is the value.
        "random_id" => "hex",
        _ => "result",
    }
}

#[async_trait::async_trait]
impl Provider for RandomProvider {
    async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
        Ok(schema())
    }

    /// Nothing to configure: no endpoint, no credentials, no client.
    async fn configure(&mut self, _: &DynamicValue, _: &str) -> Result<(), ProviderError> {
        Ok(())
    }

    async fn plan_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        proposed_new_state: &DynamicValue,
        _config: &DynamicValue,
    ) -> Result<PlannedChange, ProviderError> {
        let ty = schema()
            .resource(type_name)
            .cloned()
            .ok_or_else(|| unsupported("plan", type_name))?;

        let proposed = proposed_new_state
            .to_value(&ty)
            .map_err(|e| ProviderError::Transport(e.to_string()))?;

        // A null proposed state is a DESTROY: plan it through unchanged.
        if matches!(proposed, CtyValue::Null) {
            return Ok(PlannedChange {
                state: proposed_new_state.clone(),
                requires_replace: Vec::new(),
            });
        }

        let mut planned = obj(&proposed).cloned().unwrap_or_default();
        if type_name == "random_password" || type_name == "random_string" {
            apply_string_like_defaults(&mut planned);
        }

        let prior = prior_state.to_value(&ty).ok();
        let prior_map = prior.as_ref().and_then(obj);

        // Which force-new attributes actually changed?
        let mut requires_replace: Vec<String> = Vec::new();
        if let Some(pm) = prior_map {
            for k in force_new_attrs(type_name) {
                let before = pm.get(*k);
                let after = planned.get(*k);
                if before != after {
                    requires_replace.push((*k).to_string());
                }
            }
        }

        let creating = prior_map.is_none();
        let replacing = !requires_replace.is_empty();

        for c in computed_attrs(type_name) {
            if creating || replacing {
                // The value does not exist yet. Unknown is the honest
                // answer and is what lets the engine show "(known after
                // apply)" rather than inventing a value at plan time.
                planned.insert((*c).to_string(), CtyValue::Unknown);
            } else if let Some(pm) = prior_map {
                // Unchanged: carry the prior value forward verbatim, so a
                // re-plan of an untouched resource is a genuine no-op.
                if let Some(v) = pm.get(*c) {
                    planned.insert((*c).to_string(), v.clone());
                }
            }
        }

        let state = DynamicValue::marshal(&CtyValue::Object(planned), &ty)
            .map_err(|e| ProviderError::Transport(e.to_string()))?;
        Ok(PlannedChange {
            state,
            requires_replace,
        })
    }

    async fn apply_resource_change(
        &mut self,
        type_name: &str,
        _prior_state: &DynamicValue,
        planned_state: &DynamicValue,
        _config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        let ty = schema()
            .resource(type_name)
            .cloned()
            .ok_or_else(|| unsupported("apply", type_name))?;

        let planned = planned_state
            .to_value(&ty)
            .map_err(|e| ProviderError::Transport(e.to_string()))?;

        // Null planned state = DESTROY. There is nothing to delete: the
        // resource only ever existed as state, so dropping it IS deletion.
        if matches!(planned, CtyValue::Null) {
            return Ok(planned_state.clone());
        }

        let mut m = obj(&planned).cloned().unwrap_or_default();

        // Already generated (an unchanged apply) — return verbatim rather
        // than regenerating, which would rotate the credential on every
        // reconcile. Null and Unknown both mean "not generated": see
        // `primary_computed`.
        let already_generated = matches!(
            m.get(primary_computed(type_name)),
            Some(v) if !matches!(v, CtyValue::Unknown | CtyValue::Null)
        );
        if already_generated {
            return Ok(planned_state.clone());
        }

        match type_name {
            "random_password" | "random_string" => {
                apply_string_like_defaults(&mut m);
                let result = generate_string_like(&m);
                if result.is_empty() && get_i64(&m, "length", 0) > 0 {
                    return Err(ProviderError::Transport(
                        "magma-provider-random: every character class is disabled, so no \
                         password can be generated — refusing rather than returning an \
                         empty credential"
                            .to_string(),
                    ));
                }
                if type_name == "random_password" {
                    // See BCRYPT_HASH_IS_NULL in the module header: declared,
                    // deliberately null, salted upstream so never comparable.
                    let _ = BCRYPT_HASH_IS_NULL;
                    m.insert("bcrypt_hash".into(), CtyValue::Null);
                    // Upstream sets id="none" for random_password so the
                    // generated secret never appears in the resource id.
                    m.insert("id".into(), CtyValue::string("none"));
                } else {
                    m.insert("id".into(), CtyValue::string(result.clone()));
                }
                m.insert("result".into(), CtyValue::string(result));
            }
            "random_id" => {
                let n = usize::try_from(get_i64(&m, "byte_length", 8).max(0)).unwrap_or(8);
                let mut bytes = vec![0u8; n];
                rand::thread_rng().fill(&mut bytes[..]);
                let prefix = get_str(&m, "prefix").unwrap_or("").to_string();
                use base64::Engine as _;
                let b64_std = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let b64_url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
                let hexs = hex::encode(&bytes);
                let dec = bytes
                    .iter()
                    .fold(0u128, |acc, b| {
                        acc.wrapping_mul(256).wrapping_add(u128::from(*b))
                    })
                    .to_string();
                m.insert(
                    "b64_std".into(),
                    CtyValue::string(format!("{prefix}{b64_std}")),
                );
                m.insert(
                    "b64_url".into(),
                    CtyValue::string(format!("{prefix}{b64_url}")),
                );
                m.insert("hex".into(), CtyValue::string(format!("{prefix}{hexs}")));
                m.insert("dec".into(), CtyValue::string(format!("{prefix}{dec}")));
                m.insert("id".into(), CtyValue::string(b64_url));
            }
            "random_integer" => {
                let lo = get_i64(&m, "min", 0);
                let hi = get_i64(&m, "max", 0);
                if hi < lo {
                    return Err(ProviderError::Transport(format!(
                        "magma-provider-random: random_integer max ({hi}) < min ({lo})"
                    )));
                }
                let v = rand::thread_rng().gen_range(lo..=hi);
                m.insert("result".into(), num(v));
                m.insert("id".into(), CtyValue::string(v.to_string()));
            }
            "random_uuid" => {
                let mut b = [0u8; 16];
                rand::thread_rng().fill(&mut b[..]);
                // RFC 4122 v4: set the version and variant bits.
                b[6] = (b[6] & 0x0f) | 0x40;
                b[8] = (b[8] & 0x3f) | 0x80;
                let h = hex::encode(b);
                let uuid = format!(
                    "{}-{}-{}-{}-{}",
                    &h[0..8],
                    &h[8..12],
                    &h[12..16],
                    &h[16..20],
                    &h[20..32]
                );
                m.insert("result".into(), CtyValue::string(uuid.clone()));
                m.insert("id".into(), CtyValue::string(uuid));
            }
            other => return Err(unsupported("apply", other)),
        }

        DynamicValue::marshal(&CtyValue::Object(m), &ty)
            .map_err(|e| ProviderError::Transport(e.to_string()))
    }

    /// Refresh is the identity.
    ///
    /// A `random_*` resource has no remote counterpart to re-read: the
    /// state IS the resource. Returning the current state unchanged is
    /// what makes a re-plan a no-op; regenerating here would rotate every
    /// credential on every reconcile, and returning `Ok(None)` would tell
    /// the engine the resource had been deleted out from under it.
    async fn read_resource(
        &mut self,
        type_name: &str,
        current_state: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        if schema().resource(type_name).is_none() {
            return Err(unsupported("read", type_name));
        }
        Ok(Some(current_state.clone()))
    }

    /// This provider declares no data sources, so any read is a caller
    /// error rather than an empty result.
    async fn read_data_source(
        &mut self,
        type_name: &str,
        _config: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        Err(unsupported("read_data_source", type_name))
    }

    /// Import adopts a value that already exists: the id IS the value.
    async fn import_resource_state(
        &mut self,
        type_name: &str,
        id: &str,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        let ty = schema()
            .resource(type_name)
            .cloned()
            .ok_or_else(|| unsupported("import", type_name))?;
        let mut m: BTreeMap<String, CtyValue> = BTreeMap::new();
        match type_name {
            "random_password" | "random_string" => {
                apply_string_like_defaults(&mut m);
                m.insert("result".into(), CtyValue::string(id));
                m.insert(
                    "length".into(),
                    num(i64::try_from(id.chars().count()).unwrap_or(0)),
                );
                if type_name == "random_password" {
                    m.insert("bcrypt_hash".into(), CtyValue::Null);
                    m.insert("id".into(), CtyValue::string("none"));
                } else {
                    m.insert("id".into(), CtyValue::string(id));
                }
            }
            "random_uuid" => {
                m.insert("result".into(), CtyValue::string(id));
                m.insert("id".into(), CtyValue::string(id));
            }
            other => return Err(unsupported("import", other)),
        }
        let dv = DynamicValue::marshal(&CtyValue::Object(m), &ty)
            .map_err(|e| ProviderError::Transport(e.to_string()))?;
        Ok(Some(dv))
    }

    /// State written by an older schema version.
    ///
    /// Upstream's only migration (v0 → v1) ADDED `bcrypt_hash`, so the
    /// stored JSON is forward-compatible: decoding it against the current
    /// type yields a null for the added attribute, which is exactly what
    /// this implementation writes anyway.
    async fn upgrade_resource_state(
        &mut self,
        type_name: &str,
        _stored_version: i64,
        raw_json: &[u8],
    ) -> Result<DynamicValue, ProviderError> {
        let ty = schema()
            .resource(type_name)
            .cloned()
            .ok_or_else(|| unsupported("upgrade", type_name))?;
        let v: serde_json::Value = serde_json::from_slice(raw_json)
            .map_err(|e| ProviderError::Transport(format!("upgrade_resource_state: {e}")))?;
        DynamicValue::from_json(&v, &ty).map_err(|e| ProviderError::Transport(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(t: &str) -> CtyType {
        schema().resource(t).cloned().expect("declared type")
    }

    fn dv(t: &str, v: serde_json::Value) -> DynamicValue {
        DynamicValue::from_json(&v, &ty(t)).expect("encodes against the schema")
    }

    fn null(t: &str) -> DynamicValue {
        DynamicValue::marshal(&CtyValue::Null, &ty(t)).expect("null")
    }

    fn field(d: &DynamicValue, t: &str, k: &str) -> Option<CtyValue> {
        let v = d.to_value(&ty(t)).ok()?;
        obj(&v)?.get(k).cloned()
    }

    /// The LIVE fleet config, verbatim:
    /// `pangea-architectures/workspaces/camelot-eks-shaar-concentrator` →
    /// `{ "length": 48, "special": false }`. If this stops working the
    /// shaar-concentrator webhook credential stops being generated.
    #[tokio::test]
    async fn the_live_shaar_concentrator_config_generates() {
        let mut p = RandomProvider::new();
        let cfg = serde_json::json!({ "length": 48, "special": false });
        let plan = p
            .plan_resource_change(
                "random_password",
                &null("random_password"),
                &dv("random_password", cfg.clone()),
                &dv("random_password", cfg.clone()),
            )
            .await
            .expect("plans");
        // A create has no prior, so nothing can require replacement.
        assert!(plan.requires_replace.is_empty());
        // …and the value is Unknown, not invented at plan time.
        assert_eq!(
            field(&plan.state, "random_password", "result"),
            Some(CtyValue::Unknown)
        );

        let applied = p
            .apply_resource_change(
                "random_password",
                &null("random_password"),
                &plan.state,
                &dv("random_password", cfg),
            )
            .await
            .expect("applies");

        let Some(CtyValue::String(pw)) = field(&applied, "random_password", "result") else {
            panic!("apply must produce a string result");
        };
        assert_eq!(pw.chars().count(), 48, "length must be honoured exactly");
        assert!(
            pw.chars().all(char::is_alphanumeric),
            "special=false must exclude special characters, got {pw:?}"
        );
        // Upstream keeps the secret out of the id.
        assert_eq!(
            field(&applied, "random_password", "id"),
            Some(CtyValue::string("none"))
        );
    }

    /// ★ THE LAW THIS PROVIDER LIVES OR DIES BY.
    ///
    /// random's outputs are random by design, so it can never be a
    /// byte-differential against the Go provider. The property that
    /// actually matters is IDEMPOTENCE: once generated, a re-plan is a
    /// no-op and a re-apply does not rotate. Get this wrong and every
    /// reconcile silently issues a new credential — which is far worse
    /// than a crash, because everything downstream keeps reporting green
    /// while authentication breaks.
    #[tokio::test]
    async fn a_generated_password_never_rotates_on_reconcile() {
        let mut p = RandomProvider::new();
        let cfg = serde_json::json!({ "length": 48, "special": false });
        let plan = p
            .plan_resource_change(
                "random_password",
                &null("random_password"),
                &dv("random_password", cfg.clone()),
                &dv("random_password", cfg.clone()),
            )
            .await
            .unwrap();
        let state = p
            .apply_resource_change(
                "random_password",
                &null("random_password"),
                &plan.state,
                &dv("random_password", cfg.clone()),
            )
            .await
            .unwrap();
        let first = field(&state, "random_password", "result").unwrap();

        // Refresh must be the identity — not a regeneration, and not a
        // "resource is gone".
        let refreshed = p
            .read_resource("random_password", &state)
            .await
            .unwrap()
            .expect("a local resource is never absent");
        assert_eq!(
            field(&refreshed, "random_password", "result").unwrap(),
            first
        );

        // Re-plan against the SAME config: no replacement, value carried.
        let replan = p
            .plan_resource_change(
                "random_password",
                &state,
                &dv("random_password", cfg.clone()),
                &dv("random_password", cfg.clone()),
            )
            .await
            .unwrap();
        assert!(
            replan.requires_replace.is_empty(),
            "an unchanged config must not force replacement: {:?}",
            replan.requires_replace
        );
        assert_eq!(
            field(&replan.state, "random_password", "result").unwrap(),
            first,
            "re-plan must carry the existing value, not mark it Unknown"
        );

        // And re-applying that plan returns the same value.
        let reapplied = p
            .apply_resource_change(
                "random_password",
                &state,
                &replan.state,
                &dv("random_password", cfg),
            )
            .await
            .unwrap();
        assert_eq!(
            field(&reapplied, "random_password", "result").unwrap(),
            first,
            "RE-APPLY ROTATED THE CREDENTIAL — this is the failure this test exists for"
        );
    }

    /// Changing a ForceNew argument must replace, and the new value must
    /// be Unknown rather than the stale one.
    #[tokio::test]
    async fn changing_length_forces_replacement() {
        let mut p = RandomProvider::new();
        let old = serde_json::json!({ "length": 48, "special": false });
        let plan = p
            .plan_resource_change(
                "random_password",
                &null("random_password"),
                &dv("random_password", old.clone()),
                &dv("random_password", old.clone()),
            )
            .await
            .unwrap();
        let state = p
            .apply_resource_change(
                "random_password",
                &null("random_password"),
                &plan.state,
                &dv("random_password", old),
            )
            .await
            .unwrap();

        let new = serde_json::json!({ "length": 64, "special": false });
        let replan = p
            .plan_resource_change(
                "random_password",
                &state,
                &dv("random_password", new.clone()),
                &dv("random_password", new),
            )
            .await
            .unwrap();
        assert_eq!(replan.requires_replace, vec!["length".to_string()]);
        assert_eq!(
            field(&replan.state, "random_password", "result"),
            Some(CtyValue::Unknown),
            "a replacement must not carry the old secret forward"
        );
    }

    /// ★ REFUSE, NEVER NO-OP. A type this provider does not serve must
    /// error — an `Ok` with empty state would be recorded as a successful
    /// apply for a resource that was never created.
    #[tokio::test]
    async fn an_unserved_type_is_refused_not_silently_accepted() {
        let mut p = RandomProvider::new();
        let e = p
            .apply_resource_change(
                "random_shuffle",
                &null("random_uuid"),
                &null("random_uuid"),
                &null("random_uuid"),
            )
            .await
            .expect_err("an unserved type must not apply");
        let m = e.to_string();
        assert!(
            m.contains("random_shuffle") && m.contains("unsupported"),
            "{m}"
        );
    }

    /// Every character class disabled cannot silently yield an empty
    /// credential.
    #[tokio::test]
    async fn a_zero_entropy_request_is_refused() {
        let mut p = RandomProvider::new();
        let cfg = serde_json::json!({
            "length": 16, "special": false, "upper": false, "lower": false, "numeric": false
        });
        let planned = dv(
            "random_password",
            serde_json::json!({
                "length": 16, "special": false, "upper": false, "lower": false, "numeric": false,
                "min_numeric": 0, "min_upper": 0, "min_lower": 0, "min_special": 0
            }),
        );
        let e = p
            .apply_resource_change(
                "random_password",
                &null("random_password"),
                &planned,
                &dv("random_password", cfg),
            )
            .await
            .expect_err("no character class means no password");
        assert!(e.to_string().contains("character class"), "{e}");
    }

    /// The other served types produce well-formed values.
    #[tokio::test]
    async fn uuid_and_integer_are_well_formed() {
        let mut p = RandomProvider::new();
        let planned = dv("random_uuid", serde_json::json!({}));
        let out = p
            .apply_resource_change("random_uuid", &null("random_uuid"), &planned, &planned)
            .await
            .unwrap();
        let Some(CtyValue::String(u)) = field(&out, "random_uuid", "result") else {
            panic!("uuid result")
        };
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[14], b'4', "RFC 4122 version nibble");

        let cfg = serde_json::json!({ "min": 5, "max": 5 });
        let out = p
            .apply_resource_change(
                "random_integer",
                &null("random_integer"),
                &dv("random_integer", cfg.clone()),
                &dv("random_integer", cfg),
            )
            .await
            .unwrap();
        assert_eq!(field(&out, "random_integer", "result"), Some(num(5)));
    }
}
