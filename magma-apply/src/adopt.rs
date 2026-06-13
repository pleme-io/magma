//! magma-apply::adopt — the generic resource-adoption framework.
//!
//! Reconciliation-native answer to ObjectExistsUntracked: when a `Create`
//! collides with an object that already exists out-of-band
//! ([`crate::engine`]'s `is_already_exists`), magma ADOPTS it — discovers its
//! provider import id and imports it into state — instead of failing and
//! re-creating it every cycle (the create-conflict loop).
//!
//! Most providers key import on the resource `name` (a `github_repository`'s
//! import id IS its name). Some assign an OPAQUE server id that is absent from
//! config and only knowable by LISTING existing objects and matching the
//! resource's natural key — a `cloudflare_dns_record`'s import id is
//! `<zone_id>/<record_id>`, and `record_id` is only discoverable by reading
//! the `cloudflare_dns_records` data source.
//!
//! That opaque-id case is **data, not code**: each adoptable type is an
//! [`AdoptionSpec`] VALUE; one generic interpreter (the pure helpers here,
//! driven by the provider read in [`crate::engine`]) walks every spec. A new
//! adoptable variant is a new spec entry — built in via [`builtin_specs`]
//! today, overlay-able from typed config tomorrow (the spec derives serde, so
//! the typed-spec triplet's authoring layer slots in without touching the
//! interpreter). The interface stays uniform: no per-type code branch.
//!
//! This is the org CLAUDE.md ★★ TYPED-SPEC + INTERPRETER triplet applied to
//! adoption — a typed Rust border (`AdoptionSpec`), an authored spec set
//! (`builtin_specs`, future config overlay), and a working interpreter (the
//! pure helpers + the engine's provider read).

use serde::{Deserialize, Serialize};

/// Declarative descriptor of how to ADOPT a create-conflicted resource of one
/// type by discovering its opaque provider import id from a list data source.
/// A new adoptable variant is a new value of this type — never a new code
/// branch. serde-derived so the set can be overlaid from typed config (the
/// triplet's authoring layer) without changing the interpreter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptionSpec {
    /// Managed resource type this adopts (e.g. `"cloudflare_dns_record"`).
    pub resource_type: String,
    /// Provider list data source enumerating existing objects
    /// (e.g. `"cloudflare_dns_records"`).
    pub list_data_source: String,
    /// Data-source filter as a JSON template. String leaves of the exact form
    /// `{field}` are replaced with the resource config's `field` value
    /// ([`render_filter`]); the template's shape matches the data source's
    /// filter schema exactly (incl nested objects like cloudflare's
    /// `name: { "exact": "{name}" }`).
    pub filter_template: serde_json::Value,
    /// Fields that must be equal between the resource config and a list result
    /// row for the row to be THE match (the natural key).
    pub match_keys: Vec<String>,
    /// Import-id format. `{field}` pulls from config; `{result.field}` pulls
    /// from the matched result row ([`render_import_id`]).
    pub id_template: String,
}

/// The built-in adoption specs. Each entry is the only thing a new opaque-id
/// adoptable type adds — the interpreter is generic. (Config/Lisp overlay of
/// further entries is the next layer; the serde derive on [`AdoptionSpec`] is
/// the seam for it.)
#[must_use]
pub fn builtin_specs() -> Vec<AdoptionSpec> {
    vec![AdoptionSpec {
        resource_type: "cloudflare_dns_record".to_string(),
        list_data_source: "cloudflare_dns_records".to_string(),
        filter_template: serde_json::json!({
            "zone_id": "{zone_id}",
            "name": { "exact": "{name}" },
            "type": "{type}",
        }),
        match_keys: vec!["name".to_string(), "type".to_string()],
        id_template: "{zone_id}/{result.id}".to_string(),
    }]
}

/// The adoption spec for `resource_type`, if any opaque-id discovery is
/// registered for it.
#[must_use]
pub fn spec_for(resource_type: &str) -> Option<AdoptionSpec> {
    builtin_specs()
        .into_iter()
        .find(|s| s.resource_type == resource_type)
}

/// A whole-value placeholder string of the exact form `{field}` → `field`.
fn whole_placeholder(s: &str) -> Option<&str> {
    let inner = s.strip_prefix('{')?.strip_suffix('}')?;
    if inner.is_empty() || inner.contains('{') || inner.contains('}') {
        None
    } else {
        Some(inner)
    }
}

/// Render a data-source filter from `template` by replacing each string leaf of
/// the exact form `{field}` with `config[field]`. A placeholder whose field is
/// absent in `config` becomes JSON `null` (an unset filter). Non-placeholder
/// leaves pass through unchanged; nested objects/arrays recurse.
#[must_use]
pub fn render_filter(template: &serde_json::Value, config: &serde_json::Value) -> serde_json::Value {
    match template {
        serde_json::Value::String(s) => match whole_placeholder(s) {
            Some(field) => config.get(field).cloned().unwrap_or(serde_json::Value::Null),
            None => template.clone(),
        },
        serde_json::Value::Array(xs) => {
            serde_json::Value::Array(xs.iter().map(|x| render_filter(x, config)).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), render_filter(v, config)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Does `row` match `config` on every natural key in `match_keys`? A key
/// absent from EITHER side is a non-match (we never adopt on an unverifiable
/// key). String values compare by `as_str` (tolerating value-type differences);
/// otherwise by JSON equality.
#[must_use]
pub fn row_matches(row: &serde_json::Value, config: &serde_json::Value, match_keys: &[String]) -> bool {
    match_keys.iter().all(|k| {
        let (Some(cv), Some(rv)) = (config.get(k), row.get(k)) else {
            return false;
        };
        match (cv.as_str(), rv.as_str()) {
            (Some(a), Some(b)) => a == b,
            _ => cv == rv,
        }
    })
}

/// Render the import id from `template`, substituting `{field}` from `config`
/// and `{result.field}` from the matched `row`. Returns `None` if any
/// referenced field is missing or non-stringable — never a partial id.
#[must_use]
pub fn render_import_id(
    template: &str,
    config: &serde_json::Value,
    row: &serde_json::Value,
) -> Option<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}')? + open;
        let key = &rest[open + 1..close];
        let value = if let Some(field) = key.strip_prefix("result.") {
            row.get(field)
        } else {
            config.get(key)
        };
        out.push_str(value.and_then(serde_json::Value::as_str)?);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builtin_cloudflare_dns_record_spec_is_registered() {
        let s = spec_for("cloudflare_dns_record").expect("cloudflare_dns_record adoptable");
        assert_eq!(s.list_data_source, "cloudflare_dns_records");
        assert_eq!(s.match_keys, vec!["name".to_string(), "type".to_string()]);
        assert_eq!(s.id_template, "{zone_id}/{result.id}");
        // An unregistered type yields no spec → falls back to natural-id.
        assert!(spec_for("aws_s3_bucket").is_none());
    }

    #[test]
    fn render_filter_substitutes_nested_and_top_level() {
        let spec = spec_for("cloudflare_dns_record").unwrap();
        let config = json!({
            "zone_id": "955539184c733979ef69d42ccf814368",
            "name": "grafana.quero.cloud",
            "type": "CNAME",
            "content": "tunnel.cfargotunnel.com",
        });
        let filter = render_filter(&spec.filter_template, &config);
        assert_eq!(filter["zone_id"], "955539184c733979ef69d42ccf814368");
        assert_eq!(filter["name"]["exact"], "grafana.quero.cloud");
        assert_eq!(filter["type"], "CNAME");
    }

    #[test]
    fn render_filter_absent_field_becomes_null() {
        let tmpl = json!({ "zone_id": "{zone_id}", "type": "{type}" });
        let config = json!({ "zone_id": "z1" }); // no type
        let filter = render_filter(&tmpl, &config);
        assert_eq!(filter["zone_id"], "z1");
        assert!(filter["type"].is_null());
    }

    #[test]
    fn row_matches_on_name_and_type() {
        let keys = vec!["name".to_string(), "type".to_string()];
        let config = json!({ "name": "grafana.quero.cloud", "type": "CNAME" });
        let hit = json!({ "id": "rec-1", "name": "grafana.quero.cloud", "type": "CNAME" });
        let wrong_type = json!({ "id": "rec-2", "name": "grafana.quero.cloud", "type": "A" });
        let wrong_name = json!({ "id": "rec-3", "name": "auth.quero.cloud", "type": "CNAME" });
        assert!(row_matches(&hit, &config, &keys));
        assert!(!row_matches(&wrong_type, &config, &keys));
        assert!(!row_matches(&wrong_name, &config, &keys));
        // A key missing on the row is a non-match (never adopt unverifiably).
        assert!(!row_matches(&json!({ "name": "grafana.quero.cloud" }), &config, &keys));
    }

    #[test]
    fn render_import_id_combines_config_and_result() {
        let config = json!({ "zone_id": "955539184c733979ef69d42ccf814368" });
        let row = json!({ "id": "abc123", "name": "grafana.quero.cloud" });
        let id = render_import_id("{zone_id}/{result.id}", &config, &row).unwrap();
        assert_eq!(id, "955539184c733979ef69d42ccf814368/abc123");
        // A missing referenced field yields None — never a partial id.
        assert!(render_import_id("{zone_id}/{result.missing}", &config, &row).is_none());
    }

    #[test]
    fn end_to_end_discovery_shape() {
        // The full pure pipeline a provider read feeds: config + a result row →
        // filter (sent to the data source), match, import id.
        let spec = spec_for("cloudflare_dns_record").unwrap();
        let config = json!({
            "zone_id": "z9", "name": "grafana.quero.cloud", "type": "CNAME",
        });
        let result_rows = json!([
            { "id": "other", "name": "auth.quero.cloud", "type": "CNAME" },
            { "id": "the-one", "name": "grafana.quero.cloud", "type": "CNAME" },
        ]);
        let _filter = render_filter(&spec.filter_template, &config);
        let matched = result_rows
            .as_array()
            .unwrap()
            .iter()
            .find(|r| row_matches(r, &config, &spec.match_keys))
            .unwrap();
        let id = render_import_id(&spec.id_template, &config, matched).unwrap();
        assert_eq!(id, "z9/the-one");
    }

    #[test]
    fn adoption_spec_round_trips_through_config() {
        // The serde seam: the spec set can be authored/overlaid as typed config.
        let specs = builtin_specs();
        let yaml = serde_json::to_string(&specs).unwrap();
        let back: Vec<AdoptionSpec> = serde_json::from_str(&yaml).unwrap();
        assert_eq!(specs, back);
    }
}
