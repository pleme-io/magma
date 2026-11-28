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
    /// How the read presents its candidates.
    #[serde(default)]
    pub rows: Rows,
}

/// The built-in adoption specs. Each entry is the only thing a new opaque-id
/// adoptable type adds — the interpreter is generic. (Config/Lisp overlay of
/// further entries is the next layer; the serde derive on [`AdoptionSpec`] is
/// the seam for it.)
#[must_use]
pub fn builtin_specs() -> Vec<AdoptionSpec> {
    vec![
        AdoptionSpec {
            resource_type: "cloudflare_dns_record".to_string(),
            list_data_source: "cloudflare_dns_records".to_string(),
            filter_template: serde_json::json!({
                "zone_id": "{zone_id}",
                "name": { "exact": "{name}" },
                "type": "{type}",
            }),
            match_keys: vec!["name".to_string(), "type".to_string()],
            id_template: "{zone_id}/{result.id}".to_string(),
            rows: Rows::ResultList,
        },
        AdoptionSpec {
            resource_type: "aws_iam_policy".to_string(),
            list_data_source: "aws_iam_policy".to_string(),
            filter_template: serde_json::json!({ "name": "{name}" }),
            match_keys: vec!["name".to_string()],
            id_template: "{result.arn}".to_string(),
            rows: Rows::Singleton,
        },
        AdoptionSpec {
            resource_type: "aws_budgets_budget".to_string(),
            list_data_source: "aws_budgets_budget".to_string(),
            filter_template: serde_json::json!({ "name": "{name}" }),
            match_keys: vec!["name".to_string()],
            id_template: "{result.account_id}:{name}".to_string(),
            rows: Rows::Singleton,
        },
    ]
}

/// The adoption spec for `resource_type`, if any opaque-id discovery is
/// registered for it.
#[must_use]
pub fn spec_for(resource_type: &str) -> Option<AdoptionSpec> {
    builtin_specs()
        .into_iter()
        .find(|s| s.resource_type == resource_type)
}

/// Where a data source's read puts the candidate objects.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Rows {
    /// A list data source: the candidates are its `result` array.
    #[default]
    ResultList,
    /// A lookup data source: the read itself is the one candidate.
    Singleton,
}

/// The candidate rows a data-source read offers for matching.
#[must_use]
pub fn rows_of(spec: &AdoptionSpec, result: &serde_json::Value) -> Vec<serde_json::Value> {
    match spec.rows {
        Rows::ResultList => result
            .get("result")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Rows::Singleton if result.is_object() => vec![result.clone()],
        Rows::Singleton => Vec::new(),
    }
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
pub fn render_filter(
    template: &serde_json::Value,
    config: &serde_json::Value,
) -> serde_json::Value {
    match template {
        serde_json::Value::String(s) => match whole_placeholder(s) {
            Some(field) => config
                .get(field)
                .cloned()
                .unwrap_or(serde_json::Value::Null),
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
pub fn row_matches(
    row: &serde_json::Value,
    config: &serde_json::Value,
    match_keys: &[String],
) -> bool {
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

// ── The pre-create identity probe ─────────────────────────────────────
//
// The THIRD adoption directive source. `spec.importHints` adopts ids the
// operator already knows; `importPolicy.autoOnConflict` adopts AFTER a
// create collides. Both are reactive to a conflict the provider reports.
// The 2026-11-15 control-plane move proved the hole in that: types whose
// Create can never return AlreadyExists (AWS mints unlimited duplicates —
// `aws_vpc`, `aws_subnet`, `aws_security_group`, `aws_eip`) silently
// re-created a LIVE estate as full twins with identical tags, because
// there was no conflict to react to. The probe is proactive: BEFORE a
// planned Create for a state-absent address, ask the provider whether the
// resource's own declared identity already exists live.
//
// For these types the identity magma can resolve before creating IS the
// declared tag set (Name + house tag): every EC2 list data source takes a
// `tags` map whose pairs "must exactly match" (verified against
// hashicorp/aws docs for all four rows below), and answers with the ids
// of everything carrying them. So one rule shape covers the class — a
// list data source, a tags-map filter, and the attribute the ids come
// back in.

/// One row of the probe catalog: how to ask the live provider whether a
/// resource of `resource_type` already exists under its declared tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRule {
    /// The managed resource type this rule probes (`aws_vpc`).
    pub resource_type: &'static str,
    /// The provider list data source that enumerates live objects of the
    /// type, filtered by a `tags` map (`aws_vpcs`).
    pub list_data_source: &'static str,
    /// The attribute of the read result carrying the matched ids
    /// (`ids`, or `allocation_ids` for `aws_eips`).
    pub ids_attr: &'static str,
}

/// **The** probe table. A type with a row here is probed before every
/// planned Create for a state-absent address; a type without one is never
/// probed (no behavior change). The four rows are the types that minted
/// the 2026-11-15 twin estate — AWS types whose Create succeeds silently
/// on a duplicate. Adding a type is a row, not a branch.
pub const PROBE_RULES: &[ProbeRule] = &[
    ProbeRule {
        resource_type: "aws_vpc",
        list_data_source: "aws_vpcs",
        ids_attr: "ids",
    },
    ProbeRule {
        resource_type: "aws_subnet",
        list_data_source: "aws_subnets",
        ids_attr: "ids",
    },
    ProbeRule {
        resource_type: "aws_security_group",
        list_data_source: "aws_security_groups",
        ids_attr: "ids",
    },
    ProbeRule {
        resource_type: "aws_eip",
        list_data_source: "aws_eips",
        ids_attr: "allocation_ids",
    },
];

/// The probe rule for a resource type, if any.
#[must_use]
pub fn probe_rule_for(resource_type: &str) -> Option<&'static ProbeRule> {
    PROBE_RULES
        .iter()
        .find(|r| r.resource_type == resource_type)
}

/// The declared tag map of a resource's attributes, IF it is a usable
/// probe identity: present, non-empty, and every value a literal string.
///
/// A missing or empty tag map has no identity to key on (a `tags: {}`
/// filter would match the whole account — the many-match refusal fired by
/// everything, which is collateral scope, not safety). A tag value that
/// still carries a `${…}` reference cannot be resolved before the plan
/// runs, so the probe would query with the literal string and read its
/// silence as freshness — exactly the fast-negative probe failure the
/// house forbids. Both return `None`: no probe, and the address proceeds
/// exactly as it did before the probe existed.
#[must_use]
pub fn literal_tags(
    attrs: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    let tags = attrs.get("tags")?.as_object()?;
    if tags.is_empty() {
        return None;
    }
    tags.values()
        .all(|v| {
            v.as_str()
                .is_some_and(|s| !s.contains("${") && !s.contains("$${"))
        })
        .then_some(tags)
}

/// The data-source read config for a probe: the declared tag map, passed
/// as the `tags` filter every catalog row's list data source accepts
/// ("each pair must exactly match"). The tags are used verbatim — the
/// provider does the identity matching server-side, so what comes back is
/// the provider's own answer, not a client-side re-implementation of it.
#[must_use]
pub fn probe_filter(tags: &serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
    serde_json::json!({ "tags": tags })
}

/// The live ids a probe read matched, from the result's `ids_attr`.
///
/// `None` is a contract miss — the read succeeded but the attribute the
/// rule names is absent or not an array of strings. That is a malformed
/// answer, not "no matches" (`ids: []`), and reading it as zero would
/// turn a broken data source into a license to create.
#[must_use]
pub fn matched_ids(result: &serde_json::Value, ids_attr: &str) -> Option<Vec<String>> {
    let ids = result.get(ids_attr)?.as_array()?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(id.as_str()?.to_string());
    }
    Some(out)
}

/// An adopted resource whose tags disagree with the declared ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagMismatch {
    pub tag: String,
    pub planned: String,
    pub imported: String,
}

/// Confirm the resource the probe adopted carries the declared identity.
///
/// The tags ARE the probe's identity key, so this is the probe's own
/// [`crate::natural_id::verify_identity`]: the data-source filter matched
/// server-side, and this checks the CONFIRMED read of the adopted object
/// against the same declaration client-side. Semantics match
/// `verify_identity` exactly: only where BOTH sides carry a value — an
/// absent tag map on a sparse import stub is silence, not disagreement —
/// and the comparison is submap-wise (every DECLARED tag must agree; tags
/// the live resource carries beyond the declaration are extra identity,
/// not a wrong resource).
///
/// # Errors
/// Returns the first declared tag whose imported value disagrees.
pub fn verify_declared_tags(
    declared_tags: &serde_json::Map<String, serde_json::Value>,
    imported_attrs: &serde_json::Value,
) -> Result<(), TagMismatch> {
    let Some(imported_tags) = imported_attrs.get("tags").and_then(|t| t.as_object()) else {
        return Ok(());
    };
    for (k, planned) in declared_tags {
        let (Some(planned), Some(actual)) = (planned.as_str(), imported_tags.get(k)) else {
            continue;
        };
        if let Some(actual) = actual.as_str() {
            if planned != actual {
                return Err(TagMismatch {
                    tag: k.clone(),
                    planned: planned.to_string(),
                    imported: actual.to_string(),
                });
            }
        }
    }
    Ok(())
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
        assert!(!row_matches(
            &json!({ "name": "grafana.quero.cloud" }),
            &config,
            &keys
        ));
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
    fn aws_iam_policy_adopts_by_the_arn_its_own_data_source_reports() {
        let spec = spec_for("aws_iam_policy").expect("aws_iam_policy adoptable");
        let config = json!({ "name": "pangea-operator-ryn-policy", "policy": "{}" });
        let result = json!({
            "arn": "arn:aws:iam::123456789012:policy/pangea-operator-ryn-policy",
            "name": "pangea-operator-ryn-policy",
            "path": "/",
        });
        let filter = render_filter(&spec.filter_template, &config);
        assert_eq!(filter["name"], "pangea-operator-ryn-policy");
        let rows = rows_of(&spec, &result);
        let matched = rows
            .iter()
            .find(|r| row_matches(r, &config, &spec.match_keys))
            .expect("the policy the data source found is the planned one");
        assert_eq!(
            render_import_id(&spec.id_template, &config, matched).as_deref(),
            Some("arn:aws:iam::123456789012:policy/pangea-operator-ryn-policy")
        );
    }

    #[test]
    fn aws_budgets_budget_adopts_by_account_and_name_without_an_authored_account() {
        let spec = spec_for("aws_budgets_budget").expect("aws_budgets_budget adoptable");
        let config = json!({ "name": "kensa-pentest-monthly", "budget_type": "COST" });
        let result = json!({ "account_id": "123456789012", "name": "kensa-pentest-monthly" });
        let rows = rows_of(&spec, &result);
        let matched = rows
            .iter()
            .find(|r| row_matches(r, &config, &spec.match_keys))
            .expect("the budget the data source found is the planned one");
        assert_eq!(
            render_import_id(&spec.id_template, &config, matched).as_deref(),
            Some("123456789012:kensa-pentest-monthly")
        );
    }

    #[test]
    fn a_singleton_read_naming_a_different_object_is_not_a_match() {
        let spec = spec_for("aws_iam_policy").unwrap();
        let config = json!({ "name": "pangea-operator-ryn-policy" });
        let result = json!({ "arn": "arn:aws:iam::1:policy/other", "name": "other" });
        assert!(
            rows_of(&spec, &result)
                .iter()
                .all(|r| !row_matches(r, &config, &spec.match_keys))
        );
    }

    #[test]
    fn a_list_spec_still_reads_its_result_rows() {
        let spec = spec_for("cloudflare_dns_record").unwrap();
        let result = json!({ "result": [{ "id": "a" }, { "id": "b" }] });
        assert_eq!(rows_of(&spec, &result).len(), 2);
        assert!(rows_of(&spec, &json!({ "zone_id": "z" })).is_empty());
    }

    #[test]
    fn adoption_spec_round_trips_through_config() {
        // The serde seam: the spec set can be authored/overlaid as typed config.
        let specs = builtin_specs();
        let yaml = serde_json::to_string(&specs).unwrap();
        let back: Vec<AdoptionSpec> = serde_json::from_str(&yaml).unwrap();
        assert_eq!(specs, back);
    }

    // ── The pre-create identity probe catalog ────────────────────────────

    #[test]
    fn probe_rules_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for r in PROBE_RULES {
            assert!(
                seen.insert(r.resource_type),
                "duplicate probe rule for {}",
                r.resource_type
            );
            assert!(
                !r.list_data_source.is_empty() && !r.ids_attr.is_empty(),
                "{} has an incomplete probe rule",
                r.resource_type
            );
            // The row names a DIFFERENT data source than the type — the
            // plural list source, not the singular lookup the type's own
            // name would suggest. A copy-paste row that probes the managed
            // type itself produces a filter the provider cannot serve.
            assert_ne!(
                r.resource_type, r.list_data_source,
                "{} must probe a LIST data source",
                r.resource_type
            );
        }
    }

    /// THE forcing function, same discipline as
    /// `natural_id::every_catalog_row_is_exercised`: one expectation per
    /// [`PROBE_RULES`] row, so a row that lands without a proven filter +
    /// ids extraction fails the build rather than shipping an unproven probe.
    #[test]
    fn every_probe_rule_is_exercised() {
        struct Row {
            ty: &'static str,
            ids_attr: &'static str,
            result: serde_json::Value,
            expect: Vec<&'static str>,
        }
        let matrix: &[Row] = &[
            Row {
                ty: "aws_vpc",
                ids_attr: "ids",
                result: json!({ "id": "sa-east-1", "ids": ["vpc-0a1b2c"] }),
                expect: vec!["vpc-0a1b2c"],
            },
            Row {
                ty: "aws_subnet",
                ids_attr: "ids",
                result: json!({ "id": "sa-east-1", "ids": ["subnet-1", "subnet-2"] }),
                expect: vec!["subnet-1", "subnet-2"],
            },
            Row {
                ty: "aws_security_group",
                ids_attr: "ids",
                result: json!({ "id": "sa-east-1", "ids": ["sg-9"], "arns": ["arn:..."] }),
                expect: vec!["sg-9"],
            },
            // The one row whose ids attribute is NOT `ids` — `aws_eips`
            // answers with `allocation_ids`, and a copy-pasted row reading
            // `ids` would read every estate as empty and license a create.
            Row {
                ty: "aws_eip",
                ids_attr: "allocation_ids",
                result: json!({ "id": "sa-east-1", "allocation_ids": ["eipalloc-1"] }),
                expect: vec!["eipalloc-1"],
            },
        ];
        assert_eq!(
            matrix.len(),
            PROBE_RULES.len(),
            "every PROBE_RULES row needs an exercised expectation"
        );
        for row in matrix {
            let rule = probe_rule_for(row.ty)
                .unwrap_or_else(|| panic!("matrix row {} is not in PROBE_RULES", row.ty));
            assert_eq!(rule.ids_attr, row.ids_attr, "{}", row.ty);
            assert_eq!(
                matched_ids(&row.result, rule.ids_attr).unwrap(),
                row.expect
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<Vec<_>>(),
                "{}",
                row.ty
            );
            // The filter is the declared tags verbatim under `tags`.
            let tags = json!({ "Name": "engenho", "pleme.io/managed": "true" });
            let filter = probe_filter(tags.as_object().unwrap());
            assert_eq!(filter["tags"]["Name"], "engenho", "{}", row.ty);
        }
        // A type with no row is never probed — no behavior change.
        assert!(probe_rule_for("aws_s3_bucket").is_none());
        assert!(probe_rule_for("github_repository").is_none());
    }

    /// The probe's identity key must be LITERAL. An interpolated tag
    /// (`${var.env}`) cannot be resolved before the plan runs, and probing
    /// with the raw string would read silence as freshness — the exact
    /// shape of probe failure the absence-second-probe rule exists for.
    #[test]
    fn an_interpolated_or_missing_tag_map_is_not_a_probe_identity() {
        assert!(literal_tags(&json!({ "tags": { "Name": "engenho" } })).is_some());
        assert!(
            literal_tags(&json!({ "cidr_block": "10.0.0.0/16" })).is_none(),
            "no tags declared: no identity to key on"
        );
        assert!(
            literal_tags(&json!({ "tags": {} })).is_none(),
            "an empty tag map would match the whole account"
        );
        assert!(
            literal_tags(&json!({ "tags": { "Name": "${var.name}" } })).is_none(),
            "an unresolved reference is not a literal identity"
        );
        assert!(
            literal_tags(&json!({ "tags": { "Name": 7 } })).is_none(),
            "a non-string tag value is not a filter the data source accepts"
        );
    }

    /// A read that answers but not with the attribute the rule names is a
    /// contract miss, not zero matches.
    #[test]
    fn a_result_without_the_ids_attribute_is_a_contract_miss_not_zero() {
        assert_eq!(matched_ids(&json!({ "ids": [] }), "ids"), Some(vec![]));
        assert_eq!(matched_ids(&json!({ "id": "sa-east-1" }), "ids"), None);
        assert_eq!(matched_ids(&json!({ "ids": "vpc-1" }), "ids"), None);
        assert_eq!(matched_ids(&json!({ "ids": [1, 2] }), "ids"), None);
    }

    #[test]
    fn declared_tags_agree_submap_wise_and_silence_is_not_disagreement() {
        let declared = json!({ "Name": "engenho", "pleme.io/managed": "true" });
        let tags = declared.as_object().unwrap();
        // Extra live tags are extra identity, not a wrong resource.
        assert_eq!(
            verify_declared_tags(
                tags,
                &json!({ "tags": { "Name": "engenho", "pleme.io/managed": "true", "Team": "infra" } })
            ),
            Ok(())
        );
        // A sparse import stub with no tags at all: silence.
        assert_eq!(
            verify_declared_tags(tags, &json!({ "id": "vpc-1" })),
            Ok(())
        );
        // One declared tag disagreeing: refusal, naming the tag.
        assert_eq!(
            verify_declared_tags(tags, &json!({ "tags": { "Name": "other-estate" } })),
            Err(TagMismatch {
                tag: "Name".into(),
                planned: "engenho".into(),
                imported: "other-estate".into(),
            })
        );
    }
}
