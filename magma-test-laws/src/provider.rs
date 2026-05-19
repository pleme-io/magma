//! Provider-resource law helpers — per-resource invariants for
//! individual Pangea typed functions (`synth.aws_vpc`,
//! `synth.aws_subnet`, etc.).
//!
//! Complements the architecture / workspace / chain law layers
//! with the missing per-resource level:
//!
//! ```text
//! Provider resource   ← THIS MODULE
//!     ↓
//! Pangea architecture ← magma_test_laws::architecture
//!     ↓
//! Workspace           ← magma_test_laws::workspace
//!     ↓
//! Chain               ← magma_test_laws::chain
//! ```
//!
//! Generic helpers — no hard-coded per-type knowledge. Consumers
//! compose them inside test code that knows the relevant Pangea
//! typed function:
//!
//! ```ignore
//! use magma_test_laws::provider::*;
//!
//! #[test]
//! fn vpc_emits_valid_cidr() {
//!     let cfg = render_pangea_workspace(&vpc_spec);
//!     assert_resource_has_field(&cfg, "aws_vpc", "main", "cidr_block").unwrap();
//!     assert_field_is_cidr(&cfg, "aws_vpc", "main", "cidr_block").unwrap();
//! }
//! ```
//!
//! Gated behind `provider-laws` feature.

use magma_config::Config;
use serde::{Deserialize, Serialize};

/// Typed violation surfaced by a provider law check. Stable
/// machine-readable shape so CR status / CI gates can route on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderViolation {
    /// Resource address `type.name` that violated.
    pub resource: String,
    /// Field within that resource (or "*" for resource-level
    /// violations).
    pub field:    String,
    /// Stable rule identifier (e.g. "required-field-present").
    pub rule:     String,
    /// Human-readable explanation.
    pub message:  String,
}

pub type ProviderResult = Result<(), ProviderViolation>;

// ── Resource lookup ───────────────────────────────────────────────

/// Find the attribute Value for a resource at `(type_id, name)`,
/// or return a typed `ResourceNotFound` violation.
pub fn resource_attrs<'a>(
    cfg: &'a Config,
    type_id: &str,
    name:    &str,
) -> Result<&'a serde_json::Value, ProviderViolation> {
    cfg.resources
        .get(type_id)
        .and_then(|by_name| by_name.get(name))
        .ok_or_else(|| ProviderViolation {
            resource: format!("{type_id}.{name}"),
            field:    "*".into(),
            rule:     "resource-exists".into(),
            message:  format!("resource {type_id}.{name} not declared"),
        })
}

// ── Field presence ────────────────────────────────────────────────

/// Assert a resource has a non-null field. Required for inputs the
/// downstream provider RPC must receive.
pub fn assert_resource_has_field(
    cfg:     &Config,
    type_id: &str,
    name:    &str,
    field:   &str,
) -> ProviderResult {
    let attrs = resource_attrs(cfg, type_id, name)?;
    let value = attrs.get(field);
    match value {
        Some(serde_json::Value::Null) | None => Err(ProviderViolation {
            resource: format!("{type_id}.{name}"),
            field:    field.into(),
            rule:     "required-field-present".into(),
            message:  format!("field `{field}` missing or null"),
        }),
        _ => Ok(()),
    }
}

// ── Field validators ──────────────────────────────────────────────

/// Assert a string field matches a CIDR-block shape (basic form
/// only — `1.2.3.4/N` or `::1/N`). Doesn't validate the
/// network is reachable; just that the syntax is well-formed.
pub fn assert_field_is_cidr(
    cfg:     &Config,
    type_id: &str,
    name:    &str,
    field:   &str,
) -> ProviderResult {
    let attrs = resource_attrs(cfg, type_id, name)?;
    let v = attrs.get(field).and_then(|v| v.as_str()).ok_or_else(|| ProviderViolation {
        resource: format!("{type_id}.{name}"),
        field:    field.into(),
        rule:     "cidr-format".into(),
        message:  format!("field `{field}` is missing or not a string"),
    })?;
    if !looks_like_cidr(v) {
        return Err(ProviderViolation {
            resource: format!("{type_id}.{name}"),
            field:    field.into(),
            rule:     "cidr-format".into(),
            message:  format!("field `{field}` value `{v}` is not a valid CIDR block"),
        });
    }
    Ok(())
}

/// Assert a string field matches an AWS ARN shape (`arn:partition:service:region:account:resource`).
/// 6+ colon-separated segments; segments may be empty in some
/// service-specific ARNs.
pub fn assert_field_is_arn(
    cfg:     &Config,
    type_id: &str,
    name:    &str,
    field:   &str,
) -> ProviderResult {
    let attrs = resource_attrs(cfg, type_id, name)?;
    let v = attrs.get(field).and_then(|v| v.as_str()).ok_or_else(|| ProviderViolation {
        resource: format!("{type_id}.{name}"),
        field:    field.into(),
        rule:     "arn-format".into(),
        message:  format!("field `{field}` is missing or not a string"),
    })?;
    if !v.starts_with("arn:") || v.splitn(7, ':').count() < 6 {
        return Err(ProviderViolation {
            resource: format!("{type_id}.{name}"),
            field:    field.into(),
            rule:     "arn-format".into(),
            message:  format!("field `{field}` value `{v}` is not a valid ARN"),
        });
    }
    Ok(())
}

/// Assert a string field is one of a fixed allow-list.
pub fn assert_field_is_one_of<S: AsRef<str>>(
    cfg:        &Config,
    type_id:    &str,
    name:       &str,
    field:      &str,
    allow_list: &[S],
) -> ProviderResult {
    let attrs = resource_attrs(cfg, type_id, name)?;
    let v = attrs.get(field).and_then(|v| v.as_str()).ok_or_else(|| ProviderViolation {
        resource: format!("{type_id}.{name}"),
        field:    field.into(),
        rule:     "one-of".into(),
        message:  format!("field `{field}` is missing or not a string"),
    })?;
    if !allow_list.iter().any(|a| a.as_ref() == v) {
        return Err(ProviderViolation {
            resource: format!("{type_id}.{name}"),
            field:    field.into(),
            rule:     "one-of".into(),
            message:  format!(
                "field `{field}` value `{v}` not in allow-list {:?}",
                allow_list.iter().map(|a| a.as_ref()).collect::<Vec<_>>(),
            ),
        });
    }
    Ok(())
}

// ── Security invariants ──────────────────────────────────────────

/// Refuse any IAM policy with a `"*"` Action or Resource without
/// an explicit prefix qualifier. Catches the common
/// "I'll fix permissions later" pattern that leaks in
/// architectures by accident.
pub fn assert_no_iam_wildcards(cfg: &Config) -> Result<(), Vec<ProviderViolation>> {
    let mut violations = vec![];

    for (type_id, by_name) in &cfg.resources {
        // Look at known IAM-policy resource types. The pattern
        // generalizes — any resource with a `policy` JSON field
        // gets the same treatment.
        if !type_id.contains("iam_policy") && !type_id.contains("iam_role_policy") {
            continue;
        }
        for (name, attrs) in by_name {
            // Policy can be a JSON string or a nested object.
            let policy_value = match attrs.get("policy") {
                Some(v) => v,
                None    => continue,
            };
            let policy_obj = match policy_value {
                serde_json::Value::String(s) => match serde_json::from_str::<serde_json::Value>(s) {
                    Ok(v) => v,
                    Err(_) => continue, // not parseable JSON — skip
                },
                other => other.clone(),
            };
            // Walk statements + check Action / Resource fields.
            if let Some(stmts) = policy_obj.get("Statement").and_then(|s| s.as_array()) {
                for (i, stmt) in stmts.iter().enumerate() {
                    for key in &["Action", "Resource"] {
                        if let Some(v) = stmt.get(*key) {
                            let actions: Vec<String> = match v {
                                serde_json::Value::String(s) => vec![s.clone()],
                                serde_json::Value::Array(a)  => a
                                    .iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect(),
                                _ => continue,
                            };
                            for action in actions {
                                if action == "*" {
                                    violations.push(ProviderViolation {
                                        resource: format!("{type_id}.{name}"),
                                        field:    format!("policy.Statement[{i}].{key}"),
                                        rule:     "no-iam-wildcards".into(),
                                        message:  format!(
                                            "IAM policy contains unqualified `*` for {key}"
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn looks_like_cidr(s: &str) -> bool {
    // <ip>/<prefix>; prefix is digits, IP is dotted-quad or
    // colon-separated hextets. Heuristic — refuses syntactically
    // bogus inputs, accepts the ones tofu would.
    let (ip, prefix) = match s.split_once('/') {
        Some(pair) => pair,
        None => return false,
    };
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let prefix_n: u32 = prefix.parse().unwrap_or(255);
    if prefix_n > 128 {
        return false;
    }
    // IPv4 dotted-quad
    if ip.contains('.') {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return false;
        }
        return parts.iter().all(|p| {
            !p.is_empty()
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|n| n < 256).unwrap_or(false)
        });
    }
    // IPv6 — colon-separated hextets; accept the abbreviated `::` form.
    if ip.contains(':') {
        return ip.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg_from(json_value: serde_json::Value) -> Config {
        Config::from_json(json_value).expect("Config::from_json")
    }

    #[test]
    fn resource_attrs_finds_existing_resource() {
        let c = cfg_from(json!({
            "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
        }));
        let attrs = resource_attrs(&c, "aws_vpc", "main").unwrap();
        assert_eq!(attrs["cidr_block"], "10.0.0.0/16");
    }

    #[test]
    fn resource_attrs_errors_on_missing_resource() {
        let c = cfg_from(json!({}));
        let err = resource_attrs(&c, "aws_vpc", "main").unwrap_err();
        assert_eq!(err.rule, "resource-exists");
    }

    #[test]
    fn required_field_present_passes() {
        let c = cfg_from(json!({
            "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
        }));
        assert_resource_has_field(&c, "aws_vpc", "main", "cidr_block").unwrap();
    }

    #[test]
    fn required_field_missing_errs() {
        let c = cfg_from(json!({
            "resource": { "aws_vpc": { "main": {} } }
        }));
        let err = assert_resource_has_field(&c, "aws_vpc", "main", "cidr_block").unwrap_err();
        assert_eq!(err.rule, "required-field-present");
    }

    #[test]
    fn cidr_field_validates_ipv4() {
        let c = cfg_from(json!({
            "resource": { "aws_vpc": { "main": { "cidr_block": "10.0.0.0/16" } } }
        }));
        assert_field_is_cidr(&c, "aws_vpc", "main", "cidr_block").unwrap();
    }

    #[test]
    fn cidr_field_rejects_bogus_value() {
        let c = cfg_from(json!({
            "resource": { "aws_vpc": { "main": { "cidr_block": "not-a-cidr" } } }
        }));
        let err = assert_field_is_cidr(&c, "aws_vpc", "main", "cidr_block").unwrap_err();
        assert_eq!(err.rule, "cidr-format");
    }

    #[test]
    fn cidr_field_validates_ipv6() {
        let c = cfg_from(json!({
            "resource": { "aws_vpc": { "main": { "ipv6_block": "::/0" } } }
        }));
        assert_field_is_cidr(&c, "aws_vpc", "main", "ipv6_block").unwrap();
    }

    #[test]
    fn arn_field_validates_well_formed() {
        let c = cfg_from(json!({
            "resource": { "aws_iam_role": { "x": { "arn": "arn:aws:iam::123:role/foo" } } }
        }));
        assert_field_is_arn(&c, "aws_iam_role", "x", "arn").unwrap();
    }

    #[test]
    fn arn_field_rejects_non_arn() {
        let c = cfg_from(json!({
            "resource": { "aws_iam_role": { "x": { "arn": "not-an-arn" } } }
        }));
        let err = assert_field_is_arn(&c, "aws_iam_role", "x", "arn").unwrap_err();
        assert_eq!(err.rule, "arn-format");
    }

    #[test]
    fn one_of_accepts_allowed_value() {
        let c = cfg_from(json!({
            "resource": { "aws_instance": { "x": { "instance_type": "t3.small" } } }
        }));
        let allow: &[&str] = &["t3.small", "t3.medium"];
        assert_field_is_one_of(&c, "aws_instance", "x", "instance_type", allow).unwrap();
    }

    #[test]
    fn one_of_rejects_disallowed_value() {
        let c = cfg_from(json!({
            "resource": { "aws_instance": { "x": { "instance_type": "m6.xlarge" } } }
        }));
        let allow: &[&str] = &["t3.small", "t3.medium"];
        let err = assert_field_is_one_of(&c, "aws_instance", "x", "instance_type", allow).unwrap_err();
        assert_eq!(err.rule, "one-of");
    }

    #[test]
    fn iam_wildcard_action_is_caught() {
        let c = cfg_from(json!({
            "resource": {
                "aws_iam_policy": {
                    "lazy": {
                        "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
                    }
                }
            }
        }));
        let violations = assert_no_iam_wildcards(&c).unwrap_err();
        assert_eq!(violations.len(), 2, "expected wildcard in both Action and Resource");
    }

    #[test]
    fn iam_qualified_action_passes() {
        let c = cfg_from(json!({
            "resource": {
                "aws_iam_policy": {
                    "scoped": {
                        "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bucket/*\"}]}"
                    }
                }
            }
        }));
        assert_no_iam_wildcards(&c).unwrap();
    }
}
