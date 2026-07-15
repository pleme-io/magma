//! Security-group ingress compliance — the unbypassable gate.
//!
//! Every Pangea architecture eventually flows through here regardless
//! of which Ruby helper authored it (`create_resource`'s typed path,
//! the raw `resource()` DSL, or `synth.<type>(...)`) — the synthesized
//! Terraform JSON `Config` is the one universal shape magma consumes.
//! Confirmed live 2026-07-15: a hand-provisioned Camelot security group
//! carried an unrestricted `0.0.0.0/0` ingress rule on a NodePort
//! (unauthenticated Grafana, reachable from the entire internet) with
//! zero pipeline gate of any kind. A Ruby-side check would have missed
//! this exact case — `aws_security_group_rule` has no `pangea-aws`
//! wrapper in several architectures, so it never passes through
//! `Pangea::Resources::Base#create_resource`'s validation hook.
//!
//! Mirrors `pleme-lib`'s `compliance.enforce` / `_compliance_*.tpl`
//! shape (baseline-ranked, hard `fail()` at render time) at the one
//! layer that is genuinely universal: the plan step, before any diff
//! or apply is computed.

use std::collections::HashSet;

use magma_config::Config;
use magma_types::{ResourceAddress, ResourceKind, ResourceTypeId};

/// Ports where an unrestricted (`0.0.0.0/0`/`::/0`) ingress CIDR is an
/// intentional, common pattern (a public web endpoint / load balancer)
/// rather than an accidental exposure. Anything else — including a
/// range that merely *includes* one of these alongside other ports —
/// is a violation.
const ALLOWED_PUBLIC_PORTS: [i64; 2] = [80, 443];

const WORLD_IPV4: &str = "0.0.0.0/0";
const WORLD_IPV6: &str = "::/0";

/// Per-resource escape hatch. An architecture that genuinely needs a
/// world-open rule outside the default-allowed ports sets this
/// attribute explicitly — a conscious, auditable, per-resource
/// decision (visible in the committed Terraform JSON), never a
/// blanket kill switch on the whole check.
const ESCAPE_HATCH_ATTR: &str = "allow_public_ingress";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceViolation {
    pub address: ResourceAddress,
    pub reason: String,
}

impl std::fmt::Display for ComplianceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}: {}",
            self.address.type_id.0, self.address.name, self.reason
        )
    }
}

/// Walk every `aws_security_group_rule` and `aws_security_group` (inline
/// ingress blocks) in `config` and return every world-open-ingress
/// violation found. Empty result = compliant.
pub fn check_security_group_compliance(config: &Config) -> Vec<ComplianceViolation> {
    let mut violations = Vec::new();

    if let Some(by_name) = config.resources.get("aws_security_group_rule") {
        for (name, attrs) in by_name {
            if escape_hatch_set(attrs) {
                continue;
            }
            if !is_ingress_rule(attrs) {
                continue;
            }
            if let Some(reason) = world_open_violation(attrs) {
                violations.push(ComplianceViolation {
                    address: managed_address("aws_security_group_rule", name),
                    reason,
                });
            }
        }
    }

    if let Some(by_name) = config.resources.get("aws_security_group") {
        for (name, attrs) in by_name {
            if escape_hatch_set(attrs) {
                continue;
            }
            for block in inline_ingress_blocks(attrs) {
                if let Some(reason) = world_open_violation(block) {
                    violations.push(ComplianceViolation {
                        address: managed_address("aws_security_group", name),
                        reason,
                    });
                }
            }
        }
    }

    violations
}

fn managed_address(type_id: &str, name: &str) -> ResourceAddress {
    ResourceAddress {
        module: Default::default(),
        kind: ResourceKind::Managed,
        type_id: ResourceTypeId(type_id.to_string()),
        name: name.to_string(),
        key: None,
    }
}

fn escape_hatch_set(attrs: &serde_json::Value) -> bool {
    attrs
        .get(ESCAPE_HATCH_ATTR)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn is_ingress_rule(attrs: &serde_json::Value) -> bool {
    attrs.get("type").and_then(|v| v.as_str()) == Some("ingress")
}

/// A security group's own `ingress { ... }` inline blocks, normalized
/// to a `Vec` regardless of whether Pangea rendered one block as a
/// bare object or several as an array (both are valid Terraform JSON).
fn inline_ingress_blocks(attrs: &serde_json::Value) -> Vec<&serde_json::Value> {
    match attrs.get("ingress") {
        Some(serde_json::Value::Array(blocks)) => blocks.iter().collect(),
        Some(obj @ serde_json::Value::Object(_)) => vec![obj],
        _ => Vec::new(),
    }
}

fn cidrs_of(attrs: &serde_json::Value, key: &str) -> HashSet<String> {
    attrs
        .get(key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn world_open_violation(attrs: &serde_json::Value) -> Option<String> {
    let ipv4 = cidrs_of(attrs, "cidr_blocks");
    let ipv6 = cidrs_of(attrs, "ipv6_cidr_blocks");
    let world_open = ipv4.contains(WORLD_IPV4) || ipv6.contains(WORLD_IPV6);
    if !world_open {
        return None;
    }

    let from_port = attrs.get("from_port").and_then(|v| v.as_i64());
    let to_port = attrs.get("to_port").and_then(|v| v.as_i64());

    let single_allowed_port = match (from_port, to_port) {
        (Some(f), Some(t)) if f == t => ALLOWED_PUBLIC_PORTS.contains(&f),
        _ => false,
    };

    if single_allowed_port {
        return None;
    }

    Some(format!(
        "unrestricted ingress ({}/{} on ports {:?}..{:?}) — only exact port {:?} is allowed world-open by default; set `{}: true` if this is a deliberate, reviewed exception",
        WORLD_IPV4, WORLD_IPV6, from_port, to_port, ALLOWED_PUBLIC_PORTS, ESCAPE_HATCH_ATTR
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg_from(resources: serde_json::Value) -> Config {
        Config::from_json(json!({ "resource": resources })).unwrap()
    }

    #[test]
    fn world_open_ssh_is_a_violation() {
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "bad": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }));
        let v = check_security_group_compliance(&cfg);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].address.type_id.0, "aws_security_group_rule");
    }

    #[test]
    fn world_open_arbitrary_nodeport_is_a_violation() {
        // The exact shape of the live incident this check exists for.
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "grafana_nodeport": {
                    "type": "ingress",
                    "from_port": 32714,
                    "to_port": 32714,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }));
        let v = check_security_group_compliance(&cfg);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn world_open_443_is_allowed() {
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "https_in": {
                    "type": "ingress",
                    "from_port": 443,
                    "to_port": 443,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }));
        assert!(check_security_group_compliance(&cfg).is_empty());
    }

    #[test]
    fn world_open_range_spanning_443_is_still_a_violation() {
        // A range that HAPPENS to include 443 alongside other ports is
        // not the same as an exact single-port 443 rule.
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "wide_range": {
                    "type": "ingress",
                    "from_port": 1,
                    "to_port": 65535,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }));
        assert_eq!(check_security_group_compliance(&cfg).len(), 1);
    }

    #[test]
    fn scoped_cidr_is_never_a_violation() {
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "ssh_in": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["144.202.51.136/32"]
                }
            }
        }));
        assert!(check_security_group_compliance(&cfg).is_empty());
    }

    #[test]
    fn escape_hatch_suppresses_the_violation() {
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "reviewed_exception": {
                    "type": "ingress",
                    "from_port": 51820,
                    "to_port": 51820,
                    "protocol": "udp",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "allow_public_ingress": true
                }
            }
        }));
        assert!(check_security_group_compliance(&cfg).is_empty());
    }

    #[test]
    fn egress_rules_are_never_checked() {
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "all_egress": {
                    "type": "egress",
                    "from_port": 0,
                    "to_port": 0,
                    "protocol": "-1",
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }));
        assert!(check_security_group_compliance(&cfg).is_empty());
    }

    #[test]
    fn inline_security_group_ingress_block_is_checked() {
        let cfg = cfg_from(json!({
            "aws_security_group": {
                "web": {
                    "ingress": [
                        {
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"]
                        }
                    ]
                }
            }
        }));
        let v = check_security_group_compliance(&cfg);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].address.type_id.0, "aws_security_group");
    }

    #[test]
    fn inline_security_group_single_ingress_object_is_checked() {
        // Terraform JSON allows a single block to render as a bare
        // object instead of a one-element array.
        let cfg = cfg_from(json!({
            "aws_security_group": {
                "web": {
                    "ingress": {
                        "from_port": 3389,
                        "to_port": 3389,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                }
            }
        }));
        assert_eq!(check_security_group_compliance(&cfg).len(), 1);
    }

    #[test]
    fn ipv6_world_open_is_also_a_violation() {
        let cfg = cfg_from(json!({
            "aws_security_group_rule": {
                "v6_bad": {
                    "type": "ingress",
                    "from_port": 8080,
                    "to_port": 8080,
                    "protocol": "tcp",
                    "ipv6_cidr_blocks": ["::/0"]
                }
            }
        }));
        assert_eq!(check_security_group_compliance(&cfg).len(), 1);
    }
}
