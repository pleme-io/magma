//! magma-plan — plan algorithm: `Config × State → Plan`.
//!
//! The load-bearing semantics layer. Walks config + state, emits typed
//! `ResourceChange`s. M0 ships a config-subset drift heuristic for
//! resources present in both config and state: any config-declared
//! attribute that differs from the stored state value is classified
//! `Action::Update` + `ChangeReason::AttributeDrift`; attributes present
//! only in state (computed-only fields — `id`, `arn`, timestamps, ...)
//! are never inspected, so they can never cause a false positive. Full
//! schema-aware diffing — the Update-vs-Replace distinction
//! (`requires_replace` per attribute) and provider-typed comparison in
//! place of raw `serde_json::Value` equality — still requires provider
//! schema access via `PlanResourceChange` and lands in M0.x once
//! magma-protocol's gRPC bindings are wired in here. The apply-side RPC
//! plumbing for `Action::Update` already exists (see
//! `magma-apply`'s engine catch-all apply arm).
//!
//! Per `theory/MAGMA.md` §X.1, OpenTofu has documented plan-diff
//! quirks. Magma matches bug-for-bug for M0–M2 — each documented
//! quirk is a `magma_known_quirk!` proptest case so regressions surface
//! immediately.

use std::collections::HashSet;

use chrono::Utc;
use magma_attest::hash_plan_inputs;
use magma_config::Config;
use magma_types::{Action, ChangeReason, Plan, ResourceAddress, ResourceChange, State};

mod compliance;
pub use compliance::{
    check_cache_encryption, check_database_public_accessibility, check_security_group_compliance,
    run_compliance_checks, ComplianceBaseline, ComplianceViolation,
};

// ── Errors ─────────────────────────────────────────────────────────

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("config error: {0}")]
    Config(#[from] magma_config::ConfigError),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("compliance violation — refusing to plan:\n{}", .0.iter().map(|v| format!("  - {v}")).collect::<Vec<_>>().join("\n"))]
    Compliance(Vec<ComplianceViolation>),
}

// ── Plan ──────────────────────────────────────────────────────────

/// Compute a typed `Plan` from `config` against `state` — the M0
/// structural diff plus a config-subset drift heuristic for
/// in-both resources (see module docs). Full schema-aware diffing
/// still needs the `PlanResourceChange` provider RPC integration.
pub fn plan(config: &Config, state: &State) -> Result<Plan, PlanError> {
    // Compliance gate — default-on, unbypassable (every architecture's
    // Ruby DSL choice converges here). Refuse to compute a plan at all
    // if the config violates the configured baseline (world-open
    // security-group ingress; at High, also public databases and
    // unencrypted caches). See compliance.rs.
    let baseline = ComplianceBaseline::from_env();
    let violations = run_compliance_checks(config, baseline);
    if !violations.is_empty() {
        return Err(PlanError::Compliance(violations));
    }

    let config_addrs: HashSet<ResourceAddress> = config.resource_addresses().collect();
    let state_addrs: HashSet<ResourceAddress> =
        state.resources.iter().map(|r| r.address.clone()).collect();

    let mut changes: Vec<ResourceChange> = Vec::new();

    // Create: in config, not in state.
    for addr in config_addrs.difference(&state_addrs) {
        let after = lookup_config_value(config, addr);
        changes.push(ResourceChange {
            address: addr.clone(),
            action: Action::Create,
            before: None,
            after,
            reasons: vec![ChangeReason::NewResource],
        });
    }

    // Delete: in state, not in config.
    for addr in state_addrs.difference(&config_addrs) {
        let before = lookup_state_value(state, addr);
        changes.push(ResourceChange {
            address: addr.clone(),
            action: Action::Delete,
            before,
            after: None,
            reasons: vec![ChangeReason::DeletedResource],
        });
    }

    // Resolution map (`{type → {name → attributes}}`, `data` nested one
    // level deeper) built from the full state — the plan-time counterpart
    // of `magma-apply::engine`'s apply-time `state_map`. Needed below to
    // resolve `${type.name.attr}` cross-resource references BEFORE
    // diffing a resource's declared config against its stored state: a
    // rendered config carries those references LITERALLY (Pangea emits
    // `vpc_id = "${aws_vpc.main.id}"` verbatim; real Terraform resolves
    // it against already-applied state before diffing) — comparing the
    // literal string to the concrete value already in state made every
    // resource with a cross-reference unconditionally report drift.
    let state_map = magma_config::state_resolution_map(state);

    // Update: in both. Compare only the CONFIG-DECLARED attribute set.
    // `before` (state) is the full provider-schema-shaped attribute set,
    // including every computed field (id, arn, timestamps, ...); `after`
    // (config) is the raw user-declared JSON with no computed fields. A
    // whole-object `before != after` comparison would therefore be true
    // for essentially every real resource on every cycle — a structural
    // false positive, not an edge case. Scoping the comparison to
    // `after`'s keys makes that false positive impossible: a
    // computed-only key present solely in `before` is never inspected.
    for addr in config_addrs.intersection(&state_addrs) {
        let before = lookup_state_value(state, addr);
        let after = lookup_config_value(config, addr);
        // Resolve interpolations in a THROWAWAY copy used ONLY for the
        // drift comparison below — the `after` stored on the emitted
        // `ResourceChange` stays raw/unresolved. `magma-apply::engine`'s
        // dependency-graph builder (`collect_refs`/`ref_target`) scans a
        // real change's `after` for literal `${type.name.attr}` strings
        // to compute apply order; resolving it here would erase those
        // edges and silently break apply ordering for every resource
        // this plan still classifies as a genuine change.
        //
        // A reference that fails to resolve (e.g. it targets a resource
        // this same plan only just created, so it has no prior state to
        // resolve against) falls back to the raw, unresolved value — the
        // pre-existing, safe-by-erring-toward-drift behavior. It never
        // silently degrades to NoOp on a resolution failure.
        let after_resolved = after.as_ref().map(|v| {
            magma_config::resolve_config(v, &state_map).unwrap_or_else(|_| v.clone())
        });
        let drifted = declared_attributes_drifted(&before, &after_resolved);
        let (action, reasons) = if drifted {
            (Action::Update, vec![ChangeReason::AttributeDrift])
        } else {
            (Action::NoOp, vec![])
        };
        changes.push(ResourceChange {
            address: addr.clone(),
            action,
            before,
            after,
            reasons,
        });
    }

    // Deterministic order — proptest needs stable plan output.
    changes.sort_by_key(|c| {
        (
            c.address.type_id.0.clone(),
            c.address.name.clone(),
            format!("{:?}", c.address.key),
        )
    });

    // Hash inputs for the typed PlanId.
    let canonical = serde_json::to_vec(&PlanInputs {
        changes: &changes,
        state_serial: state.serial,
        state_lineage: state.lineage,
    })?;
    let plan_id = hash_plan_inputs(&canonical);

    Ok(Plan {
        id: plan_id,
        created_at: Utc::now(),
        config_root: std::path::PathBuf::new(),
        variables: Default::default(),
        resource_changes: changes,
        output_changes: Vec::new(),
    })
}

fn lookup_config_value(config: &Config, addr: &ResourceAddress) -> Option<serde_json::Value> {
    config
        .resources
        .get(&addr.type_id.0)
        .and_then(|by_name| by_name.get(&addr.name))
        .cloned()
}

/// Look up the diffable attribute value for `addr`.
///
/// `magma-config::Config::resource_addresses()` never expands
/// `count`/`for_each` (neither Pangea nor magma's JSON config reader
/// supports either today — see `theory/MAGMA.md` §IX), so every
/// config-declared address is inherently singular: at most one
/// `StateInstance` is ever the "right" one to diff against. A real,
/// pre-existing state file adopted from tofu/terraform CAN carry
/// multiple instances under one address (a resource originally
/// created with `count`/`for_each`); taking `.first()` unconditionally
/// would silently drop drift in every instance but the first — the
/// exact silent-corruption class this function must not produce.
/// Until config-side `count`/`for_each` expansion lands, magma still
/// diffs only the first instance (there is no config-side target for
/// the others to diff against), but a multi-instance match is surfaced
/// loudly via `tracing::warn!` instead of silently swallowed.
fn lookup_state_value(state: &State, addr: &ResourceAddress) -> Option<serde_json::Value> {
    let resource = state.resources.iter().find(|r| r.address == *addr)?;
    if resource.instances.len() > 1 {
        tracing::warn!(
            address = %format!("{}.{}", addr.type_id.0, addr.name),
            instance_count = resource.instances.len(),
            "state resource has multiple instances (count/for_each) but magma-config \
             does not expand count/for_each; diffing only the first instance — drift \
             in the remaining instances is not detected",
        );
    }
    resource.instances.first().map(|i| i.attributes.clone())
}

/// Config-subset drift comparison: `true` iff some attribute `after`
/// (config) actually declares differs from the matching attribute in
/// `before` (state). Keys present only in `before` — computed-only
/// fields the provider populates (`id`, `arn`, timestamps, ...) — are
/// never inspected, so they can never trigger a false positive.
///
/// The per-key comparison recurses into nested JSON objects with the
/// SAME subset semantics (`subset_matches`, below): a nested attribute
/// (`tags`, `vpc_config`, `scaling_config`, ...) is only drifted if a key
/// the config actually declares differs — extra keys a provider injects
/// into a nested map (e.g. AWS's auto-added `kubernetes.io/cluster/<name>`
/// tag alongside a config-declared `tags = { Name = "x" }`) are not
/// drift, matching real Terraform's own attribute-diff semantics (state
/// carrying MORE nested keys than config declares is never itself
/// treated as a change).
fn declared_attributes_drifted(
    before: &Option<serde_json::Value>,
    after: &Option<serde_json::Value>,
) -> bool {
    let Some(after_val) = after else {
        // Nothing declared in config — nothing to compare.
        return false;
    };
    let Some(after_obj) = after_val.as_object() else {
        // Config value isn't a JSON object (unexpected shape for a
        // resource attribute map) — fall back to a whole-value
        // comparison rather than silently treating it as never-drifted.
        return before.as_ref() != Some(after_val);
    };
    match before.as_ref().and_then(|v| v.as_object()) {
        Some(before_obj) => after_obj.iter().any(|(k, after_v)| {
            !before_obj
                .get(k)
                .is_some_and(|before_v| subset_matches(before_v, after_v))
        }),
        // State has no recorded instance attributes at all (or they
        // aren't an object) but config declares some — every declared
        // key is effectively new.
        None => !after_obj.is_empty(),
    }
}

/// `true` iff `after_v` (a config-declared value) subset-matches
/// `before_v` (the corresponding stored-state value). JSON objects
/// recurse with the same subset semantics used at the top level of
/// `declared_attributes_drifted` — every key `after_v` declares must be
/// present in `before_v` with a (recursively) subset-matching value; a
/// key present ONLY in `before_v`, at any nesting depth, is never drift.
/// Arrays and scalars still compare by whole-value equality — real
/// Terraform DOES flag any difference in a list/scalar attribute; the
/// "extra keys aren't drift" relief is specific to object-valued
/// (map / nested-block) attributes.
fn subset_matches(before_v: &serde_json::Value, after_v: &serde_json::Value) -> bool {
    match (before_v, after_v) {
        (serde_json::Value::Object(before_obj), serde_json::Value::Object(after_obj)) => after_obj
            .iter()
            .all(|(k, av)| before_obj.get(k).is_some_and(|bv| subset_matches(bv, av))),
        _ => before_v == after_v,
    }
}

#[derive(serde::Serialize)]
struct PlanInputs<'a> {
    changes: &'a [ResourceChange],
    state_serial: u64,
    state_lineage: uuid::Uuid,
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_types::{InstanceStatus, ProviderReference, StateInstance, StateResource};
    use serde_json::json;

    fn empty_state() -> State {
        State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: uuid::Uuid::new_v4(),
            outputs: Default::default(),
            resources: Vec::new(),
        }
    }

    fn cfg_with_vpc() -> Config {
        let json_v = json!({
            "resource": {
                "aws_vpc": {
                    "main": { "cidr_block": "10.0.0.0/16" }
                }
            }
        });
        Config::from_json(json_v).unwrap()
    }

    /// Build a single-instance `StateResource` — the boilerplate every
    /// hand-rolled `StateResource` literal in this module repeats.
    fn mk_state_resource(type_id: &str, name: &str, attrs: serde_json::Value) -> StateResource {
        StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: magma_types::ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId(type_id.into()),
                name: name.into(),
                key: None,
            },
            provider: ProviderReference {
                source: "hashicorp/aws".into(),
                name: "aws".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: attrs,
                sensitive_attribute_paths: Vec::new(),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }],
        }
    }

    #[test]
    fn plan_refuses_a_world_open_security_group_rule() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_security_group_rule": {
                    "grafana_nodeport": {
                        "type": "ingress",
                        "from_port": 32714,
                        "to_port": 32714,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                }
            }
        }))
        .unwrap();
        let st = empty_state();
        let err = plan(&cfg, &st).unwrap_err();
        assert!(matches!(err, PlanError::Compliance(_)));
    }

    #[test]
    fn empty_in_empty_out() {
        let cfg = Config::default();
        let st = empty_state();
        let p = plan(&cfg, &st).unwrap();
        assert!(p.resource_changes.is_empty());
    }

    #[test]
    fn one_resource_creates() {
        let cfg = cfg_with_vpc();
        let st = empty_state();
        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::Create);
        assert_eq!(p.resource_changes[0].address.type_id.0, "aws_vpc");
    }

    #[test]
    fn missing_in_config_deletes() {
        let cfg = Config::default();
        let mut st = empty_state();
        st.resources.push(StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: magma_types::ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId("aws_vpc".into()),
                name: "main".into(),
                key: None,
            },
            provider: ProviderReference {
                source: "hashicorp/aws".into(),
                name: "aws".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: json!({"id": "vpc-abc"}),
                sensitive_attribute_paths: Vec::new(),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }],
        });
        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::Delete);
    }

    #[test]
    fn identical_yields_noop() {
        let cfg = cfg_with_vpc();
        let mut st = empty_state();
        st.resources.push(StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: magma_types::ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId("aws_vpc".into()),
                name: "main".into(),
                key: None,
            },
            provider: ProviderReference {
                source: "hashicorp/aws".into(),
                name: "aws".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: json!({"cidr_block": "10.0.0.0/16"}),
                sensitive_attribute_paths: Vec::new(),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }],
        });
        let p = plan(&cfg, &st).unwrap();
        // For M0, "in-both" is a NoOp pending provider RPC.
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::NoOp);
    }

    #[test]
    fn computed_only_attribute_yields_noop() {
        // State carries a computed-only key (`id`) absent from config.
        // Every config-declared key matches → must NOT be classified as
        // drifted just because `before` is a superset of `after`.
        let cfg = cfg_with_vpc();
        let mut st = empty_state();
        st.resources.push(StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: magma_types::ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId("aws_vpc".into()),
                name: "main".into(),
                key: None,
            },
            provider: ProviderReference {
                source: "hashicorp/aws".into(),
                name: "aws".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: json!({
                    "cidr_block": "10.0.0.0/16",
                    "id": "vpc-abc123",
                }),
                sensitive_attribute_paths: Vec::new(),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }],
        });
        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "a computed-only attribute present solely in state must never trigger drift"
        );
        assert!(p.resource_changes[0].reasons.is_empty());
    }

    #[test]
    fn declared_attribute_drift_yields_update() {
        // A config-declared key (`cidr_block`) genuinely differs between
        // state and config → must be classified Update/AttributeDrift.
        let cfg = cfg_with_vpc(); // declares cidr_block = 10.0.0.0/16
        let mut st = empty_state();
        st.resources.push(StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: magma_types::ResourceKind::Managed,
                type_id: magma_types::ResourceTypeId("aws_vpc".into()),
                name: "main".into(),
                key: None,
            },
            provider: ProviderReference {
                source: "hashicorp/aws".into(),
                name: "aws".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: json!({
                    "cidr_block": "10.0.0.0/8",
                    "id": "vpc-abc123",
                }),
                sensitive_attribute_paths: Vec::new(),
                private: Vec::new(),
                dependencies: Vec::new(),
                status: InstanceStatus::Ready,
            }],
        });
        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::Update);
        assert_eq!(
            p.resource_changes[0].reasons,
            vec![ChangeReason::AttributeDrift]
        );
    }

    // ── BUG 1 regression: unresolved `${type.name.attr}` references ──
    //
    // Live incident: a production camelot-eks InfrastructureTemplate's
    // plan went from correctly showing 1 real drift to falsely showing
    // 53 of 54 resources as "update" the moment an unrelated
    // plan-diff hardcoded-NoOp bug was fixed earlier the same session —
    // every resource whose config referenced a sibling resource
    // (`vpc_id = "${aws_vpc.main.id}"`) was comparing that literal,
    // unresolved string against the sibling's concrete state value and
    // finding them unequal by construction.

    #[test]
    fn cross_reference_to_unchanged_value_is_noop_not_spurious_update() {
        // `aws_subnet.priv`'s config declares
        // `vpc_id = "${aws_vpc.main.id}"`. The VPC's real id (in state)
        // is exactly what that reference resolves to, and the subnet's
        // own stored `vpc_id` already matches it — nothing has actually
        // changed.
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_vpc": {
                    "main": { "cidr_block": "10.0.0.0/16" }
                },
                "aws_subnet": {
                    "priv": { "vpc_id": "${aws_vpc.main.id}" }
                }
            }
        }))
        .unwrap();

        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_vpc",
            "main",
            json!({ "cidr_block": "10.0.0.0/16", "id": "vpc-090f93f4590e59ebc" }),
        ));
        let subnet_before = json!({
            "vpc_id": "vpc-090f93f4590e59ebc",
            "id": "subnet-abc123",
        });
        st.resources
            .push(mk_state_resource("aws_subnet", "priv", subnet_before.clone()));

        // Prove the OLD (pre-fix) bug shape directly: comparing the RAW,
        // unresolved config value against state's concrete value reports
        // drift even though nothing changed.
        let subnet_after_raw = Some(json!({ "vpc_id": "${aws_vpc.main.id}" }));
        assert!(
            declared_attributes_drifted(&Some(subnet_before), &subnet_after_raw),
            "old code path (raw, unresolved comparison) must reproduce the spurious-drift bug shape"
        );

        // The FIXED pipeline resolves the reference against state before
        // comparing — the genuinely-unchanged cross-reference must be a
        // NoOp, not a spurious Update.
        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 2);
        let subnet_change = p
            .resource_changes
            .iter()
            .find(|c| c.address.type_id.0 == "aws_subnet")
            .unwrap();
        assert_eq!(
            subnet_change.action,
            Action::NoOp,
            "a config reference that resolves to the SAME value already in state must not report drift"
        );
        let vpc_change = p
            .resource_changes
            .iter()
            .find(|c| c.address.type_id.0 == "aws_vpc")
            .unwrap();
        assert_eq!(vpc_change.action, Action::NoOp);
    }

    #[test]
    fn cross_reference_to_genuinely_changed_value_still_reports_update() {
        // Inverse of the above: the reference target's value in state
        // genuinely differs from what the referencing resource has
        // stored (e.g. the VPC was recreated with a new id since the
        // subnet was last applied). The fix must not suppress ALL drift
        // detection for reference-shaped attributes — only the false
        // positive where the resolved value is unchanged.
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_vpc": {
                    "main": { "cidr_block": "10.0.0.0/16" }
                },
                "aws_subnet": {
                    "priv": { "vpc_id": "${aws_vpc.main.id}" }
                }
            }
        }))
        .unwrap();

        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_vpc",
            "main",
            json!({ "cidr_block": "10.0.0.0/16", "id": "vpc-newid00000000" }),
        ));
        st.resources.push(mk_state_resource(
            "aws_subnet",
            "priv",
            json!({ "vpc_id": "vpc-stale0000000", "id": "subnet-abc123" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        let subnet_change = p
            .resource_changes
            .iter()
            .find(|c| c.address.type_id.0 == "aws_subnet")
            .unwrap();
        assert_eq!(
            subnet_change.action,
            Action::Update,
            "a config reference that resolves to a DIFFERENT value than what's stored must still report drift"
        );
        assert_eq!(
            subnet_change.reasons,
            vec![ChangeReason::AttributeDrift]
        );
    }

    // ── BUG 2 regression: nested object attributes, whole-value compare ──

    #[test]
    fn nested_object_attribute_with_extra_state_only_keys_is_noop() {
        // Config declares a SUBSET of a nested object's keys
        // (`tags = { Name = "x" }`); state carries an EXTRA
        // provider-injected key alongside it (AWS auto-adds
        // `kubernetes.io/cluster/<name>` tags to VPCs/subnets it
        // manages). Every config-declared key genuinely matches — this
        // must not be flagged as drift just because state's nested
        // object is a superset of config's.
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_vpc": {
                    "main": {
                        "cidr_block": "10.0.0.0/16",
                        "tags": { "Name": "camelot-eks-vpc" }
                    }
                }
            }
        }))
        .unwrap();

        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_vpc",
            "main",
            json!({
                "cidr_block": "10.0.0.0/16",
                "id": "vpc-090f93f4590e59ebc",
                "tags": {
                    "Name": "camelot-eks-vpc",
                    "kubernetes.io/cluster/camelot-eks": "owned"
                }
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "extra provider-injected keys inside a nested object must never trigger drift"
        );
    }

    #[test]
    fn nested_object_attribute_with_genuinely_different_declared_key_still_updates() {
        // The subset relief must not swallow real nested drift: a
        // config-declared key INSIDE the nested object genuinely
        // differs from state.
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_vpc": {
                    "main": {
                        "cidr_block": "10.0.0.0/16",
                        "tags": { "Name": "camelot-eks-vpc" }
                    }
                }
            }
        }))
        .unwrap();

        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_vpc",
            "main",
            json!({
                "cidr_block": "10.0.0.0/16",
                "id": "vpc-090f93f4590e59ebc",
                "tags": {
                    "Name": "old-name",
                    "kubernetes.io/cluster/camelot-eks": "owned"
                }
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(p.resource_changes[0].action, Action::Update);
        assert_eq!(
            p.resource_changes[0].reasons,
            vec![ChangeReason::AttributeDrift]
        );
    }

    #[test]
    fn plan_id_deterministic_for_same_inputs() {
        let cfg = cfg_with_vpc();
        let st = empty_state();
        let p1 = plan(&cfg, &st).unwrap();
        let p2 = plan(&cfg, &st).unwrap();
        // PlanId only depends on inputs + structural changes, not timestamp.
        assert_eq!(p1.id.0, p2.id.0);
    }
}
