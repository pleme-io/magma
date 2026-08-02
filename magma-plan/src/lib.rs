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
//!
//! On top of the config-subset heuristic, `subset_matches` /
//! `attribute_matches` absorb six confirmed, schema-free
//! false-positive classes plus one narrowly-scoped fix, all found via
//! direct Postgres inspection of a live production example-eks
//! `InfrastructureTemplate`'s plan output (54 real AWS resources) after
//! the interpolation-resolution and nested-object-recursion fixes above
//! had already closed the dominant causes, leaving 27 false-positive-
//! heavy "update" flags:
//!
//! 1. JSON-encoded string attributes (`assume_role_policy`) compare by
//!    parsed value, not literal string — AWS re-serializes with
//!    reordered keys.
//! 2. Scalar-only array attributes (`subnet_ids`, `route_table_ids`)
//!    compare as multisets, not ordered sequences — AWS returns them
//!    reordered.
//! 3. A `max_items = 1` nested block encoded as `[{...}]` in tfstate vs
//!    a bare `{...}` in Pangea's rendered config (`access_config`,
//!    `access_scope`, `scaling_config`, `update_config`) is unwrapped
//!    and compared as the same value.
//! 4. NACL-rule `protocol` values are canonicalized (`"tcp"` ==
//!    `"6"`) before comparing — AWS returns numeric codes, config
//!    declares names.
//! 5. NACL-rule `from_port`/`to_port` treat `null` (AWS, on an
//!    allow-all `-1` rule) and `0` (Pangea's declared value for the
//!    same rule) as equal, scoped to allow-all rules only.
//! 6. `aws_eks_addon.resolve_conflicts_on_{create,update}` — apply-time
//!    directives with no readable counterpart in `DescribeAddon` — are
//!    never compared at all (a named write-only-attribute exemption
//!    list).
//!
//! Plus two narrowly-scoped fixes outside that class:
//!
//! - `aws_iam_openid_connect_provider.url` compares with a leading
//!   `https://`/`http://` scheme stripped from both sides — a
//!   config-resolved reference to an EKS cluster's OIDC issuer carries
//!   the scheme, AWS's `DescribeOpenIDConnectProvider` strips it.
//! - BUG 7: a genuinely readable, bidirectional attribute that a
//!   separate, sibling controller mutates directly against the live
//!   provider API — Terraform's own `lifecycle.ignore_changes`
//!   semantic, address-scoped (never resource-type-scoped, unlike BUG
//!   6) via `EXTERNALLY_MANAGED_ATTRIBUTES`. Confirmed case:
//!   `example-eks_controllers_ng`'s `scaling_config`, live-owned by
//!   `breathe-controller`'s `EksNodegroupProvedor`.
//!
//! See the `BUG 3`–`BUG 8` regression tests below for the exact
//! confirmed-real before/after shapes.

use std::collections::HashSet;

use chrono::Utc;
use magma_attest::hash_plan_inputs;
use magma_config::Config;
use magma_types::{
    Action, ChangeReason, Plan, ResourceAddress, ResourceChange, ResourceKind, ResourceMeta, State,
};

mod compliance;
pub use compliance::{
    ComplianceBaseline, ComplianceViolation, check_cache_encryption,
    check_database_public_accessibility, check_security_group_compliance, run_compliance_checks,
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
/// Split a resource block's meta-arguments out of its attributes.
///
/// Thin adapter over `magma_config::split_resource_body`, kept here so the
/// three construction sites in `plan` read identically and none of them can
/// forget the split. `None` (no config body) carries empty meta.
///
/// The error is deliberately propagated, not swallowed: an UNIMPLEMENTED
/// meta-argument (e.g. an aliased `provider`) must stop the plan rather than
/// be silently dropped into a resource that then applies through the wrong
/// provider — which is the failure this whole split exists to end.
fn split_meta(
    addr: &ResourceAddress,
    body: Option<serde_json::Value>,
) -> Result<(ResourceMeta, Option<serde_json::Value>), PlanError> {
    let Some(body) = body else {
        return Ok((ResourceMeta::default(), None));
    };
    let label = format!("{}.{}", addr.type_id.0, addr.name);
    let (meta, attrs) = magma_config::split_resource_body(&label, &body)?;
    Ok((meta, Some(attrs)))
}

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
    //
    // A DATA SOURCE IS NEVER CREATED. `config.resource_addresses()` yields
    // managed resources and data sources into one address set, so a `data`
    // block with no state row is structurally identical here to a brand-new
    // managed resource — and until 2026-07-31 both came out as
    // `Action::Create`. `Action::Read` was declared in `magma_types::Action`
    // and constructed NOWHERE in this crate; the downstream mapping that
    // folds it away (`magma-converge::terraform`, `Read => NoOp`) was dead
    // code waiting for a producer.
    //
    // That is not cosmetic. Apply is kind-driven, so it did the right thing
    // regardless — but the PLAN is what the approval gate reads:
    // `magma_drift::classify` saw a Create, demanded approval, and counted the
    // read into `+N`. Measured on example-eks-cache-nlb-sg, whose rendered
    // tf.json holds exactly 3 `resource` entries and 1 `data` entry: the CR
    // reported `planSummary: +4 ~0 -0` with
    // `action: create / address: aws_security_group.vpn-hub_concentrator` — a
    // security group that workspace does not declare. An operator reading that
    // should refuse to approve, and did. The inverse is worse: once "some of
    // those creates are really data sources" becomes folklore, a genuine
    // unexpected create gets waved through.
    for addr in config_addrs.difference(&state_addrs) {
        let raw_after = lookup_config_value(config, addr);
        // Split meta-arguments OUT of the block before anything downstream
        // sees the attributes. A meta-argument left in `after` is handed to
        // the cty encoder (which silently drops unknown keys — so
        // `provider = "aws.x"` evaporated and the resource applied through
        // the DEFAULT provider) and counted as a declared attribute for
        // drift, which no provider ever returns — so the resource re-planned
        // as Update on EVERY cycle, forever.
        let (meta, after) = split_meta(addr, raw_after)?;
        let (action, reasons) = match addr.kind {
            ResourceKind::Data => (Action::Read, vec![ChangeReason::NewResource]),
            _ => (Action::Create, vec![ChangeReason::NewResource]),
        };
        changes.push(ResourceChange {
            address: addr.clone(),
            action,
            before: None,
            after,
            reasons,
            meta,
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
            // A delete has no config block left to carry meta-arguments.
            meta: ResourceMeta::default(),
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
        // Same split as the create loop: a meta-argument must never reach the
        // attribute comparison, or the resource drifts against a key no
        // provider returns and re-plans as Update forever.
        let (meta, after) = split_meta(addr, lookup_config_value(config, addr))?;
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
        let after_resolved = after
            .as_ref()
            .map(|v| magma_config::resolve_config(v, &state_map).unwrap_or_else(|_| v.clone()));
        let drifted =
            declared_attributes_drifted(&addr.type_id.0, &addr.name, &before, &after_resolved);
        // Same rule as the Create arm: a data source is never UPDATED either.
        // A `data` block whose filter changed needs re-reading, not mutating —
        // and apply already treats it that way (`partition_changes` routes by
        // `kind`, never by action). Emitting `Update` only ever inflated the
        // `~N` column of a summary a human approves against.
        //
        // The Delete arm above is deliberately NOT given this treatment: apply
        // relies on a data source removed from config arriving as
        // `Delete`/`Forget` so the `datas` loop FORGETS it rather than
        // re-reading it against config that no longer exists (see REACTION C in
        // `magma-apply::engine::run_plan_with_providers` — re-reading an orphan
        // is the documented crash trigger). Data reads are Read; data ORPHANS
        // stay Delete.
        let (action, reasons) = match (addr.kind, drifted) {
            // A data source ALREADY IN STATE and unchanged stays NoOp — it must
            // NOT be re-read at apply.
            //
            // This arm said `Read` unconditionally for one commit (2026-08-01)
            // and that was a REGRESSION, caught live on
            // example-eks-vpn-concentrator. `Read` bypasses the apply loop's
            // deliberate carry-forward fast path, whose comment predicts the
            // exact failure in advance: "the plan's `after` for a NoOp data
            // source is null, so a re-read would hand the provider a
            // null/empty config". Measured consequences, all from that one
            // word:
            //     reading SSM Parameter (): …      <- empty name
            //     multiple EC2 VPCs matched        <- empty filter matched all
            //     multiple EC2 Subnets matched
            // and, on a provider that nil-derefs instead of erroring, the
            // documented cloudflare SIGSEGV that once needed a manual Postgres
            // purge to recover.
            //
            // The original defect this whole change set fixes is narrower than
            // it first looked: a NEW data source (the `difference` loop above)
            // was labelled `Create`, inflating +N and making a READ of an
            // existing VPC read as "creating a VPC". That is fixed there, where
            // there is genuinely a first read to perform. Here there is not —
            // the value is already in `before`.
            (ResourceKind::Data, false) => (Action::NoOp, vec![]),
            // Config genuinely changed, so the cached read is stale and must be
            // re-taken. `Read` rather than the `Update` this used to emit: an
            // `Update` on a data source is meaningless (nothing is mutated),
            // and the apply loop routes on the action.
            (ResourceKind::Data, true) => (Action::Read, vec![ChangeReason::AttributeDrift]),
            (_, true) => (Action::Update, vec![ChangeReason::AttributeDrift]),
            (_, false) => (Action::NoOp, vec![]),
        };
        changes.push(ResourceChange {
            address: addr.clone(),
            action,
            before,
            after,
            reasons,
            meta,
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
        // `plan` diffs config against whatever `state` it was handed and
        // never talks to a provider itself, so the honest trust record is
        // "nothing was observed". A caller that DID refresh first stamps
        // the real one — `magma_apply::engine::refresh_then_plan` is the
        // one place that does, and `Plan::with_observation` is the seam
        // for any other caller that runs its own refresh.
        observation: magma_types::Observation::unrefreshed(),
    })
}

/// The config block for `addr` — from `data:` for a data source, `resource:`
/// for a managed one.
///
/// THE KIND SPLIT IS LOAD-BEARING. This used to read `config.resources`
/// unconditionally, so every `ResourceKind::Data` address resolved to `None`
/// and its `ResourceChange.after` was null. A data source whose config never
/// reaches the plan is then READ WITH AN EMPTY CONFIG, and an empty filter
/// does not error — it MATCHES EVERYTHING:
///
/// ```text
/// multiple EC2 VPCs matched; use additional constraints ...
/// multiple EC2 Subnets matched ...
/// reading SSM Parameter (): ...                    <- empty name
/// ```
///
/// Measured 2026-08-01 on example-eks-vpn-concentrator, whose
/// `data.aws_vpc.example_eks` is `{"id": "vpc-0123456789abcdef0"}` — a fully
/// constrained, exact id that never reached the provider. The failure reads
/// like an under-constrained filter in the CONFIG, which is what makes it
/// expensive: the evidence points away from the defect.
///
/// It predates the Read/NoOp work and was merely hidden by it — while data
/// sources planned as `Create`/`NoOp` they were rarely re-read, so the null
/// `after` mostly went unnoticed.
fn lookup_config_value(config: &Config, addr: &ResourceAddress) -> Option<serde_json::Value> {
    let table = match addr.kind {
        ResourceKind::Data => &config.data,
        _ => &config.resources,
    };
    table
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
///
/// `resource_type` (`addr.type_id.0`, e.g. `"aws_network_acl_rule"`)
/// threads down to `attribute_matches` for the small set of comparisons
/// that need to know WHICH field or WHICH resource they're looking at
/// (protocol-name normalization, allow-all port nulling, the
/// write-only-attribute exemption list, the OIDC-provider URL-scheme
/// normalization) — none of which are expressible as a pure
/// `Value × Value → bool` heuristic. Confirmed live against a
/// production example-eks `InfrastructureTemplate`'s plan output (see
/// the BUG 3–8 regression tests below): six schema-free false-positive
/// classes plus one narrowly-scoped OIDC fix, none of which need the
/// bigger provider-schema (`PlanResourceChange`) M0.x work.
fn declared_attributes_drifted(
    resource_type: &str,
    resource_name: &str,
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
            // BUG 6: write-only / never-refreshable attributes (e.g.
            // `aws_eks_addon.resolve_conflicts_on_{create,update}`) have
            // no readable counterpart in the provider's Describe/Read
            // API — state is permanently unable to match config for
            // these keys, by design, so they never contribute to drift.
            if is_write_only_attribute(resource_type, k) {
                return false;
            }
            // BUG 7: an attribute that IS genuinely readable but is
            // authoritatively mutated by a separate, sibling controller
            // directly against the live API (bypassing Terraform/magma
            // state entirely) — Terraform's own `lifecycle.ignore_changes`
            // semantic. Unlike BUG 6 this is address-scoped, not
            // type-scoped: exempting it fleet-wide would silently hide
            // real drift on every OTHER resource of the same type that
            // ISN'T managed by that sibling controller.
            if is_externally_managed_attribute(resource_type, resource_name, k) {
                return false;
            }
            !before_obj.get(k).is_some_and(|before_v| {
                attribute_matches(resource_type, k, before_v, after_v, before_obj, after_obj)
            })
        }),
        // State has no recorded instance attributes at all (or they
        // aren't an object) but config declares some — every declared
        // key is effectively new (still respecting the write-only and
        // externally-managed exemptions, for consistency with the
        // populated-state branch above).
        None => after_obj.keys().any(|k| {
            !is_write_only_attribute(resource_type, k)
                && !is_externally_managed_attribute(resource_type, resource_name, k)
        }),
    }
}

/// Field-name- and resource-type-aware dispatch sitting in front of the
/// generic `subset_matches`. Most attributes fall straight through to
/// `subset_matches`; a handful of confirmed AWS provider read/write
/// asymmetries need to know the specific field (and, for the OIDC case,
/// the specific resource type) they're comparing:
///
/// - `protocol` on any resource — AWS returns numeric protocol codes
///   (`"6"`), config declares names (`"tcp"`) — BUG 4.
/// - `from_port` / `to_port` on a rule whose `protocol` (either side)
///   is allow-all (`-1`) — AWS returns `null`, config declares `0` —
///   BUG 5. Scoped to allow-all only: a genuine port difference on a
///   normal rule still compares by equality.
/// - `aws_iam_openid_connect_provider.url` — a config-resolved
///   reference to an EKS cluster's OIDC issuer carries the `https://`
///   scheme; AWS's `DescribeOpenIDConnectProvider` strips it on read.
fn attribute_matches(
    resource_type: &str,
    field_name: &str,
    before_v: &serde_json::Value,
    after_v: &serde_json::Value,
    before_obj: &serde_json::Map<String, serde_json::Value>,
    after_obj: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    if field_name == "protocol" {
        return protocol_values_match(before_v, after_v);
    }
    if (field_name == "from_port" || field_name == "to_port")
        && (is_allow_all_protocol(before_obj) || is_allow_all_protocol(after_obj))
    {
        return port_matches(before_v, after_v);
    }
    if resource_type == "aws_iam_openid_connect_provider" && field_name == "url" {
        return url_scheme_normalized_matches(before_v, after_v);
    }
    subset_matches(before_v, after_v)
}

/// `true` iff `after_v` (a config-declared value) subset-matches
/// `before_v` (the corresponding stored-state value). JSON objects
/// recurse with the same subset semantics used at the top level of
/// `declared_attributes_drifted` — every key `after_v` declares must be
/// present in `before_v` with a (recursively) subset-matching value; a
/// key present ONLY in `before_v`, at any nesting depth, is never drift.
///
/// Three schema-free structural/semantic relaxations apply before
/// falling back to whole-value equality (each confirmed against a real
/// example-eks plan false positive):
///
/// - **BUG 3** — a single-element array wrapping an object on one side
///   and a bare object on the other (`aws_eks_cluster.access_config`,
///   `aws_eks_node_group.scaling_config`/`update_config`) are the SAME
///   `max_items = 1` nested block; tfstate's array wrapper is unwrapped
///   before comparing, recursively, so a nested block's OWN nested
///   blocks get the same treatment.
/// - **BUG 2** — an array whose elements are all JSON scalars (never an
///   array of nested-block objects, which can carry real positional
///   meaning) compares as a multiset, not an ordered sequence
///   (`aws_network_acl.subnet_ids`, `aws_vpc_endpoint.route_table_ids`).
/// - **BUG 1** — a JSON-encoded string attribute (`assume_role_policy`)
///   compares by its PARSED value, not the literal string, so AWS
///   re-serializing the same policy with reordered keys doesn't drift.
///
/// Arrays-of-objects and non-JSON strings still compare by whole-value
/// equality — real Terraform DOES flag any difference in a genuinely
/// order-sensitive list attribute; these relaxations are additive, not
/// a general "ignore order/shape" switch.
fn subset_matches(before_v: &serde_json::Value, after_v: &serde_json::Value) -> bool {
    // BUG 3: max_items=1 nested-block shape mismatch — normalize
    // BEFORE the main dispatch so the unwrapped values still get the
    // full recursive treatment (a nested block's own nested blocks may
    // carry the same array-vs-object mismatch).
    if let Some(unwrapped_before) = unwrap_single_object_array(before_v) {
        if after_v.is_object() {
            return subset_matches(unwrapped_before, after_v);
        }
    }
    if let Some(unwrapped_after) = unwrap_single_object_array(after_v) {
        if before_v.is_object() {
            return subset_matches(before_v, unwrapped_after);
        }
    }

    match (before_v, after_v) {
        (serde_json::Value::Object(before_obj), serde_json::Value::Object(after_obj)) => after_obj
            .iter()
            .all(|(k, av)| before_obj.get(k).is_some_and(|bv| subset_matches(bv, av))),

        // BUG 2: scalar-only arrays compare as multisets.
        (serde_json::Value::Array(before_arr), serde_json::Value::Array(after_arr))
            if before_arr.iter().all(is_json_scalar) && after_arr.iter().all(is_json_scalar) =>
        {
            scalar_multiset_matches(before_arr, after_arr)
        }

        // BUG 1: JSON-encoded string attributes compare by parsed
        // value. A parse failure on either side (not JSON to begin
        // with — a genuine plain-string attribute) falls back to the
        // existing literal comparison below.
        (serde_json::Value::String(before_s), serde_json::Value::String(after_s)) => {
            match (
                serde_json::from_str::<serde_json::Value>(before_s),
                serde_json::from_str::<serde_json::Value>(after_s),
            ) {
                (Ok(before_parsed), Ok(after_parsed)) => before_parsed == after_parsed,
                _ => before_v == after_v,
            }
        }

        _ => before_v == after_v,
    }
}

/// If `v` is a single-element JSON array whose sole element is an
/// object, return that object; otherwise `None`. tfstate encodes
/// Terraform `max_items = 1` nested blocks as `[{...}]`; Pangea's
/// rendered config JSON emits the equivalent block as a bare `{...}`
/// with no wrapping array — the two are the SAME semantic value, just
/// two different provider-vs-renderer serializations of one block.
fn unwrap_single_object_array(v: &serde_json::Value) -> Option<&serde_json::Value> {
    match v {
        serde_json::Value::Array(items) if items.len() == 1 && items[0].is_object() => {
            Some(&items[0])
        }
        _ => None,
    }
}

/// `true` iff `v` is never itself a container that can carry
/// per-position semantic meaning beyond "a set of values" — i.e. every
/// scalar (`String`/`Number`/`Bool`/`Null`), but never `Object` or
/// `Array`. Used to scope the BUG 2 multiset relief to lists that are,
/// in practice, sets: a list of nested-block objects (which CAN encode
/// real positional meaning) is deliberately excluded and keeps the
/// original ordered-equality behavior.
fn is_json_scalar(v: &serde_json::Value) -> bool {
    !matches!(
        v,
        serde_json::Value::Object(_) | serde_json::Value::Array(_)
    )
}

/// Compare two arrays of JSON scalars as multisets rather than ordered
/// sequences. AWS's `Describe*` APIs frequently return list-typed
/// attributes in a different order than the order a config declares
/// them in (`aws_network_acl.subnet_ids`, `aws_vpc_endpoint.route_table_ids`
/// — confirmed live, same elements, different order). Terraform's own
/// `TypeSet` vs `TypeList` split means SOME lists are genuinely
/// order-sensitive, but restricting this relief to scalar-only arrays
/// (see `is_json_scalar`) keeps the false-negative risk to "silently
/// swallows reordering-as-drift" — it can never silently swallow a
/// genuine element addition/removal/value-change, since the multiset
/// comparison still requires identical element multisets (duplicate
/// counts included, via a full sorted-string comparison).
fn scalar_multiset_matches(
    before_arr: &[serde_json::Value],
    after_arr: &[serde_json::Value],
) -> bool {
    let mut before_sorted: Vec<String> = before_arr.iter().map(canonical_scalar_key).collect();
    let mut after_sorted: Vec<String> = after_arr.iter().map(canonical_scalar_key).collect();
    before_sorted.sort();
    after_sorted.sort();
    before_sorted == after_sorted
}

/// Deterministic sort/equality key for a JSON scalar. `serde_json`
/// serializes a given scalar identically every time, so this stands in
/// for `Ord` (which `serde_json::Value` doesn't implement — `Number`
/// can't total-order `f64`/`NaN`).
fn canonical_scalar_key(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Canonicalize an AWS NACL-rule `protocol` value to its numeric IP
/// protocol-number string. AWS's `DescribeNetworkAcls` always returns
/// the numeric string (`"6"`, `"17"`, `"-1"`); Pangea's rendered config
/// declares the human name (`"tcp"`, `"udp"`, `"all"`). `None` if `v`
/// isn't a string (e.g. `null` — the caller falls back to whole-value
/// equality in that case). Table is intentionally the confirmed set
/// only — extend with evidence, never a guess.
fn canonicalize_protocol_value(v: &serde_json::Value) -> Option<String> {
    let s = v.as_str()?;
    Some(match s.to_ascii_lowercase().as_str() {
        "tcp" => "6".to_string(),
        "udp" => "17".to_string(),
        "icmp" => "1".to_string(),
        "all" => "-1".to_string(),
        "-1" => "-1".to_string(),
        _ => s.to_string(),
    })
}

/// BUG 4: compare two `protocol` values after canonicalizing both to
/// the numeric-code form (`"tcp"` == `"6"`). Falls back to whole-value
/// equality when either side doesn't canonicalize (non-string / an
/// already-numeric code not in the table) — a genuinely different
/// protocol (`"tcp"` vs `"udp"`) still canonicalizes to different codes
/// and correctly reports drift.
fn protocol_values_match(before_v: &serde_json::Value, after_v: &serde_json::Value) -> bool {
    match (
        canonicalize_protocol_value(before_v),
        canonicalize_protocol_value(after_v),
    ) {
        (Some(b), Some(a)) => b == a,
        _ => before_v == after_v,
    }
}

/// `true` iff the resource's `protocol` attribute — checked in `obj`,
/// which the caller invokes for BOTH `before_obj` and `after_obj` since
/// state and config are being compared mid-transition — canonicalizes
/// to `"-1"` (all protocols/ports).
fn is_allow_all_protocol(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    obj.get("protocol")
        .and_then(canonicalize_protocol_value)
        .as_deref()
        == Some("-1")
}

/// `true` iff `v` is JSON `null` or the numeric zero.
fn is_null_or_zero(v: &serde_json::Value) -> bool {
    v.is_null() || v.as_i64() == Some(0) || v.as_f64() == Some(0.0)
}

/// BUG 5: AWS returns `null` for `from_port`/`to_port` when `protocol`
/// is `-1` (all protocols/ports); Pangea's rendered config declares `0`
/// for the same allow-all rule. The caller only invokes this once it
/// has confirmed the rule IS allow-all — `null` and `0` compare equal
/// in that case, but any other genuine difference (e.g. `0` vs `100`)
/// still falls through to whole-value equality and correctly reports
/// drift.
fn port_matches(before_v: &serde_json::Value, after_v: &serde_json::Value) -> bool {
    (is_null_or_zero(before_v) && is_null_or_zero(after_v)) || before_v == after_v
}

/// Apply-time-only Terraform AWS-provider directives with no
/// corresponding readable field in the provider's own `Describe`/`Read`
/// API — state is permanently unable to reflect a config-declared value
/// for these, by design, so they must never be compared for drift.
/// Confirmed cases only; extend with evidence, never a guess.
const WRITE_ONLY_ATTRIBUTES: &[(&str, &str)] = &[
    ("aws_eks_addon", "resolve_conflicts_on_create"),
    ("aws_eks_addon", "resolve_conflicts_on_update"),
];

fn is_write_only_attribute(resource_type: &str, attribute: &str) -> bool {
    WRITE_ONLY_ATTRIBUTES
        .iter()
        .any(|(rt, attr)| *rt == resource_type && *attr == attribute)
}

/// Terraform's `lifecycle.ignore_changes` semantic: a genuinely
/// readable, bidirectional attribute that a separate, sibling
/// controller mutates directly against the live provider API — not via
/// Terraform/magma at all — so config and state legitimately, durably
/// disagree on it without either side being wrong. Distinct from
/// `WRITE_ONLY_ATTRIBUTES` (which is never readable, by provider
/// design) and deliberately scoped to `(resource_type, resource_name,
/// attribute)`, never resource-type-only — exempting an attribute
/// fleet-wide would silently hide real drift on every other resource of
/// the same type that ISN'T under that sibling controller's ownership.
///
/// Confirmed case: `example-eks_controllers_ng`'s `scaling_config` is
/// live-mutated by `breathe-controller`'s `EksNodegroupProvedor`
/// (`update_nodegroup_config` against AWS directly, gated by its own
/// `BreatheCloudPool` CR) on every breathe reconcile tick — magma's
/// static `min_size`/`max_size`/`desired_size` declaration would
/// otherwise fight breathe's live scaling on every plan cycle.
/// `example-eks_system_ng` has no `BreatheCloudPool` targeting it, so
/// its `scaling_config` stays fully drift-checked, as does every other
/// node group in the fleet.
const EXTERNALLY_MANAGED_ATTRIBUTES: &[(&str, &str, &str)] = &[(
    "aws_eks_node_group",
    "example-eks_controllers_ng",
    "scaling_config",
)];

fn is_externally_managed_attribute(
    resource_type: &str,
    resource_name: &str,
    attribute: &str,
) -> bool {
    EXTERNALLY_MANAGED_ATTRIBUTES
        .iter()
        .any(|(rt, name, attr)| {
            *rt == resource_type && *name == resource_name && *attr == attribute
        })
}

/// `aws_iam_openid_connect_provider.url` — a config-resolved reference
/// to an EKS cluster's OIDC issuer (`aws_eks_cluster.*.identity[0].oidc[0].issuer`)
/// carries the `https://` scheme; AWS's `DescribeOpenIDConnectProvider`
/// strips the scheme on read, so state never carries it. Compare with a
/// leading scheme stripped from both sides — a genuinely different
/// issuer (different host or path) still compares unequal.
fn url_scheme_normalized_matches(
    before_v: &serde_json::Value,
    after_v: &serde_json::Value,
) -> bool {
    match (before_v.as_str(), after_v.as_str()) {
        (Some(b), Some(a)) => strip_url_scheme(b) == strip_url_scheme(a),
        _ => before_v == after_v,
    }
}

fn strip_url_scheme(s: &str) -> &str {
    s.strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s)
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

    /// A data source with no state row is a READ, never a CREATE.
    ///
    /// Regression for the example-eks-cache-nlb-sg mislabel (2026-07-31): that
    /// workspace declares 3 `resource` entries and 1 `data` entry, and the CR
    /// reported `planSummary: +4 ~0 -0` with
    /// `action: create / address: aws_security_group.vpn-hub_concentrator` — a
    /// security group it does not declare. `plan()` diffed config addresses
    /// against state addresses without ever inspecting `addr.kind`, so an
    /// unread `data` block was structurally identical to a new managed
    /// resource.
    ///
    /// This is the approval surface, so the mislabel is load-bearing:
    /// `magma_drift::classify` reads a Create and demands approval.
    #[test]
    fn a_data_source_absent_from_state_plans_as_read_not_create() {
        let cfg = Config::from_json(json!({
            "data": {
                "aws_security_group": {
                    "vpn-hub_concentrator": {
                        "filter": { "name": "tag:Name", "values": ["nope"] }
                    }
                }
            }
        }))
        .unwrap();
        let p = plan(&cfg, &empty_state()).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        let c = &p.resource_changes[0];
        assert_eq!(c.address.kind, ResourceKind::Data);
        assert_eq!(
            c.action,
            Action::Read,
            "a data source must never plan as {:?} — that inflates +N and trips the approval gate",
            c.action
        );
    }

    /// A data source's config must reach the plan's `after`.
    ///
    /// `lookup_config_value` read only `config.resources`, so every data
    /// source got `after = None` and was later READ WITH AN EMPTY CONFIG —
    /// and an empty filter does not error, it matches EVERYTHING
    /// ("multiple EC2 VPCs matched"). The failure blames the config's filter,
    /// which is exactly where the defect is NOT.
    #[test]
    fn a_data_sources_config_reaches_the_plan_not_just_a_resources_config() {
        let cfg = serde_json::from_value(serde_json::json!({
            "data": { "aws_vpc": { "example_eks": { "id": "vpc-0123456789abcdef0" } } }
        }))
        .unwrap();

        let p = plan(&cfg, &empty_state()).unwrap();
        let c = p
            .resource_changes
            .iter()
            .find(|c| c.address.kind == ResourceKind::Data)
            .expect("the data source must appear in the plan");
        let after = c.after.as_ref().expect(
            "a data source MUST carry its config as `after` — a null one is read \
                     with an empty filter, which matches every VPC in the account",
        );
        assert_eq!(
            after["id"], "vpc-0123456789abcdef0",
            "the exact filter must survive into the plan, got {after:?}"
        );
    }

    /// The REGRESSION guard. An in-state, unchanged data source must plan as
    /// NoOp, NOT Read — `Read` sends it down the apply-time re-read path,
    /// which hands the provider the plan's null `after` config. Live
    /// consequences on example 2026-08-01: `reading SSM Parameter ()` (empty
    /// name), `multiple EC2 VPCs matched` (empty filter matched everything),
    /// 20/20 nodes failed. Fixing the NEW-data-source label (Create -> Read)
    /// must not drag the already-read case along with it.
    #[test]
    fn an_unchanged_in_state_data_source_stays_noop_and_is_never_re_read() {
        let cfg = serde_json::from_value(serde_json::json!({
            "data": { "aws_vpc": { "main": { "id": "vpc-123" } } }
        }))
        .unwrap();

        // Same value in state as in config => not drifted.
        let mut st = empty_state();
        st.resources.push(magma_types::StateResource {
            address: ResourceAddress {
                module: magma_types::ModulePath::root(),
                kind: ResourceKind::Data,
                type_id: magma_types::ResourceTypeId("aws_vpc".to_string()),
                name: "main".to_string(),
                key: None,
            },
            provider: magma_types::ProviderReference {
                source: "hashicorp/aws".to_string(),
                name: "aws".to_string(),
                alias: None,
            },
            instances: vec![magma_types::StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: serde_json::json!({ "id": "vpc-123" }),
                sensitive_attribute_paths: Vec::new(),
                private: vec![],
                dependencies: vec![],
                status: magma_types::InstanceStatus::Ready,
            }],
        });

        let p = plan(&cfg, &st).unwrap();
        let c = p
            .resource_changes
            .iter()
            .find(|c| c.address.kind == ResourceKind::Data)
            .expect("the data source must appear in the plan");
        assert_eq!(
            c.action,
            Action::NoOp,
            "an unchanged in-state data source must carry forward, not re-read; got {:?}",
            c.action
        );
    }

    /// The counting consequence, asserted directly: managed resources and data
    /// sources in one config must not produce one uniform action.
    ///
    /// Mirrors example-eks-cache-nlb-sg's real shape (N managed + 1 data). The
    /// bug made this report 2 creates; the truth is 1 create + 1 read.
    #[test]
    fn managed_and_data_in_one_config_do_not_share_an_action() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_security_group": {
                    "example-eks-cache-nlb-sg": { "name": "example-eks-cache-nlb-sg" }
                }
            },
            "data": {
                "aws_security_group": {
                    "vpn-hub_concentrator": {
                        "filter": { "name": "tag:Name", "values": ["vpn-concentrator-example-sg"] }
                    }
                }
            }
        }))
        .unwrap();
        let p = plan(&cfg, &empty_state()).unwrap();

        let creates: Vec<_> = p
            .resource_changes
            .iter()
            .filter(|c| c.action == Action::Create)
            .collect();
        let reads: Vec<_> = p
            .resource_changes
            .iter()
            .filter(|c| c.action == Action::Read)
            .collect();

        assert_eq!(creates.len(), 1, "exactly the one managed resource creates");
        assert_eq!(creates[0].address.kind, ResourceKind::Managed);
        assert_eq!(reads.len(), 1, "exactly the one data source reads");
        assert_eq!(reads[0].address.kind, ResourceKind::Data);
    }

    /// A data ORPHAN — in state, gone from config — must still plan as
    /// `Delete`, NOT `Read`.
    ///
    /// This is deliberately the opposite assertion from the two above, and it
    /// guards the fix from over-reaching. `magma-apply::engine` routes every
    /// Data change into the `datas` partition by KIND, where a `Delete`/`Forget`
    /// is FORGOTTEN (dropped from state) rather than re-read — because an
    /// orphan has no config left to read against, and re-reading it is the
    /// documented orphan-refresh crash trigger (REACTION C in
    /// `run_plan_with_providers`). Turning this arm into a Read would
    /// reintroduce that crash.
    #[test]
    fn a_data_source_removed_from_config_still_plans_as_delete() {
        let mut st = empty_state();
        // Reuse the module's own helper, then retag the address as a DATA
        // source — the helper builds Managed, which is the whole distinction
        // under test here.
        let mut orphan = mk_state_resource(
            "aws_security_group",
            "vpn-hub_concentrator",
            json!({ "id": "sg-dead" }),
        );
        orphan.address.kind = ResourceKind::Data;
        st.resources.push(orphan);

        let p = plan(&Config::default(), &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Delete,
            "a data orphan must stay Delete so apply FORGETS it instead of re-reading it"
        );
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
    // Live incident: a production example-eks InfrastructureTemplate's
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
            json!({ "cidr_block": "10.0.0.0/16", "id": "vpc-0123456789abcdef0" }),
        ));
        let subnet_before = json!({
            "vpc_id": "vpc-0123456789abcdef0",
            "id": "subnet-abc123",
        });
        st.resources.push(mk_state_resource(
            "aws_subnet",
            "priv",
            subnet_before.clone(),
        ));

        // Prove the OLD (pre-fix) bug shape directly: comparing the RAW,
        // unresolved config value against state's concrete value reports
        // drift even though nothing changed.
        let subnet_after_raw = Some(json!({ "vpc_id": "${aws_vpc.main.id}" }));
        assert!(
            declared_attributes_drifted(
                "aws_subnet",
                "priv",
                &Some(subnet_before),
                &subnet_after_raw
            ),
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
        assert_eq!(subnet_change.reasons, vec![ChangeReason::AttributeDrift]);
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
                        "tags": { "Name": "example-eks-vpc" }
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
                "id": "vpc-0123456789abcdef0",
                "tags": {
                    "Name": "example-eks-vpc",
                    "kubernetes.io/cluster/example-eks": "owned"
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
                        "tags": { "Name": "example-eks-vpc" }
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
                "id": "vpc-0123456789abcdef0",
                "tags": {
                    "Name": "old-name",
                    "kubernetes.io/cluster/example-eks": "owned"
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

    // ── BUG 3 regression: JSON-encoded string attribute, key reorder ──
    //
    // Live incident: a production example-eks `InfrastructureTemplate`'s
    // plan carried 27 false-positive-heavy "update" flags after the
    // interpolation-resolution and nested-object-recursion fixes above
    // had already closed the dominant causes. `aws_iam_role.*.assume_role_policy`
    // is a JSON-encoded string; AWS re-serializes the policy document
    // with its own key order on read, and the raw-string comparison
    // reported drift on every cycle even though the policy never
    // actually changed.

    #[test]
    fn json_string_attribute_with_reordered_keys_is_noop_not_spurious_update() {
        // Hand-written raw strings, NOT `json!(..).to_string()` — this
        // crate's `serde_json::Map` is a `BTreeMap` (no `preserve_order`
        // feature), so two `json!()` values built from the SAME Rust
        // process always serialize with identical (alphabetically
        // sorted) key order regardless of literal source order. Real
        // AWS (its own JSON serializer) and Pangea's Ruby `to_json`
        // (insertion-ordered) are two independent, differently-ordered
        // serializers — reproduced here as two distinct string literals.
        let before_policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#.to_string();
        let after_policy = r#"{"Statement":[{"Action":"sts:AssumeRole","Principal":{"Service":"eks.amazonaws.com"},"Effect":"Allow"}],"Version":"2012-10-17"}"#.to_string();
        assert_ne!(
            before_policy, after_policy,
            "the two policy documents must be byte-different strings — exactly the \
             shape the old, unconditional `before_v == after_v` fallback misclassified"
        );

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_iam_role": {
                    "eks_cluster_role": { "assume_role_policy": after_policy }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_iam_role",
            "eks_cluster_role",
            json!({ "assume_role_policy": before_policy, "id": "AROAEXAMPLE123" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "a JSON policy re-serialized with reordered keys must not report drift"
        );
    }

    #[test]
    fn json_string_attribute_with_genuinely_different_content_still_updates() {
        let before_policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": { "Service": "eks.amazonaws.com" }
            }]
        })
        .to_string();
        let after_policy = json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Principal": { "Service": "eks.amazonaws.com" }
            }]
        })
        .to_string();

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_iam_role": {
                    "eks_cluster_role": { "assume_role_policy": after_policy }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_iam_role",
            "eks_cluster_role",
            json!({ "assume_role_policy": before_policy, "id": "AROAEXAMPLE123" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "a genuinely different policy document (different Action) must still report drift"
        );
    }

    // ── BUG 4 regression: scalar-array reordering ──
    //
    // Live incident: `aws_network_acl.subnet_ids` and
    // `aws_vpc_endpoint.route_table_ids` — AWS returns the same
    // elements in a different order than Pangea's config declares them.

    #[test]
    fn scalar_array_attribute_reordered_is_noop_not_spurious_update() {
        let before_ids = json!(["subnet-b222", "subnet-a111", "subnet-c333"]);
        let after_ids = json!(["subnet-a111", "subnet-b222", "subnet-c333"]);
        assert_ne!(
            before_ids, after_ids,
            "same elements, different order — raw Value equality (the old fallback) \
             sees these as different"
        );

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_network_acl": {
                    "main": { "subnet_ids": after_ids }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_network_acl",
            "main",
            json!({ "subnet_ids": before_ids, "id": "acl-abc123" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "same subnet ids in a different order must not report drift"
        );
    }

    #[test]
    fn scalar_array_attribute_genuinely_different_element_still_updates() {
        let before_ids = json!(["subnet-a111", "subnet-b222", "subnet-c333"]);
        let after_ids = json!(["subnet-a111", "subnet-b222", "subnet-d444"]);

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_network_acl": {
                    "main": { "subnet_ids": after_ids }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_network_acl",
            "main",
            json!({ "subnet_ids": before_ids, "id": "acl-abc123" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "a genuinely different subnet id (not just reordered) must still report drift"
        );
    }

    // ── BUG 5 regression: max_items=1 nested block, array vs bare object ──
    //
    // Live incident: `aws_eks_cluster.access_config`,
    // `aws_eks_access_policy_association.access_scope`,
    // `aws_eks_node_group.{scaling_config,update_config}` — tfstate
    // encodes a `max_items = 1` nested block as a single-element array
    // `[{...}]`; Pangea's rendered config JSON emits the equivalent
    // block as a bare `{...}`. Confirmed pure false positives — the
    // values underneath are identical.

    #[test]
    fn nested_block_array_of_one_object_vs_bare_object_is_noop() {
        let before_scaling = json!([{ "desired_size": 3, "max_size": 5, "min_size": 1 }]);
        let after_scaling = json!({ "desired_size": 3, "max_size": 5, "min_size": 1 });
        assert_ne!(
            before_scaling, after_scaling,
            "an Array and an Object are never `==` under raw serde_json::Value equality \
             (the old fallback) even when the values underneath are identical"
        );

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_eks_node_group": {
                    "workers": { "scaling_config": after_scaling }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_eks_node_group",
            "workers",
            json!({ "scaling_config": before_scaling, "id": "example-eks:workers" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "a max_items=1 block wrapped in an array (state) vs bare (config) must not report drift"
        );
    }

    #[test]
    fn nested_block_array_of_one_object_genuinely_different_value_still_updates() {
        let before_scaling = json!([{ "desired_size": 3, "max_size": 5, "min_size": 1 }]);
        let after_scaling = json!({ "desired_size": 4, "max_size": 5, "min_size": 1 });

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_eks_node_group": {
                    "workers": { "scaling_config": after_scaling }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_eks_node_group",
            "workers",
            json!({ "scaling_config": before_scaling, "id": "example-eks:workers" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "a genuinely different desired_size inside the unwrapped block must still report drift"
        );
    }

    // ── BUG 6 regression: NACL-rule protocol name vs number ──
    //
    // Live incident: 10 of 14 `aws_network_acl_rule.*` resources
    // false-positived because AWS's `DescribeNetworkAcls` returns the
    // numeric IP protocol code while Pangea's config declares the name.

    #[test]
    fn nacl_rule_protocol_name_vs_number_is_noop() {
        let before_protocol = json!("6");
        let after_protocol = json!("tcp");
        assert_ne!(before_protocol, after_protocol);

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_network_acl_rule": {
                    "allow_https": {
                        "rule_number": 100,
                        "egress": false,
                        "protocol": after_protocol,
                        "rule_action": "allow",
                        "cidr_block": "10.0.0.0/16",
                        "from_port": 443,
                        "to_port": 443
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_network_acl_rule",
            "allow_https",
            json!({
                "rule_number": 100,
                "egress": false,
                "protocol": before_protocol,
                "rule_action": "allow",
                "cidr_block": "10.0.0.0/16",
                "from_port": 443,
                "to_port": 443,
                "id": "nacl-abc123"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "protocol \"6\" (state) and \"tcp\" (config) name the same protocol and must not report drift"
        );
    }

    #[test]
    fn nacl_rule_genuinely_different_protocol_still_updates() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_network_acl_rule": {
                    "allow_https": {
                        "rule_number": 100,
                        "egress": false,
                        "protocol": "udp",
                        "rule_action": "allow",
                        "cidr_block": "10.0.0.0/16",
                        "from_port": 443,
                        "to_port": 443
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_network_acl_rule",
            "allow_https",
            json!({
                "rule_number": 100,
                "egress": false,
                "protocol": "6",
                "rule_action": "allow",
                "cidr_block": "10.0.0.0/16",
                "from_port": 443,
                "to_port": 443,
                "id": "nacl-abc123"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "tcp (\"6\") vs udp (\"17\") are genuinely different protocols and must still report drift"
        );
    }

    // ── BUG 7 regression: allow-all NACL rule, null vs 0 ports ──
    //
    // Live incident: the 4 `protocol = "-1"` (allow-all) NACL rules —
    // AWS returns `null` for `from_port`/`to_port` on an allow-all
    // rule; Pangea's rendered config declares `0` for the same rule.

    #[test]
    fn nacl_rule_allow_all_null_vs_zero_ports_is_noop() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_network_acl_rule": {
                    "allow_all_egress": {
                        "rule_number": 200,
                        "egress": true,
                        "protocol": "all",
                        "rule_action": "allow",
                        "cidr_block": "0.0.0.0/0",
                        "from_port": 0,
                        "to_port": 0
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_network_acl_rule",
            "allow_all_egress",
            json!({
                "rule_number": 200,
                "egress": true,
                "protocol": "-1",
                "rule_action": "allow",
                "cidr_block": "0.0.0.0/0",
                "from_port": null,
                "to_port": null,
                "id": "nacl-def456"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "null (state) and 0 (config) for from_port/to_port on an allow-all rule must not report drift"
        );
    }

    #[test]
    fn nacl_rule_allow_all_genuinely_different_port_still_updates() {
        // Even under an allow-all protocol, a genuinely different
        // from_port value (not the null-vs-0 shape) must still surface
        // as drift — the relief is narrowly scoped, not "ignore ports
        // on allow-all rules".
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_network_acl_rule": {
                    "allow_all_egress": {
                        "rule_number": 200,
                        "egress": true,
                        "protocol": "all",
                        "rule_action": "allow",
                        "cidr_block": "0.0.0.0/0",
                        "from_port": 100,
                        "to_port": 100
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_network_acl_rule",
            "allow_all_egress",
            json!({
                "rule_number": 200,
                "egress": true,
                "protocol": "-1",
                "rule_action": "allow",
                "cidr_block": "0.0.0.0/0",
                "from_port": 0,
                "to_port": 0,
                "id": "nacl-def456"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "a genuinely different from_port (0 vs 100) must still report drift even on an allow-all rule"
        );
    }

    // ── BUG 8 regression: write-only EKS-addon fields ──
    //
    // Live incident: `aws_eks_addon.resolve_conflicts_on_{create,update}`
    // are apply-time-only directives with no corresponding readable
    // field in AWS's `DescribeAddon` API — state is permanently `null`
    // for these regardless of what a correct refresh does.

    #[test]
    fn eks_addon_write_only_fields_never_report_drift() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_eks_addon": {
                    "vpc_cni": {
                        "cluster_name": "example-eks",
                        "addon_name": "vpc-cni",
                        "resolve_conflicts_on_create": "OVERWRITE",
                        "resolve_conflicts_on_update": "OVERWRITE"
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_eks_addon",
            "vpc_cni",
            json!({
                "cluster_name": "example-eks",
                "addon_name": "vpc-cni",
                "resolve_conflicts_on_create": null,
                "resolve_conflicts_on_update": null,
                "id": "example-eks:vpc-cni"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "null (state, unreadable) vs \"OVERWRITE\" (config, write-only) must never report drift"
        );
    }

    #[test]
    fn eks_addon_other_attribute_genuinely_different_still_updates() {
        // The write-only exemption must be narrowly scoped to the two
        // named keys — a genuinely different, REAL attribute on the
        // same resource (`addon_version`) must still report drift.
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_eks_addon": {
                    "vpc_cni": {
                        "cluster_name": "example-eks",
                        "addon_name": "vpc-cni",
                        "addon_version": "v1.18.0-eksbuild.1",
                        "resolve_conflicts_on_create": "OVERWRITE",
                        "resolve_conflicts_on_update": "OVERWRITE"
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_eks_addon",
            "vpc_cni",
            json!({
                "cluster_name": "example-eks",
                "addon_name": "vpc-cni",
                "addon_version": "v1.15.4-eksbuild.1",
                "resolve_conflicts_on_create": null,
                "resolve_conflicts_on_update": null,
                "id": "example-eks:vpc-cni"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "a genuinely different addon_version must still report drift even though the \
             write-only fields on the same resource are exempt"
        );
    }

    // ── BUG 7 regression: address-scoped externally-managed attribute
    //    (breathe-controller vs magma on example-eks_controllers_ng's
    //    scaling_config) ──
    //
    // Live incident: `breathe-controller`'s `EksNodegroupProvedor` calls
    // `UpdateNodegroupConfig` directly against AWS on every reconcile
    // tick, gated by a live `BreatheCloudPool` CR targeting
    // `example-eks_controllers_ng` — bypassing Terraform/magma state
    // entirely. Pangea's static `scaling_config` declaration would
    // otherwise fight breathe's live scaling on every plan cycle.

    #[test]
    fn externally_managed_scaling_config_on_named_resource_never_reports_drift() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_eks_node_group": {
                    "example-eks_controllers_ng": {
                        "cluster_name": "example-eks",
                        "node_group_name": "example-eks-controllers",
                        "scaling_config": { "min_size": 1, "max_size": 4, "desired_size": 1 }
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_eks_node_group",
            "example-eks_controllers_ng",
            json!({
                "cluster_name": "example-eks",
                "node_group_name": "example-eks-controllers",
                "scaling_config": { "min_size": 1, "max_size": 5, "desired_size": 5 },
                "id": "example-eks:example-eks-controllers"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "example-eks_controllers_ng's scaling_config is breathe-owned — a live disagreement \
             with magma's static declaration must never report drift"
        );
    }

    #[test]
    fn externally_managed_scaling_config_exemption_does_not_leak_to_other_resources() {
        // The exemption is address-scoped, not resource-type-scoped —
        // a DIFFERENT aws_eks_node_group (no BreatheCloudPool targets
        // it) with the exact same scaling_config disagreement must
        // still report drift. This is the safety-critical test: it
        // proves the fix can't silently widen into a fleet-wide
        // scaling_config blind spot.
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_eks_node_group": {
                    "example-eks_system_ng": {
                        "cluster_name": "example-eks",
                        "node_group_name": "example-eks-system",
                        "scaling_config": { "min_size": 1, "max_size": 4, "desired_size": 1 }
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_eks_node_group",
            "example-eks_system_ng",
            json!({
                "cluster_name": "example-eks",
                "node_group_name": "example-eks-system",
                "scaling_config": { "min_size": 1, "max_size": 5, "desired_size": 5 },
                "id": "example-eks:example-eks-system"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "example-eks_system_ng has no BreatheCloudPool owner — its scaling_config drift \
             must still be reported, proving the exemption is address-scoped, not type-scoped"
        );
    }

    // ── OIDC-provider issuer URL regression (narrowly-scoped, not
    //    part of the 6-class family) ──
    //
    // Live incident: `aws_iam_openid_connect_provider.example-eks_oidc`'s
    // `url` resolves (via
    // `${aws_eks_cluster.main.identity[0].oidc[0].issuer}`) to a value
    // WITH the `https://` scheme; AWS's `DescribeOpenIDConnectProvider`
    // strips the scheme on read, so state never carries it.

    #[test]
    fn oidc_provider_url_scheme_prefix_is_noop() {
        let before_url = json!("oidc.eks.us-east-2.amazonaws.com/id/ABCDEF0123456789");
        let after_url = json!("https://oidc.eks.us-east-2.amazonaws.com/id/ABCDEF0123456789");
        assert_ne!(before_url, after_url);

        let cfg = Config::from_json(json!({
            "resource": {
                "aws_iam_openid_connect_provider": {
                    "example-eks_oidc": { "url": after_url }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_iam_openid_connect_provider",
            "example-eks_oidc",
            json!({
                "url": before_url,
                "id": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-2.amazonaws.com/id/ABCDEF0123456789"
            }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::NoOp,
            "the same issuer URL with vs without an https:// scheme must not report drift"
        );
    }

    #[test]
    fn oidc_provider_url_genuinely_different_issuer_still_updates() {
        let cfg = Config::from_json(json!({
            "resource": {
                "aws_iam_openid_connect_provider": {
                    "example-eks_oidc": {
                        "url": "https://oidc.eks.us-east-2.amazonaws.com/id/DIFFERENT9999999"
                    }
                }
            }
        }))
        .unwrap();
        let mut st = empty_state();
        st.resources.push(mk_state_resource(
            "aws_iam_openid_connect_provider",
            "example-eks_oidc",
            json!({ "url": "oidc.eks.us-east-2.amazonaws.com/id/ABCDEF0123456789" }),
        ));

        let p = plan(&cfg, &st).unwrap();
        assert_eq!(p.resource_changes.len(), 1);
        assert_eq!(
            p.resource_changes[0].action,
            Action::Update,
            "a genuinely different OIDC issuer id must still report drift regardless of scheme normalization"
        );
    }
}
