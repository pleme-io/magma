//! Reusable composition laws for Pangea-rendered architectures.
//!
//! A "typed architecture" is a Pangea Ruby DSL composition that
//! emits a Terraform JSON workspace (`SecureVpc`, `TieredSubnets`,
//! `K3sDevCluster`, etc.). These helpers consume the rendered JSON
//! and assert load-bearing invariants the architecture promised:
//!
//! ```no_run
//! # use magma_test_laws::architecture::*;
//! # use magma_config::Config;
//! # let cfg = Config::default();
//! assert_resource_addresses_unique(&cfg);
//! assert_no_dangling_references(&cfg);
//! assert_outputs_have_values(&cfg);
//! ```
//!
//! Gated behind `architecture-laws`. Per
//! `theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md` §III (typed
//! architectures = composable proofs).

use std::collections::{HashMap, HashSet};

use magma_config::Config;

// ── Law 1: every resource address is unique ────────────────────────

/// Two different declarations cannot share the same `(type, name)`
/// pair. Real Pangea Ruby refuses this at render time; the law
/// guards against a renderer regression.
pub fn assert_resource_addresses_unique(cfg: &Config) {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for (type_name, by_name) in &cfg.resources {
        for name in by_name.keys() {
            let key = (type_name.clone(), name.clone());
            assert!(
                seen.insert(key.clone()),
                "Architecture law violated: duplicate resource address: {}.{}",
                key.0, key.1,
            );
        }
    }
    for (type_name, by_name) in &cfg.data {
        for name in by_name.keys() {
            let key = (format!("data.{}", type_name), name.clone());
            assert!(
                seen.insert(key.clone()),
                "Architecture law violated: duplicate data source address: {}.{}",
                key.0, key.1,
            );
        }
    }
}

// ── Law 2: every `${a.b.c}` reference points to a declared address

/// Walk every JSON value in resource attributes + outputs, find
/// `${type.name.attr}` interpolations, and assert each refers to a
/// `type.name` that's declared somewhere in the config. Dangling
/// references mean the architecture would fail at apply-time with
/// `Reference to undeclared resource`.
pub fn assert_no_dangling_references(cfg: &Config) {
    // Build the set of declared addresses (resources + data + modules + outputs).
    let mut declared: HashSet<String> = HashSet::new();
    for (type_name, by_name) in &cfg.resources {
        for name in by_name.keys() {
            declared.insert(format!("{type_name}.{name}"));
        }
    }
    for (type_name, by_name) in &cfg.data {
        for name in by_name.keys() {
            declared.insert(format!("data.{type_name}.{name}"));
        }
    }
    for name in cfg.modules.keys() {
        declared.insert(format!("module.{name}"));
    }
    for name in cfg.outputs.keys() {
        declared.insert(format!("output.{name}"));
    }
    // Variable references — Pangea variables are flattened at render
    // time so any `${var.X}` left in JSON is a leak, but we let it
    // pass here since rendering tests use their own var.* fixtures.
    // Skip `var.*` and `local.*` references.

    // Collect every `${...}` reference across all resource attribute
    // trees.
    let mut refs: Vec<String> = vec![];
    for by_name in cfg.resources.values() {
        for attrs in by_name.values() {
            collect_references(attrs, &mut refs);
        }
    }
    for by_name in cfg.data.values() {
        for attrs in by_name.values() {
            collect_references(attrs, &mut refs);
        }
    }
    for out in cfg.outputs.values() {
        collect_references(&out.value, &mut refs);
    }

    // Each ref must either resolve to a declared address (first two
    // path segments) OR be a `var.*` / `local.*` / `each.*` /
    // `count.*` / `path.*` / `terraform.*` (HCL-builtin) ref that
    // the renderer leaves intact.
    for r in refs {
        let head = first_two_segments(&r);
        let is_builtin = ["var", "local", "each", "count", "path", "terraform", "self"]
            .iter()
            .any(|b| r.starts_with(b));
        if is_builtin {
            continue;
        }
        assert!(
            declared.contains(&head),
            "Architecture law violated: dangling reference `{r}` — `{head}` is not declared",
        );
    }
}

// ── Law 3: every output has a `value` field ────────────────────────

/// `OutputDecl::value` is deserialized as `serde_json::Value` and
/// is always present per the type. The check is structural — we
/// confirm the value isn't the JSON null literal, since a null
/// output is almost always a Pangea bug.
pub fn assert_outputs_have_values(cfg: &Config) {
    for (name, out) in &cfg.outputs {
        assert!(
            !out.value.is_null(),
            "Architecture law violated: output `{name}` has null value",
        );
    }
}

// ── Law 4: terraform.required_providers is non-empty when resources

/// If the architecture declares any resources, it must also declare
/// at least one required_provider in the `terraform.required_providers`
/// block. Otherwise `tofu init` / magma's plan stage would fail.
pub fn assert_terraform_required_providers_present(cfg: &Config) {
    if cfg.resources.is_empty() && cfg.data.is_empty() {
        return; // empty workspace is vacuously valid
    }
    assert!(
        !cfg.terraform.required_providers.is_empty(),
        "Architecture law violated: resources declared but no terraform.required_providers entry",
    );
}

// ── Law 5: every provider referenced has a required_providers entry

/// Every resource type's prefix (e.g. `aws_vpc` → `aws`) must
/// correspond to a registered required_provider. Catches typos
/// where a resource is declared under a provider the workspace
/// didn't import.
pub fn assert_every_resource_type_has_a_provider(cfg: &Config) {
    let providers: HashSet<&str> = cfg
        .terraform
        .required_providers
        .keys()
        .map(String::as_str)
        .collect();
    for type_name in cfg.resources.keys().chain(cfg.data.keys()) {
        // The provider prefix is everything before the first `_`.
        // Pangea uses canonical Terraform names like `aws_vpc`,
        // `cloudflare_record`, `kubernetes_namespace`.
        let provider = match type_name.split_once('_') {
            Some((p, _)) => p,
            None         => continue, // single-token type, skip
        };
        assert!(
            providers.contains(provider),
            "Architecture law violated: resource type `{type_name}` references provider `{provider}` which is not in terraform.required_providers (declared: {providers:?})",
        );
    }
}

// ── Composite ─────────────────────────────────────────────────────

/// Run every architecture composition law. Panics on the first
/// violation with a clear message naming the broken law.
pub fn assert_all_laws(cfg: &Config) {
    assert_resource_addresses_unique(cfg);
    assert_terraform_required_providers_present(cfg);
    assert_every_resource_type_has_a_provider(cfg);
    assert_outputs_have_values(cfg);
    assert_no_dangling_references(cfg);
}

// ── Reference-collection helpers ──────────────────────────────────

/// Recursively walk a JSON value and append every `${...}` reference
/// found in string positions to `out`. References are stored as
/// their inner path (without the `${...}` wrapper).
fn collect_references(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => {
            // Multiple `${...}` substrings can appear in one string —
            // e.g. concatenated names. Walk them all.
            let mut rest = s.as_str();
            while let Some(start) = rest.find("${") {
                rest = &rest[start + 2..];
                if let Some(end) = rest.find('}') {
                    out.push(rest[..end].to_string());
                    rest = &rest[end + 1..];
                } else {
                    break;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for x in arr {
                collect_references(x, out);
            }
        }
        serde_json::Value::Object(obj) => {
            for v in obj.values() {
                collect_references(v, out);
            }
        }
        _ => {}
    }
}

/// Extract the first two `.`-separated segments of a reference path
/// — e.g. `aws_vpc.main.id` → `aws_vpc.main`. Used to compare
/// references against declared addresses.
fn first_two_segments(reference: &str) -> String {
    let parts: Vec<&str> = reference.splitn(3, '.').collect();
    match parts.len() {
        0 => String::new(),
        1 => parts[0].to_string(),
        _ => format!("{}.{}", parts[0], parts[1]),
    }
}

// ── Build helpers for the `data.` prefix case (collect_addresses) ──

/// Public helper: collect every fully-qualified declared address in
/// a Config. Useful for assertions outside this module that need to
/// reason about address sets.
pub fn collect_declared_addresses(cfg: &Config) -> HashSet<String> {
    let mut out = HashSet::new();
    for (t, b) in &cfg.resources {
        for n in b.keys() {
            out.insert(format!("{t}.{n}"));
        }
    }
    for (t, b) in &cfg.data {
        for n in b.keys() {
            out.insert(format!("data.{t}.{n}"));
        }
    }
    for n in cfg.modules.keys() {
        out.insert(format!("module.{n}"));
    }
    for n in cfg.outputs.keys() {
        out.insert(format!("output.{n}"));
    }
    out
}

/// Public helper: collect every `${...}` reference found inside
/// resource attributes + outputs. Returned references DO NOT include
/// the `${...}` wrapper.
pub fn collect_all_references(cfg: &Config) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for by_name in cfg.resources.values() {
        for attrs in by_name.values() {
            collect_references(attrs, &mut out);
        }
    }
    for by_name in cfg.data.values() {
        for attrs in by_name.values() {
            collect_references(attrs, &mut out);
        }
    }
    for o in cfg.outputs.values() {
        collect_references(&o.value, &mut out);
    }
    out
}

// Avoid `unused` warning when feature is enabled but no caller uses
// HashMap.
#[allow(dead_code)]
fn _hashmap_keeplive() -> HashMap<String, String> { HashMap::new() }
