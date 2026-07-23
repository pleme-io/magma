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
                key.0,
                key.1,
            );
        }
    }
    for (type_name, by_name) in &cfg.data {
        for name in by_name.keys() {
            let key = (format!("data.{}", type_name), name.clone());
            assert!(
                seen.insert(key.clone()),
                "Architecture law violated: duplicate data source address: {}.{}",
                key.0,
                key.1,
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
        let head = reference_head(&r);
        let is_builtin = [
            "var.",
            "local.",
            "each.",
            "count.",
            "path.",
            "terraform.",
            "self.",
        ]
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
            None => continue, // single-token type, skip
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

/// Recursively walk a JSON value and append every genuine `${...}`
/// interpolation reference found in string positions to `out`.
/// References are stored as their inner path (without the `${...}`
/// wrapper).
///
/// ## Escaped literals are not references (2026-07-23 incident)
///
/// HCL2's own escaping convention — the syntax Terraform-JSON string
/// values are subject to just like native HCL — is `$${` / `%%{` for
/// a literal `${` / `%{` that must render as-is and NEVER be
/// interpolated. `HclContentEscaping.escape` in pangea-architectures
/// emits exactly this doubling for opaque foreign content (a GitHub
/// Actions workflow's `${{ secrets.BOT_PAT }}`, a shell `${VAR}`, …)
/// before it lands in a `github_repository_file.content` string, so
/// that Terraform's own JSON parser doesn't choke on it.
///
/// A naive `s.find("${")` (the previous implementation here) has no
/// concept of that escape: for `$${{ secrets.BOT_PAT }}` it matches
/// the SECOND `$` + the FIRST `{` (a real substring `"${"` sits right
/// there, one byte into the escape), then scans forward to the next
/// `}` and extracts `{ secrets.BOT_PAT ` — note the stray leading
/// brace, the leftover second `{` of GitHub Actions' double-brace
/// `${{ }}` syntax — as a "reference". That string can never match a
/// declared resource address, so `assert_no_dangling_references`
/// rejects the ENTIRE workspace. This is exactly what broke
/// `pleme-io-opensource`'s 2,567-resource apply on 2026-07-23, one
/// release after the escaping fix itself (pangea-architectures commit
/// 236cd42) landed — the escape was correct, this scanner just didn't
/// know how to read it.
///
/// The fix: scan left to right and, at every position, prefer the
/// escape-sequence match (`$${` / `%%{`, 3 bytes, consumed whole and
/// never re-examined) over the reference-open match (`${`, 2 bytes).
/// This is the same greedy, position-local decision HCL2's own
/// tokenizer makes — it never "looks back" past the current byte —
/// so a real, adjacent, or immediately-following reference is still
/// found correctly, and the escaped sequence's trailing brace can
/// never be mistaken for a fresh opener.
fn collect_references(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => scan_string_for_references(s, out),
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

/// The actual per-string scan behind [`collect_references`], factored
/// out so it's directly unit-testable against raw `&str` fixtures
/// without wrapping every case in a `serde_json::Value::String`.
///
/// Walks `s` byte by byte (all of `$`, `%`, `{`, `}` are single-byte
/// ASCII, so byte-index scanning never lands mid-codepoint on the
/// surrounding UTF-8 content). At each position, in priority order:
///
/// 1. `$${` or `%%{` — an HCL2-escaped literal `${` / `%{`. NOT a
///    reference. All 3 bytes are consumed as one inert unit, so the
///    second `{` is never re-examined as if it were a fresh opener —
///    the exact shape of the production bug, since GitHub Actions'
///    `${{ }}` has a DOUBLE brace immediately after the escape.
/// 2. `${` (a single, unescaped `$`) — a genuine interpolation open.
///    Scanned forward to the matching `}` and the inner path is
///    recorded.
/// 3. anything else — advance one byte and keep scanning.
///
/// `%{...}` (HCL2 template directives — `%{if}` / `%{for}`) is walked
/// over like ordinary text when NOT escaped, matching this scanner's
/// behavior before this fix: this law validates resource
/// *references*, which are always `${...}`-wrapped. Recognizing
/// `%%{` only prevents it from ever being misread, symmetric with the
/// `$${` case — it does not newly treat `%{` as a reference opener.
fn scan_string_for_references(s: &str, out: &mut Vec<String>) {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Escaped literal: `$$` or `%%` immediately followed by `{`.
        // Consume all 3 bytes as one unit — never a reference, and
        // the trailing `{` must not restart a scan on the next loop.
        if i + 2 < bytes.len()
            && (bytes[i] == b'$' || bytes[i] == b'%')
            && bytes[i + 1] == bytes[i]
            && bytes[i + 2] == b'{'
        {
            i += 3;
            continue;
        }
        // Genuine, unescaped interpolation open.
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let after = &s[i + 2..];
            if let Some(end) = after.find('}') {
                out.push(after[..end].to_string());
                i += 2 + end + 1;
                continue;
            }
            // Unterminated `${` — nothing left worth scanning.
            break;
        }
        i += 1;
    }
}

/// Extract the address head of a reference path. Two cases:
///
/// * managed resource ref: `aws_vpc.main.id` → `aws_vpc.main`
/// * data source ref: `data.aws_vpc.main.id` → `data.aws_vpc.main`
/// * module ref: `module.foo.output_x` → `module.foo`
/// * output ref: `output.bar` → `output.bar`
///
/// Used to compare references against declared addresses.
fn reference_head(reference: &str) -> String {
    let parts: Vec<&str> = reference.split('.').collect();
    match parts.first().copied() {
        Some("data") => {
            // data.<type>.<name>... → 3-segment head
            match (parts.get(1), parts.get(2)) {
                (Some(t), Some(n)) => format!("data.{t}.{n}"),
                _ => reference.to_string(),
            }
        }
        Some("module") => {
            // module.<name>.<output>... → 2-segment head
            match parts.get(1) {
                Some(n) => format!("module.{n}"),
                _ => reference.to_string(),
            }
        }
        Some("output") => {
            // output.<name> — already the head
            match parts.get(1) {
                Some(n) => format!("output.{n}"),
                _ => reference.to_string(),
            }
        }
        _ => {
            // Managed resource: <type>.<name>... → 2-segment head
            match (parts.first(), parts.get(1)) {
                (Some(t), Some(n)) => format!("{t}.{n}"),
                (Some(t), None) => t.to_string(),
                _ => reference.to_string(),
            }
        }
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
fn _hashmap_keeplive() -> HashMap<String, String> {
    HashMap::new()
}

// ── Unit tests: the escape-aware scanner itself ────────────────────
//
// White-box tests against `scan_string_for_references` directly —
// the exact byte-level fix for the 2026-07-23 incident. See the
// integration battery in `tests/architecture_law_battery.rs` for the
// same fix proven end-to-end through `assert_no_dangling_references`
// on a real `Config`.
#[cfg(test)]
mod scan_tests {
    use super::scan_string_for_references;

    fn refs(s: &str) -> Vec<String> {
        let mut out = vec![];
        scan_string_for_references(s, &mut out);
        out
    }

    #[test]
    fn real_unescaped_reference_is_found() {
        assert_eq!(refs("${aws_vpc.main.id}"), vec!["aws_vpc.main.id"]);
    }

    #[test]
    fn escaped_dollar_brace_literal_yields_no_reference() {
        // The exact incident shape: GitHub Actions' `${{ }}` (double
        // brace) after HclContentEscaping.escape has doubled the `$`.
        assert_eq!(refs("$${{ secrets.BOT_PAT }}"), Vec::<String>::new());
    }

    #[test]
    fn escaped_dollar_brace_single_brace_yields_no_reference() {
        assert_eq!(refs("$${aws_vpc.foo.id}"), Vec::<String>::new());
    }

    #[test]
    fn escaped_percent_brace_literal_yields_no_reference() {
        assert_eq!(refs("%%{if var.enabled}"), Vec::<String>::new());
    }

    #[test]
    fn unescaped_percent_brace_directive_is_not_treated_as_a_reference() {
        // `%{if}` / `%{for}` are HCL2 template directives, not
        // interpolations — this scanner only ever extracts `${...}`
        // references, escaped or not. Unchanged from before the fix.
        assert_eq!(refs("%{if var.enabled}yes%{endif}"), Vec::<String>::new());
    }

    #[test]
    fn mixed_escaped_and_real_reference_each_handled_on_their_own_terms() {
        assert_eq!(
            refs("$${aws_vpc.foo.id} plus real ${aws_vpc.main.id}"),
            vec!["aws_vpc.main.id"],
        );
    }

    #[test]
    fn escaped_sequence_immediately_followed_by_a_real_reference() {
        // No text between them — proves the escape consumption doesn't
        // eat into or shift the start of the next, genuine `${`.
        assert_eq!(refs("$${x}${aws_vpc.main.id}"), vec!["aws_vpc.main.id"],);
    }

    #[test]
    fn two_real_references_back_to_back_are_both_found() {
        assert_eq!(
            refs("${aws_vpc.a.id}${aws_vpc.b.id}"),
            vec!["aws_vpc.a.id", "aws_vpc.b.id"],
        );
    }

    #[test]
    fn escaped_sequence_at_the_very_start_of_the_string() {
        assert_eq!(
            refs("$${aws_vpc.main.id} trailing text"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn escaped_sequence_at_the_very_end_of_the_string() {
        assert_eq!(
            refs("leading text $${aws_vpc.main.id}"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn truncated_dollar_at_end_of_string_does_not_panic() {
        // No `{` follows — must not index out of bounds.
        assert_eq!(refs("trailing dollar $"), Vec::<String>::new());
        assert_eq!(refs("trailing pair $$"), Vec::<String>::new());
    }

    #[test]
    fn no_interpolation_at_all_yields_no_references() {
        assert_eq!(refs("plain string, nothing special"), Vec::<String>::new());
    }
}
