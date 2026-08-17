//! Publishability gate: this repo must not name a real estate.
//!
//! magma is intended to be open-sourced. The blocker found on 2026-08-01 was
//! NOT a credential — it was ~110 references to real infrastructure scattered
//! through doc comments and fixtures: cluster names, a live VPC id, an
//! internal DNS zone, and the name of a skunkworks environment. All of it was
//! written in good faith, as "measured, not assumed" evidence, which is
//! exactly the right instinct for a private repo and becomes a disclosure the
//! moment the repo is published.
//!
//! A one-time cleanup would drift back within a week, because the habit that
//! produced it is a GOOD habit. So the cleanup is sealed here instead: cite
//! the SHAPE of the evidence, not the live resource names.
//!
//! WHAT THIS DOES NOT FORBID, deliberately: vendor and product names. This
//! repo integrates with a secrets vendor and generates providers for it, so
//! `akeyless` as a provider/gem name (`lava-akeyless`, `pangea-akeyless`) is
//! legitimate and stays. The line is between naming a PRODUCT and naming
//! SOMEBODY'S DEPLOYMENT.
//!
//! Fixing a failure here is nearly always "genericize the comment", not
//! "delete the evidence" — `example-eks`, `vpc-0123456789abcdef0` and
//! friends carry the same explanatory weight with none of the disclosure.
//!
//! ── WHY THIS SCANS DECODED BASE64 (2026-08-17) ─────────────────────────
//!
//! The 2026-08-07 cleanup ran this gate, saw 3/3 green, and shipped. It was
//! wrong, and the gate said nothing for ten days on a public repo: one
//! fixture carried a rendered `user_data` blob, and a `user_data` is base64.
//! A textual find-and-replace cannot reach inside it, so every name the
//! cleanup removed from the plaintext was still sitting in the same file
//! one decode away — and a grep-based gate is exactly the tool that cannot
//! see that.
//!
//! So the unit of scanning is no longer "the file's bytes"; it is the file's
//! bytes PLUS every base64 run in it that decodes to UTF-8. That closes the
//! class rather than the instance: any future encoded payload — a user_data,
//! a cloud-init, an embedded cert body — is scanned on the way in.
//!
//! The same pass added `subnet-` to the id prefixes, for the same reason
//! from the other direction: a real subnet id sat in that fixture through
//! the cleanup because nothing had ever put `subnet-` on the list.

use base64::Engine as _;
use std::path::{Path, PathBuf};

/// Substrings that name a real deployment rather than a product.
const FORBIDDEN_NAMES: &[&str] = &[
    "camelot",
    "shaar",
    "akeyless-dev",
    "akeyless_dev",
    "dev.akeyless.io",
];

/// The AWS account this repo is developed against. Not a credential, but it
/// belongs to a host whose ground we are borrowing.
const FORBIDDEN_ACCOUNT: &str = "376129857990";

/// Real AWS resource-id prefixes. A genuine id is 8–17 hex chars; the
/// canonical placeholders (`0123456789abcdef0`, `0a1b2c3d`) are allowed
/// because they are obviously not real.
const ID_PREFIXES: &[&str] = &[
    "vpc-",
    "subnet-",
    "eipalloc-",
    "acl-",
    "igw-",
    "nat-",
    "eni-",
];

const ALLOWED_ID_BODIES: &[&str] = &["0123456789abcdef0", "0a1b2c3d", "0e1f2a3b", "xxx"];

fn repo_root() -> PathBuf {
    // magma-test/ -> workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("magma-test has a parent")
        .to_path_buf()
}

fn scannable(p: &Path) -> bool {
    if p.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == "target" || s == ".git"
    }) {
        return false;
    }
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("rs" | "nix" | "toml" | "json" | "md" | "yml" | "yaml")
    )
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        // A symlink is never repo content — git stores the link, not the
        // target — so following one scans somebody's local scratch (a search
        // index, a build cache) and reports it as a finding in this repo.
        // `file_type()` is lstat and does not follow; `path().is_dir()` does.
        if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue;
        }
        let p = e.path();
        if p.is_dir() {
            if !p.components().any(|c| {
                let s = c.as_os_str().to_string_lossy();
                s == "target" || s == ".git"
            }) {
                walk(&p, out);
            }
        } else if scannable(&p) {
            out.push(p);
        }
    }
}

fn sources() -> Vec<PathBuf> {
    let mut v = Vec::new();
    walk(&repo_root(), &mut v);
    assert!(
        v.len() > 50,
        "publishability scan found only {} files — the walk is broken, and a \
         gate that scans nothing passes everything",
        v.len()
    );
    v
}

/// Shortest run worth decoding. A `user_data` script is hundreds of bytes;
/// this only needs to be long enough that a stray word is not a candidate.
const MIN_BASE64_RUN: usize = 40;

/// Every maximal base64 run in `text` that decodes to UTF-8, as text.
///
/// A hex digest or a long identifier is also spelled in the base64 alphabet,
/// but it decodes to bytes that are not UTF-8, so it filters itself out.
fn decoded_base64(text: &str) -> Vec<String> {
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=';
    let mut out = Vec::new();
    for run in text.split(|c: char| !is_b64(c)) {
        if run.len() < MIN_BASE64_RUN || !run.len().is_multiple_of(4) {
            continue;
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(run) else {
            continue;
        };
        if let Ok(s) = String::from_utf8(bytes) {
            out.push(s);
        }
    }
    out
}

/// The units one file contributes: its own text, then each decoded payload
/// carried inside it. Labelled so a hit says WHERE it was hiding.
fn scan_units(p: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(p) else {
        return Vec::new();
    };
    let payloads = decoded_base64(&text);
    let mut units = vec![(p.display().to_string(), text)];
    for (i, decoded) in payloads.into_iter().enumerate() {
        units.push((format!("{} (base64 payload #{i})", p.display()), decoded));
    }
    units
}

/// Files to scan, minus this one — it names the forbidden strings in order
/// to forbid them.
fn scannable_units() -> Vec<(String, String)> {
    sources()
        .into_iter()
        .filter(|p| {
            p.file_name().and_then(|f| f.to_str()) != Some("publishability_no_host_estate.rs")
        })
        .flat_map(|p| scan_units(&p))
        .collect()
}

#[test]
fn no_real_deployment_names() {
    let mut hits = Vec::new();
    for (where_, text) in scannable_units() {
        let lower = text.to_lowercase();
        for name in FORBIDDEN_NAMES {
            if lower.contains(name) {
                hits.push(format!("{where_}: {name}"));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "this repo is meant to be publishable, and these name a real \
         deployment rather than a product:\n  {}\n\nGenericize the reference \
         (example-eks, example-dev, vpn-concentrator). Keep the evidence, drop \
         the address.",
        hits.join("\n  ")
    );
}

#[test]
fn no_host_account_id() {
    let hits: Vec<String> = scannable_units()
        .into_iter()
        .filter(|(_, text)| text.contains(FORBIDDEN_ACCOUNT))
        .map(|(where_, _)| where_)
        .collect();
    assert!(
        hits.is_empty(),
        "the host's AWS account id appears in:\n  {}",
        hits.join("\n  ")
    );
}

#[test]
fn no_real_aws_resource_ids() {
    let mut hits = Vec::new();
    for (where_, text) in scannable_units() {
        for prefix in ID_PREFIXES {
            let mut rest = text.as_str();
            while let Some(i) = rest.find(prefix) {
                rest = &rest[i + prefix.len()..];
                let body: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                if body.len() >= 8 && !ALLOWED_ID_BODIES.contains(&body.as_str()) {
                    hits.push(format!("{where_}: {prefix}{body}"));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "these look like REAL AWS resource ids:\n  {}\n\nUse a placeholder \
         (vpc-0123456789abcdef0). The id is never the point of the example.",
        hits.join("\n  ")
    );
}
