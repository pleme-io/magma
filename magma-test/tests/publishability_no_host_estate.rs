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
const ID_PREFIXES: &[&str] = &["vpc-", "eipalloc-", "acl-", "igw-", "nat-", "eni-"];

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

#[test]
fn no_real_deployment_names() {
    let mut hits = Vec::new();
    for p in sources() {
        // This very file names the forbidden strings in order to forbid them.
        if p.file_name().and_then(|f| f.to_str()) == Some("publishability_no_host_estate.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let lower = text.to_lowercase();
        for name in FORBIDDEN_NAMES {
            if lower.contains(name) {
                hits.push(format!("{}: {name}", p.display()));
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
    let hits: Vec<String> = sources()
        .into_iter()
        .filter(|p| {
            p.file_name().and_then(|f| f.to_str()) != Some("publishability_no_host_estate.rs")
        })
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|t| t.contains(FORBIDDEN_ACCOUNT))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
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
    for p in sources() {
        if p.file_name().and_then(|f| f.to_str()) == Some("publishability_no_host_estate.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        for prefix in ID_PREFIXES {
            let mut rest = text.as_str();
            while let Some(i) = rest.find(prefix) {
                rest = &rest[i + prefix.len()..];
                let body: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                if body.len() >= 8 && !ALLOWED_ID_BODIES.contains(&body.as_str()) {
                    hits.push(format!("{}: {prefix}{body}", p.display()));
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
