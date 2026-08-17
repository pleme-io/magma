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

/// Twelve-digit runs that are allowed to look like an AWS account id. Anything
/// else matching `\d{12}` is treated as a real one.
///
/// This used to be a single `FORBIDDEN_ACCOUNT` literal naming the host's real
/// account. That is self-defeating on a public repo: a gate that detects a
/// string by carrying it publishes the very thing it exists to keep out, and
/// the literal was in fact the last occurrence of that account left in this
/// repo after the 2026-08-17 sweep. Inverting it to "no unrecognised 12-digit
/// run" publishes nothing and is a strictly stronger check — it catches ANY
/// account id, including the ones nobody thought to add to a list.
const ALLOWED_ACCOUNT_IDS: &[&str] = &["000000000000", "123456789012", "111122223333"];

/// Is this a 12-digit run standing on its own, rather than a slice of a longer
/// number (a timestamp in nanos, a hash, a size)?
fn is_standalone_12_digits(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
}

/// Every unrecognised standalone 12-digit run in `text`.
fn account_like_runs(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let run = &text[start..i];
        if run.len() == 12
            && is_standalone_12_digits(text, start, i)
            && !ALLOWED_ACCOUNT_IDS.contains(&run)
        {
            out.push(run.to_string());
        }
    }
    out
}

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

/// Paths git actually tracks, as absolute paths.
///
/// Publishability is a property of what git SHIPS, so the walk has to be
/// filtered by that and not by what happens to be on this disk. Measured
/// 2026-08-17: without this the gate reported four "AWS account ids" out of
/// `Cargo.build-spec.json`, a gitignored local build artifact that no consumer
/// of this repo will ever see — a false positive that would fire differently on
/// every machine. The same hole runs the other way and matters more: an
/// untracked file is invisible to a reader of the repo but a tracked one is
/// not, and only git knows which is which.
fn tracked() -> std::collections::HashSet<PathBuf> {
    let root = repo_root();
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args(["ls-files", "-z"])
        .output()
        .expect("git ls-files must run — this gate is meaningless without it");
    assert!(out.status.success(), "git ls-files failed in {root:?}");
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|rel| root.join(rel))
        .collect()
}

fn sources() -> Vec<PathBuf> {
    let mut v = Vec::new();
    walk(&repo_root(), &mut v);
    let tracked = tracked();
    v.retain(|p| tracked.contains(p));
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
fn no_aws_account_ids() {
    let mut hits = Vec::new();
    for (where_, text) in scannable_units() {
        for run in account_like_runs(&text) {
            hits.push(format!("{where_}: {run}"));
        }
    }
    assert!(
        hits.is_empty(),
        "these look like real AWS account ids:\n  {}\n\nUse one of the reserved \
         placeholders (000000000000, 123456789012, 111122223333). An account id \
         is never the point of an example, and this repo is meant to be \
         publishable.",
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
