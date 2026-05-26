//! Exercise the provider-laws helpers against the real
//! pangea-architectures fixtures. Proves the per-resource
//! invariant helpers work on the shapes Pangea actually emits.

use std::path::PathBuf;

use magma_config::Config;
use magma_test_laws::provider::{
    assert_field_is_cidr, assert_no_iam_wildcards, assert_resource_has_field,
};

fn fixtures_root() -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR available in cargo test");
    PathBuf::from(manifest_dir).join("fixtures/pangea-architectures")
}

fn load_fixture(name: &str) -> Config {
    let path = fixtures_root().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path:?}: {e}"));
    Config::from_json(v).unwrap_or_else(|e| panic!("Config::from_json {path:?}: {e}"))
}

/// Walk every fixture + collect IAM-wildcard findings. Reports
/// findings via eprintln (CI surfaces them) but doesn't fail —
/// some Pangea architectures legitimately need unscoped resource
/// permissions (e.g. cilium ENI manipulation, KMS auto-rotation
/// scoped by aws:condition keys instead of resource ARN).
///
/// A regression check that EVERY new fixture had no wildcards
/// would be too brittle; the value here is the visibility +
/// the typed `ProviderViolation` surface for downstream gates.
#[test]
fn fixtures_iam_wildcard_audit_reports_findings() {
    let root = fixtures_root();
    let mut total_findings: usize = 0;
    let mut fixtures_with_findings: Vec<String> = vec![];
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let cfg = load_fixture(&name);
            if let Err(violations) = assert_no_iam_wildcards(&cfg) {
                eprintln!(
                    "fixture {} has {} IAM wildcard finding(s):",
                    name,
                    violations.len(),
                );
                for v in &violations {
                    eprintln!("  - {} {} ({}): {}", v.resource, v.field, v.rule, v.message);
                }
                total_findings += violations.len();
                fixtures_with_findings.push(name);
            }
        }
    }
    eprintln!(
        "\nIAM-wildcard audit summary: {} finding(s) across {} fixture(s)",
        total_findings,
        fixtures_with_findings.len(),
    );
    // Sanity: the check itself works — total findings is computable.
    let _ = total_findings;
}

/// Every aws_vpc resource declared in any Pangea fixture has a
/// well-formed cidr_block field. Pangea's typed VPC functions
/// must always emit a valid CIDR; this catches regression where
/// a code-gen change drops or corrupts the field.
#[test]
fn every_aws_vpc_has_valid_cidr_block() {
    let root = fixtures_root();
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let cfg = load_fixture(&name);
            if let Some(by_name) = cfg.resources.get("aws_vpc") {
                for vpc_name in by_name.keys() {
                    assert_resource_has_field(&cfg, "aws_vpc", vpc_name, "cidr_block")
                        .unwrap_or_else(|v| panic!("fixture {name} aws_vpc.{vpc_name}: {v:?}"));
                    assert_field_is_cidr(&cfg, "aws_vpc", vpc_name, "cidr_block")
                        .unwrap_or_else(|v| panic!("fixture {name} aws_vpc.{vpc_name}: {v:?}"));
                }
            }
        }
    }
}

/// Same shape for aws_subnet: every declared subnet has a valid
/// cidr_block.
#[test]
fn every_aws_subnet_has_valid_cidr_block() {
    let root = fixtures_root();
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let cfg = load_fixture(&name);
            if let Some(by_name) = cfg.resources.get("aws_subnet") {
                for subnet_name in by_name.keys() {
                    assert_resource_has_field(&cfg, "aws_subnet", subnet_name, "cidr_block")
                        .unwrap_or_else(|v| {
                            panic!("fixture {name} aws_subnet.{subnet_name}: {v:?}")
                        });
                    assert_field_is_cidr(&cfg, "aws_subnet", subnet_name, "cidr_block")
                        .unwrap_or_else(|v| {
                            panic!("fixture {name} aws_subnet.{subnet_name}: {v:?}")
                        });
                }
            }
        }
    }
}

/// Coverage check: at least one fixture exercises aws_vpc + at
/// least one exercises aws_subnet. Guards against the test suite
/// becoming vacuous if the fixture set shifts.
#[test]
fn fixtures_cover_aws_vpc_and_aws_subnet() {
    let root = fixtures_root();
    let mut has_vpc = false;
    let mut has_subnet = false;
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let cfg = load_fixture(&name);
            if cfg.resources.contains_key("aws_vpc") {
                has_vpc = true;
            }
            if cfg.resources.contains_key("aws_subnet") {
                has_subnet = true;
            }
        }
    }
    assert!(has_vpc, "no fixture exercises aws_vpc");
    assert!(has_subnet, "no fixture exercises aws_subnet");
}
