//! Cross-workspace coverage test — proves magma can render + plan
//! every shape in `magma-test/fixtures/pangea-architectures/`.
//!
//! Powered by `magma-arch-test`'s typed `WorkspaceTestHarness` +
//! `verify_directory` so adding a new fixture is a one-file drop —
//! no test edits required. The compounding piece: every new fixture
//! adds proof; the test code never grows.

use std::path::PathBuf;

use magma_arch_test::{WorkspaceTestHarness, verify_directory};

fn fixtures_root() -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR available in cargo test");
    PathBuf::from(manifest_dir).join("fixtures/pangea-architectures")
}

#[tokio::test]
async fn every_pangea_architectures_fixture_plans_cleanly() {
    let root = fixtures_root();
    assert!(root.exists(), "fixtures dir missing: {}", root.display());

    let agg = verify_directory(&root).await.expect("verify_directory");

    // Print the human report regardless of outcome.
    eprintln!(
        "magma can render+plan {}/{} pangea-architectures fixtures:",
        agg.passed, agg.total_workspaces,
    );
    for ws in &agg.workspaces {
        match &ws.report {
            Some(r) => eprintln!(
                "  + {:<32} {:>2} changes  [providers: {}]",
                ws.name,
                r.resource_change_count,
                r.providers.join(", "),
            ),
            None => eprintln!(
                "  - {:<32} FAILED: {}",
                ws.name,
                ws.error.as_deref().unwrap_or("<no error>"),
            ),
        }
    }

    assert_eq!(
        agg.failed, 0,
        "{} fixture(s) failed verification — see report above",
        agg.failed,
    );
    assert!(
        agg.total_workspaces >= 15,
        "expected ≥15 fixtures, found {}",
        agg.total_workspaces,
    );
}

#[tokio::test]
async fn every_fixture_uses_at_least_one_provider() {
    let root = fixtures_root();
    let agg = verify_directory(&root).await.expect("verify_directory");
    for ws in &agg.workspaces {
        let report = ws
            .report
            .as_ref()
            .unwrap_or_else(|| panic!("fixture {} did not produce a report", ws.name));
        assert!(
            !report.providers.is_empty(),
            "fixture {} declares no providers",
            ws.name,
        );
    }
}

#[tokio::test]
async fn every_fixture_is_pure_creates_against_empty_state() {
    let root = fixtures_root();
    let agg = verify_directory(&root).await.expect("verify_directory");
    for ws in &agg.workspaces {
        let report = ws.report.as_ref().expect("report present");
        assert!(
            report.compatibility.all_creates,
            "fixture {} produced non-Create actions: {:?}",
            ws.name, report.action_histogram,
        );
    }
}

#[tokio::test]
async fn every_fixture_plan_id_is_deterministic() {
    let root = fixtures_root();
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let harness = WorkspaceTestHarness::new(path.clone());
            harness
                .assert_plan_id_deterministic()
                .await
                .unwrap_or_else(|e| panic!("fixture {} failed determinism: {e}", path.display()));
        }
    }
}

/// The headline test: every fixture passes the FULL substrate law
/// battery — architecture composition + workspace lifecycle. One
/// line per fixture (delegated to `assert_all_substrate_laws`),
/// every law from `magma-test-laws` is exercised.
///
/// A regression in any layer (architecture composition checks,
/// workspace plan determinism, apply convergence, destroy
/// round-trip, apply enumeration, serial monotonicity) surfaces
/// here with a clear message naming the broken law.
#[tokio::test]
async fn every_fixture_passes_all_substrate_laws() {
    let root = fixtures_root();
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let harness = WorkspaceTestHarness::new(path.clone());
            harness
                .assert_all_substrate_laws()
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "fixture {} failed substrate law battery: {e}",
                        path.display()
                    )
                });
        }
    }
}

#[tokio::test]
async fn coverage_spans_diverse_provider_sources() {
    let root = fixtures_root();
    let agg = verify_directory(&root).await.expect("verify_directory");

    let mut all_providers: std::collections::HashSet<String> = Default::default();
    for ws in &agg.workspaces {
        if let Some(r) = &ws.report {
            for p in &r.providers {
                all_providers.insert(p.clone());
            }
        }
    }

    // The fixture corpus must span at least these provider sources to
    // be considered representative of pangea-architectures.
    let required = [
        "hashicorp/aws",
        "cloudflare/cloudflare",
        "datadog/datadog",
        "hashicorp/kubernetes",
        "akeyless-community/akeyless",
        "splunk/splunk",
        "tailscale/tailscale",
        "integrations/github",
        "hetznercloud/hcloud",
    ];
    for r in &required {
        assert!(
            all_providers.contains(&(*r).to_string()),
            "fixture corpus missing provider {r}; got {:?}",
            all_providers,
        );
    }

    eprintln!(
        "Coverage spans {} distinct providers across {} fixtures",
        all_providers.len(),
        agg.total_workspaces,
    );
}
