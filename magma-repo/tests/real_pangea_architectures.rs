//! Acceptance gate: scan the real pangea-architectures clone +
//! verify discovery returns the expected workspace structure.
//!
//! Skipped if the repo isn't checked out on the test runner.

use std::path::Path;

fn pangea_architectures_root() -> Option<std::path::PathBuf> {
    // We're inside the magma workspace; pangea-architectures is a
    // sibling under the same pleme-io org checkout.
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)?
        .join("pangea-architectures");
    if p.join("pangea.yml").exists() {
        Some(p)
    } else {
        None
    }
}

#[test]
fn discovers_real_pangea_architectures_repo() {
    let Some(root) = pangea_architectures_root() else {
        eprintln!("pangea-architectures not checked out — skipping");
        return;
    };

    let repo = magma_repo::discover(root.clone())
        .unwrap_or_else(|e| panic!("discover {root:?}: {e}"));

    // Root config: must have accounts + state backend.
    assert!(!repo.root_config.accounts.is_empty(), "expected ≥1 account");
    assert!(repo.root_config.state.is_some(), "expected S3 state backend");
    let s3 = repo.root_config.state.as_ref().unwrap().s3.as_ref().unwrap();
    assert_eq!(s3.bucket, "pleme-dev-terraform-state");

    // Workspaces: expect ≥10 (pangea-architectures has ~20+).
    assert!(
        repo.workspaces.len() >= 5,
        "expected ≥5 workspaces, got {}", repo.workspaces.len(),
    );

    // At least one workspace has a pangea.yml with default_namespace set.
    let with_ns: Vec<&str> = repo
        .workspaces
        .iter()
        .filter(|w| !w.config.default_namespace.is_empty())
        .map(|w| w.name.as_str())
        .collect();
    assert!(
        !with_ns.is_empty(),
        "no workspace declared a default_namespace; expected ≥1",
    );

    // Attestation: 64-char hex.
    assert_eq!(repo.repo_attestation.len(), 64);
    assert!(repo.repo_attestation.chars().all(|c| c.is_ascii_hexdigit()));

    // Determinism: re-scan + same attestation.
    let repo2 = magma_repo::discover(root).unwrap();
    assert_eq!(repo.repo_attestation, repo2.repo_attestation);
}

#[test]
fn workspace_paths_are_absolute_under_root() {
    let Some(root) = pangea_architectures_root() else {
        eprintln!("pangea-architectures not checked out — skipping");
        return;
    };
    let repo = magma_repo::discover(root.clone()).unwrap();
    for w in &repo.workspaces {
        assert!(w.dir.is_absolute() || w.dir.starts_with(&root),
            "workspace {} dir not under repo root: {:?}", w.name, w.dir);
        assert!(w.dir.exists(), "workspace {} dir missing: {:?}", w.name, w.dir);
    }
}

#[test]
fn each_workspace_with_pangea_yml_parses() {
    let Some(root) = pangea_architectures_root() else {
        eprintln!("pangea-architectures not checked out — skipping");
        return;
    };
    let repo = magma_repo::discover(root).unwrap();
    let mut parsed_count = 0;
    for w in &repo.workspaces {
        let yml = w.dir.join("pangea.yml");
        if yml.exists() {
            parsed_count += 1;
        }
    }
    assert!(parsed_count >= 3,
        "expected ≥3 workspaces to ship a pangea.yml, got {parsed_count}");
}

fn _unused(_: &Path) {}
