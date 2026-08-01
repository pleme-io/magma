//! Pangea-shape directory discovery.
//!
//! Scans a directory rooted at `<root>/`, expects:
//!
//!   <root>/pangea.yml             # root config (required)
//!   <root>/workspaces/<name>/     # workspace dir (one per subdir)
//!     pangea.yml                  # workspace config (optional;
//!                                  # missing yields default
//!                                  # `WorkspaceConfig`)
//!     *.rb                        # optional template file
//!
//! Workspaces are emitted sorted alphabetically by name so the
//! discovery result is deterministic across operators.

use std::path::PathBuf;

use crate::{DiscoveredRepo, DiscoveredWorkspace, RepoError, Result, config, workspace};

/// Scan `root` + return a typed `DiscoveredRepo`.
pub fn discover(root: PathBuf) -> Result<DiscoveredRepo> {
    if !root.exists() {
        return Err(RepoError::Discovery(format!(
            "root path does not exist: {}",
            root.display(),
        )));
    }
    if !root.is_dir() {
        return Err(RepoError::Discovery(format!(
            "root path is not a directory: {}",
            root.display(),
        )));
    }

    // Root pangea.yml is REQUIRED — the repo's identity depends
    // on it. Missing -> error.
    let root_yml = root.join("pangea.yml");
    if !root_yml.exists() {
        return Err(RepoError::MissingFile("pangea.yml at repo root".into()));
    }
    let root_text = std::fs::read_to_string(&root_yml)?;
    let root_config = config::parse(&root_text)?;

    // Walk `<root>/workspaces/`. Absent = empty workspace list
    // (repo has root config but no workspaces yet).
    let mut workspaces: Vec<DiscoveredWorkspace> = vec![];
    let ws_root = root.join("workspaces");
    if ws_root.is_dir() {
        for entry in std::fs::read_dir(&ws_root)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(String::from)
                .ok_or_else(|| {
                    RepoError::Discovery(format!(
                        "workspace dir name not utf-8: {}",
                        path.display(),
                    ))
                })?;
            // Workspace pangea.yml is optional; default-construct
            // if missing so the workspace still appears.
            let ws_yml = path.join("pangea.yml");
            let ws_config = if ws_yml.exists() {
                let text = std::fs::read_to_string(&ws_yml)?;
                workspace::parse(&text)?
            } else {
                workspace::WorkspaceConfig::default()
            };
            // Optional template: first `.rb` file in the workspace.
            let template = find_first_rb(&path);
            workspaces.push(DiscoveredWorkspace {
                name,
                dir: path,
                config: ws_config,
                template,
            });
        }
        workspaces.sort_by(|a, b| a.name.cmp(&b.name));
    }

    let repo_attestation = crate::attestation::attest_discovered(&root_config, &workspaces);

    Ok(DiscoveredRepo {
        root,
        root_config,
        workspaces,
        repo_attestation,
    })
}

fn find_first_rb(dir: &std::path::Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut rbs: Vec<PathBuf> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "rb") {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    rbs.sort();
    rbs.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn stage_minimal_repo() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("pangea.yml"),
            "tags: { ManagedBy: pangea }\naccounts: {}\n",
        )
        .unwrap();
        // workspace alpha with pangea.yml + template
        let alpha = tmp.path().join("workspaces/alpha");
        fs::create_dir_all(&alpha).unwrap();
        fs::write(
            alpha.join("pangea.yml"),
            "default_namespace: alpha\naccount: example-development\n",
        )
        .unwrap();
        fs::write(alpha.join("alpha.rb"), "# pangea template\n").unwrap();
        // workspace beta with no pangea.yml (default-construct).
        let beta = tmp.path().join("workspaces/beta");
        fs::create_dir_all(&beta).unwrap();
        tmp
    }

    #[test]
    fn discovers_minimal_repo() {
        let tmp = stage_minimal_repo();
        let repo = discover(tmp.path().to_path_buf()).unwrap();
        assert_eq!(repo.workspaces.len(), 2);
        assert_eq!(repo.workspaces[0].name, "alpha");
        assert_eq!(repo.workspaces[1].name, "beta");
        assert!(repo.workspaces[0].template.is_some());
        assert!(repo.workspaces[1].template.is_none());
        assert_eq!(repo.workspaces[0].config.default_namespace, "alpha");
        // beta defaulted -> empty default_namespace.
        assert!(repo.workspaces[1].config.default_namespace.is_empty());
    }

    #[test]
    fn missing_root_pangea_yml_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = discover(tmp.path().to_path_buf()).unwrap_err();
        assert!(matches!(err, RepoError::MissingFile(_)));
    }

    #[test]
    fn missing_root_path_errors() {
        let err = discover("/this/does/not/exist".into()).unwrap_err();
        assert!(matches!(err, RepoError::Discovery(_)));
    }

    #[test]
    fn discovered_workspaces_are_sorted() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("pangea.yml"), "accounts: {}\n").unwrap();
        // Out-of-order names; discover() must sort them.
        for n in &["zulu", "alpha", "mike"] {
            let d = tmp.path().join("workspaces").join(n);
            fs::create_dir_all(&d).unwrap();
        }
        let repo = discover(tmp.path().to_path_buf()).unwrap();
        let names: Vec<&str> = repo.workspaces.iter().map(|w| w.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mike", "zulu"]);
    }

    #[test]
    fn repo_with_no_workspaces_dir_yields_empty_list() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("pangea.yml"), "accounts: {}\n").unwrap();
        let repo = discover(tmp.path().to_path_buf()).unwrap();
        assert!(repo.workspaces.is_empty());
    }
}
