//! magma-providers — provider discovery: locate the provider binary the
//! workspace already has on disk.
//!
//! After `tofu init` / `terraform init`, providers live under
//! `<workspace>/.terraform/providers/<registry>/<ns>/<name>/<version>/
//! <os>_<arch>/terraform-provider-<name>_v<version>[...]`. The operator
//! runs init before apply, so the binary is present; magma just needs to
//! find it to [`magma_plugin::Plugin::spawn`] it. (Registry download +
//! `.terraform.lock.hcl` round-trip is a later milestone; this is the
//! path the operator exercises today.)

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ProviderLocateError {
    #[error("no .terraform/providers dir under workspace {0:?} — run `init` first")]
    NoProvidersDir(PathBuf),
    #[error("provider binary for {name:?} not found under {root:?}")]
    NotFound { name: String, root: PathBuf },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Locate the provider binary for `provider_name` (e.g. `"github"`)
/// under a workspace's `.terraform/providers` tree.
///
/// Matches a file named `terraform-provider-<name>` or
/// `terraform-provider-<name>_v<version>` (optionally `_x5`), as written
/// by `terraform/tofu init`. Returns the first match in a deterministic
/// (sorted) walk so repeated locates are stable.
pub fn locate_provider(
    workspace: &Path,
    provider_name: &str,
) -> Result<PathBuf, ProviderLocateError> {
    let exact = format!("terraform-provider-{provider_name}");
    let prefix = format!("terraform-provider-{provider_name}_v");

    // Search roots, in priority order:
    //   1. the workspace's own `.terraform/providers` (tofu/terraform init),
    //   2. `$MAGMA_PROVIDER_DIR` — a Nix-baked provider mirror in the image.
    // (2) is the no-tofu path: the operator image ships the provider
    // binaries (via Nix), so `init` need not download anything and the
    // workspace tree may be absent. Either layout works — a flat dir of
    // binaries or the registry `<reg>/<ns>/<name>/<ver>/<os>_<arch>/…` tree.
    let mut roots: Vec<PathBuf> = vec![workspace.join(".terraform").join("providers")];
    if let Some(dir) = std::env::var_os("MAGMA_PROVIDER_DIR") {
        roots.push(PathBuf::from(dir));
    }

    let mut found: Vec<PathBuf> = Vec::new();
    let mut any_root = false;
    for root in &roots {
        if root.is_dir() {
            any_root = true;
            walk_for(root, &exact, &prefix, &mut found)?;
        }
    }
    if !any_root {
        return Err(ProviderLocateError::NoProvidersDir(workspace.to_path_buf()));
    }
    found.sort();
    found
        .into_iter()
        .next()
        .ok_or_else(|| ProviderLocateError::NotFound {
            name: provider_name.to_string(),
            root: roots.into_iter().next().unwrap_or_default(),
        })
}

/// Bounded recursive walk collecting files whose name is exactly `exact`
/// or starts with `prefix` (the `_v<version>` form).
///
/// Uses `Path::is_dir`/`is_file` (which FOLLOW symlinks) rather than the
/// dir-entry's own type — tofu's `plugin-cache` symlinks the provider
/// binary into `.terraform/providers`, and a symlink's `file_type()` is
/// neither dir nor file, so an entry-type check would silently miss it.
fn walk_for(
    dir: &Path,
    exact: &str,
    prefix: &str,
    out: &mut Vec<PathBuf>,
) -> Result<(), ProviderLocateError> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            walk_for(&path, exact, prefix, out)?;
        } else if path.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name == exact || name.starts_with(prefix) {
                    out.push(path);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn touch(p: &Path) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"#!/bin/sh\n").unwrap();
    }

    #[test]
    fn locates_versioned_provider_binary() {
        let td = TempDir::new().unwrap();
        let ws = td.path();
        let bin = ws
            .join(
                ".terraform/providers/registry.terraform.io/integrations/github/6.2.1/linux_amd64",
            )
            .join("terraform-provider-github_v6.2.1");
        touch(&bin);
        assert_eq!(locate_provider(ws, "github").unwrap(), bin);
    }

    #[test]
    fn errors_when_no_providers_dir() {
        let td = TempDir::new().unwrap();
        assert!(matches!(
            locate_provider(td.path(), "github"),
            Err(ProviderLocateError::NoProvidersDir(_))
        ));
    }

    #[test]
    fn errors_when_provider_absent() {
        let td = TempDir::new().unwrap();
        let ws = td.path();
        touch(&ws.join(".terraform/providers/registry.terraform.io/hashicorp/aws/5.0.0/linux_amd64/terraform-provider-aws_v5.0.0"));
        assert!(matches!(
            locate_provider(ws, "github"),
            Err(ProviderLocateError::NotFound { .. })
        ));
    }

    #[test]
    fn does_not_match_other_providers() {
        let td = TempDir::new().unwrap();
        let ws = td.path();
        touch(&ws.join(
            ".terraform/providers/r/i/github/6.2.1/linux_amd64/terraform-provider-github_v6.2.1",
        ));
        touch(
            &ws.join(
                ".terraform/providers/r/h/aws/5.0.0/linux_amd64/terraform-provider-aws_v5.0.0",
            ),
        );
        let got = locate_provider(ws, "github").unwrap();
        assert!(
            got.to_string_lossy()
                .contains("terraform-provider-github_v6.2.1")
        );
    }
}
