//! [`DirRegistry`] — the directory-mirror resolver (§IV tier 2).
//!
//! Resolves a provider binary from `MAGMA_PROVIDER_DIR` (the Nix-baked
//! seed / offline fallback) by bounded recursive walk, matching the
//! exact same `terraform-provider-<name>` / `terraform-provider-<name>_<ver>`
//! shapes `magma-providers::locate_provider` matches. This is the
//! "no-tofu" path: the operator image ships provider binaries via Nix,
//! so `init` need not download anything.
//!
//! The directory mirror carries no recorded content-hash, so a resolved
//! [`ProviderHandle`] here has `info: None`. (The DB registry is the
//! tier that hash-verifies; the dir mirror is trusted-by-construction —
//! it is a Nix output, content-addressed by the store path itself.)

use std::path::{Path, PathBuf};

use crate::{ProviderHandle, ProviderRegistry, RegistryError};

/// Resolves provider binaries from a directory tree (default:
/// `$MAGMA_PROVIDER_DIR`). Either layout works — a flat dir of
/// binaries or the registry `<reg>/<ns>/<name>/<ver>/<os>_<arch>/…`
/// tree that `tofu init` writes.
#[derive(Debug, Clone)]
pub struct DirRegistry {
    root: Option<PathBuf>,
}

impl DirRegistry {
    /// A registry rooted at an explicit directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: Some(root.into()),
        }
    }

    /// A registry rooted at `$MAGMA_PROVIDER_DIR`, if set. When the env
    /// var is absent, `resolve` always returns `Ok(None)` (a clean
    /// miss) so this can sit at the tail of a [`crate::ChainRegistry`]
    /// without erroring on a fleet node that has no baked mirror.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            root: std::env::var_os("MAGMA_PROVIDER_DIR").map(PathBuf::from),
        }
    }
}

#[async_trait::async_trait]
impl ProviderRegistry for DirRegistry {
    async fn resolve(
        &self,
        source: &str,
        _version: &str,
        _os: &str,
        _arch: &str,
    ) -> Result<Option<ProviderHandle>, RegistryError> {
        let Some(root) = self.root.as_deref() else {
            return Ok(None);
        };
        if !root.is_dir() {
            return Ok(None);
        }
        // The bare provider name (last `/`-segment of source) is what
        // the `terraform-provider-<name>` binary is named after.
        let name = source.rsplit('/').next().unwrap_or(source);
        let exact = format!("terraform-provider-{name}");
        // Underscore (not `_v`) so we match BOTH tofu/terraform's
        // `terraform-provider-github_v6.2.1` AND nixpkgs's
        // `terraform-provider-github_6.8.3`.
        let prefix = format!("terraform-provider-{name}_");

        let mut found: Vec<PathBuf> = Vec::new();
        walk_for(root, &exact, &prefix, &mut found)?;
        found.sort();
        Ok(found.into_iter().next().map(ProviderHandle::from_path))
    }
}

/// Bounded recursive walk collecting files whose name is exactly
/// `exact` or starts with `prefix` (the `_v<version>` form). Follows
/// symlinks (tofu's plugin-cache symlinks the binary in), matching
/// `magma-providers::locate_provider`.
fn walk_for(
    dir: &Path,
    exact: &str,
    prefix: &str,
    out: &mut Vec<PathBuf>,
) -> Result<(), RegistryError> {
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
