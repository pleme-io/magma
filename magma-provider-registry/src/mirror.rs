//! Reading a Nix-baked provider mirror as registry COORDINATES.
//!
//! The seed half of `theory/MAGMA-PROVIDER-PLANE.md` §VI's "interim →
//! destination path": *seed the registry from the current bake*. The bake
//! stops being the mechanism and becomes the seed + the offline fallback.
//!
//! ── ★ THE PATH IS THE KEY, so there is no manifest ───────────────────
//! The plan for this phase assumed the mirror could not be seeded, because
//! a filename like `terraform-provider-aws_6.21.0` carries the LOCAL name
//! and the registry key needs the SOURCE (`hashicorp/aws`) — the namespace
//! is not recoverable from a filename. That was going to need a Nix-emitted
//! manifest.
//!
//! It was wrong. nixpkgs lays every provider out in terraform's own
//! filesystem-mirror layout, and `buildEnv` preserves it:
//!
//! ```text
//! libexec/terraform-providers/registry.terraform.io/hashicorp/aws/6.21.0/linux_amd64/terraform-provider-aws_6.21.0
//!                             └─ registry ───────┘ └── source ──┘ └ver─┘ └platform─┘
//! ```
//!
//! Source, version and platform are all in the path. Measured, not assumed
//! — including that two providers in one `buildEnv` keep their separate
//! trees. So the seeder reads coordinates rather than being told them, and
//! adding a provider to the image stays a one-line flake edit with nothing
//! to keep in sync.
//!
//! ── WHY THIS IS NOT `locate_provider`'s WALK ─────────────────────────
//! `magma_providers::locate_provider` searches for a FILENAME anywhere
//! under its roots and ignores the directory structure — which is why it
//! cannot tell `aws 5.x` from `aws 6.x` and resolves by lexicographic path
//! order. This module reads the structure instead, so a version is a fact
//! rather than a coincidence of sort order.

use std::path::{Path, PathBuf};

/// One provider binary found in a mirror, with its registry coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorEntry {
    /// `hashicorp/aws` — namespace and name, registry host stripped.
    pub source: String,
    /// `6.21.0`.
    pub version: String,
    /// `linux_amd64` — terraform's spelling, already joined.
    pub platform: String,
    /// The binary itself.
    pub path: PathBuf,
}

/// The marker directory terraform's filesystem-mirror layout hangs off.
const MIRROR_ROOT: &str = "terraform-providers";

/// Read a path's registry coordinates, if it looks like a mirror entry.
///
/// Returns `None` for anything that is not
/// `…/terraform-providers/<registry>/<ns>/<name>/<version>/<platform>/<file>`
/// rather than guessing — a file that does not carry coordinates has none,
/// and inventing them would put a wrong key in the registry, which is worse
/// than skipping it.
#[must_use]
pub fn coordinates_of(path: &Path) -> Option<MirrorEntry> {
    let parts: Vec<&str> = path
        .components()
        .map(|c| c.as_os_str().to_str().unwrap_or_default())
        .collect();

    // Walk from the RIGHT: the mirror may be nested under any prefix
    // (a nix store path, a buildEnv, a bind mount), and only the tail is
    // contractual.
    let marker = parts.iter().rposition(|p| *p == MIRROR_ROOT)?;
    // marker, registry, ns, name, version, platform, file
    let tail = parts.get(marker + 1..)?;
    if tail.len() != 6 {
        return None;
    }
    let (ns, name, version, platform) = (tail[1], tail[2], tail[3], tail[4]);
    if ns.is_empty() || name.is_empty() || version.is_empty() || platform.is_empty() {
        return None;
    }
    Some(MirrorEntry {
        source: format!("{ns}/{name}"),
        version: version.to_string(),
        platform: platform.to_string(),
        path: path.to_path_buf(),
    })
}

/// Every provider binary under `root`, with coordinates.
///
/// Follows symlinks: a `buildEnv` mirror is entirely symlinks into the nix
/// store, so refusing to follow them would find nothing at all — the same
/// reasoning `locate_provider` records for its own walk.
///
/// A `root` that does not exist yields an empty vector rather than an
/// error. Absence is a legitimate state (no bake in this image); it is the
/// CALLER's job to decide whether empty is acceptable, and
/// [`SeedReport`](crate::SeedReport) carries the denominator so it can.
#[must_use]
pub fn scan(root: &Path) -> Vec<MirrorEntry> {
    let mut out = Vec::new();
    walk(root, &mut out, 0);
    out.sort_by(|a, b| (&a.source, &a.version).cmp(&(&b.source, &b.version)));
    out
}

/// Bounded recursive walk. The depth cap is not decoration: the mirror is
/// symlinks, `follow`ing them can cycle, and an unbounded walk over a cycle
/// hangs the seed rather than failing it.
fn walk(dir: &Path, out: &mut Vec<MirrorEntry>, depth: usize) {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out, depth + 1);
        } else if path.is_file() {
            if let Some(found) = coordinates_of(&path) {
                out.push(found);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real shape, measured from a live `nix build` of
    /// `terraform-providers.hashicorp_aws`.
    #[test]
    fn reads_the_real_nixpkgs_layout() {
        let p = Path::new(
            "/nix/store/abc-terraform-provider-aws-6.21.0/libexec/terraform-providers/\
             registry.terraform.io/hashicorp/aws/6.21.0/linux_amd64/terraform-provider-aws_6.21.0",
        );
        let e = coordinates_of(p).expect("the real layout must parse");
        assert_eq!(e.source, "hashicorp/aws");
        assert_eq!(e.version, "6.21.0");
        assert_eq!(e.platform, "linux_amd64");
    }

    /// A third-party namespace is not special — this is exactly why the
    /// namespace has to come from the PATH and not from the filename.
    #[test]
    fn a_non_hashicorp_namespace_keeps_its_owner() {
        let p = Path::new(
            "/x/libexec/terraform-providers/registry.terraform.io/cyrilgdn/rabbitmq/\
             1.8.0/linux_amd64/terraform-provider-rabbitmq_1.8.0",
        );
        let e = coordinates_of(p).expect("parses");
        assert_eq!(e.source, "cyrilgdn/rabbitmq");
    }

    /// The filename alone cannot produce a key. `terraform-provider-aws_6.21.0`
    /// says nothing about `hashicorp`, which is the whole reason this module
    /// reads the directory structure.
    #[test]
    fn a_bare_binary_outside_the_layout_yields_nothing() {
        assert!(coordinates_of(Path::new("/usr/bin/terraform-provider-aws_6.21.0")).is_none());
        assert!(coordinates_of(Path::new("/x/terraform-providers/too/short/path")).is_none());
    }

    /// Two versions of one provider are two DISTINCT coordinates. Under
    /// `locate_provider`'s filename walk they are indistinguishable and the
    /// winner is decided by lexicographic path order; here they are separate
    /// keys and both can be registered.
    #[test]
    fn two_versions_of_one_provider_are_two_keys() {
        let base = "/x/libexec/terraform-providers/registry.terraform.io/hashicorp/aws";
        let old = coordinates_of(Path::new(&format!(
            "{base}/5.31.0/linux_amd64/terraform-provider-aws_5.31.0"
        )))
        .expect("parses");
        let new = coordinates_of(Path::new(&format!(
            "{base}/6.21.0/linux_amd64/terraform-provider-aws_6.21.0"
        )))
        .expect("parses");
        assert_eq!(old.source, new.source);
        assert_ne!(old.version, new.version);
    }

    /// Same provider, same version, two platforms — distinct, because the
    /// registry key includes platform and a darwin binary must never be
    /// served to a linux pod.
    #[test]
    fn platforms_do_not_collide() {
        let base = "/x/libexec/terraform-providers/registry.terraform.io/hashicorp/aws/6.21.0";
        let l = coordinates_of(Path::new(&format!(
            "{base}/linux_amd64/terraform-provider-aws_6.21.0"
        )))
        .expect("parses");
        let d = coordinates_of(Path::new(&format!(
            "{base}/darwin_arm64/terraform-provider-aws_6.21.0"
        )))
        .expect("parses");
        assert_ne!(l.platform, d.platform);
    }

    #[test]
    fn scanning_an_absent_root_is_empty_not_an_error() {
        assert!(scan(Path::new("/nonexistent-mirror-root")).is_empty());
    }
}

/// Proof against a REAL mirror, not a string fixture.
///
/// Skips unless `MAGMA_MIRROR_PROBE` names a built mirror, so CI stays green
/// without one. Build a probe with:
///
/// ```text
/// nix build --impure --expr 'let p = import <nixpkgs> {}; in p.buildEnv {
///   name = "probe"; paths = [ p.terraform-providers.hashicorp_aws
///                             p.terraform-providers.hashicorp_random ]; }'
/// ```
#[cfg(test)]
#[test]
fn scans_a_real_nix_built_mirror() {
    let Ok(root) = std::env::var("MAGMA_MIRROR_PROBE") else {
        eprintln!("MAGMA_MIRROR_PROBE unset — skipping the real-mirror proof");
        return;
    };
    let found = scan(Path::new(&root));
    assert!(
        !found.is_empty(),
        "a real mirror scanned to nothing — the layout contract broke"
    );
    for e in &found {
        assert!(
            e.source.contains('/'),
            "source must be namespace/name, got {:?}",
            e.source
        );
        assert!(!e.version.is_empty() && !e.platform.is_empty());
        assert!(e.path.exists(), "path must resolve through the symlink");
    }
    eprintln!("REAL MIRROR: {} provider(s)", found.len());
    for e in &found {
        eprintln!("  {} {} {}", e.source, e.version, e.platform);
    }
}
