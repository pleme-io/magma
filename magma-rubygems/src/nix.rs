//! bundix-equivalent — emit `gemset.nix` from a typed Lockfile
//! (M7 destination).
//!
//! Bundix's job is to convert a Gemfile.lock into a Nix derivation
//! set that `nix-build` materializes into a gem closure. This
//! module does the same thing in-memory: given a typed
//! `Lockfile`, emit canonical `gemset.nix` text.
//!
//! ## What's complete today
//!
//! * PATH sources (`source = { path = …; type = "path"; }`)
//! * GIT sources (`source = { url = …; rev = …; type = "git"; }`)
//! * Top-level structure with sorted gem entries
//! * `dependencies` block per gem when transitives present
//! * Canonical `groups = ["default"]` + `platforms = []`
//!
//! ## What's pending M3 (fetcher)
//!
//! * Real `sha256` hashes for rubygems.org sources. Today we
//!   emit `"TODO_M3_FETCHER_SHA256"` as a placeholder; the
//!   produced gemset.nix is structurally correct but won't
//!   nix-build until M3 fetches each gem + computes the
//!   `nix-hash` digest. Compliance gate: any consumer
//!   downstream that requires a usable gemset.nix must wait for
//!   M3, but the M7 emission is the load-bearing typed bridge.
//!
//! Per [`theory/MAGMA-AS-PLATFORM.md`](https://github.com/pleme-io/theory/blob/main/MAGMA-AS-PLATFORM.md) §IV.M7.

use crate::{
    Result,
    lockfile::{Lockfile, ResolvedGem},
    source::Source,
};

/// Sentinel emitted for rubygems.org-sourced gems until M3
/// fetcher lands. Operators that want a usable gemset.nix today
/// regex-substitute these with the matching `nix-prefetch-url`
/// output; future M3 fills them in mechanically.
pub const PLACEHOLDER_SHA256: &str = "TODO_M3_FETCHER_SHA256";

/// Emit canonical gemset.nix text from a typed `Lockfile`.
///
/// The output is structurally identical to bundix's emission for
/// the same logical closure: same set of top-level gem entries,
/// same per-gem structure. Ordering is alphabetical by gem name
/// (bundix's also alphabetical; this is byte-identical for the
/// keys, near-identical for the content modulo sha256 placeholder).
pub fn emit_gemset(lock: &Lockfile) -> Result<String> {
    let mut gems_sorted: Vec<&ResolvedGem> = lock.gems.iter().collect();
    gems_sorted.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out = String::new();
    out.push_str("{\n");

    for gem in gems_sorted {
        out.push_str(&format!("  {} = {{\n", gem.name));

        // dependencies block (only when non-empty)
        if !gem.depends_on.is_empty() {
            let mut deps_sorted = gem.depends_on.clone();
            deps_sorted.sort();
            let inner = deps_sorted
                .iter()
                .map(|d| format!("\"{d}\""))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!("    dependencies = [{inner}];\n"));
        }

        // groups: always ["default"] in bundix's canonical output;
        // dependency-group tracking lands when M1 Gemfile parser
        // populates `groups` per dep.
        out.push_str("    groups = [\"default\"];\n");

        // platforms: always [] for now; bundler emits per-platform
        // variants when needed.
        out.push_str("    platforms = [];\n");

        // source block, dispatched by typed Source.
        out.push_str("    source = {\n");
        match &gem.source {
            Source::Path { dir } => {
                let dir_str = dir.to_string_lossy();
                // bundix writes path entries as a Nix path expression
                // (./.) when local, or relative ../foo for siblings.
                out.push_str(&format!("      path = {};\n", emit_path_expr(&dir_str)));
                out.push_str("      type = \"path\";\n");
            }
            Source::Git { url, reference } => {
                out.push_str(&format!("      url = \"{url}\";\n"));
                if !reference.is_empty() {
                    out.push_str(&format!("      rev = \"{reference}\";\n"));
                }
                // Same placeholder until M3 fetches + hashes.
                out.push_str(&format!("      sha256 = \"{PLACEHOLDER_SHA256}\";\n"));
                out.push_str("      type = \"git\";\n");
            }
            Source::RubyGemsOrg { mirror_url } => {
                let remote = mirror_url
                    .clone()
                    .unwrap_or_else(|| "https://rubygems.org".into());
                out.push_str(&format!(
                    "      remotes = [\"{}\"];\n",
                    remote.trim_end_matches('/')
                ));
                out.push_str(&format!("      sha256 = \"{PLACEHOLDER_SHA256}\";\n"));
                out.push_str("      type = \"gem\";\n");
            }
        }
        out.push_str("    };\n");

        out.push_str(&format!("    version = \"{}\";\n", gem.version));
        out.push_str("  };\n");
    }

    out.push_str("}\n");
    Ok(out)
}

/// Emit a Nix path expression for a path string. Bundix-style:
/// * `.`         -> `./.`
/// * `./foo`     -> `./foo`
/// * `../foo`    -> `../foo`
/// * `/abs`      -> `/abs`
/// * `foo`       -> `./foo` (relative paths get the `./` prefix)
fn emit_path_expr(dir: &str) -> String {
    if dir.is_empty() || dir == "." {
        "./.".into()
    } else if dir.starts_with('/') || dir.starts_with("./") || dir.starts_with("../") {
        dir.into()
    } else {
        format!("./{dir}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::ResolvedGem;

    fn sample_lock() -> Lockfile {
        Lockfile {
            bundler_version: Some("2.5.22".into()),
            ruby: None,
            platforms: vec!["ruby".into()],
            dependencies: vec!["rspec".into()],
            specs: vec![],
            gems: vec![
                ResolvedGem {
                    name: "pangea-core".into(),
                    version: "0.3.0".into(),
                    source: Source::Path {
                        dir: std::path::PathBuf::from("../pangea-core"),
                    },
                    depends_on: vec!["dry-struct".into(), "dry-types".into(), "base64".into()],
                },
                ResolvedGem {
                    name: "rspec".into(),
                    version: "3.12.0".into(),
                    source: Source::default_rubygems(),
                    depends_on: vec!["rspec-core".into()],
                },
            ],
        }
    }

    #[test]
    fn emits_top_level_braces() {
        let text = emit_gemset(&sample_lock()).unwrap();
        assert!(text.starts_with("{\n"));
        assert!(text.trim_end().ends_with("}"));
    }

    #[test]
    fn emits_gems_alphabetically() {
        let text = emit_gemset(&sample_lock()).unwrap();
        let pangea_pos = text.find("pangea-core").unwrap();
        let rspec_pos = text.find("rspec").unwrap();
        assert!(pangea_pos < rspec_pos);
    }

    #[test]
    fn path_source_emits_relative_path() {
        let text = emit_gemset(&sample_lock()).unwrap();
        assert!(text.contains("path = ../pangea-core;"));
        assert!(text.contains("type = \"path\";"));
    }

    #[test]
    fn rubygems_source_emits_remotes_and_placeholder_sha() {
        let text = emit_gemset(&sample_lock()).unwrap();
        assert!(text.contains("remotes = [\"https://rubygems.org\"];"));
        assert!(text.contains("type = \"gem\";"));
        assert!(text.contains(PLACEHOLDER_SHA256));
    }

    #[test]
    fn dependencies_block_sorted_and_emitted_only_when_present() {
        let text = emit_gemset(&sample_lock()).unwrap();
        // pangea-core has 3 transitive deps — they must emit sorted.
        assert!(text.contains("dependencies = [\"base64\" \"dry-struct\" \"dry-types\"];"));
        // The "rspec" gem also has a dep (rspec-core), which should appear.
        assert!(text.contains("dependencies = [\"rspec-core\"];"));
    }

    #[test]
    fn empty_lockfile_emits_empty_attrset() {
        let text = emit_gemset(&Lockfile::default()).unwrap();
        assert_eq!(text, "{\n}\n");
    }

    #[test]
    fn version_block_uses_double_quotes() {
        let text = emit_gemset(&sample_lock()).unwrap();
        assert!(text.contains("version = \"0.3.0\";"));
        assert!(text.contains("version = \"3.12.0\";"));
    }

    #[test]
    fn path_expr_handles_various_shapes() {
        assert_eq!(emit_path_expr("."), "./.");
        assert_eq!(emit_path_expr("./foo"), "./foo");
        assert_eq!(emit_path_expr("../foo"), "../foo");
        assert_eq!(emit_path_expr("/abs"), "/abs");
        assert_eq!(emit_path_expr("relative/path"), "./relative/path");
    }
}
