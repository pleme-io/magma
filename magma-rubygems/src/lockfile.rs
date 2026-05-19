//! Gemfile.lock parser + emitter (M0 — parse landed; emit TBD).
//!
//! Reads bundler's lockfile format, produces typed `Lockfile`.
//! M0 acceptance gate: every Pangea Gemfile.lock parses cleanly +
//! the parsed lockfile carries every dependency.
//!
//! Format reference: <https://docs.ruby-lang.org/en/3.4/Gemfile_lock.html>.
//! Parser is line-based with significant indentation (2 spaces per
//! level). Sections recognized:
//!
//! * `PATH` / `GEM` / `GIT` blocks — gem source declarations
//! * `PLATFORMS` — supported platform list
//! * `DEPENDENCIES` — top-level deps (the Gemfile's surface)
//! * `RUBY VERSION` — pinned Ruby version
//! * `BUNDLED WITH` — bundler version that wrote the file

use serde::{Deserialize, Serialize};

use crate::{Result, RubygemsError, Spec};

/// Typed Gemfile.lock content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lockfile {
    /// Bundler version that produced this lockfile (preserved for
    /// round-trip compat, NOT load-bearing — magma's own resolver
    /// can regenerate from manifest).
    pub bundler_version: Option<String>,
    /// Pinned Ruby version (mirrors manifest::RubyVersion).
    pub ruby: Option<crate::manifest::RubyVersion>,
    /// Supported platform list (e.g. `arm64-darwin-25`, `ruby`).
    #[serde(default)]
    pub platforms: Vec<String>,
    /// Resolved gems: name + version + source.
    pub gems: Vec<ResolvedGem>,
    /// Per-gem specs (transitive closure).
    pub specs: Vec<Spec>,
    /// Dependencies block (top-level deps the Gemfile asked for).
    pub dependencies: Vec<String>,
}

/// One resolved gem instance — name + version + source pinning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedGem {
    pub name:    String,
    pub version: String,
    pub source:  crate::source::Source,
    /// Resolved dependencies of this gem (transitive surface).
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// Parse a Gemfile.lock source string into a typed `Lockfile`.
pub fn parse(source: &str) -> Result<Lockfile> {
    let mut lock = Lockfile::default();
    let mut section: Section = Section::Top;
    let mut current_source: Option<crate::source::Source> = None;
    let mut current_remote: Option<String> = None;
    let mut current_specs: Vec<ResolvedGem> = vec![];
    let mut current_gem_name: Option<String> = None;

    for raw_line in source.lines() {
        let trimmed = raw_line.trim_end();

        // Top-level section headers are uppercase + start at column 0.
        if !trimmed.starts_with(' ') && !trimmed.is_empty() {
            // Finalize any in-flight block before transitioning.
            flush_block(&mut lock, &current_source, &mut current_specs);
            current_source = None;
            current_remote = None;
            current_gem_name = None;
            section = match trimmed {
                "GIT"          => Section::Git,
                "PATH"         => Section::Path,
                "GEM"          => Section::Gem,
                "PLATFORMS"    => Section::Platforms,
                "DEPENDENCIES" => Section::Dependencies,
                "RUBY VERSION" => Section::RubyVersion,
                "BUNDLED WITH" => Section::BundledWith,
                other => {
                    return Err(RubygemsError::LockfileParse(format!(
                        "unknown section header: {other:?}",
                    )));
                }
            };
            continue;
        }

        match section {
            Section::Top => {} // skip blank lines / whitespace

            Section::Path | Section::Gem | Section::Git => {
                // Two-space indent: section-level key (`remote: …`,
                // `revision: …`, `specs:`).
                if let Some(rest) = trimmed.strip_prefix("  ") {
                    if !rest.starts_with(' ') {
                        // section-level field
                        if let Some(v) = rest.strip_prefix("remote: ") {
                            current_remote = Some(v.trim().to_string());
                        } else if let Some(_) = rest.strip_prefix("revision: ") {
                            // Git revision; M0 parses but ignores —
                            // M3 fetcher uses it.
                        } else if rest == "specs:" {
                            // Materialize the source enum + start
                            // collecting specs.
                            current_source = Some(match section {
                                Section::Path => crate::source::Source::Path {
                                    dir: std::path::PathBuf::from(
                                        current_remote.clone().unwrap_or_default(),
                                    ),
                                },
                                Section::Git => crate::source::Source::Git {
                                    url:       current_remote.clone().unwrap_or_default(),
                                    reference: String::new(),
                                },
                                Section::Gem => crate::source::Source::RubyGemsOrg {
                                    mirror_url: current_remote.clone(),
                                },
                                _ => unreachable!(),
                            });
                        }
                    } else if let Some(spec_rest) = rest.strip_prefix("  ") {
                        // 4-space indent: gem spec line `name (version)`.
                        if !spec_rest.starts_with(' ') {
                            if let Some((name, version)) = parse_spec_line(spec_rest) {
                                current_gem_name = Some(name.clone());
                                current_specs.push(ResolvedGem {
                                    name,
                                    version,
                                    source:     current_source.clone().unwrap_or_else(
                                        crate::source::Source::default_rubygems,
                                    ),
                                    depends_on: vec![],
                                });
                            }
                        } else if let Some(dep_rest) = spec_rest.strip_prefix("  ") {
                            // 6-space indent: transitive dep of the
                            // last gem.
                            let dep_name = dep_rest
                                .split_whitespace()
                                .next()
                                .unwrap_or("")
                                .to_string();
                            if !dep_name.is_empty() {
                                if let Some(parent) = current_gem_name.as_deref() {
                                    if let Some(g) = current_specs
                                        .iter_mut()
                                        .find(|g| g.name == parent)
                                    {
                                        g.depends_on.push(dep_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Section::Platforms => {
                if let Some(p) = trimmed.strip_prefix("  ") {
                    lock.platforms.push(p.trim().to_string());
                }
            }

            Section::Dependencies => {
                if let Some(d) = trimmed.strip_prefix("  ") {
                    let dep = d.trim().to_string();
                    if !dep.is_empty() {
                        lock.dependencies.push(dep);
                    }
                }
            }

            Section::RubyVersion => {
                if let Some(v) = trimmed.strip_prefix("   ") {
                    // Format: `ruby 3.4.1p128`
                    let parts: Vec<&str> = v.trim().split_whitespace().collect();
                    if parts.len() >= 2 {
                        lock.ruby = Some(crate::manifest::RubyVersion {
                            version:     parts[1].to_string(),
                            interpreter: parts[0].to_string(),
                        });
                    }
                }
            }

            Section::BundledWith => {
                if let Some(v) = trimmed.strip_prefix("   ") {
                    lock.bundler_version = Some(v.trim().to_string());
                }
            }
        }
    }

    // Flush the final in-flight block.
    flush_block(&mut lock, &current_source, &mut current_specs);

    Ok(lock)
}

fn flush_block(
    lock: &mut Lockfile,
    _source: &Option<crate::source::Source>,
    in_flight: &mut Vec<ResolvedGem>,
) {
    if !in_flight.is_empty() {
        lock.gems.append(in_flight);
    }
}

fn parse_spec_line(line: &str) -> Option<(String, String)> {
    // Format: `name (version)` or `name (= version)`.
    let line = line.trim();
    let open = line.find(" (")?;
    let name = line[..open].to_string();
    let rest = &line[open + 2..];
    let close = rest.find(')')?;
    let version_chunk = &rest[..close];
    // Strip optional `= ` constraint prefix; the bare version is what
    // we want for the resolved spec.
    let version = version_chunk
        .trim_start_matches("= ")
        .trim()
        .to_string();
    Some((name, version))
}

#[derive(Debug, Clone, Copy)]
enum Section {
    Top,
    Path,
    Gem,
    Git,
    Platforms,
    Dependencies,
    RubyVersion,
    BundledWith,
}

/// Emit a typed `Lockfile` back to bundler-compatible YAML-ish
/// text. Round-trip with `parse` is the next M0 milestone.
pub fn emit(_lock: &Lockfile) -> Result<String> {
    Err(RubygemsError::LockfileParse(
        "M0 emit not yet implemented — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"PATH
  remote: ../pangea-core
  specs:
    pangea-core (0.3.0)
      base64
      dry-struct (~> 1.6)
      dry-types (~> 1.7)

GEM
  remote: https://rubygems.org/
  specs:
    dry-struct (1.6.0)
      dry-core (~> 1.0)
      dry-types (~> 1.7)
    rspec (3.12.0)
      rspec-core (~> 3.12)

PLATFORMS
  arm64-darwin-25
  ruby

DEPENDENCIES
  pangea-core!
  rspec (~> 3.12)

BUNDLED WITH
   2.5.22
"#;

    #[test]
    fn parse_minimal_lockfile() {
        let lock = parse(SAMPLE).unwrap();
        assert_eq!(lock.bundler_version.as_deref(), Some("2.5.22"));
        assert_eq!(lock.platforms, vec!["arm64-darwin-25", "ruby"]);
        assert_eq!(lock.dependencies, vec!["pangea-core!", "rspec (~> 3.12)"]);
        // 1 PATH gem + 2 GEM gems = 3 resolved.
        assert_eq!(lock.gems.len(), 3);
    }

    #[test]
    fn path_gem_has_path_source() {
        let lock = parse(SAMPLE).unwrap();
        let pangea_core = lock.gems.iter().find(|g| g.name == "pangea-core").unwrap();
        assert_eq!(pangea_core.version, "0.3.0");
        assert!(matches!(pangea_core.source, crate::source::Source::Path { .. }));
        assert_eq!(pangea_core.depends_on, vec!["base64", "dry-struct", "dry-types"]);
    }

    #[test]
    fn rubygems_org_gem_has_rubygems_source() {
        let lock = parse(SAMPLE).unwrap();
        let rspec = lock.gems.iter().find(|g| g.name == "rspec").unwrap();
        assert_eq!(rspec.version, "3.12.0");
        assert!(matches!(
            rspec.source,
            crate::source::Source::RubyGemsOrg { .. },
        ));
        assert_eq!(rspec.depends_on, vec!["rspec-core"]);
    }

    #[test]
    fn empty_input_yields_default_lockfile() {
        let lock = parse("").unwrap();
        assert!(lock.gems.is_empty());
        assert!(lock.platforms.is_empty());
        assert!(lock.dependencies.is_empty());
        assert!(lock.bundler_version.is_none());
    }

    #[test]
    fn unknown_section_errors() {
        let bogus = "BOGUS\n  whatever\n";
        assert!(parse(bogus).is_err());
    }
}
