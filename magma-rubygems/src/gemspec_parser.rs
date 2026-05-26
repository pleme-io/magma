//! `*.gemspec` parser (M1.5 — narrow Pangea-shape subset).
//!
//! Parses the typed surface every Pangea-* gem ships:
//!
//!   Gem::Specification.new do |spec|
//!     spec.name                  = %(pangea-core)
//!     spec.version               = '0.3.0'                # or skipped
//!     spec.license               = 'Apache-2.0'
//!     spec.required_ruby_version = '>=3.3.0'
//!     spec.add_dependency             'name', '~> 1.2'
//!     spec.add_development_dependency 'rspec'
//!   end
//!
//! Refuses unknown Ruby (interpolated strings, blocks within
//! blocks, eval). Pangea gemspecs don't embed these — refusing
//! keeps the parser deterministic.

use crate::{Result, RubygemsError, manifest::Dependency};
use serde::{Deserialize, Serialize};

/// Typed Pangea-shape gemspec surface. Matches the bundler-input
/// fields a gem needs at install time; ignores cosmetic fields
/// (description, summary, email) that don't affect resolution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GemSpec {
    pub name: String,
    pub version: Option<String>,
    pub license: Option<String>,
    pub required_ruby_version: Option<String>,
    /// Runtime deps via `spec.add_dependency`.
    pub dependencies: Vec<Dependency>,
    /// Test-only deps via `spec.add_development_dependency`.
    pub development_dependencies: Vec<Dependency>,
}

/// Parse a gemspec source string into a typed `GemSpec`.
pub fn parse(source: &str) -> Result<GemSpec> {
    let mut spec = GemSpec::default();

    for raw_line in source.lines() {
        let line = strip_inline_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // Skip Ruby boilerplate Pangea gemspecs use:
        //   lib = File.expand_path(%(lib), __dir__)
        //   $LOAD_PATH.unshift(lib) ...
        //   require_relative '...'
        //   Gem::Specification.new do |spec|
        //   end
        //   spec.files = `git ls-files -z`...
        if line.starts_with("lib =")
            || line.starts_with("$LOAD_PATH")
            || line.starts_with("require_relative")
            || line.starts_with("require ")
            || line.starts_with("Gem::Specification")
            || line == "end"
            || line.starts_with("spec.files")
            || line.starts_with("end")
            || line.starts_with("spec.metadata")
            || line.starts_with("spec.bindir")
            || line.starts_with("spec.executables")
            || line.starts_with("spec.authors")
            || line.starts_with("spec.email")
            || line.starts_with("spec.description")
            || line.starts_with("spec.summary")
            || line.starts_with("spec.homepage")
            || line.starts_with("spec.require_paths")
            || line.starts_with("f.match")
        {
            continue;
        }

        // spec.name = '...' or %(...) or "..."
        if let Some(rest) = line.strip_prefix("spec.name") {
            spec.name = parse_assignment_value(rest).ok_or_else(|| {
                RubygemsError::GemspecParse(format!("malformed spec.name: {line:?}"))
            })?;
            continue;
        }

        // spec.version = CONSTANT (PangeaCore::VERSION) — skip to None.
        // spec.version = '0.3.0' — capture.
        if let Some(rest) = line.strip_prefix("spec.version") {
            spec.version = parse_assignment_value(rest);
            continue;
        }

        // spec.license = 'Apache-2.0'
        if let Some(rest) = line.strip_prefix("spec.license") {
            spec.license = parse_assignment_value(rest);
            continue;
        }

        // spec.required_ruby_version = '>= 3.3.0'
        if let Some(rest) = line.strip_prefix("spec.required_ruby_version") {
            spec.required_ruby_version = parse_assignment_value(rest);
            continue;
        }

        // spec.add_development_dependency 'name', 'constraint'
        if let Some(rest) = line.strip_prefix("spec.add_development_dependency") {
            if let Some(dep) = parse_dep_args(rest) {
                spec.development_dependencies.push(dep);
            }
            continue;
        }

        // spec.add_dependency 'name', 'constraint'
        if let Some(rest) = line.strip_prefix("spec.add_dependency") {
            if let Some(dep) = parse_dep_args(rest) {
                spec.dependencies.push(dep);
            }
            continue;
        }

        // Unknown line — refuse.
        return Err(RubygemsError::GemspecParse(format!(
            "unsupported gemspec directive: {line:?}",
        )));
    }

    if spec.name.is_empty() {
        return Err(RubygemsError::GemspecParse("missing spec.name".into()));
    }

    Ok(spec)
}

/// Parse the RHS of `spec.foo = 'value'` (also handles `%(value)`
/// and `"value"`). Returns None for non-string RHS (constants like
/// `PangeaCore::VERSION` get skipped to None).
fn parse_assignment_value(rest: &str) -> Option<String> {
    let after_eq = rest.trim_start().strip_prefix('=')?.trim_start();
    extract_string_literal(after_eq)
}

/// Extract a Ruby string literal starting at `s`:
/// * `'value'` -> `value`
/// * `"value"` -> `value`
/// * `%(value)` -> `value`
fn extract_string_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] == b'\'' || bytes[0] == b'"' {
        let quote = bytes[0];
        let end = bytes.iter().skip(1).position(|&b| b == quote)? + 1;
        return Some(std::str::from_utf8(&bytes[1..end]).ok()?.to_string());
    }
    // %(...) style.
    if bytes.len() >= 3 && bytes[0] == b'%' && bytes[1] == b'(' {
        let end = bytes.iter().skip(2).position(|&b| b == b')')? + 2;
        return Some(std::str::from_utf8(&bytes[2..end]).ok()?.to_string());
    }
    None
}

/// Parse `spec.add_dependency` arg tail: `'name', 'constraint'` or
/// just `'name'`.
fn parse_dep_args(rest: &str) -> Option<Dependency> {
    let trimmed = rest.trim_start();
    let name = extract_string_literal(trimmed)?;
    // Look for a second arg after the first comma.
    let after_name = trimmed
        .splitn(2, ',')
        .nth(1)
        .map(|s| s.trim_start())
        .unwrap_or("");
    let requirement = if !after_name.is_empty() {
        extract_string_literal(after_name)
    } else {
        None
    };
    Some(Dependency {
        name,
        requirement,
        source: None,
        groups: vec![],
    })
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (i, c) in line.char_indices() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..i],
            _ => {}
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    const PANGEA_CORE_GEMSPEC: &str = r#"
# frozen_string_literal: true

lib = File.expand_path(%(lib), __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require_relative %(lib/pangea-core/version)

Gem::Specification.new do |spec|
  spec.name                  = %(pangea-core)
  spec.version               = PangeaCore::VERSION
  spec.authors               = [%(Luis Zayas)]
  spec.email                 = [%(drzthslnt@gmail.com)]
  spec.description           = %(Core types for Pangea)
  spec.summary               = %(Core types)
  spec.homepage              = %(https://github.com/pleme-io/pangea-core)
  spec.license               = %(Apache-2.0)
  spec.require_paths         = [%(lib)]
  spec.required_ruby_version = %(>=3.3.0)
  spec.bindir                = %(exe)
  spec.executables           = [%(pangea)]

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end

  spec.add_dependency "terraform-synthesizer", ">= 0.0.28"
  spec.add_dependency "dry-types", "~> 1.7"
  spec.add_dependency "dry-struct", "~> 1.6"
  spec.add_dependency "base64"

  spec.add_development_dependency "rspec", "~> 3.12"
end
"#;

    #[test]
    fn parses_pangea_core_gemspec() {
        let spec = parse(PANGEA_CORE_GEMSPEC).unwrap();
        assert_eq!(spec.name, "pangea-core");
        // VERSION is a constant — version stays None.
        assert!(spec.version.is_none());
        assert_eq!(spec.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(spec.required_ruby_version.as_deref(), Some(">=3.3.0"));
        assert_eq!(spec.dependencies.len(), 4);
        assert_eq!(spec.development_dependencies.len(), 1);
    }

    #[test]
    fn captures_runtime_deps_with_constraints() {
        let spec = parse(PANGEA_CORE_GEMSPEC).unwrap();
        let ts = spec
            .dependencies
            .iter()
            .find(|d| d.name == "terraform-synthesizer")
            .unwrap();
        assert_eq!(ts.requirement.as_deref(), Some(">= 0.0.28"));
        let dry_types = spec
            .dependencies
            .iter()
            .find(|d| d.name == "dry-types")
            .unwrap();
        assert_eq!(dry_types.requirement.as_deref(), Some("~> 1.7"));
        // base64 has no version constraint.
        let base64 = spec
            .dependencies
            .iter()
            .find(|d| d.name == "base64")
            .unwrap();
        assert!(base64.requirement.is_none());
    }

    #[test]
    fn captures_dev_deps() {
        let spec = parse(PANGEA_CORE_GEMSPEC).unwrap();
        let rspec = &spec.development_dependencies[0];
        assert_eq!(rspec.name, "rspec");
        assert_eq!(rspec.requirement.as_deref(), Some("~> 3.12"));
    }

    #[test]
    fn parses_string_literal_version() {
        let src = r#"Gem::Specification.new do |spec|
  spec.name = 'foo'
  spec.version = '0.1.0'
end
"#;
        let spec = parse(src).unwrap();
        assert_eq!(spec.name, "foo");
        assert_eq!(spec.version.as_deref(), Some("0.1.0"));
    }

    #[test]
    fn refuses_missing_name() {
        let src = "Gem::Specification.new do |spec|\nend\n";
        assert!(parse(src).is_err());
    }
}
