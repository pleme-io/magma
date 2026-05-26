//! Gemfile DSL parser (M1 destination).
//!
//! Parses the narrow Ruby DSL Pangea workspaces use:
//! * `source 'URL'`
//! * `gem 'name'`
//! * `gem 'name', '~> 1.2'`
//! * `gem 'name', path: '../foo'`
//! * `gem 'name', git: 'URL', ref: 'tag'`
//! * `gem 'name', git: 'URL', branch: 'main'`
//! * `gemspec` (import sibling .gemspec)
//! * `group :test, :development do ... end`
//! * `ruby '3.4.1'`
//! * `# comment` (any position) and blank lines
//! * `# frozen_string_literal: true` magic comment (treated as
//!   regular comment)
//!
//! Refuses arbitrary Ruby (`eval`, `if`/`unless`, helper methods).
//! Pangea workspaces don't use them; refusing keeps the parser
//! tractable + the typed Manifest deterministic.

use crate::{
    Result, RubygemsError,
    manifest::{Dependency, Manifest, RubyVersion},
    source::Source,
};

/// Parse a Gemfile source string into a typed `Manifest`.
pub fn parse(source: &str) -> Result<Manifest> {
    let mut manifest = Manifest {
        ruby: RubyVersion {
            version: String::new(),
            interpreter: "mri".into(),
        },
        deps: vec![],
        sources: vec![],
        gemspec_paths: vec![],
    };
    let mut current_groups: Vec<String> = vec![]; // nested `group` block tracker

    for (line_no, raw_line) in source.lines().enumerate() {
        let line = strip_inline_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // group :a, :b do  -> push groups
        if let Some(rest) = line.strip_prefix("group ") {
            if let Some(groups_part) = rest.split_once(" do").map(|(g, _)| g) {
                let names: Vec<String> = groups_part
                    .split(',')
                    .map(|s| s.trim().trim_start_matches(':').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                current_groups.extend(names);
                continue;
            }
        }
        if line == "end" {
            current_groups.clear();
            continue;
        }

        // source 'URL'
        if let Some(rest) = line.strip_prefix("source ") {
            let url = extract_quoted(rest)
                .ok_or_else(|| parse_err(line_no, format!("malformed source: {line:?}")))?;
            manifest.sources.push(Source::RubyGemsOrg {
                mirror_url: Some(url),
            });
            continue;
        }

        // ruby '3.4.1'
        if let Some(rest) = line.strip_prefix("ruby ") {
            let version = extract_quoted(rest)
                .ok_or_else(|| parse_err(line_no, format!("malformed ruby: {line:?}")))?;
            manifest.ruby = RubyVersion {
                version,
                interpreter: "mri".into(),
            };
            continue;
        }

        // gemspec  -> import sibling .gemspec
        if line == "gemspec" || line.starts_with("gemspec ") {
            // The plain `gemspec` form imports `<dir>/<name>.gemspec`.
            manifest.gemspec_paths.push(".".into());
            continue;
        }

        // gem 'name', ...
        if let Some(rest) = line.strip_prefix("gem ") {
            let dep = parse_gem_line(rest, &current_groups)
                .map_err(|e| parse_err(line_no, format!("{e}: {line:?}")))?;
            manifest.deps.push(dep);
            continue;
        }

        // Anything else: refuse.
        return Err(parse_err(
            line_no,
            format!("unsupported Gemfile directive: {line:?}"),
        ));
    }

    Ok(manifest)
}

/// Strip inline `# comment` (respecting that `#` inside string
/// literals isn't a comment, but Pangea Gemfiles don't embed `#`
/// in strings — keep this simple).
fn strip_inline_comment(line: &str) -> &str {
    // If there's a `#` outside any quote, take the prefix.
    // Simple heuristic: find the first `#` that isn't preceded by
    // an unmatched `'` or `"`.
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

fn extract_quoted(s: &str) -> Option<String> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let quote = bytes[0];
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut end = None;
    for (i, &b) in bytes.iter().enumerate().skip(1) {
        if b == quote {
            end = Some(i);
            break;
        }
    }
    end.map(|e| s[1..e].to_string())
}

fn parse_gem_line(
    rest: &str,
    current_groups: &[String],
) -> std::result::Result<Dependency, String> {
    // Tokenize as: <quoted name>[, <quoted version>][, key: value pairs]
    let rest = rest.trim();
    let name = extract_quoted(rest).ok_or_else(|| "missing gem name".to_string())?;

    // Drop the name literal + its trailing comma.
    let after_name = rest.splitn(2, ',').nth(1).map(|s| s.trim()).unwrap_or("");

    // Optional version: a quoted string as the FIRST remaining token.
    let (requirement, after_version) =
        if after_name.starts_with('\'') || after_name.starts_with('"') {
            let req = extract_quoted(after_name)
                .ok_or_else(|| "malformed version constraint".to_string())?;
            let dropped = after_name
                .splitn(2, ',')
                .nth(1)
                .map(|s| s.trim())
                .unwrap_or("");
            (Some(req), dropped)
        } else {
            (None, after_name)
        };

    // Parse optional kwargs: `path: '../foo'`, `git: 'URL'`, `ref: 'tag'`, `branch: 'main'`, `group: :test`
    let mut path: Option<String> = None;
    let mut git: Option<String> = None;
    let mut reference: Option<String> = None;
    let mut group_kw: Option<String> = None;

    if !after_version.is_empty() {
        for kv in split_kwargs(after_version) {
            let (k, v) = kv;
            match k.as_str() {
                "path" => path = Some(v),
                "git" => git = Some(v),
                "ref" => reference = Some(v),
                "branch" => reference = Some(v),
                "tag" => reference = Some(v),
                "group" => group_kw = Some(v),
                _ => {} // ignore unknown kwargs
            }
        }
    }

    let source = match (path, git) {
        (Some(p), _) => Some(Source::Path {
            dir: std::path::PathBuf::from(p),
        }),
        (_, Some(u)) => Some(Source::Git {
            url: u,
            reference: reference.unwrap_or_default(),
        }),
        _ => None,
    };

    let mut groups = current_groups.to_vec();
    if let Some(g) = group_kw {
        groups.push(g);
    }

    Ok(Dependency {
        name,
        requirement,
        source,
        groups,
    })
}

/// Split a `key: value, key: value` string into (key, value)
/// pairs. Values can be quoted strings, `:symbols`, or bare
/// tokens (rare in Pangea Gemfiles; supported for completeness).
///
/// Cursor-driven: advances character-by-character so quote
/// boundaries and comma separators are unambiguous regardless of
/// whitespace.
fn split_kwargs(s: &str) -> Vec<(String, String)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut out = vec![];

    while i < bytes.len() {
        // Skip whitespace + commas.
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Read identifier (key) until `:` or whitespace.
        let key_start = i;
        while i < bytes.len() && bytes[i] != b':' && bytes[i] != b' ' {
            i += 1;
        }
        let key = std::str::from_utf8(&bytes[key_start..i])
            .unwrap_or("")
            .to_string();

        // Expect `:`.
        if i >= bytes.len() || bytes[i] != b':' {
            break;
        }
        i += 1; // consume ':'
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        // Read value: quoted | :symbol | bare-until-comma.
        let value = if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote = bytes[i];
            i += 1;
            let v_start = i;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            let v = std::str::from_utf8(&bytes[v_start..i])
                .unwrap_or("")
                .to_string();
            if i < bytes.len() {
                i += 1; // consume closing quote
            }
            v
        } else if bytes[i] == b':' {
            i += 1; // consume leading `:` of symbol
            let v_start = i;
            while i < bytes.len() && bytes[i] != b',' && bytes[i] != b' ' {
                i += 1;
            }
            std::str::from_utf8(&bytes[v_start..i])
                .unwrap_or("")
                .to_string()
        } else {
            let v_start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            std::str::from_utf8(&bytes[v_start..i])
                .unwrap_or("")
                .trim()
                .to_string()
        };

        if !key.is_empty() {
            out.push((key, value));
        }
    }

    out
}

fn parse_err(line_no: usize, msg: String) -> RubygemsError {
    RubygemsError::GemfileParse(format!("line {}: {msg}", line_no + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_gemfile() {
        let src = r#"source 'https://rubygems.org'

gem 'rspec'
"#;
        let m = parse(src).unwrap();
        assert_eq!(m.sources.len(), 1);
        assert_eq!(m.deps.len(), 1);
        assert_eq!(m.deps[0].name, "rspec");
        assert!(m.deps[0].requirement.is_none());
    }

    #[test]
    fn parses_gem_with_version_constraint() {
        let src = "gem 'rspec', '~> 3.12'\n";
        let m = parse(src).unwrap();
        assert_eq!(m.deps[0].requirement.as_deref(), Some("~> 3.12"));
    }

    #[test]
    fn parses_path_sourced_gem() {
        let src = "gem 'pangea-core', path: '../pangea-core'\n";
        let m = parse(src).unwrap();
        assert!(
            matches!(&m.deps[0].source, Some(Source::Path { dir }) if dir.to_string_lossy() == "../pangea-core")
        );
    }

    #[test]
    fn parses_git_sourced_gem_with_ref() {
        let src = "gem 'foo', git: 'https://github.com/x/foo', ref: 'v1.0'\n";
        let m = parse(src).unwrap();
        assert!(matches!(
            &m.deps[0].source,
            Some(Source::Git { url, reference }) if url == "https://github.com/x/foo" && reference == "v1.0"
        ));
    }

    #[test]
    fn parses_gemspec_directive() {
        let src = "gemspec\n";
        let m = parse(src).unwrap();
        assert_eq!(m.gemspec_paths, vec!["."]);
    }

    #[test]
    fn parses_ruby_version() {
        let src = "ruby '3.4.1'\n";
        let m = parse(src).unwrap();
        assert_eq!(m.ruby.version, "3.4.1");
    }

    #[test]
    fn parses_group_block() {
        let src = r#"group :test, :development do
  gem 'rspec'
end
gem 'rake'
"#;
        let m = parse(src).unwrap();
        assert_eq!(m.deps.len(), 2);
        assert_eq!(m.deps[0].name, "rspec");
        assert!(m.deps[0].groups.contains(&"test".to_string()));
        assert!(m.deps[0].groups.contains(&"development".to_string()));
        // rake is outside the group block — no groups.
        assert_eq!(m.deps[1].name, "rake");
        assert!(m.deps[1].groups.is_empty());
    }

    #[test]
    fn skips_blank_lines_and_comments() {
        let src = r#"# frozen_string_literal: true

source 'https://rubygems.org'

# Important gem below
gem 'rspec'
"#;
        let m = parse(src).unwrap();
        assert_eq!(m.deps.len(), 1);
        assert_eq!(m.sources.len(), 1);
    }

    #[test]
    fn refuses_unknown_directive() {
        let src = "load 'something.rb'\n";
        assert!(parse(src).is_err());
    }

    #[test]
    fn inline_comment_is_stripped() {
        let src = "gem 'rspec' # the testing gem\n";
        let m = parse(src).unwrap();
        assert_eq!(m.deps[0].name, "rspec");
    }
}
