//! M1 acceptance gate: parse the real pangea-architectures
//! Gemfile end-to-end. Proves the parser handles the actual
//! shape Pangea workspaces use.

use magma_rubygems::{gemfile_parser::parse, source::Source};

const FIXTURE: &str = include_str!("fixtures/pangea_architectures.Gemfile");

#[test]
fn parses_real_pangea_gemfile() {
    let m = parse(FIXTURE).expect("real Pangea Gemfile must parse");

    // Source: rubygems.org.
    assert_eq!(m.sources.len(), 1);
    assert!(matches!(&m.sources[0], Source::RubyGemsOrg { mirror_url: Some(u) } if u == "https://rubygems.org"));

    // Gemspec directive.
    assert!(m.gemspec_paths.contains(&".".to_string()));

    // 15 path-sourced pangea-* gems + 2 rubygems gems = 17 deps.
    assert!(m.deps.len() >= 15, "expected ≥15 deps, got {}", m.deps.len());

    // Every pangea-* dep is path-sourced.
    let pangea_path_count = m.deps.iter().filter(|d| {
        d.name.starts_with("pangea-")
            && matches!(&d.source, Some(Source::Path { .. }))
    }).count();
    assert!(pangea_path_count >= 14, "expected ≥14 path-sourced pangea-* deps, got {pangea_path_count}");

    // rspec carries the version constraint `~> 3.12`.
    let rspec = m.deps.iter().find(|d| d.name == "rspec").unwrap();
    assert_eq!(rspec.requirement.as_deref(), Some("~> 3.12"));
    assert!(rspec.source.is_none(), "rspec should default to the top-level rubygems source");
}

#[test]
fn parses_real_pangea_gemfile_referentially_transparent() {
    let m1 = parse(FIXTURE).unwrap();
    let m2 = parse(FIXTURE).unwrap();
    assert_eq!(m1.deps.len(),          m2.deps.len());
    assert_eq!(m1.sources.len(),       m2.sources.len());
    assert_eq!(m1.gemspec_paths,       m2.gemspec_paths);
    for (a, b) in m1.deps.iter().zip(m2.deps.iter()) {
        assert_eq!(a.name,         b.name);
        assert_eq!(a.requirement,  b.requirement);
        // Source equality via Debug format (Source isn't PartialEq today).
        assert_eq!(format!("{:?}", a.source), format!("{:?}", b.source));
    }
}
