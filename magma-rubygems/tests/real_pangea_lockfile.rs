//! M0 acceptance gate: parse the real pangea-architectures
//! Gemfile.lock end-to-end. Proves the parser handles the actual
//! shape Pangea workspaces use today.

use magma_rubygems::{
    attestation::attest_lockfile,
    lockfile::{emit, parse},
    nix::emit_gemset,
    source::Source,
};

const FIXTURE: &str = include_str!("fixtures/pangea_architectures.Gemfile.lock");

#[test]
fn parses_real_pangea_lockfile() {
    let lock = parse(FIXTURE).expect("real Pangea Gemfile.lock must parse");

    // Bundler version is captured at the bottom of the file.
    assert!(
        lock.bundler_version.is_some(),
        "bundler_version should be captured from BUNDLED WITH",
    );

    // Platforms include at least one entry.
    assert!(
        !lock.platforms.is_empty(),
        "platforms list shouldn't be empty"
    );

    // Dependencies include the pangea-* gem set.
    assert!(
        lock.dependencies.iter().any(|d| d.starts_with("pangea-")),
        "expected at least one pangea-* dep, got: {:?}",
        lock.dependencies,
    );

    // Resolved gems include the pangea-* PATH-sourced gems.
    let pangea_core = lock.gems.iter().find(|g| g.name == "pangea-core");
    assert!(pangea_core.is_some(), "pangea-core must resolve");
    assert!(
        matches!(pangea_core.unwrap().source, Source::Path { .. }),
        "pangea-core should be PATH-sourced (sibling gem)",
    );

    // Resolved gems include at least one rubygems.org gem (rspec etc.).
    let rubygems_count = lock
        .gems
        .iter()
        .filter(|g| matches!(g.source, Source::RubyGemsOrg { .. }))
        .count();
    assert!(
        rubygems_count >= 5,
        "expected ≥5 rubygems.org gems, got {rubygems_count}"
    );
}

#[test]
fn attestation_over_real_lockfile_is_well_formed() {
    let lock = parse(FIXTURE).unwrap();
    let a = attest_lockfile(&lock);
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    // Second pass should be deterministic.
    let b = attest_lockfile(&lock);
    assert_eq!(a, b);
}

#[test]
fn real_pangea_lockfile_emits_structurally_valid_gemset_nix() {
    // M7 acceptance: parse the real Pangea Gemfile.lock + emit
    // gemset.nix that name-matches the checked-in bundix output.
    let lock = parse(FIXTURE).unwrap();
    let gemset = emit_gemset(&lock).expect("gemset.nix emission must succeed");

    // Structural sanity: braces + sorted + every gem name appears.
    assert!(gemset.starts_with("{\n"));
    assert!(gemset.trim_end().ends_with("}"));

    // Every gem in the lockfile appears in the gemset.
    for gem in &lock.gems {
        let expected = format!("  {} = {{", gem.name);
        assert!(
            gemset.contains(&expected),
            "gemset.nix missing entry for `{}`",
            gem.name,
        );
        let expected_version = format!("version = \"{}\";", gem.version);
        assert!(
            gemset.contains(&expected_version),
            "gemset.nix missing version `{}` for `{}`",
            gem.version,
            gem.name,
        );
    }

    // PATH-sourced gems emit `type = "path";`.
    let path_count = lock
        .gems
        .iter()
        .filter(|g| matches!(g.source, Source::Path { .. }))
        .count();
    let path_type_count = gemset.matches("type = \"path\";").count();
    assert_eq!(
        path_type_count, path_count,
        "expected {path_count} path-type entries, got {path_type_count}",
    );

    // RubyGems-sourced gems emit `type = "gem";`.
    let rubygems_count = lock
        .gems
        .iter()
        .filter(|g| matches!(g.source, Source::RubyGemsOrg { .. }))
        .count();
    let gem_type_count = gemset.matches("type = \"gem\";").count();
    assert_eq!(
        gem_type_count, rubygems_count,
        "expected {rubygems_count} gem-type entries, got {gem_type_count}",
    );
}

#[test]
fn real_pangea_lockfile_emit_roundtrips_structurally() {
    // M0 acceptance gate completion: parse the real Pangea
    // Gemfile.lock → emit → re-parse yields a structurally
    // equivalent Lockfile.
    let lock1 = parse(FIXTURE).unwrap();
    let emitted = emit(&lock1).unwrap();
    let lock2 = parse(&emitted).expect("re-parse of emitted lockfile must succeed");

    // Bundler version preserved.
    assert_eq!(lock1.bundler_version, lock2.bundler_version);

    // Same set of resolved gems (by name + version + source kind).
    let by_id = |l: &magma_rubygems::lockfile::Lockfile| {
        let mut v: Vec<(String, String, &'static str)> = l
            .gems
            .iter()
            .map(|g| {
                (
                    g.name.clone(),
                    g.version.clone(),
                    match g.source {
                        Source::Path { .. } => "path",
                        Source::Git { .. } => "git",
                        Source::RubyGemsOrg { .. } => "rubygems",
                    },
                )
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        by_id(&lock1),
        by_id(&lock2),
        "round-trip lost gems or changed source kinds"
    );

    // BLAKE3 attestation: emitted+re-parsed has same attestation
    // as the original (because attestation hashes the typed
    // shape, not the text).
    assert_eq!(
        attest_lockfile(&lock1),
        attest_lockfile(&lock2),
        "attestation must survive structural round-trip"
    );
}

#[test]
fn parse_is_referentially_transparent() {
    let lock1 = parse(FIXTURE).unwrap();
    let lock2 = parse(FIXTURE).unwrap();
    assert_eq!(lock1.bundler_version, lock2.bundler_version);
    assert_eq!(lock1.platforms, lock2.platforms);
    assert_eq!(lock1.dependencies, lock2.dependencies);
    assert_eq!(lock1.gems.len(), lock2.gems.len());
    // Per-gem identity check.
    for (a, b) in lock1.gems.iter().zip(lock2.gems.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.version, b.version);
        assert_eq!(a.depends_on, b.depends_on);
    }
}
