//! BLAKE3 attestation over the canonical gem-closure projection
//! (M4 destination).

use crate::lockfile::Lockfile;

/// Compute the BLAKE3 attestation over the canonical projection of
/// a Lockfile's resolved gems. The projection is sorted by name +
/// version + source so two operators with structurally-identical
/// lockfiles produce byte-identical attestations — regardless of
/// the order bundler / magma's emitter wrote the gems in.
///
/// Output is 64-char hex BLAKE3.
pub fn attest_lockfile(lock: &Lockfile) -> String {
    // Sort gems by (name, version) for order-independence.
    let mut sorted_gems: Vec<_> = lock
        .gems
        .iter()
        .map(|g| {
            let mut deps = g.depends_on.clone();
            deps.sort();
            serde_json::json!({
                "name":       g.name,
                "version":    g.version,
                "source":     g.source,
                "depends_on": deps,
            })
        })
        .collect();
    sorted_gems.sort_by(|a, b| {
        let a_key = (
            a.get("name").and_then(|v| v.as_str()),
            a.get("version").and_then(|v| v.as_str()),
        );
        let b_key = (
            b.get("name").and_then(|v| v.as_str()),
            b.get("version").and_then(|v| v.as_str()),
        );
        a_key.cmp(&b_key)
    });

    // Same for specs.
    let mut sorted_specs: Vec<_> = lock
        .specs
        .iter()
        .map(|s| {
            serde_json::json!({
                "name":         s.name,
                "version":      s.version,
                "gemspec_hash": s.gemspec_hash,
            })
        })
        .collect();
    sorted_specs.sort_by(|a, b| {
        let a_key = (
            a.get("name").and_then(|v| v.as_str()),
            a.get("version").and_then(|v| v.as_str()),
        );
        let b_key = (
            b.get("name").and_then(|v| v.as_str()),
            b.get("version").and_then(|v| v.as_str()),
        );
        a_key.cmp(&b_key)
    });

    let canonical = serde_json::json!({
        "ruby":  lock.ruby,
        "gems":  sorted_gems,
        "specs": sorted_specs,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lockfile::Lockfile, source::Source};

    #[test]
    fn empty_lockfile_attestation_is_64_hex_chars() {
        let lock = Lockfile::default();
        let attestation = attest_lockfile(&lock);
        assert_eq!(attestation.len(), 64);
        assert!(attestation.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn attestation_changes_when_a_gem_is_added() {
        let lock_a = Lockfile::default();
        let mut lock_b = lock_a.clone();
        lock_b.gems.push(crate::lockfile::ResolvedGem {
            name: "pangea-aws".into(),
            version: "0.1.0".into(),
            source: Source::default_rubygems(),
            depends_on: vec![],
        });
        assert_ne!(attest_lockfile(&lock_a), attest_lockfile(&lock_b));
    }

    #[test]
    fn attestation_is_deterministic() {
        let mut lock = Lockfile::default();
        lock.gems.push(crate::lockfile::ResolvedGem {
            name: "pangea-core".into(),
            version: "1.0.0".into(),
            source: Source::default_rubygems(),
            depends_on: vec![],
        });
        lock.dependencies.push("pangea-core".into());
        let a = attest_lockfile(&lock);
        let b = attest_lockfile(&lock);
        assert_eq!(a, b);
    }
}
