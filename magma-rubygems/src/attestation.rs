//! BLAKE3 attestation over the canonical gem-closure projection
//! (M4 destination).

use crate::lockfile::Lockfile;

/// Compute the BLAKE3 attestation over the canonical projection of
/// a Lockfile's resolved gems. The projection is sorted by name +
/// version + source so two operators with byte-identical lockfiles
/// produce byte-identical attestations.
///
/// Output is 64-char hex BLAKE3.
pub fn attest_lockfile(lock: &Lockfile) -> String {
    let canonical = serde_json::json!({
        "ruby": lock.ruby,
        "gems": lock.gems.iter().map(|g| serde_json::json!({
            "name": g.name,
            "version": g.version,
            "source": g.source,
        })).collect::<Vec<_>>(),
        "specs": lock.specs.iter().map(|s| serde_json::json!({
            "name": s.name,
            "version": s.version,
            "gemspec_hash": s.gemspec_hash,
        })).collect::<Vec<_>>(),
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
            name:       "pangea-aws".into(),
            version:    "0.1.0".into(),
            source:     Source::default_rubygems(),
            depends_on: vec![],
        });
        assert_ne!(attest_lockfile(&lock_a), attest_lockfile(&lock_b));
    }

    #[test]
    fn attestation_is_deterministic() {
        let mut lock = Lockfile::default();
        lock.gems.push(crate::lockfile::ResolvedGem {
            name:       "pangea-core".into(),
            version:    "1.0.0".into(),
            source:     Source::default_rubygems(),
            depends_on: vec![],
        });
        lock.dependencies.push("pangea-core".into());
        let a = attest_lockfile(&lock);
        let b = attest_lockfile(&lock);
        assert_eq!(a, b);
    }
}
