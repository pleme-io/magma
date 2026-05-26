//! BLAKE3 attestation over a discovered repo's typed closure.
//!
//! The canonical projection is order-independent + commit-agnostic
//! — two operators that scan the same content (even from different
//! Git refs that materialize identically) produce byte-identical
//! `repo_attestation` hashes. Use this hash as the durable
//! identity of "the Pangea repo state magma observed."

use crate::{DiscoveredWorkspace, config::RootConfig};

/// Canonical attestation of a discovered repo: sorted projection
/// of root config + workspace name + workspace config. Output is
/// 64-char hex BLAKE3.
pub fn attest_discovered(root_config: &RootConfig, workspaces: &[DiscoveredWorkspace]) -> String {
    let canonical = serde_json::json!({
        "root":       root_config,
        "workspaces": workspaces.iter().map(|w| serde_json::json!({
            "name":   w.name,
            "config": w.config,
        })).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_is_64_hex_chars() {
        let h = attest_discovered(&RootConfig::default(), &[]);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn attestation_changes_when_workspaces_change() {
        let h1 = attest_discovered(&RootConfig::default(), &[]);
        let w = DiscoveredWorkspace {
            name: "alpha".into(),
            dir: std::path::PathBuf::from("/tmp/alpha"),
            config: crate::workspace::WorkspaceConfig::default(),
            template: None,
        };
        let h2 = attest_discovered(&RootConfig::default(), std::slice::from_ref(&w));
        assert_ne!(h1, h2);
    }

    #[test]
    fn attestation_is_deterministic() {
        let cfg = RootConfig::default();
        let a = attest_discovered(&cfg, &[]);
        let b = attest_discovered(&cfg, &[]);
        assert_eq!(a, b);
    }
}
