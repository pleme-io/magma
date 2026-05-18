//! magma-discover — reverse reconciliation.
//!
//! Reconcilers normally answer "given a desired config, what
//! changes converge state to it?". `Discoverable` flips that:
//! "given a live system, what resources are actually present?".
//!
//! Useful for:
//!
//! * **Adoption flows** — declare existing infrastructure.
//! * **Drift surveys** — find resources not in any CR.
//! * **Audit** — list everything the operator could be reconciling.
//! * **Continuous discovery** — new resource appears → operator
//!   notifies.
//!
//! Every reconciler kind with a list-API can implement this trait.
//! The convergence substrate gets a reverse capability for free.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §IV.4.

#![deny(unsafe_code)]

use std::collections::HashSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("list: {0}")]
    List(String),
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
}

// ── Typed shape ───────────────────────────────────────────────────

/// One resource the reconciler observed in the live system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredResource {
    /// Reconciler kind that discovered this resource (matches
    /// `Reconciler::kind()`).
    pub kind:    String,
    /// Stable resource address — same format the reconciler would
    /// use in `Plan` changes.
    pub address: String,
    /// Live attributes of this resource as JSON.
    pub current: Value,
}

/// Output of `find_undeclared`: each undeclared resource paired
/// with the address-prefix that the consumer can use to filter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryClassification {
    /// Resources present in both the live system and the declared
    /// config — these are "known/managed".
    pub managed:    Vec<DiscoveredResource>,
    /// Resources in the live system but NOT in the declared config.
    /// These are candidates for adoption or removal.
    pub undeclared: Vec<DiscoveredResource>,
}

impl DiscoveryClassification {
    pub fn total(&self) -> usize {
        self.managed.len() + self.undeclared.len()
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

// ── The Discoverable trait ────────────────────────────────────────

/// What a reconciler implements to expose its live resources.
/// Optional — not every reconciler kind has a list-API.
#[async_trait]
pub trait Discoverable {
    /// Discover every resource currently present in the live
    /// system. Returns a vec — order is unspecified (consumers
    /// should sort by address if stable order is needed).
    async fn discover(&self) -> Result<Vec<DiscoveredResource>, DiscoverError>;
}

// ── Helpers ───────────────────────────────────────────────────────

/// Classify discovered resources against a set of declared
/// addresses. The declared set typically comes from the declared
/// config — extract addresses, pass them here.
pub fn classify_discovered(
    discovered: Vec<DiscoveredResource>,
    declared:   &HashSet<String>,
) -> DiscoveryClassification {
    let mut managed    = vec![];
    let mut undeclared = vec![];
    for r in discovered {
        if declared.contains(&r.address) {
            managed.push(r);
        } else {
            undeclared.push(r);
        }
    }
    // Stable order.
    managed.sort_by(|a, b| a.address.cmp(&b.address));
    undeclared.sort_by(|a, b| a.address.cmp(&b.address));
    DiscoveryClassification { managed, undeclared }
}

/// Find the addresses currently absent from a declared config.
/// Used as a quick sanity-check before any adoption flow.
pub fn find_undeclared(
    discovered: &[DiscoveredResource],
    declared:   &HashSet<String>,
) -> Vec<DiscoveredResource> {
    let mut out: Vec<_> = discovered
        .iter()
        .filter(|r| !declared.contains(&r.address))
        .cloned()
        .collect();
    out.sort_by(|a, b| a.address.cmp(&b.address));
    out
}

/// Build a typed config blob that adopts the given resources.
/// Kind-specific: each reconciler kind defines its own config
/// shape, so the resulting Value is a `serde_json::Map<address →
/// current_attrs>` that the operator's config-generator can
/// further reshape per kind.
pub fn emit_adoption_config(resources: &[DiscoveredResource]) -> Value {
    let mut by_address = serde_json::Map::new();
    for r in resources {
        by_address.insert(r.address.clone(), r.current.clone());
    }
    Value::Object(by_address)
}

// ── A MockDiscoverable reconciler for tests ──────────────────────

pub mod test_support {
    //! Shared test scaffolding so consumers of magma-discover can
    //! write tests against a deterministic Discoverable impl
    //! without rolling their own mock.

    use super::*;

    /// A static `Discoverable` impl with a fixed list of resources.
    pub struct StaticDiscoverable {
        kind:      String,
        resources: Vec<DiscoveredResource>,
    }

    impl StaticDiscoverable {
        pub fn new(kind: impl Into<String>, resources: Vec<DiscoveredResource>) -> Self {
            Self { kind: kind.into(), resources }
        }

        pub fn kind(&self) -> &str {
            &self.kind
        }
    }

    #[async_trait]
    impl Discoverable for StaticDiscoverable {
        async fn discover(&self) -> Result<Vec<DiscoveredResource>, DiscoverError> {
            Ok(self.resources.clone())
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use test_support::StaticDiscoverable;

    fn mk(kind: &str, addr: &str, current: Value) -> DiscoveredResource {
        DiscoveredResource { kind: kind.into(), address: addr.into(), current }
    }

    #[tokio::test]
    async fn discover_returns_static_list() {
        let resources = vec![
            mk("inmemory_kv", "kv.a", json!(1)),
            mk("inmemory_kv", "kv.b", json!("x")),
        ];
        let d = StaticDiscoverable::new("inmemory_kv", resources.clone());
        let got = d.discover().await.unwrap();
        assert_eq!(got, resources);
    }

    #[test]
    fn classify_partitions_managed_and_undeclared() {
        let discovered = vec![
            mk("k", "a", json!(1)),
            mk("k", "b", json!(2)),
            mk("k", "c", json!(3)),
        ];
        let declared: HashSet<String> = ["a", "c"].iter().map(|s| s.to_string()).collect();
        let result = classify_discovered(discovered, &declared);
        assert_eq!(result.managed.len(), 2);
        assert_eq!(result.undeclared.len(), 1);
        assert_eq!(result.undeclared[0].address, "b");
    }

    #[test]
    fn classify_handles_empty_inputs() {
        let empty: Vec<DiscoveredResource> = vec![];
        let declared: HashSet<String> = HashSet::new();
        let result = classify_discovered(empty, &declared);
        assert!(result.is_empty());
        assert_eq!(result.total(), 0);
    }

    #[test]
    fn classify_handles_all_declared() {
        let discovered = vec![mk("k", "a", json!(1)), mk("k", "b", json!(2))];
        let declared: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let result = classify_discovered(discovered, &declared);
        assert_eq!(result.undeclared.len(), 0);
        assert_eq!(result.managed.len(), 2);
    }

    #[test]
    fn classify_handles_all_undeclared() {
        let discovered = vec![mk("k", "a", json!(1)), mk("k", "b", json!(2))];
        let declared = HashSet::new();
        let result = classify_discovered(discovered, &declared);
        assert_eq!(result.undeclared.len(), 2);
        assert_eq!(result.managed.len(), 0);
    }

    #[test]
    fn find_undeclared_filters_correctly() {
        let resources = vec![
            mk("k", "x", json!(1)),
            mk("k", "y", json!(2)),
            mk("k", "z", json!(3)),
        ];
        let declared: HashSet<String> = ["y"].iter().map(|s| s.to_string()).collect();
        let undeclared = find_undeclared(&resources, &declared);
        let addrs: Vec<&str> = undeclared.iter().map(|r| r.address.as_str()).collect();
        assert_eq!(addrs, vec!["x", "z"]);
    }

    #[test]
    fn emit_adoption_config_maps_address_to_attrs() {
        let resources = vec![
            mk("k", "alpha", json!({ "name": "alpha" })),
            mk("k", "beta",  json!({ "name": "beta" })),
        ];
        let cfg = emit_adoption_config(&resources);
        assert_eq!(cfg["alpha"]["name"], "alpha");
        assert_eq!(cfg["beta"]["name"], "beta");
    }

    #[test]
    fn emit_adoption_config_empty_yields_empty_object() {
        let cfg = emit_adoption_config(&[]);
        assert_eq!(cfg, json!({}));
    }
}
