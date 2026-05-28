//! Typed K8s resource set + diff — the canonical `Inventory` primitive
//! every Kustomization-style reconciler consumes.
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III, P1.3.
//!
//! Subsumes FluxCD Kustomization's load-bearing `inventory.entries[]`
//! concept (the set of GVKNN tuples the controller currently owns)
//! plus the implicit "what did we apply last cycle vs this cycle"
//! diff that today lives as ad-hoc code inside lava-operator and
//! tend's reconcile path.
//!
//! Lifts the shape into a typed value:
//!
//! - `ResourceRef` — a single (group, version, kind, namespace?, name)
//!   tuple. Cluster-scoped resources carry `namespace: None`.
//! - `Inventory` — ordered set of `ResourceRef`. Construction is
//!   from any iterable; iteration is in canonical (sorted) order so
//!   inventory serialization is deterministic across reconcile cycles.
//! - `InventoryDiff` — (added, removed) sets when comparing two
//!   inventories. Set semantics; the rightmost inventory "wins" for
//!   the diff's perspective (typical: `prev.diff(curr)` ⇒ what
//!   `curr` adds + removes relative to `prev`).
//!
//! # Composition
//!
//! `Artifact<Inventory>` is the natural shape for a Kustomization
//! controller's apply output: the typed artifact carries the
//! inventory plus a BLAKE3 digest plus provenance.
//!
//! # Why not detect "updated"?
//!
//! `Inventory` only carries refs (not content). Detecting "updated"
//! requires per-ref content digests. Use `Artifact<T>` per resource
//! when that's needed; `Inventory` is the typed K8s reference set
//! at the GVKNN grain, and (added, removed) is the minimum diff that
//! shape supports.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Single typed K8s resource reference. Mirrors the GVKNN tuple the
/// K8s API server keys resources by.
///
/// `namespace == None` means cluster-scoped (CRDs, ClusterRoles,
/// ClusterRoleBindings, Namespaces themselves, etc.).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResourceRef {
    pub group: String,
    pub version: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
}

impl ResourceRef {
    /// Construct a namespaced ResourceRef.
    pub fn namespaced(
        group: impl Into<String>,
        version: impl Into<String>,
        kind: impl Into<String>,
        namespace: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            version: version.into(),
            kind: kind.into(),
            namespace: Some(namespace.into()),
            name: name.into(),
        }
    }

    /// Construct a cluster-scoped ResourceRef.
    pub fn cluster_scoped(
        group: impl Into<String>,
        version: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            version: version.into(),
            kind: kind.into(),
            namespace: None,
            name: name.into(),
        }
    }

    /// `true` for cluster-scoped resources (no namespace).
    pub fn is_cluster_scoped(&self) -> bool {
        self.namespace.is_none()
    }

    /// `<group>/<version>/<Kind>` apiVersion-like discriminator
    /// useful as a metrics label.
    pub fn api_kind(&self) -> String {
        if self.group.is_empty() {
            format!("{}/{}", self.version, self.kind)
        } else {
            format!("{}/{}/{}", self.group, self.version, self.kind)
        }
    }
}

impl std::fmt::Display for ResourceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // kustomize/flux GVKNN form: <api>/<Kind>/<ns>/<name> with
        // "_cluster" for cluster-scoped.
        let ns = self.namespace.as_deref().unwrap_or("_cluster");
        write!(f, "{}/{}/{}", self.api_kind(), ns, self.name)
    }
}

/// Ordered set of `ResourceRef`. Iteration is in canonical (sorted)
/// order so two inventories with the same elements serialize
/// identically across reconcile cycles.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Inventory {
    entries: BTreeSet<ResourceRef>,
}

impl Inventory {
    /// Empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from any iterable of refs (deduplicates + sorts).
    pub fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = ResourceRef>,
    {
        let mut entries = BTreeSet::new();
        for r in iter {
            entries.insert(r);
        }
        Self { entries }
    }

    pub fn insert(&mut self, r: ResourceRef) -> bool {
        self.entries.insert(r)
    }

    pub fn contains(&self, r: &ResourceRef) -> bool {
        self.entries.contains(r)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ResourceRef> {
        self.entries.iter()
    }

    /// Take ownership of the inner set. Consumes self.
    pub fn into_inner(self) -> BTreeSet<ResourceRef> {
        self.entries
    }

    /// Diff `self` against `other`. Returns (added-in-other,
    /// removed-from-self) — i.e. `other.diff_from(self)` is the
    /// transition `self → other`.
    pub fn diff_to(&self, other: &Inventory) -> InventoryDiff {
        let added: Vec<_> = other
            .entries
            .difference(&self.entries)
            .cloned()
            .collect();
        let removed: Vec<_> = self
            .entries
            .difference(&other.entries)
            .cloned()
            .collect();
        InventoryDiff { added, removed }
    }
}

impl FromIterator<ResourceRef> for Inventory {
    fn from_iter<I: IntoIterator<Item = ResourceRef>>(iter: I) -> Self {
        Inventory::from_iter(iter)
    }
}

/// Typed diff between two inventories.
///
/// `added` lists refs present in the target inventory but not the
/// source. `removed` lists refs present in the source but not the
/// target. Both lists are in canonical (sorted) order.
///
/// `Inventory` doesn't carry per-ref content, so "updated" is NOT
/// represented here — use `Artifact<T>` per resource when content
/// change detection is needed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InventoryDiff {
    pub added: Vec<ResourceRef>,
    pub removed: Vec<ResourceRef>,
}

impl InventoryDiff {
    /// `true` when the two inventories were identical (no added, no
    /// removed). The reconciler's noop case.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Total number of changed refs (`|added| + |removed|`).
    pub fn change_count(&self) -> usize {
        self.added.len() + self.removed.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment(ns: &str, name: &str) -> ResourceRef {
        ResourceRef::namespaced("apps", "v1", "Deployment", ns, name)
    }

    fn crd(name: &str) -> ResourceRef {
        ResourceRef::cluster_scoped("apiextensions.k8s.io", "v1", "CustomResourceDefinition", name)
    }

    fn pod(ns: &str, name: &str) -> ResourceRef {
        // Core group is "".
        ResourceRef::namespaced("", "v1", "Pod", ns, name)
    }

    // ── ResourceRef ────────────────────────────────────────────────

    #[test]
    fn namespaced_constructor_carries_namespace() {
        let r = deployment("default", "nginx");
        assert_eq!(r.namespace.as_deref(), Some("default"));
        assert!(!r.is_cluster_scoped());
    }

    #[test]
    fn cluster_scoped_constructor_carries_no_namespace() {
        let r = crd("widgets.example.com");
        assert!(r.namespace.is_none());
        assert!(r.is_cluster_scoped());
    }

    #[test]
    fn api_kind_with_group() {
        let r = deployment("default", "nginx");
        assert_eq!(r.api_kind(), "apps/v1/Deployment");
    }

    #[test]
    fn api_kind_without_group_uses_core_form() {
        let r = pod("default", "mypod");
        assert_eq!(r.api_kind(), "v1/Pod");
    }

    #[test]
    fn display_uses_cluster_marker_for_cluster_scoped() {
        let r = crd("widgets.example.com");
        let s = r.to_string();
        assert!(s.contains("_cluster"), "got {s:?}");
    }

    #[test]
    fn display_uses_namespace_for_namespaced() {
        let r = deployment("kube-system", "coredns");
        let s = r.to_string();
        assert!(s.contains("kube-system"));
    }

    #[test]
    fn resource_ref_orders_canonically() {
        // BTreeSet orders by field lex order: group, version, kind, namespace, name.
        let refs = vec![
            deployment("z", "a"),
            deployment("a", "b"),
            deployment("a", "a"),
            crd("widgets"),
            pod("default", "x"),
        ];
        let inv = Inventory::from_iter(refs);
        let sorted: Vec<_> = inv.iter().cloned().collect();
        // Manually compute the expected canonical order via sort.
        let mut expected = vec![
            deployment("z", "a"),
            deployment("a", "b"),
            deployment("a", "a"),
            crd("widgets"),
            pod("default", "x"),
        ];
        expected.sort();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn resource_ref_serde_omits_namespace_when_none() {
        let r = crd("widgets.example.com");
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"namespace\""));
        let back: ResourceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── Inventory ──────────────────────────────────────────────────

    #[test]
    fn empty_inventory() {
        let inv = Inventory::new();
        assert!(inv.is_empty());
        assert_eq!(inv.len(), 0);
    }

    #[test]
    fn insert_deduplicates() {
        let mut inv = Inventory::new();
        assert!(inv.insert(deployment("default", "nginx")));
        assert!(!inv.insert(deployment("default", "nginx")), "duplicate insert returns false");
        assert_eq!(inv.len(), 1);
    }

    #[test]
    fn from_iter_deduplicates() {
        let inv = Inventory::from_iter(vec![
            deployment("default", "a"),
            deployment("default", "a"), // dup
            deployment("default", "b"),
        ]);
        assert_eq!(inv.len(), 2);
    }

    #[test]
    fn contains_works() {
        let inv = Inventory::from_iter(vec![deployment("default", "a")]);
        assert!(inv.contains(&deployment("default", "a")));
        assert!(!inv.contains(&deployment("default", "b")));
    }

    #[test]
    fn inventory_serde_round_trip_via_btreeset() {
        let inv = Inventory::from_iter(vec![
            deployment("default", "a"),
            crd("widgets"),
            pod("kube-system", "coredns"),
        ]);
        let json = serde_json::to_string(&inv).unwrap();
        let back: Inventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn inventory_serializes_deterministically_across_construction_order() {
        // Same elements inserted in different orders MUST serialize
        // to identical JSON — the BTreeSet ordering canonicalizes.
        let a = Inventory::from_iter(vec![
            deployment("default", "z"),
            deployment("default", "a"),
            crd("widgets"),
        ]);
        let b = Inventory::from_iter(vec![
            crd("widgets"),
            deployment("default", "a"),
            deployment("default", "z"),
        ]);

        let ja = serde_json::to_string(&a).unwrap();
        let jb = serde_json::to_string(&b).unwrap();
        assert_eq!(
            ja, jb,
            "inventory serialization must be deterministic across insert order"
        );
    }

    // ── InventoryDiff ──────────────────────────────────────────────

    #[test]
    fn diff_to_identical_is_empty() {
        let a = Inventory::from_iter(vec![deployment("default", "a"), crd("widgets")]);
        let b = Inventory::from_iter(vec![deployment("default", "a"), crd("widgets")]);

        let diff = a.diff_to(&b);
        assert!(diff.is_empty());
        assert_eq!(diff.change_count(), 0);
    }

    #[test]
    fn diff_to_addition_only() {
        let prev = Inventory::from_iter(vec![deployment("default", "a")]);
        let curr = Inventory::from_iter(vec![deployment("default", "a"), deployment("default", "b")]);

        let diff = prev.diff_to(&curr);
        assert_eq!(diff.added, vec![deployment("default", "b")]);
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn diff_to_removal_only() {
        let prev = Inventory::from_iter(vec![deployment("default", "a"), deployment("default", "b")]);
        let curr = Inventory::from_iter(vec![deployment("default", "a")]);

        let diff = prev.diff_to(&curr);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec![deployment("default", "b")]);
    }

    #[test]
    fn diff_to_both_added_and_removed() {
        let prev = Inventory::from_iter(vec![
            deployment("default", "a"),
            deployment("default", "b"),
        ]);
        let curr = Inventory::from_iter(vec![
            deployment("default", "a"),
            deployment("default", "c"),
        ]);

        let diff = prev.diff_to(&curr);
        assert_eq!(diff.added, vec![deployment("default", "c")]);
        assert_eq!(diff.removed, vec![deployment("default", "b")]);
        assert_eq!(diff.change_count(), 2);
    }

    #[test]
    fn diff_to_full_replacement() {
        let prev = Inventory::from_iter(vec![deployment("default", "old")]);
        let curr = Inventory::from_iter(vec![deployment("default", "new"), crd("widgets")]);

        let diff = prev.diff_to(&curr);
        assert_eq!(diff.added.len(), 2);
        assert_eq!(diff.removed.len(), 1);
    }

    #[test]
    fn diff_is_asymmetric() {
        // a.diff_to(b).added == b.diff_to(a).removed and vice versa
        let a = Inventory::from_iter(vec![deployment("ns", "x")]);
        let b = Inventory::from_iter(vec![deployment("ns", "y")]);

        let a_to_b = a.diff_to(&b);
        let b_to_a = b.diff_to(&a);

        assert_eq!(a_to_b.added, b_to_a.removed);
        assert_eq!(a_to_b.removed, b_to_a.added);
    }

    #[test]
    fn diff_is_deterministic_across_construction_order() {
        let prev_v1 = Inventory::from_iter(vec![deployment("ns", "z"), deployment("ns", "a")]);
        let prev_v2 = Inventory::from_iter(vec![deployment("ns", "a"), deployment("ns", "z")]);
        let curr = Inventory::from_iter(vec![deployment("ns", "a")]);

        let diff1 = prev_v1.diff_to(&curr);
        let diff2 = prev_v2.diff_to(&curr);
        assert_eq!(diff1, diff2, "diff must be deterministic across insert order");
    }

    #[test]
    fn inventory_diff_serde_round_trip() {
        let prev = Inventory::from_iter(vec![deployment("ns", "a")]);
        let curr = Inventory::from_iter(vec![deployment("ns", "b"), crd("widgets")]);
        let diff = prev.diff_to(&curr);

        let json = serde_json::to_string(&diff).unwrap();
        let back: InventoryDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, back);
    }
}
