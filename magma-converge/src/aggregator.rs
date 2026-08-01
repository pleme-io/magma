//! `Aggregator<K, V>` — typed sorted per-key map.
//!
//! Spec: `theory/PATTERN-EXTRACTION.md` Pattern 4 (Aggregator).
//! Extracted after 3+ primitives shipped the same shape:
//!
//!   - `HealthReport` — `Vec<(ResourceRef, ReadyState)>`
//!   - `ApplyReport` — `Vec<(ResourceRef, ApplyOutcome<T>)>` (partial fit)
//!   - `ConditionSet` — `Vec<Condition>` keyed by `type` (partial fit)
//!
//! Each repeated the same:
//!
//!   - sorted `Vec<(K, V)>` for canonical order + O(log n) lookups
//!   - `set(K, V)` / `get(&K)` / `len()` / `is_empty()` / `iter()`
//!   - When `V: OutcomeLattice`: `overall()` via `worst_of(...)`
//!
//! The generic factors out all of that; consumers either use the
//! type alias directly or wrap with a newtype for domain-specific
//! methods.
//!
//! # Canonical-order invariant
//!
//! Entries are kept sorted by `K`. This makes:
//!   - `iter()` return entries in canonical order (deterministic
//!     serialization)
//!   - `get(&K)` O(log n) via binary search
//!   - `set(K, V)` O(n) in worst case (insert into sorted vec); the
//!     typical aggregator size is small (tens to low-hundreds) so
//!     the linear insert cost is amortized away
//!   - The serialized form is identical regardless of insertion order
//!
//! # OutcomeLattice integration
//!
//! When `V: OutcomeLattice`, the generic exposes `.overall() -> V`
//! via `worst_of(...)`. This is the canonical aggregation operation
//! the substrate uses for "fold-by-severity" — vacuous-truth on
//! empty, worst-severity-wins on non-empty.
//!
//! # Why not `BTreeMap<K, V>`?
//!
//! `BTreeMap` serializes via `serde` as a JSON object, which requires
//! string keys. `K` here is often a struct (`ResourceRef`) that has
//! no canonical string form — round-trip through JSON would require
//! a `KeyAsString` shim per `K`. The `Vec<(K, V)>` form serializes as
//! a JSON array of pairs, requiring no per-`K` machinery and round-
//! trips losslessly via `serde_json::to_value` / `from_value`.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::outcome::{OutcomeLattice, worst_of};

/// Typed sorted per-key aggregator. Entries are kept sorted by `K`
/// so iteration + serialization are canonical.
///
/// `K: Ord + Clone` covers the typical resource-ref / condition-type
/// keys. `V` is unconstrained at the type level; specific methods
/// (like `overall()`) gate on `V: OutcomeLattice` separately.
///
/// `#[serde(transparent)]` so the wire format is the underlying
/// `Vec<(K, V)>` (a JSON array of pairs). No object/key restriction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Aggregator<K: Ord + Clone, V: Clone> {
    entries: Vec<(K, V)>,
}

impl<K: Ord + Clone, V: Clone> Default for Aggregator<K, V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<K: Ord + Clone, V: Clone> Aggregator<K, V> {
    /// Construct an empty aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of recorded entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a single key's value. If the key is already present,
    /// its value is overwritten.
    pub fn set(&mut self, key: K, value: V) {
        match self.entries.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(idx) => self.entries[idx].1 = value,
            Err(idx) => self.entries.insert(idx, (key, value)),
        }
    }

    /// Lookup a single key's recorded value. O(log n).
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries
            .binary_search_by(|(k, _)| k.cmp(key))
            .ok()
            .map(|idx| &self.entries[idx].1)
    }

    /// Iterate `(K, V)` pairs in canonical (sorted) `K` order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    /// Drain entries by predicate. Convenience for cleanup paths
    /// (e.g. "drop entries whose K no longer in inventory").
    pub fn retain<F: FnMut(&K, &V) -> bool>(&mut self, mut f: F) {
        self.entries.retain(|(k, v)| f(k, v));
    }
}

impl<K: Ord + Clone, V: OutcomeLattice> Aggregator<K, V> {
    /// Aggregate by `worst_of(...)`. Vacuous-truth on empty (returns
    /// `V::baseline()` per the `OutcomeLattice` law).
    ///
    /// When multiple entries share the worst severity, the first one
    /// encountered (in canonical `K` order) wins — meets the
    /// `OutcomeLattice` tie-break rule.
    pub fn overall(&self) -> V {
        worst_of(self.entries.iter().map(|(_, v)| v.clone()))
    }
}

impl<K: Ord + Clone, V: Clone> FromIterator<(K, V)> for Aggregator<K, V> {
    /// Build from a `(K, V)` iterator. Duplicate `K`s overwrite in
    /// iteration order — final value wins.
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut agg = Self::new();
        for (k, v) in iter {
            agg.set(k, v);
        }
        agg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::ReadyState;

    // ── Empty / construction ──────────────────────────────────────

    #[test]
    fn empty_is_empty() {
        let agg: Aggregator<u32, &str> = Aggregator::new();
        assert!(agg.is_empty());
        assert_eq!(agg.len(), 0);
        assert!(agg.iter().next().is_none());
    }

    #[test]
    fn default_is_empty() {
        let agg: Aggregator<u32, &str> = Aggregator::default();
        assert!(agg.is_empty());
    }

    // ── set / get ─────────────────────────────────────────────────

    #[test]
    fn set_and_get() {
        let mut agg = Aggregator::<u32, &str>::new();
        agg.set(7, "seven");
        assert_eq!(agg.get(&7), Some(&"seven"));
        assert_eq!(agg.get(&8), None);
    }

    #[test]
    fn set_overwrites_existing() {
        let mut agg = Aggregator::<u32, &str>::new();
        agg.set(7, "a");
        agg.set(7, "b");
        assert_eq!(agg.len(), 1);
        assert_eq!(agg.get(&7), Some(&"b"));
    }

    // ── Canonical-order invariant ─────────────────────────────────

    #[test]
    fn iter_is_canonical_order_regardless_of_insertion() {
        let mut a = Aggregator::<u32, &str>::new();
        a.set(3, "c");
        a.set(1, "a");
        a.set(2, "b");

        let mut b = Aggregator::<u32, &str>::new();
        b.set(2, "b");
        b.set(3, "c");
        b.set(1, "a");

        let ordered_a: Vec<_> = a.iter().collect();
        let ordered_b: Vec<_> = b.iter().collect();
        assert_eq!(ordered_a, ordered_b);
        assert_eq!(ordered_a, vec![(&1, &"a"), (&2, &"b"), (&3, &"c")],);
    }

    #[test]
    fn serialization_is_deterministic_across_insertion_order() {
        let mut a = Aggregator::<u32, String>::new();
        a.set(3, "c".into());
        a.set(1, "a".into());

        let mut b = Aggregator::<u32, String>::new();
        b.set(1, "a".into());
        b.set(3, "c".into());

        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
        );
    }

    #[test]
    fn round_trips_through_json() {
        let mut agg = Aggregator::<u32, String>::new();
        agg.set(1, "one".into());
        agg.set(2, "two".into());

        let json = serde_json::to_string(&agg).unwrap();
        let back: Aggregator<u32, String> = serde_json::from_str(&json).unwrap();
        assert_eq!(agg, back);
    }

    // ── retain ────────────────────────────────────────────────────

    #[test]
    fn retain_drops_by_predicate() {
        let mut agg = Aggregator::<u32, &str>::new();
        agg.set(1, "a");
        agg.set(2, "b");
        agg.set(3, "c");
        agg.retain(|k, _| *k != 2);
        assert_eq!(agg.len(), 2);
        assert_eq!(agg.get(&1), Some(&"a"));
        assert_eq!(agg.get(&2), None);
        assert_eq!(agg.get(&3), Some(&"c"));
    }

    // ── OutcomeLattice gating ─────────────────────────────────────

    #[test]
    fn overall_empty_returns_baseline() {
        let agg: Aggregator<u32, ReadyState> = Aggregator::new();
        assert_eq!(agg.overall(), ReadyState::baseline());
    }

    #[test]
    fn overall_returns_worst() {
        let mut agg = Aggregator::<u32, ReadyState>::new();
        agg.set(1, ReadyState::Ready);
        agg.set(
            2,
            ReadyState::InProgress {
                reason: "deploying".into(),
            },
        );
        agg.set(
            3,
            ReadyState::Failed {
                reason: "crash".into(),
            },
        );
        assert!(matches!(agg.overall(), ReadyState::Failed { .. }));
    }

    #[test]
    fn overall_all_ready_is_ready() {
        let mut agg = Aggregator::<u32, ReadyState>::new();
        agg.set(1, ReadyState::Ready);
        agg.set(2, ReadyState::Ready);
        assert_eq!(agg.overall(), ReadyState::Ready);
    }

    // ── FromIterator ──────────────────────────────────────────────

    #[test]
    fn from_iter_builds_aggregator() {
        let agg: Aggregator<u32, &str> = vec![(2, "b"), (1, "a"), (3, "c")].into_iter().collect();
        let canon: Vec<_> = agg.iter().collect();
        assert_eq!(canon, vec![(&1, &"a"), (&2, &"b"), (&3, &"c")]);
    }

    #[test]
    fn from_iter_duplicate_keys_last_wins() {
        let agg: Aggregator<u32, &str> = vec![(1, "a"), (1, "b"), (1, "c")].into_iter().collect();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg.get(&1), Some(&"c"));
    }

    // ── Composability with existing HealthReport semantics ──────

    /// `HealthReport` IS `Aggregator<ResourceRef, ReadyState>` —
    /// proof that the generic abstracts the existing shape.
    #[test]
    fn composes_as_healthreport_shape() {
        use crate::ResourceRef;
        let mut agg: Aggregator<ResourceRef, ReadyState> = Aggregator::new();
        let d1 = ResourceRef::namespaced("apps", "v1", "Deployment", "ns", "a");
        let d2 = ResourceRef::namespaced("apps", "v1", "Deployment", "ns", "b");
        agg.set(d1.clone(), ReadyState::Ready);
        agg.set(
            d2.clone(),
            ReadyState::InProgress {
                reason: "rollout".into(),
            },
        );
        assert_eq!(agg.len(), 2);
        assert!(matches!(agg.overall(), ReadyState::InProgress { .. }));
    }
}
