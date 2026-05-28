//! Typed K8s label selector — the canonical `LabelSelector` predicate
//! every controller uses to select Pods / Deployments / Services /
//! ResourceSets / etc by label.
//!
//! Subsumes K8s `metav1.LabelSelector` as a typed substrate primitive
//! so:
//!
//! - The substrate never depends on kube-rs (`k8s-openapi` pulls in
//!   the full client cake); adapters convert to/from the kube-rs
//!   shape at the API boundary
//! - Per-controller selector matching becomes a typed
//!   `selector.matches(&labels) -> bool` call instead of a hand-rolled
//!   loop over both `matchLabels` and `matchExpressions`
//! - The wire format is byte-identical to K8s metav1.LabelSelector
//!   JSON (`matchLabels` + `matchExpressions[{key,operator,values}]`)
//!
//! # Trait laws
//!
//! 1. **Empty selector matches every label set.** A selector with
//!    no matchLabels and no matchExpressions IS the universal set.
//! 2. **AND semantics across all conditions.** Every `matchLabels`
//!    key+value pair AND every `matchExpressions` requirement must
//!    hold for the selector to match.
//! 3. **Determinism.** `s.matches(l) == s.matches(l)` for the same
//!    `(selector, labels)`.
//! 4. **Operator semantics per K8s:**
//!    - `In`: label exists AND its value is in `values`
//!    - `NotIn`: label absent OR its value is NOT in `values`
//!    - `Exists`: label exists (values ignored)
//!    - `DoesNotExist`: label absent (values ignored)
//!
//! # Composition
//!
//! `LabelSelector` is the typed predicate; consumers compose it with
//! [`crate::Inventory`] to filter resources by label, with
//! [`crate::Classifier<…, ReconcileTrigger>`] for routing webhook
//! events to label-selected destinations, and with K8s controllers'
//! per-CR selector fields (HPA targets, NetworkPolicy podSelector,
//! ServiceMonitor matchLabels, etc).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// K8s set-based operator. Wire format matches K8s exactly: `"In"` /
/// `"NotIn"` / `"Exists"` / `"DoesNotExist"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LabelSelectorOperator {
    /// Label exists AND its value is in `values`.
    In,
    /// Label absent OR its value is NOT in `values`.
    NotIn,
    /// Label exists. `values` MUST be empty.
    Exists,
    /// Label absent. `values` MUST be empty.
    DoesNotExist,
}

impl LabelSelectorOperator {
    /// `true` when this operator ignores the `values` field. The
    /// caller's invariant: `Exists` and `DoesNotExist` must carry
    /// `values: vec![]` per K8s spec.
    pub fn ignores_values(self) -> bool {
        matches!(self, Self::Exists | Self::DoesNotExist)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::In => "In",
            Self::NotIn => "NotIn",
            Self::Exists => "Exists",
            Self::DoesNotExist => "DoesNotExist",
        }
    }
}

/// A single set-based requirement (`key`, `operator`, `values`) in
/// a `LabelSelector`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: LabelSelectorOperator,
    /// Values to match against. MUST be empty for `Exists` /
    /// `DoesNotExist`; SHOULD be non-empty for `In` / `NotIn`
    /// (per K8s; an empty `In`/`NotIn` is a vacuous selector that
    /// never matches).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

impl LabelSelectorRequirement {
    pub fn new(
        key: impl Into<String>,
        operator: LabelSelectorOperator,
        values: Vec<String>,
    ) -> Self {
        Self {
            key: key.into(),
            operator,
            values,
        }
    }

    /// Convenience: `In` requirement.
    pub fn r#in(key: impl Into<String>, values: Vec<String>) -> Self {
        Self::new(key, LabelSelectorOperator::In, values)
    }

    /// Convenience: `NotIn` requirement.
    pub fn not_in(key: impl Into<String>, values: Vec<String>) -> Self {
        Self::new(key, LabelSelectorOperator::NotIn, values)
    }

    /// Convenience: `Exists` requirement.
    pub fn exists(key: impl Into<String>) -> Self {
        Self::new(key, LabelSelectorOperator::Exists, vec![])
    }

    /// Convenience: `DoesNotExist` requirement.
    pub fn does_not_exist(key: impl Into<String>) -> Self {
        Self::new(key, LabelSelectorOperator::DoesNotExist, vec![])
    }

    /// Evaluate this requirement against a label map. Per K8s spec.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        match self.operator {
            LabelSelectorOperator::In => labels
                .get(&self.key)
                .map(|v| self.values.iter().any(|e| e == v))
                .unwrap_or(false),
            LabelSelectorOperator::NotIn => labels
                .get(&self.key)
                .map(|v| !self.values.iter().any(|e| e == v))
                .unwrap_or(true),
            LabelSelectorOperator::Exists => labels.contains_key(&self.key),
            LabelSelectorOperator::DoesNotExist => !labels.contains_key(&self.key),
        }
    }

    /// `true` if this requirement carries values when the operator
    /// requires empty values (i.e. `Exists`/`DoesNotExist` with
    /// non-empty `values`). Useful for validation at construction.
    pub fn has_invalid_values(&self) -> bool {
        self.operator.ignores_values() && !self.values.is_empty()
    }
}

/// Typed K8s label selector. Wire format matches K8s metav1.LabelSelector
/// JSON byte-for-byte via `#[serde(rename_all = "camelCase")]`.
///
/// An empty selector (both `match_labels` and `match_expressions`
/// empty) matches **every** label set per K8s convention — it IS
/// the universal selector.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// `matchLabels`: every key/value MUST be present in the target.
    /// Equivalent to a list of `In` requirements with single values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,

    /// `matchExpressions`: every requirement MUST hold per its
    /// operator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

impl LabelSelector {
    /// Empty selector — matches every label set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from a single key=value match.
    pub fn from_label(key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.match_labels.insert(key.into(), value.into());
        s
    }

    /// Add a `matchLabels` entry. Returns self for chaining.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.match_labels.insert(key.into(), value.into());
        self
    }

    /// Add a `matchExpressions` requirement. Returns self for chaining.
    #[must_use]
    pub fn with_expression(mut self, req: LabelSelectorRequirement) -> Self {
        self.match_expressions.push(req);
        self
    }

    /// `true` when this selector has neither matchLabels nor
    /// matchExpressions — the universal "matches everything" form.
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }

    /// Evaluate this selector against a label map. AND semantics:
    /// every matchLabels entry AND every matchExpressions requirement
    /// must hold for the selector to match.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        // matchLabels: every k/v pair must be exactly equal in target.
        for (k, v) in &self.match_labels {
            match labels.get(k) {
                Some(actual) if actual == v => continue,
                _ => return false,
            }
        }
        // matchExpressions: every requirement must hold.
        for req in &self.match_expressions {
            if !req.matches(labels) {
                return false;
            }
        }
        true
    }

    /// `true` when ANY requirement is invalid (Exists/DoesNotExist
    /// carrying values). Returns first-fail; iterates expressions
    /// only. Use at construction time to validate operator-supplied
    /// selectors.
    pub fn has_invalid_requirements(&self) -> bool {
        self.match_expressions.iter().any(|r| r.has_invalid_values())
    }
}

/// Convenience: build a `BTreeMap<String, String>` from a slice of
/// `(&str, &str)` pairs. Useful for tests + ergonomic construction.
pub fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── LabelSelectorOperator ─────────────────────────────────────

    #[test]
    fn operator_ignores_values_only_for_exists_kinds() {
        assert!(LabelSelectorOperator::Exists.ignores_values());
        assert!(LabelSelectorOperator::DoesNotExist.ignores_values());
        assert!(!LabelSelectorOperator::In.ignores_values());
        assert!(!LabelSelectorOperator::NotIn.ignores_values());
    }

    #[test]
    fn operator_serde_titlecase_matches_k8s() {
        let op = LabelSelectorOperator::In;
        let json = serde_json::to_string(&op).unwrap();
        assert_eq!(json, "\"In\"");
        let back: LabelSelectorOperator = serde_json::from_str("\"DoesNotExist\"").unwrap();
        assert_eq!(back, LabelSelectorOperator::DoesNotExist);
    }

    #[test]
    fn operator_names_match_k8s_wire_format() {
        assert_eq!(LabelSelectorOperator::In.name(), "In");
        assert_eq!(LabelSelectorOperator::NotIn.name(), "NotIn");
        assert_eq!(LabelSelectorOperator::Exists.name(), "Exists");
        assert_eq!(LabelSelectorOperator::DoesNotExist.name(), "DoesNotExist");
    }

    // ── LabelSelectorRequirement ──────────────────────────────────

    #[test]
    fn requirement_constructors_set_operator_correctly() {
        assert_eq!(
            LabelSelectorRequirement::r#in("k", vec!["v".into()]).operator,
            LabelSelectorOperator::In
        );
        assert_eq!(
            LabelSelectorRequirement::not_in("k", vec!["v".into()]).operator,
            LabelSelectorOperator::NotIn
        );
        assert_eq!(
            LabelSelectorRequirement::exists("k").operator,
            LabelSelectorOperator::Exists
        );
        assert_eq!(
            LabelSelectorRequirement::does_not_exist("k").operator,
            LabelSelectorOperator::DoesNotExist
        );
    }

    #[test]
    fn requirement_exists_does_not_carry_values() {
        let r = LabelSelectorRequirement::exists("k");
        assert!(r.values.is_empty());
        assert!(!r.has_invalid_values());
    }

    #[test]
    fn requirement_invalid_when_exists_carries_values() {
        let r = LabelSelectorRequirement::new(
            "k",
            LabelSelectorOperator::Exists,
            vec!["bad".into()],
        );
        assert!(r.has_invalid_values());
    }

    #[test]
    fn requirement_in_matches_value_present() {
        let r = LabelSelectorRequirement::r#in("env", vec!["prod".into(), "staging".into()]);
        assert!(r.matches(&labels(&[("env", "prod")])));
        assert!(r.matches(&labels(&[("env", "staging")])));
        assert!(!r.matches(&labels(&[("env", "dev")])));
        assert!(!r.matches(&labels(&[])));
    }

    #[test]
    fn requirement_not_in_matches_value_absent_or_other() {
        let r = LabelSelectorRequirement::not_in("env", vec!["prod".into()]);
        assert!(r.matches(&labels(&[("env", "dev")])));
        assert!(r.matches(&labels(&[("env", "staging")])));
        assert!(r.matches(&labels(&[])), "absent label satisfies NotIn");
        assert!(!r.matches(&labels(&[("env", "prod")])));
    }

    #[test]
    fn requirement_exists_matches_label_present() {
        let r = LabelSelectorRequirement::exists("tier");
        assert!(r.matches(&labels(&[("tier", "frontend")])));
        assert!(r.matches(&labels(&[("tier", "")])), "empty value still exists");
        assert!(!r.matches(&labels(&[("env", "prod")])));
    }

    #[test]
    fn requirement_does_not_exist_matches_label_absent() {
        let r = LabelSelectorRequirement::does_not_exist("legacy");
        assert!(r.matches(&labels(&[])));
        assert!(r.matches(&labels(&[("env", "prod")])));
        assert!(!r.matches(&labels(&[("legacy", "true")])));
    }

    #[test]
    fn requirement_in_with_empty_values_never_matches() {
        // K8s spec: In with empty values is vacuous (matches nothing).
        let r = LabelSelectorRequirement::new("k", LabelSelectorOperator::In, vec![]);
        assert!(!r.matches(&labels(&[("k", "v")])));
        assert!(!r.matches(&labels(&[])));
    }

    #[test]
    fn requirement_serde_omits_empty_values() {
        let r = LabelSelectorRequirement::exists("tier");
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"values\""), "got {json:?}");
        let back: LabelSelectorRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn requirement_serde_round_trip_with_values() {
        let r = LabelSelectorRequirement::r#in("env", vec!["prod".into(), "staging".into()]);
        let json = serde_json::to_string(&r).unwrap();
        let back: LabelSelectorRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── LabelSelector evaluation ──────────────────────────────────

    #[test]
    fn empty_selector_matches_anything() {
        let s = LabelSelector::new();
        assert!(s.is_empty());
        assert!(s.matches(&labels(&[])));
        assert!(s.matches(&labels(&[("env", "prod"), ("tier", "frontend")])));
    }

    #[test]
    fn match_labels_requires_all_keys_present_with_correct_values() {
        let s = LabelSelector::from_label("env", "prod")
            .with_label("tier", "frontend");
        assert!(s.matches(&labels(&[("env", "prod"), ("tier", "frontend")])));
        // Wrong value for env.
        assert!(!s.matches(&labels(&[("env", "dev"), ("tier", "frontend")])));
        // Missing tier.
        assert!(!s.matches(&labels(&[("env", "prod")])));
        // Empty.
        assert!(!s.matches(&labels(&[])));
    }

    #[test]
    fn match_labels_ignores_extra_labels_in_target() {
        let s = LabelSelector::from_label("env", "prod");
        assert!(s.matches(&labels(&[
            ("env", "prod"),
            ("extra", "yes"),
            ("more", "stuff"),
        ])));
    }

    #[test]
    fn match_expressions_evaluated_in_addition_to_match_labels() {
        let s = LabelSelector::new()
            .with_label("env", "prod")
            .with_expression(LabelSelectorRequirement::exists("tier"))
            .with_expression(LabelSelectorRequirement::not_in(
                "version",
                vec!["v0".into()],
            ));

        // env=prod ✓ + tier exists ✓ + version not in [v0] ✓
        assert!(s.matches(&labels(&[
            ("env", "prod"),
            ("tier", "frontend"),
            ("version", "v1"),
        ])));

        // env=prod ✓ + tier MISSING → fail
        assert!(!s.matches(&labels(&[("env", "prod"), ("version", "v1")])));

        // env=prod ✓ + tier ✓ + version=v0 → fail (NotIn rejects)
        assert!(!s.matches(&labels(&[
            ("env", "prod"),
            ("tier", "frontend"),
            ("version", "v0"),
        ])));

        // env=dev → fail (matchLabels mismatch)
        assert!(!s.matches(&labels(&[
            ("env", "dev"),
            ("tier", "frontend"),
            ("version", "v1"),
        ])));
    }

    #[test]
    fn match_expressions_alone_select_correctly() {
        let s = LabelSelector::new()
            .with_expression(LabelSelectorRequirement::r#in(
                "env",
                vec!["prod".into(), "staging".into()],
            ));

        assert!(s.matches(&labels(&[("env", "prod")])));
        assert!(s.matches(&labels(&[("env", "staging")])));
        assert!(!s.matches(&labels(&[("env", "dev")])));
    }

    #[test]
    fn selector_and_semantics_short_circuits_on_first_failure() {
        // First condition false → selector returns false without
        // evaluating later conditions. Tested indirectly via
        // a long chain.
        let s = LabelSelector::new()
            .with_label("a", "1")
            .with_label("b", "2")
            .with_label("c", "3")
            .with_label("d", "4");

        // Missing a → false (the other 3 don't need to evaluate).
        assert!(!s.matches(&labels(&[("b", "2"), ("c", "3"), ("d", "4")])));
    }

    #[test]
    fn selector_has_invalid_requirements_detects_exists_with_values() {
        let s = LabelSelector::new().with_expression(LabelSelectorRequirement::new(
            "k",
            LabelSelectorOperator::Exists,
            vec!["bad".into()],
        ));
        assert!(s.has_invalid_requirements());

        let clean = LabelSelector::from_label("env", "prod")
            .with_expression(LabelSelectorRequirement::exists("tier"));
        assert!(!clean.has_invalid_requirements());
    }

    // ── Wire format conformance ───────────────────────────────────

    #[test]
    fn selector_serde_camel_case_matches_k8s() {
        let s = LabelSelector::from_label("env", "prod")
            .with_expression(LabelSelectorRequirement::r#in(
                "tier",
                vec!["frontend".into()],
            ));

        let json = serde_json::to_string(&s).unwrap();
        // K8s wire format keys.
        assert!(json.contains("\"matchLabels\""));
        assert!(json.contains("\"matchExpressions\""));
        // No camel-case→snake-case slip.
        assert!(!json.contains("match_labels"));
        assert!(!json.contains("match_expressions"));
    }

    #[test]
    fn selector_serde_omits_empty_match_labels_and_expressions() {
        let s = LabelSelector::new();
        let json = serde_json::to_string(&s).unwrap();
        // Empty selector serializes as `{}`.
        assert_eq!(json, "{}");

        let back: LabelSelector = serde_json::from_str(&json).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn selector_deserializes_real_k8s_payload() {
        let payload = r#"{
            "matchLabels": {
                "app": "nginx",
                "tier": "frontend"
            },
            "matchExpressions": [
                {"key": "environment", "operator": "In", "values": ["prod", "staging"]},
                {"key": "deprecated", "operator": "DoesNotExist"}
            ]
        }"#;
        let s: LabelSelector = serde_json::from_str(payload).unwrap();

        assert_eq!(s.match_labels.len(), 2);
        assert_eq!(s.match_labels.get("app").map(|s| s.as_str()), Some("nginx"));
        assert_eq!(s.match_expressions.len(), 2);
        assert_eq!(s.match_expressions[0].operator, LabelSelectorOperator::In);
        assert_eq!(
            s.match_expressions[1].operator,
            LabelSelectorOperator::DoesNotExist
        );
        // DoesNotExist requirement parsed without values (omitted).
        assert!(s.match_expressions[1].values.is_empty());
    }

    #[test]
    fn selector_round_trip_compound() {
        let s = LabelSelector::new()
            .with_label("env", "prod")
            .with_label("tier", "frontend")
            .with_expression(LabelSelectorRequirement::r#in(
                "version",
                vec!["v1".into(), "v2".into()],
            ))
            .with_expression(LabelSelectorRequirement::does_not_exist("deprecated"));

        let json = serde_json::to_string(&s).unwrap();
        let back: LabelSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ── labels() convenience ──────────────────────────────────────

    #[test]
    fn labels_helper_builds_map() {
        let m = labels(&[("a", "1"), ("b", "2")]);
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("a").map(|s| s.as_str()), Some("1"));
    }

    // ── Determinism ───────────────────────────────────────────────

    #[test]
    fn matches_is_deterministic() {
        let s = LabelSelector::from_label("env", "prod")
            .with_expression(LabelSelectorRequirement::not_in(
                "version",
                vec!["v0".into()],
            ));

        let cases = [
            labels(&[]),
            labels(&[("env", "prod")]),
            labels(&[("env", "prod"), ("version", "v1")]),
            labels(&[("env", "prod"), ("version", "v0")]),
            labels(&[("env", "dev"), ("version", "v1")]),
        ];

        for c in &cases {
            let a = s.matches(c);
            let b = s.matches(c);
            assert_eq!(a, b, "non-deterministic match for labels {c:?}");
        }
    }
}
