//! magma-drift — typed drift classification + policies.
//!
//! Walks a `magma_converge::Plan`, classifies each `Change` by
//! severity (Cosmetic / Functional / Critical) according to typed
//! policies, and emits typed `DriftEvent` for downstream consumers
//! (K8s events, audit log, alerting).
//!
//! Every reconciler kind gets drift classification for free.

#![deny(unsafe_code)]

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use magma_converge::{Change, ChangeSeverity, Plan};

// ── Decisions a policy produces ───────────────────────────────────

/// What the policy engine wants done with a Change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftDecision {
    /// Apply the change immediately without human approval.
    AutoCorrect,
    /// Apply but emit an alert event.
    AutoCorrectWithAlert,
    /// Hold the change until an approver acknowledges.
    RequireApproval,
    /// Refuse the change entirely; surface as a failed reconcile.
    Refuse,
}

/// Typed event the operator emits per Change after policy decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    pub kind:           String,
    pub address:        String,
    pub action:         magma_converge::Action,
    pub severity:       ChangeSeverity,
    pub decision:       DriftDecision,
    pub matched_policy: Option<String>,
    pub observed_at:    DateTime<Utc>,
    /// BLAKE3 fingerprint of (kind, address, action, before, after) — used to
    /// dedupe consecutive observations of the same drift.
    pub fingerprint:    String,
}

impl DriftEvent {
    pub fn fingerprint_for(kind: &str, change: &Change) -> String {
        let canonical = serde_json::json!({
            "kind":    kind,
            "address": change.address,
            "action":  change.action,
            "before":  change.before,
            "after":   change.after,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        hex::encode(blake3::hash(&bytes).as_bytes())
    }
}

// ── Policies ──────────────────────────────────────────────────────

/// A typed policy rule. Evaluated top-to-bottom against each Change;
/// the FIRST matching rule decides. Unmatched changes fall back to
/// `DriftPolicy::fallback`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name:             String,
    /// Only apply this rule when severity matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity:         Option<ChangeSeverity>,
    /// Only apply when action matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action:           Option<magma_converge::Action>,
    /// Only apply when address prefix matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_prefix:   Option<String>,
    /// What to do on match.
    pub decision:         DriftDecision,
}

impl PolicyRule {
    pub fn matches(&self, change: &Change) -> bool {
        if let Some(s) = self.severity {
            if change.severity != s {
                return false;
            }
        }
        if let Some(a) = self.action {
            if change.action != a {
                return false;
            }
        }
        if let Some(prefix) = &self.address_prefix {
            if !change.address.starts_with(prefix) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftPolicy {
    pub rules:    Vec<PolicyRule>,
    /// Decision applied when no rule matches.
    pub fallback: DriftDecision,
}

impl DriftPolicy {
    /// Conservative built-in default: auto-correct Cosmetic,
    /// alert+auto-correct Functional, require approval for Critical.
    /// New deployments can override.
    pub fn conservative_default() -> Self {
        Self {
            rules: vec![
                PolicyRule {
                    name:           "auto-fix-cosmetic".into(),
                    severity:       Some(ChangeSeverity::Cosmetic),
                    action:         None,
                    address_prefix: None,
                    decision:       DriftDecision::AutoCorrect,
                },
                PolicyRule {
                    name:           "alert-on-functional".into(),
                    severity:       Some(ChangeSeverity::Functional),
                    action:         None,
                    address_prefix: None,
                    decision:       DriftDecision::AutoCorrectWithAlert,
                },
                PolicyRule {
                    name:           "approval-required-for-critical".into(),
                    severity:       Some(ChangeSeverity::Critical),
                    action:         None,
                    address_prefix: None,
                    decision:       DriftDecision::RequireApproval,
                },
            ],
            fallback: DriftDecision::RequireApproval,
        }
    }

    /// Decision for a single change. Returns the decision + the
    /// matched policy name (or `None` if fallback used).
    pub fn evaluate(&self, change: &Change) -> (DriftDecision, Option<&str>) {
        for rule in &self.rules {
            if rule.matches(change) {
                return (rule.decision, Some(rule.name.as_str()));
            }
        }
        (self.fallback, None)
    }
}

// ── DriftReport — engine output ───────────────────────────────────

/// Classification report for one Plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub kind:       String,
    pub plan_id:    magma_converge::PlanId,
    pub events:     Vec<DriftEvent>,
    pub summary:    DriftSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftSummary {
    pub total_changes:           usize,
    pub auto_corrected:          usize,
    pub auto_corrected_with_alert: usize,
    pub awaiting_approval:       usize,
    pub refused:                 usize,
}

impl DriftSummary {
    fn tally(&mut self, decision: DriftDecision) {
        self.total_changes += 1;
        match decision {
            DriftDecision::AutoCorrect          => self.auto_corrected += 1,
            DriftDecision::AutoCorrectWithAlert => self.auto_corrected_with_alert += 1,
            DriftDecision::RequireApproval      => self.awaiting_approval += 1,
            DriftDecision::Refuse               => self.refused += 1,
        }
    }
}

/// Classify every Change in `plan` under `policy`, returning a
/// typed `DriftReport`.
pub fn classify(plan: &Plan, policy: &DriftPolicy) -> DriftReport {
    let observed_at = Utc::now();
    let mut events = Vec::with_capacity(plan.changes.len());
    let mut summary = DriftSummary::default();
    for change in &plan.changes {
        if matches!(change.action, magma_converge::Action::NoOp) {
            continue;
        }
        let (decision, matched) = policy.evaluate(change);
        summary.tally(decision);
        events.push(DriftEvent {
            kind:           plan.kind.clone(),
            address:        change.address.clone(),
            action:         change.action,
            severity:       change.severity,
            decision,
            matched_policy: matched.map(String::from),
            observed_at,
            fingerprint:    DriftEvent::fingerprint_for(&plan.kind, change),
        });
    }
    DriftReport { kind: plan.kind.clone(), plan_id: plan.id.clone(), events, summary }
}

/// Dedupe consecutive observations of the same drift by fingerprint.
/// Used by long-running drift-detection loops that don't want to
/// emit the same alert every minute.
#[derive(Debug, Default)]
pub struct DriftDeduplicator {
    seen: HashMap<String, DateTime<Utc>>,
}

impl DriftDeduplicator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if this fingerprint is new (or older than
    /// `min_age`). Updates the seen timestamp.
    pub fn observe(&mut self, fingerprint: &str, min_age: chrono::Duration) -> bool {
        let now = Utc::now();
        match self.seen.get(fingerprint) {
            Some(&prev) if now - prev < min_age => false,
            _ => {
                self.seen.insert(fingerprint.to_string(), now);
                true
            }
        }
    }

    pub fn known(&self, fingerprint: &str) -> bool {
        self.seen.contains_key(fingerprint)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_converge::{change, Action, change_with_severity};
    use serde_json::json;

    fn mk_plan(changes: Vec<Change>) -> Plan {
        Plan::new("inmemory_kv", changes)
    }

    #[test]
    fn classify_empty_plan_yields_no_events() {
        let plan = mk_plan(vec![]);
        let report = classify(&plan, &DriftPolicy::conservative_default());
        assert!(report.events.is_empty());
        assert_eq!(report.summary.total_changes, 0);
    }

    #[test]
    fn noop_changes_are_ignored() {
        let plan = mk_plan(vec![change("kv.x", Action::NoOp, None, None)]);
        let report = classify(&plan, &DriftPolicy::conservative_default());
        assert!(report.events.is_empty());
    }

    #[test]
    fn conservative_default_routes_by_severity() {
        let plan = mk_plan(vec![
            change_with_severity("kv.cosmetic", Action::Update,
                ChangeSeverity::Cosmetic, Some(json!(1)), Some(json!(2))),
            change_with_severity("kv.functional", Action::Update,
                ChangeSeverity::Functional, Some(json!("a")), Some(json!("b"))),
            change_with_severity("kv.critical", Action::Delete,
                ChangeSeverity::Critical, Some(json!({})), None),
        ]);
        let report = classify(&plan, &DriftPolicy::conservative_default());
        assert_eq!(report.events.len(), 3);
        assert_eq!(report.summary.auto_corrected, 1);
        assert_eq!(report.summary.auto_corrected_with_alert, 1);
        assert_eq!(report.summary.awaiting_approval, 1);
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = DriftPolicy {
            rules: vec![
                PolicyRule {
                    name: "refuse-anything-prod".into(),
                    severity: None, action: None,
                    address_prefix: Some("aws_iam_role.prod".into()),
                    decision: DriftDecision::Refuse,
                },
                PolicyRule {
                    name: "auto-fix-everything-else".into(),
                    severity: None, action: None, address_prefix: None,
                    decision: DriftDecision::AutoCorrect,
                },
            ],
            fallback: DriftDecision::RequireApproval,
        };
        let plan = mk_plan(vec![
            change("aws_iam_role.prod-cluster", Action::Update, Some(json!(1)), Some(json!(2))),
            change("aws_iam_role.dev-cluster",  Action::Update, Some(json!(1)), Some(json!(2))),
        ]);
        let report = classify(&plan, &policy);
        let prod = report.events.iter().find(|e| e.address.contains("prod")).unwrap();
        let dev  = report.events.iter().find(|e| e.address.contains("dev")).unwrap();
        assert_eq!(prod.decision, DriftDecision::Refuse);
        assert_eq!(dev.decision, DriftDecision::AutoCorrect);
    }

    #[test]
    fn fallback_used_when_no_rule_matches() {
        let policy = DriftPolicy {
            rules: vec![],
            fallback: DriftDecision::AutoCorrect,
        };
        let plan = mk_plan(vec![change("x.y", Action::Update, Some(json!(1)), Some(json!(2)))]);
        let report = classify(&plan, &policy);
        assert_eq!(report.events[0].decision, DriftDecision::AutoCorrect);
        assert_eq!(report.events[0].matched_policy, None);
    }

    #[test]
    fn fingerprint_is_stable_across_classifications() {
        let c = change("kv.a", Action::Update, Some(json!(1)), Some(json!(2)));
        let f1 = DriftEvent::fingerprint_for("inmemory_kv", &c);
        let f2 = DriftEvent::fingerprint_for("inmemory_kv", &c);
        assert_eq!(f1, f2);
        // 64 hex chars (BLAKE3 32 bytes).
        assert_eq!(f1.len(), 64);
    }

    #[test]
    fn fingerprint_changes_with_payload() {
        let a = change("kv.a", Action::Update, Some(json!(1)), Some(json!(2)));
        let b = change("kv.a", Action::Update, Some(json!(1)), Some(json!(99)));
        assert_ne!(
            DriftEvent::fingerprint_for("k", &a),
            DriftEvent::fingerprint_for("k", &b),
        );
    }

    #[test]
    fn deduplicator_suppresses_repeats_within_window() {
        let mut d = DriftDeduplicator::new();
        let fp = "abcd";
        let window = chrono::Duration::seconds(60);
        assert!(d.observe(fp, window),  "first observation should pass");
        assert!(!d.observe(fp, window), "immediate re-observation should be suppressed");
    }

    #[test]
    fn deduplicator_lets_new_fingerprints_through() {
        let mut d = DriftDeduplicator::new();
        let window = chrono::Duration::seconds(60);
        assert!(d.observe("fp-a", window));
        assert!(d.observe("fp-b", window));
        assert_eq!(d.len(), 2);
    }
}
