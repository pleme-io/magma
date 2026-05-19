//! Property-based proofs for the drift classifier.
//!
//! `classify(plan, policy)` is the substrate's policy layer — every
//! reconcile flows through it before reaching the apply phase, and
//! compliance teams rely on it to surface RequireApproval for
//! security-relevant changes. These proptests turn the classifier's
//! load-bearing contracts into proven theorems over hundreds of
//! random Plans:
//!
//! 1. Determinism: same plan + policy → identical DriftReport.
//! 2. Summary is a partition of non-NoOp changes.
//! 3. NoOp changes never appear in events (they aren't drift).
//! 4. Conservative-default routing: Cosmetic→AutoCorrect,
//!    Functional→AutoCorrectWithAlert, Critical→RequireApproval.
//! 5. Every emitted event carries a well-formed BLAKE3 fingerprint.
//! 6. plan_id + kind in the report match the input plan.

use magma_converge::{Action, ChangeSeverity};
use magma_drift::{classify, DriftDecision, DriftPolicy};
use magma_test_laws::strategies::arb_plan;
use proptest::prelude::*;

// ── Property 1: determinism ────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn classify_is_deterministic(plan in arb_plan()) {
        let p = DriftPolicy::conservative_default();
        let r1 = classify(&plan, &p);
        let r2 = classify(&plan, &p);
        prop_assert_eq!(&r1.kind,     &r2.kind);
        prop_assert_eq!(&r1.plan_id,  &r2.plan_id);
        prop_assert_eq!(r1.events.len(), r2.events.len());
        prop_assert_eq!(&r1.summary.total_changes,           &r2.summary.total_changes);
        prop_assert_eq!(&r1.summary.auto_corrected,          &r2.summary.auto_corrected);
        prop_assert_eq!(&r1.summary.auto_corrected_with_alert, &r2.summary.auto_corrected_with_alert);
        prop_assert_eq!(&r1.summary.awaiting_approval,       &r2.summary.awaiting_approval);
        prop_assert_eq!(&r1.summary.refused,                 &r2.summary.refused);
    }
}

// ── Property 2: summary is a partition of total ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn summary_partitions_total(plan in arb_plan()) {
        let p = DriftPolicy::conservative_default();
        let r = classify(&plan, &p);
        let s = &r.summary;
        prop_assert_eq!(
            s.total_changes,
            s.auto_corrected + s.auto_corrected_with_alert + s.awaiting_approval + s.refused,
            "summary partition violated: {:?}", s,
        );
    }
}

// ── Property 3: NoOp changes are NOT classified ────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn noop_changes_excluded_from_events(plan in arb_plan()) {
        let p = DriftPolicy::conservative_default();
        let r = classify(&plan, &p);
        for e in &r.events {
            prop_assert!(
                !matches!(e.action, Action::NoOp),
                "drift event for NoOp change: {:?}", e,
            );
        }
        // Total in summary == count of non-NoOp changes in the plan.
        let non_noop = plan.changes.iter().filter(|c| !matches!(c.action, Action::NoOp)).count();
        prop_assert_eq!(r.summary.total_changes, non_noop);
        prop_assert_eq!(r.events.len(),          non_noop);
    }
}

// ── Property 4: conservative default routes by severity ─────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn conservative_default_routes_by_severity(plan in arb_plan()) {
        let p = DriftPolicy::conservative_default();
        let r = classify(&plan, &p);
        for event in &r.events {
            let expected = match event.severity {
                ChangeSeverity::Cosmetic   => DriftDecision::AutoCorrect,
                ChangeSeverity::Functional => DriftDecision::AutoCorrectWithAlert,
                ChangeSeverity::Critical   => DriftDecision::RequireApproval,
            };
            prop_assert_eq!(
                event.decision, expected,
                "severity {:?} routed to {:?}, expected {:?}",
                event.severity, event.decision, expected,
            );
        }
    }
}

// ── Property 5: every event has a 64-char hex fingerprint ──────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn every_event_has_well_formed_fingerprint(plan in arb_plan()) {
        let p = DriftPolicy::conservative_default();
        let r = classify(&plan, &p);
        for event in &r.events {
            prop_assert_eq!(event.fingerprint.len(), 64);
            prop_assert!(
                event.fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                "malformed fingerprint: {}", event.fingerprint,
            );
        }
    }
}

// ── Property 6: report carries the plan's identity ─────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn report_preserves_plan_identity(plan in arb_plan()) {
        let p = DriftPolicy::conservative_default();
        let r = classify(&plan, &p);
        prop_assert_eq!(&r.kind,    &plan.kind);
        prop_assert_eq!(&r.plan_id, &plan.id);
    }
}

// ── Property 7: events preserve order of non-NoOp changes ──────────
//
// Reconcilers rely on events appearing in the same order they were
// computed. A reorder would scramble the audit log + bundle's
// canonical hash.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn events_preserve_plan_change_order(plan in arb_plan()) {
        let p = DriftPolicy::conservative_default();
        let r = classify(&plan, &p);
        let plan_addrs: Vec<&str> = plan
            .changes
            .iter()
            .filter(|c| !matches!(c.action, Action::NoOp))
            .map(|c| c.address.as_str())
            .collect();
        let event_addrs: Vec<&str> = r.events.iter().map(|e| e.address.as_str()).collect();
        prop_assert_eq!(plan_addrs, event_addrs);
    }
}
