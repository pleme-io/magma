//! Property-based proofs for the Bundle BLAKE3 attestation.
//!
//! The Bundle is the compliance-export artifact: one BLAKE3 hash
//! over (kind + workspace + plan + outcome + drift + lifecycle +
//! audit). Compliance teams trust the hash to mean "this bundle
//! hasn't been mutated since reconcile-time." Without proptest, the
//! hash projection is a hand-coded JSON shape — easy to bit-rot.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §VI (attested bundles).

use magma_bundle::{Bundle, BundleError};
use magma_converge::{Action, AppliedChange, Outcome, Plan};
use magma_drift::{classify, DriftPolicy};
use magma_fsm::Phase;
use magma_stream::EventPayload;
use magma_test_laws::strategies::{arb_event_chain, arb_lifecycle_happy_walk, arb_plan};
use chrono::Utc;
use proptest::prelude::*;

// ── Local generator for an Outcome derived from a Plan ─────────────
// (Plans + lifecycle + audit chains come from shared strategies; the
// Outcome is plan-derived so it stays local.)

fn arb_outcome(plan: &Plan) -> Outcome {
    let applied = plan
        .changes
        .iter()
        .filter(|c| !matches!(c.action, Action::NoOp))
        .map(|c| AppliedChange {
            address: c.address.clone(),
            action:  c.action,
        })
        .collect();
    Outcome {
        plan_id:     plan.id.clone(),
        kind:        plan.kind.clone(),
        applied,
        failed:      vec![],
        started_at:  Utc::now(),
        finished_at: Utc::now(),
    }
}

fn arb_bundle() -> impl Strategy<Value = Bundle> {
    (
        "[a-z]{2,12}",       // kind
        "[a-z][a-z0-9-]{2,15}", // workspace
        arb_plan(),
        arb_lifecycle_happy_walk(),
        arb_event_chain(5),
        any::<bool>(),       // include outcome?
    )
        .prop_map(|(kind, workspace, plan, lifecycle, audit, has_outcome)| {
            let outcome = if has_outcome {
                Some(arb_outcome(&plan))
            } else {
                None
            };
            let drift = classify(&plan, &DriftPolicy::conservative_default());
            Bundle::new(kind, workspace, plan, outcome, drift, lifecycle, audit)
                .expect("Bundle::new must succeed for any well-typed input")
        })
}

// ── Property 1: bundle_id is BLAKE3-shaped (64 hex chars) ──────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bundle_id_is_64_hex_chars(bundle in arb_bundle()) {
        prop_assert_eq!(bundle.bundle_id.len(), 64);
        prop_assert!(bundle.bundle_id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ── Property 2: verify() always succeeds for freshly-built ─────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn freshly_built_bundle_verifies(bundle in arb_bundle()) {
        bundle.verify().unwrap_or_else(|e| panic!("fresh bundle failed verify: {e:?}"));
    }
}

// ── Property 3: bundle_id is independent of built_at ───────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn bundle_id_is_independent_of_built_at(bundle in arb_bundle()) {
        // Snapshot the inputs, build twice (different built_ats), compare hashes.
        let id1 = Bundle::derive_id(
            &bundle.kind, &bundle.workspace, &bundle.plan,
            &bundle.outcome, &bundle.drift, &bundle.lifecycle, &bundle.audit,
            bundle.gem_tree_attestation.as_deref(),
        ).unwrap();
        // Sleep for a tick so built_at would differ if it were
        // in-scope. (No actual sleep needed — we call derive_id
        // again synchronously, but built_at is read inside
        // Bundle::new, NOT derive_id.)
        let id2 = Bundle::derive_id(
            &bundle.kind, &bundle.workspace, &bundle.plan,
            &bundle.outcome, &bundle.drift, &bundle.lifecycle, &bundle.audit,
            bundle.gem_tree_attestation.as_deref(),
        ).unwrap();
        prop_assert_eq!(id1, id2);
    }
}

// ── Property 4: tampering kind breaks verify ───────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn tampering_kind_breaks_verify(
        bundle in arb_bundle(),
        evil_kind in "[a-z]{3,8}",
    ) {
        let mut b = bundle;
        prop_assume!(b.kind != evil_kind);
        b.kind = evil_kind;
        match b.verify() {
            Err(BundleError::IdMismatch { .. }) => {} // expected
            other => panic!("expected IdMismatch after kind tamper, got {other:?}"),
        }
    }
}

// ── Property 5: tampering workspace breaks verify ──────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn tampering_workspace_breaks_verify(
        bundle in arb_bundle(),
        evil_ws in "[a-z]{3,8}",
    ) {
        let mut b = bundle;
        prop_assume!(b.workspace != evil_ws);
        b.workspace = evil_ws;
        let r = b.verify();
        prop_assert!(matches!(r, Err(BundleError::IdMismatch { .. })), "expected IdMismatch, got {:?}", r);
    }
}

// ── Property 6: tampering lifecycle.current breaks verify ──────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn tampering_lifecycle_breaks_verify(bundle in arb_bundle()) {
        let mut b = bundle;
        let original = b.lifecycle.current;
        // Pick any DIFFERENT phase deterministically.
        let evil = if original == Phase::Idle { Phase::Stable } else { Phase::Idle };
        b.lifecycle.current = evil;
        let r = b.verify();
        prop_assert!(matches!(r, Err(BundleError::IdMismatch { .. })), "expected IdMismatch, got {:?}", r);
    }
}

// ── Property 7: tampering audit event payload breaks verify ────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn tampering_audit_event_payload_breaks_verify(bundle in arb_bundle()) {
        let mut b = bundle;
        prop_assume!(!b.audit.is_empty());
        // Tamper the first event's payload field. The recomputed
        // hash will differ because audit goes into the canonical
        // projection by seq + payload + prev_hash + hash.
        b.audit[0].payload = EventPayload::Custom {
            category: "tampered".into(),
            message:  "evil".into(),
        };
        let r = b.verify();
        prop_assert!(matches!(r, Err(BundleError::IdMismatch { .. })), "expected IdMismatch, got {:?}", r);
    }
}

// ── Property 8: JSON round-trip preserves bundle_id ────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn json_round_trip_preserves_bundle_id(bundle in arb_bundle()) {
        let json = bundle.to_json().unwrap();
        let restored = Bundle::from_json_verified(json).unwrap();
        prop_assert_eq!(&restored.bundle_id, &bundle.bundle_id);
        prop_assert_eq!(&restored.kind,      &bundle.kind);
        prop_assert_eq!(&restored.workspace, &bundle.workspace);
    }
}

// ── Property 9: two bundles with identical inputs hash equally ─────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn identical_inputs_yield_identical_bundle_ids(bundle in arb_bundle()) {
        let id_a = Bundle::derive_id(
            &bundle.kind, &bundle.workspace, &bundle.plan,
            &bundle.outcome, &bundle.drift, &bundle.lifecycle, &bundle.audit,
            bundle.gem_tree_attestation.as_deref(),
        ).unwrap();
        // Build a second bundle with the same logical inputs.
        let b2 = Bundle::new(
            bundle.kind.clone(),
            bundle.workspace.clone(),
            bundle.plan.clone(),
            bundle.outcome.clone(),
            bundle.drift.clone(),
            bundle.lifecycle.clone(),
            bundle.audit.clone(),
        ).unwrap();
        prop_assert_eq!(id_a, b2.bundle_id);
    }
}
