//! Property-based proof: the universal substrate law battery
//! handles arbitrary Pangea-shaped workspaces, not just hand-
//! written fixtures.
//!
//! `workspace::arb_workspace_config()` generates random
//! architecturally-valid Pangea workspaces (1-3 providers, 1-6
//! resources matching declared provider types, 0-3 outputs with
//! valid interpolation refs). Each generated shape goes through:
//!
//! * Architecture composition laws (no dangling refs, every
//!   resource type has a registered provider, …)
//! * Workspace lifecycle laws (plan deterministic, apply
//!   converges, destroy round-trips, …)
//!
//! 64 random shapes per property. A regression in any law surfaces
//! with proptest's minimized counterexample.

#![cfg(all(feature = "workspace-laws", feature = "strategies"))]

use magma_test_laws::workspace::arb_workspace_config;
use proptest::prelude::*;

// ── Property 1: every generated workspace passes architecture laws

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn generated_workspace_passes_architecture_laws(cfg in arb_workspace_config()) {
        magma_test_laws::architecture::assert_all_laws(&cfg);
    }
}

// ── Property 2: every generated workspace passes lifecycle laws ───

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn generated_workspace_passes_lifecycle_laws(cfg in arb_workspace_config()) {
        magma_test_laws::workspace::assert_all_laws(&cfg);
    }
}

// ── Property 3: every generated workspace passes preflight ────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn generated_workspace_passes_preflight(cfg in arb_workspace_config()) {
        let violations = magma_test_laws::preflight::check_workspace_full(&cfg);
        prop_assert!(
            violations.is_empty(),
            "preflight surfaced violations on a generator-produced workspace: {violations:?}",
        );
    }
}
