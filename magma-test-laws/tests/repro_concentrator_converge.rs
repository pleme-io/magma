//! Reproduction: the example-eks-vpn-concentrator preflight failure.
//!
//! Live symptom (2026-08-02 07:32Z, example-eks, operator image
//! sha256:8a85100f…, magma pinned at 5b159e3): the InfrastructureTemplate sits
//! at phase=Failed with
//!
//!   Magma execution failed: substrate preflight violations:
//!   workspace::assert_all_laws: Workspace law violated: apply didn't converge
//!   — re-plan has 1 non-NoOp changes: [... aws_security_group
//!     "vpn-concentrator-example-sg", action: Update,
//!     reasons: [AttributeDrift]]
//!
//! and the printed `before` / `after` are BYTE-IDENTICAL, which is what makes
//! it read as impossible. Both printed values are the RAW ones; the pair
//! actually compared is `before` (state) against a resolved throwaway copy of
//! `after` (magma-plan/src/lib.rs:288-292), and that pair is never printed.
//!
//! The resource's only non-trivial attribute is
//!   vpc_id = "${data.aws_vpc.example_eks.id}"
//! — a reference INTO A DATA SOURCE. `assert_apply_converges` runs the whole
//! lifecycle in memory with NO providers, so that data source can never
//! actually be read.
//!
//! ── Why the fixture is the RENDERED config, not the workspace tf.json.
//! The operator does not preflight the tf.json. `MagmaExecutor::plan` calls
//! `load_config_routed`, which pulls `kind = 'rendered_config'` out of the
//! artifact store (`pangea_meta.artifacts`) — the COMPILE phase's output,
//! 15,804 bytes against the committed tf.json's 21,268. Both carry the same
//! four `lifecycle` blocks, so the choice is not about which one parses; it
//! is about testing the bytes the failing component actually consumed rather
//! than a plausible-looking sibling of them.
//!
//! The fixture below is exactly those bytes, read straight out of Postgres
//! (updated 2026-08-02T07:31:04Z — sixty seconds before the failure above).
//!
//! ── The two defects this pins, in the order they surface.
//! 1. `lifecycle` was refused WHOLESALE (`UnimplementedMeta`), so this
//!    workspace could not be planned at all once that catalog landed. It is
//!    now refused per SUB-KEY: `ignore_changes` is implemented, the rest keep
//!    the identical typed refusal.
//! 2. With planning unblocked, the real failure appears — and it is an
//!    ORDERING bug. `ref_target` returns `None` for `data.*` paths, on the
//!    documented premise that a data source is "resolved from existing
//!    state". From EMPTY state that premise is false: the data source is
//!    read in the same pass, so with no edge the fallback plan order
//!    (alphabetical) put `aws_security_group` before `aws_vpc`, the SG's
//!    `${data.aws_vpc.example_eks.id}` failed to resolve, and state recorded
//!    the raw literal. The re-plan then resolved it fine and compared
//!    `vpc-0123456789abcdef0` against that literal — permanent drift.
//!    `magma_apply::run_plan` now applies `Action::Read` ahead of every
//!    mutation.
#![cfg(feature = "workspace-laws")]

use magma_config::Config;

fn concentrator_cfg() -> Config {
    let raw = include_str!("fixtures/example-eks-concentrator.rendered.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("rendered config parses");
    Config::from_json(v).expect("Config::from_json on the rendered config")
}

/// Pins the live failure. Reproduces the operator's own call, not a
/// hand-rolled approximation of it.
#[test]
fn concentrator_preflight_is_clean() {
    let cfg = concentrator_cfg();
    let violations = magma_test_laws::preflight::check_workspace_full(&cfg);
    assert!(
        violations.is_empty(),
        "preflight reported {} violation(s):\n{}",
        violations.len(),
        violations
            .iter()
            .map(|v| format!("  {}: {}", v.law, v.message))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
