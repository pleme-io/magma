//! Reusable workspace lifecycle laws.
//!
//! A workspace is one state-boundary in Pangea — one rendered
//! Terraform JSON + one state file. The "lifecycle" is the typed
//! sequence:
//!
//!   read_state → plan → apply → re-read → re-plan (must be no-op)
//!                       │
//!                       └─→ destroy_plan → run_destroy → state empty
//!
//! These helpers run the lifecycle in memory against `magma_state`'s
//! empty backing + `magma_apply::run_plan`, no cloud / filesystem
//! involvement. Every Pangea-rendered workspace can call
//! `assert_workspace_lifecycle(&cfg)` and gain the full lifecycle
//! contract.
//!
//! Gated behind `workspace-laws`.

use magma_apply::run_plan;
use magma_config::Config;
use magma_plan::plan;
use magma_state::empty_state;
use magma_types::Action;

// ── Law 1: plan(cfg, empty_state) is deterministic ────────────────

/// Two calls to `plan(cfg, state)` against the SAME state value
/// yield the same PlanId. The bytes of the PlanId are the typed
/// attestation identifier.
pub fn assert_plan_deterministic(cfg: &Config) {
    let state = empty_state();
    let a = plan(cfg, &state).expect("plan #1 failed");
    let b = plan(cfg, &state).expect("plan #2 failed");
    assert_eq!(
        a.id, b.id,
        "Workspace law violated: plan(cfg, state) is non-deterministic — got {:?} then {:?}",
        a.id, b.id,
    );
}

// ── Law 2: apply converges ────────────────────────────────────────

/// Plan from empty state → apply → plan again. The second plan
/// must produce zero changes. This is the apply-convergence
/// contract: after `apply`, the system is fixed-point.
pub fn assert_apply_converges(cfg: &Config) {
    let mut state = empty_state();
    let p1 = plan(cfg, &state).expect("initial plan failed");
    let outcome = run_plan(&p1, &mut state).expect("apply failed");
    assert!(
        outcome.failed.is_empty(),
        "Workspace law violated: apply produced {} failures — {:?}",
        outcome.failed.len(), outcome.failed,
    );
    // Re-plan against post-apply state.
    let p2 = plan(cfg, &state).expect("post-apply plan failed");
    let non_noop: Vec<_> = p2
        .resource_changes
        .iter()
        .filter(|c| !matches!(c.action, Action::NoOp))
        .collect();
    assert!(
        non_noop.is_empty(),
        "Workspace law violated: apply didn't converge — re-plan has {} non-NoOp changes: {:?}",
        non_noop.len(), non_noop,
    );
}

// ── Law 3: destroy round-trip ─────────────────────────────────────

/// Apply the workspace, then plan against an EMPTY config — the
/// resulting plan must be all Deletes for the previously-applied
/// resources. Running that destroy plan empties the state.
pub fn assert_destroy_round_trip(cfg: &Config) {
    let mut state = empty_state();
    let p_apply = plan(cfg, &state).expect("apply plan failed");
    let _ = run_plan(&p_apply, &mut state).expect("apply run failed");
    let before_count = state.resources.len();

    // Now plan against empty config + populated state.
    let empty_cfg = Config::default();
    let p_destroy = plan(&empty_cfg, &state).expect("destroy plan failed");
    let destroys = p_destroy
        .resource_changes
        .iter()
        .filter(|c| matches!(c.action, Action::Delete))
        .count();
    assert_eq!(
        destroys, before_count,
        "Workspace law violated: destroy plan should emit Delete for each applied resource — got {} Deletes for {} resources",
        destroys, before_count,
    );

    let _ = run_plan(&p_destroy, &mut state).expect("destroy run failed");
    assert!(
        state.resources.is_empty(),
        "Workspace law violated: destroy didn't empty state — {} resources remain",
        state.resources.len(),
    );
}

// ── Law 4: apply outcome carries every change as applied ──────────

/// `run_plan(plan, state)` must report `applied.len() == plan.change_count()`
/// when the plan is well-formed and the state is consistent. The
/// in-memory engine doesn't fail individual resources, so this
/// catches drift between the plan and the apply enumeration.
pub fn assert_apply_enumerates_all_changes(cfg: &Config) {
    let mut state = empty_state();
    let p = plan(cfg, &state).expect("plan failed");
    let expected = p.resource_changes.len();
    let outcome = run_plan(&p, &mut state).expect("apply failed");
    let visible = outcome.applied.len() + outcome.failed.len();
    assert_eq!(
        visible, expected,
        "Workspace law violated: apply enumeration drift — plan had {expected} changes, outcome has {visible} ({} applied + {} failed)",
        outcome.applied.len(), outcome.failed.len(),
    );
}

// ── Law 5: apply bumps serial ─────────────────────────────────────

/// Successful applies that mutate state advance `state.serial`.
/// (No-op applies don't, per magma-apply's contract.)
pub fn assert_apply_bumps_serial(cfg: &Config) {
    let mut state = empty_state();
    let before = state.serial;
    let p = plan(cfg, &state).expect("plan failed");
    if p.resource_changes.is_empty() {
        return; // vacuously satisfied
    }
    let _ = run_plan(&p, &mut state).expect("apply failed");
    assert!(
        state.serial > before,
        "Workspace law violated: apply with {} changes didn't bump serial (was {before}, still {})",
        p.resource_changes.len(), state.serial,
    );
}

// ── Composite ─────────────────────────────────────────────────────

/// Run every workspace lifecycle law. Panics on the first violation
/// with a clear message naming the broken law.
pub fn assert_all_laws(cfg: &Config) {
    assert_plan_deterministic(cfg);
    assert_apply_enumerates_all_changes(cfg);
    assert_apply_converges(cfg);
    assert_apply_bumps_serial(cfg);
    assert_destroy_round_trip(cfg);
}
