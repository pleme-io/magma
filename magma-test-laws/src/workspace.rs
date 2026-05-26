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
        outcome.failed.len(),
        outcome.failed,
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
        non_noop.len(),
        non_noop,
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
        visible,
        expected,
        "Workspace law violated: apply enumeration drift — plan had {expected} changes, outcome has {visible} ({} applied + {} failed)",
        outcome.applied.len(),
        outcome.failed.len(),
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
        p.resource_changes.len(),
        state.serial,
    );
}

// ── Law 6: import absorbs externally-discovered resources ──────────

/// Given a state seeded with externally-discovered resources whose
/// addresses match declarations in `cfg`, planning produces NO
/// Create actions for those addresses. This is the "tofu import"
/// + magma-discover adoption flow: when an operator imports a
/// live resource into the typed state, the next plan must absorb
/// it (treating it as managed), not propose to re-create it.
///
/// `seed_state_with` is invoked once with a fresh empty State so
/// the caller can populate it with whatever import simulation
/// shape they want (e.g. a single aws_iam_role with id "node").
/// The function then asserts the planner sees no Create for the
/// resources the seed inserted.
pub fn assert_import_absorbs(cfg: &Config, seed_state_with: impl FnOnce(&mut magma_types::State)) {
    let mut state = empty_state();
    seed_state_with(&mut state);
    let seeded_addresses: std::collections::HashSet<String> = state
        .resources
        .iter()
        .map(|r| format!("{}.{}", r.address.type_id.0, r.address.name))
        .collect();
    if seeded_addresses.is_empty() {
        return; // vacuously satisfied
    }
    let p = plan(cfg, &state).expect("plan against seeded state failed");
    for change in &p.resource_changes {
        let addr = format!("{}.{}", change.address.type_id.0, change.address.name);
        if seeded_addresses.contains(&addr) {
            assert!(
                !matches!(change.action, Action::Create),
                "Workspace law violated: import absorption failed — imported {addr} planned as Create (should be NoOp or Update)",
            );
        }
    }
}

// ── Composite ─────────────────────────────────────────────────────

/// Run every workspace lifecycle law. Panics on the first violation
/// with a clear message naming the broken law.
///
/// Does NOT include `assert_import_absorbs` — that one is opt-in
/// because it requires the caller to provide a seed function for
/// the imported resources.
pub fn assert_all_laws(cfg: &Config) {
    assert_plan_deterministic(cfg);
    assert_apply_enumerates_all_changes(cfg);
    assert_apply_converges(cfg);
    assert_apply_bumps_serial(cfg);
    assert_destroy_round_trip(cfg);
}

// ── Proptest strategy: random Pangea-shaped workspaces ────────────

/// Generate a random architecturally-valid Pangea workspace shape.
/// Returns a `Config` parsed from synthesized JSON with:
/// * 1-3 random providers in `terraform.required_providers`
/// * 1-6 resources whose types match a declared provider
/// * 0-3 outputs referencing existing resource attributes
///
/// Every generated shape passes
/// `architecture::assert_no_dangling_references` by construction.
/// Useful for proptest-based exploration of the law battery's
/// robustness against arbitrary shapes.
///
/// Requires the `strategies` feature (in addition to `workspace-laws`).
#[cfg(feature = "strategies")]
pub fn arb_workspace_config() -> impl proptest::prelude::Strategy<Value = Config> {
    use proptest::prelude::*;
    use serde_json::{Map, Value, json};

    // Canonical providers + the resource types Pangea emits for each.
    // Kept small to keep the proptest fast; the structure matters
    // more than coverage.
    let providers: &[(&str, &str, &[&str])] = &[
        (
            "aws",
            "hashicorp/aws",
            &["aws_vpc", "aws_subnet", "aws_iam_role"],
        ),
        (
            "cloudflare",
            "cloudflare/cloudflare",
            &["cloudflare_zone", "cloudflare_record"],
        ),
        (
            "kubernetes",
            "hashicorp/kubernetes",
            &["kubernetes_namespace", "kubernetes_service_account"],
        ),
        ("datadog", "datadog/datadog", &["datadog_monitor"]),
        ("tailscale", "tailscale/tailscale", &["tailscale_acl"]),
    ];

    // Pick 1-3 providers, then for each provider pick 1-N resource types.
    let provider_indices =
        proptest::collection::vec(0..providers.len(), 1..=3).prop_map(|mut v| {
            v.sort();
            v.dedup();
            v
        });

    (
        provider_indices,
        proptest::collection::vec("[a-z][a-z0-9_]{0,7}", 1..=6),
    )
        .prop_map(move |(provider_ids, names)| {
            let mut required_providers = Map::new();
            let mut provider_block = Map::new();
            let mut resource_block = Map::new();
            let mut all_addresses = vec![];

            for &pid in &provider_ids {
                let (pname, psource, ptypes) = providers[pid];
                required_providers.insert(pname.into(), json!({ "source": psource }));
                provider_block.insert(pname.into(), json!({}));

                // For each name, deterministically pick a type
                // based on the name's first char.
                for (i, name) in names.iter().enumerate() {
                    let type_id = ptypes[(i + pid) % ptypes.len()];
                    let type_bucket = resource_block
                        .entry(type_id.to_string())
                        .or_insert_with(|| Value::Object(Map::new()))
                        .as_object_mut()
                        .unwrap();
                    type_bucket.insert(format!("{name}_{pid}"), json!({}));
                    all_addresses.push((type_id.to_string(), format!("{name}_{pid}")));
                }
            }

            let mut top = Map::new();
            top.insert(
                "terraform".into(),
                json!({
                    "required_providers": required_providers,
                }),
            );
            top.insert("provider".into(), Value::Object(provider_block));
            top.insert("resource".into(), Value::Object(resource_block));

            // 0-3 outputs that reference existing addresses (no dangling).
            if !all_addresses.is_empty() {
                let mut output_block = Map::new();
                for (i, (ty, name)) in all_addresses.iter().take(3).enumerate() {
                    output_block.insert(
                        format!("out_{i}"),
                        json!({ "value": format!("${{{ty}.{name}.id}}") }),
                    );
                }
                top.insert("output".into(), Value::Object(output_block));
            }

            Config::from_json(Value::Object(top)).expect("synth produced invalid Config")
        })
}
