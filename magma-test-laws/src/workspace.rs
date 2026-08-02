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
    //
    // `Read` is settled work, not pending work. A data source is READ on every
    // plan by definition — it has no state row to converge into, so it can
    // never become a NoOp. Counting it as unconverged makes this law
    // unsatisfiable for any workspace containing a `data` block.
    //
    // This mattered the moment `Action::Read` became a thing magma actually
    // EMITS. Before 3de7bbb, `magma_plan::plan` never constructed `Read` at all
    // — an unread data source came out as `Create`, so this filter only ever
    // saw managed-resource actions and "non-NoOp" was a fine proxy for "work
    // remaining". Making data sources honest turned that proxy false.
    //
    // Measured 2026-08-01 on example-eks-vpn-concentrator: the apply failed
    // with "re-plan has 4 non-NoOp changes", and all four were
    // `kind: Data, action: Read` — the workspace's aws_vpc / aws_subnet /
    // aws_network_acl / aws_ssm_parameter lookups. Nothing was unconverged;
    // the law was counting reads as debt.
    //
    // Deliberately matched on the ACTION rather than `address.kind == Data`:
    // the law is about whether the plan still has work to do, and a `Read` is
    // not work whatever it is attached to. Delete/Forget on a data ORPHAN stays
    // counted — that IS pending work (dropping it from state).
    let non_noop: Vec<_> = p2
        .resource_changes
        .iter()
        .filter(|c| !matches!(c.action, Action::NoOp | Action::Read))
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

// ── Law 7: the import prepass absorbs through an ImportEnvironment ──

/// Given any `ImportEnvironment` impl and an explicit
/// `address → import-id` directive map, the import prepass:
///
///   1. absorbs each hinted resource into state (Create-free plan after);
///   2. is idempotent — a second prepass over the same state absorbs
///      nothing new and issues no further imports;
///   3. isolates per-resource failures into typed `FailedImport`s
///      rather than aborting.
///
/// This is the universal contract every real provider-backed
/// `ImportEnvironment` (and any future mock) satisfies. `make_env`
/// builds the environment fresh; `good` is an address→id pair the
/// environment imports successfully; `bad` is an address→id pair the
/// environment rejects (so the failure-isolation arm is exercised).
///
/// The helper is async because the prepass drives async RPC. Call it
/// from a `#[tokio::test]`.
pub async fn assert_import_prepass_absorbs<E, F>(make_env: F, good: (&str, &str), bad: (&str, &str))
where
    E: magma_apply::import_prepass::ImportEnvironment,
    F: Fn() -> E,
{
    use magma_apply::run_explicit_prepass;
    use magma_types::ImportDirectives;

    // ── Sub-law 1: a good hint absorbs ──
    let env = make_env();
    let directives = ImportDirectives::default().with_explicit(good.0, good.1);
    let mut state = empty_state();
    let outcome = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("import prepass structural failure");
    assert_eq!(
        outcome.newly_absorbed(),
        1,
        "Workspace law violated: import prepass didn't absorb the good hint {good:?} — {outcome:?}",
    );
    assert!(
        outcome.all_succeeded(),
        "Workspace law violated: good-hint prepass reported failures — {outcome:?}",
    );

    // ── Sub-law 2: idempotent re-run ──
    let second = run_explicit_prepass(&env, &directives, &mut state)
        .await
        .expect("idempotent re-run structural failure");
    assert_eq!(
        second.newly_absorbed(),
        0,
        "Workspace law violated: import prepass is not idempotent — second run absorbed {} — {second:?}",
        second.newly_absorbed(),
    );

    // ── Sub-law 3: per-resource failure isolation ──
    let env2 = make_env();
    let mixed = ImportDirectives::default()
        .with_explicit(good.0, good.1)
        .with_explicit(bad.0, bad.1);
    let mut state2 = empty_state();
    let outcome2 = run_explicit_prepass(&env2, &mixed, &mut state2)
        .await
        .expect("mixed prepass must not abort on a per-resource failure");
    assert_eq!(
        outcome2.newly_absorbed(),
        1,
        "Workspace law violated: the good hint must still absorb when a sibling fails — {outcome2:?}",
    );
    assert_eq!(
        outcome2.failed.len(),
        1,
        "Workspace law violated: the bad hint must be a typed FailedImport — {outcome2:?}",
    );
    assert_eq!(
        outcome2.failed[0].address, bad.0,
        "Workspace law violated: the FailedImport names the wrong address — {outcome2:?}",
    );
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
