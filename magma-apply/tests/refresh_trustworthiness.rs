//! Regression suite: a plan-time refresh that learned NOTHING must never
//! be publishable as "reality matched".
//!
//! # The bug
//!
//! `refresh_state` never drops state on uncertainty — a provider it cannot
//! spawn, a schema it cannot find, an RPC that fails, all keep the instance
//! unchanged and count it `kept_on_error`. Correct behavior, with one
//! consequence: when EVERY read fails, state comes out byte-identical, the
//! plan built from it is all-`NoOp`, and that is bit-indistinguishable from
//! a refresh in which reality genuinely matched desired state.
//!
//! `RefreshReport` knew the difference and was thrown away — printed to
//! stderr by the CLI, reduced to `.is_some()` by the operator. So under a
//! provider outage or an expired credential, magma reported "everything is
//! fine" having learned nothing.
//!
//! # What these tests pin
//!
//! The two cases are DIFFERENT VALUES of a type a consumer must match on,
//! they survive into the persisted artifact, and telling them apart costs
//! no counter-reading — while `PlanId` stays byte-stable across both, which
//! is the property the whole design is built to protect.

use std::collections::HashSet;

use magma_apply::engine::{ApplyContext, RefreshReport, refresh_then_plan};
use magma_types::{
    Action, Coverage, DriftVerdict, InstanceStatus, ModulePath, Observation, Plan,
    ProviderReference, ResourceAddress, ResourceKind, ResourceTypeId, State, StateInstance,
    StateResource,
};

/// A config + state pair that agree exactly: every resource plans `NoOp`.
/// The shape of a clean reconcile — and, identically, the shape of a
/// reconcile in which nothing could be read.
fn agreeing_config_and_state(n: usize) -> (magma_config::Config, State) {
    let mut resources = serde_json::Map::new();
    let mut state_resources = Vec::new();
    for i in 0..n {
        let name = ResourceName::of(i);
        resources.insert(
            name.0.clone(),
            serde_json::json!({ "name": name.0.clone() }),
        );
        state_resources.push(StateResource {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId("github_repository".into()),
                name: name.0.clone(),
                key: None,
            },
            provider: ProviderReference {
                source: "integrations/github".into(),
                name: "github".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: serde_json::json!({ "name": name.0.clone() }),
                sensitive_attribute_paths: Vec::new(),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        });
    }
    let cfg = magma_config::Config::from_json(serde_json::json!({
        "resource": { "github_repository": serde_json::Value::Object(resources) }
    }))
    .expect("fixture config parses");
    let state = State {
        version: 4,
        terraform_version: "1.9.0".into(),
        serial: 1,
        lineage: uuid::Uuid::nil(),
        outputs: Default::default(),
        resources: state_resources,
    };
    (cfg, state)
}

/// Typed fixture name — keeps the `format!()`-free rule honest without
/// reaching for string composition in the test body.
struct ResourceName(String);
impl ResourceName {
    fn of(i: usize) -> Self {
        let mut s = String::from("repo_");
        s.push_str(&i.to_string());
        Self(s)
    }
}

/// The persisted shape of a plan, minus the one field that is deliberately
/// wall-clock: what a consumer actually reads back out of a store.
fn persisted(plan: &Plan) -> serde_json::Value {
    let mut v = serde_json::to_value(plan).expect("a Plan serializes");
    if let Some(obj) = v.as_object_mut() {
        obj.remove("created_at");
    }
    v
}

/// Run a REAL refresh with no provider reachable: every `ReadResource`
/// fails, state survives untouched, the plan comes out all-`NoOp`. This is
/// the production code path, not a mock.
async fn blind_refresh_then_plan(n: usize) -> (Plan, RefreshReport) {
    // SAFETY: single-threaded test; no other thread reads this var.
    unsafe { std::env::remove_var("MAGMA_PROVIDER_DIR") };
    let (cfg, mut state) = agreeing_config_and_state(n);
    let td = tempfile::tempdir().expect("tempdir");
    let ctx = ApplyContext::new(td.path().to_path_buf());
    let (plan, report) = refresh_then_plan(&cfg, &mut state, Some(&ctx))
        .await
        .expect("plan computes even when every read fails");
    let report = report.expect("ctx = Some(_) must produce a refresh report");
    // Precondition of the whole suite: this really is the blind case.
    assert_eq!(
        report.kept_on_error, n,
        "fixture must produce a TOTAL read failure, not a partial one",
    );
    assert_eq!(report.refreshed, 0, "no read may have succeeded");
    assert_eq!(state.resources.len(), n, "state untouched on uncertainty");
    assert!(
        plan.resource_changes
            .iter()
            .all(|c| c.action == Action::NoOp),
        "the fixture must produce the all-NoOp shape that looks like a clean reconcile",
    );
    (plan, report)
}

// ── THE regression test ────────────────────────────────────────────

/// **The bug's regression test.** Two plans over the same world, both
/// all-`NoOp`, both "no drift" to the naked eye:
///
/// * A — every `ReadResource` failed. Magma learned nothing.
/// * B — every `ReadResource` succeeded and reality matched.
///
/// Before the fix these were the same artifact. They must not be.
#[tokio::test]
async fn a_fully_failed_refresh_is_distinguishable_from_a_clean_no_drift_observation() {
    let n = 5;
    let (blind_plan, blind_report) = blind_refresh_then_plan(n).await;

    // The control: the same plan, had every read succeeded. Same changes,
    // same state, same everything — only the observation differs.
    let clean_plan = blind_plan.clone().with_observation(Observation::of(
        RefreshReport {
            refreshed: n,
            ..RefreshReport::default()
        }
        .into(),
    ));

    // 1. The artifact that SURVIVES carries the difference. A consumer
    //    reading a stored plan out of Postgres can tell them apart without
    //    ever having seen stderr.
    assert_ne!(
        persisted(&blind_plan),
        persisted(&clean_plan),
        "a blind observation and a clean one must not persist as the same artifact",
    );

    // 2. The difference is a TYPE a consumer must match on, not a counter
    //    they have to know to inspect.
    assert_eq!(blind_plan.observation.coverage(), Coverage::Blind);
    assert_eq!(clean_plan.observation.coverage(), Coverage::Complete);

    // 3. The question that matters gets the honest answer. The blind plan
    //    REFUSES to claim reality matched; the clean one claims it, and
    //    carries the subject set it checked.
    assert!(
        !blind_plan.drift_verdict().is_confirmed_in_sync(),
        "a plan that learned nothing must never report a clean bill of health",
    );
    assert!(matches!(
        blind_plan.drift_verdict(),
        DriftVerdict::Unobserved {
            coverage: Coverage::Blind,
            changes: 0,
            in_sync: 5,
        },
    ));
    assert_eq!(
        clean_plan.drift_verdict(),
        DriftVerdict::InSync { in_sync: n },
    );

    // 4. The raw accounting survives too, for the operator who wants it.
    assert_eq!(blind_plan.observation.counts().kept_on_error, n);
    assert_eq!(blind_report.kept_on_error, n);
}

/// The property the whole design is built to protect, pinned against the
/// change that most threatens it: `PlanId` must NOT move when the
/// observation does.
///
/// Two observations of an unchanged world hash equal — that is what lets a
/// restart recognize a plan it already computed, and it is what `tofu plan
/// -refresh-only -json` cannot do because it embeds timestamps. A refresh
/// stat inside the digest would mint a "new plan" on every transient RPC
/// failure and destroy the property.
#[tokio::test]
async fn plan_id_is_invariant_under_the_observation() {
    let (blind_plan, _) = blind_refresh_then_plan(3).await;
    let before = blind_plan.id;

    let mut ids = HashSet::new();
    for counts in [
        Observation::unrefreshed(),
        Observation::of(RefreshReport::default().into()),
        Observation::of(
            RefreshReport {
                refreshed: 3,
                ..RefreshReport::default()
            }
            .into(),
        ),
        Observation::of(
            RefreshReport {
                refreshed: 1,
                kept_on_error: 2,
                ..RefreshReport::default()
            }
            .into(),
        ),
        Observation::of(
            RefreshReport {
                kept_on_error: 3,
                ..RefreshReport::default()
            }
            .into(),
        ),
    ] {
        ids.insert(blind_plan.clone().with_observation(counts).id);
    }
    assert_eq!(
        ids.len(),
        1,
        "the observation must never perturb PlanId — transient RPC weather \
         would otherwise mint a new plan id on every flaky read",
    );
    assert!(ids.contains(&before));
}

/// A refresh that could not reach a provider is `Blind`, never `Complete`
/// — asserted against the REAL refresh path rather than a synthesized
/// report, so the wiring is what is under test.
#[tokio::test]
async fn the_real_refresh_path_stamps_the_plan_it_produces() {
    let (plan, _) = blind_refresh_then_plan(2).await;
    assert!(
        !plan.observation.is_unrefreshed(),
        "refresh_then_plan ran a refresh — the plan must not claim otherwise",
    );
    assert!(plan.observation.is_blind());
}

/// `ctx = None` means no refresh ran, and the plan must say exactly that
/// — not "complete over an empty probe set", which would be the vacuous
/// round-up.
#[tokio::test]
async fn skipping_the_refresh_is_recorded_as_unrefreshed() {
    let (cfg, mut state) = agreeing_config_and_state(2);
    let (plan, report) = refresh_then_plan(&cfg, &mut state, None).await.unwrap();
    assert!(report.is_none());
    assert!(plan.observation.is_unrefreshed());
    assert!(
        !plan.drift_verdict().is_confirmed_in_sync(),
        "an unrefreshed plan compares config against REMEMBERED state; it \
         has no standing to claim reality matched",
    );
}

/// The counts partition the subject set: every instance the refresh
/// considered lands in exactly one bucket. `probed()` is what makes
/// `Blind` distinguishable from `Vacuous`, so the partition is load-bearing
/// rather than decorative.
#[tokio::test]
async fn the_refresh_counts_partition_every_probed_instance() {
    let n = 4;
    let (plan, report) = blind_refresh_then_plan(n).await;
    let counts = plan.observation.counts();
    assert_eq!(
        counts.probed(),
        n,
        "refreshed + dropped_instances + kept_on_error must equal the instances considered",
    );
    assert_eq!(counts.answered(), 0);
    assert_eq!(counts.refreshed, report.refreshed);
    assert_eq!(counts.kept_on_error, report.kept_on_error);
}
