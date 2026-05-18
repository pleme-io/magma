//! magma-metrics — typed Prometheus metrics the convergence
//! substrate emits.
//!
//! Closes the loop with `pleme-reconciler.prometheusRule` in
//! helmworks — that PrometheusRule alerts on
//! `magma_drift_classified_total{kind, severity}`. This crate
//! is the canonical source of those metrics.
//!
//! Every reconciler kind gets the same metric shape; consumers
//! create one `Metrics` once and share via `Arc`. Reconcilers
//! report via `metrics.record_plan(...)`,
//! `metrics.record_drift_classification(...)`,
//! `metrics.record_apply_outcome(...)`.
//!
//! Designed to be drop-in for any consumer that already owns a
//! `prometheus::Registry`. `Metrics::register(registry)` returns
//! a typed handle.

#![deny(unsafe_code)]

use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry,
};
use thiserror::Error;

use magma_converge::{ChangeSeverity, Outcome, Plan};
use magma_drift::{DriftDecision, DriftReport};

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("prometheus: {0}")]
    Prometheus(#[from] prometheus::Error),
}

/// Typed metrics handle. Construct once per process via
/// `Metrics::register(&registry)`; share via `Arc<Metrics>`.
pub struct Metrics {
    /// `magma_plan_computed_total{kind}` — every successful
    /// `compute_plan` increments. Plans with zero changes count
    /// too (operators want to know reconcile attempts, not just
    /// applies).
    pub plans_computed_total: IntCounterVec,

    /// `magma_plan_changes_total{kind, action}` — per-action
    /// counter (Create / Update / Delete / Replace / NoOp). NoOp
    /// emissions are reported separately so operators can spot
    /// "every reconcile diffs but never converges" patterns.
    pub plan_changes_total: IntCounterVec,

    /// `magma_drift_classified_total{kind, severity}` — load-bearing
    /// metric the helmworks PrometheusRule alerts on. Incremented
    /// per Change emitted by `magma_drift::classify`.
    pub drift_classified_total: IntCounterVec,

    /// `magma_drift_decisions_total{kind, decision}` — counter
    /// keyed by drift policy decision (auto_correct /
    /// auto_correct_with_alert / require_approval / refuse).
    pub drift_decisions_total: IntCounterVec,

    /// `magma_apply_outcome_total{kind, result}` — apply lifecycle
    /// counter. result ∈ {applied, failed, partial}.
    pub apply_outcome_total: IntCounterVec,

    /// `magma_apply_resources_total{kind, status}` — per-resource
    /// counter from each apply. status ∈ {applied, failed}.
    pub apply_resources_total: IntCounterVec,

    /// `magma_apply_duration_seconds{kind}` — apply latency. Wide
    /// buckets because apply latencies span ms (no-op) to
    /// minutes (real cloud calls).
    pub apply_duration_seconds: HistogramVec,

    /// `magma_in_flight_applies{kind}` — gauge of currently
    /// in-flight applies per kind. Pairs with magma-budget's
    /// ConcurrencyLimit so operators can see "are we hitting the
    /// concurrency cap?".
    pub in_flight_applies: IntGaugeVec,
}

impl Metrics {
    /// Build + register every metric on the given Prometheus
    /// registry. Returns the typed handle.
    pub fn register(registry: &Registry) -> Result<Self, MetricsError> {
        let plans_computed_total = IntCounterVec::new(
            Opts::new("magma_plan_computed_total", "magma — total compute_plan invocations per reconciler kind"),
            &["kind"],
        )?;
        registry.register(Box::new(plans_computed_total.clone()))?;

        let plan_changes_total = IntCounterVec::new(
            Opts::new("magma_plan_changes_total", "magma — typed change count per (kind, action) emitted by compute_plan"),
            &["kind", "action"],
        )?;
        registry.register(Box::new(plan_changes_total.clone()))?;

        let drift_classified_total = IntCounterVec::new(
            Opts::new("magma_drift_classified_total", "magma — drift-classification count per (kind, severity)"),
            &["kind", "severity"],
        )?;
        registry.register(Box::new(drift_classified_total.clone()))?;

        let drift_decisions_total = IntCounterVec::new(
            Opts::new("magma_drift_decisions_total", "magma — drift-policy decisions per (kind, decision)"),
            &["kind", "decision"],
        )?;
        registry.register(Box::new(drift_decisions_total.clone()))?;

        let apply_outcome_total = IntCounterVec::new(
            Opts::new("magma_apply_outcome_total", "magma — apply lifecycle outcomes per (kind, result)"),
            &["kind", "result"],
        )?;
        registry.register(Box::new(apply_outcome_total.clone()))?;

        let apply_resources_total = IntCounterVec::new(
            Opts::new("magma_apply_resources_total", "magma — per-resource apply outcomes per (kind, status)"),
            &["kind", "status"],
        )?;
        registry.register(Box::new(apply_resources_total.clone()))?;

        let apply_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "magma_apply_duration_seconds",
                "magma — apply latency in seconds per reconciler kind",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0,
            ]),
            &["kind"],
        )?;
        registry.register(Box::new(apply_duration_seconds.clone()))?;

        let in_flight_applies = IntGaugeVec::new(
            Opts::new("magma_in_flight_applies", "magma — current in-flight applies per reconciler kind"),
            &["kind"],
        )?;
        registry.register(Box::new(in_flight_applies.clone()))?;

        Ok(Self {
            plans_computed_total,
            plan_changes_total,
            drift_classified_total,
            drift_decisions_total,
            apply_outcome_total,
            apply_resources_total,
            apply_duration_seconds,
            in_flight_applies,
        })
    }

    /// Record a Plan into the typed counters. Increments
    /// plans_computed_total + plan_changes_total per action.
    pub fn record_plan(&self, plan: &Plan) {
        self.plans_computed_total
            .with_label_values(&[&plan.kind])
            .inc();
        for change in &plan.changes {
            self.plan_changes_total
                .with_label_values(&[&plan.kind, action_label(change.action)])
                .inc();
        }
    }

    /// Record a DriftReport into typed counters.
    /// Increments drift_classified_total + drift_decisions_total.
    pub fn record_drift(&self, report: &DriftReport) {
        for event in &report.events {
            self.drift_classified_total
                .with_label_values(&[&report.kind, severity_label(event.severity)])
                .inc();
            self.drift_decisions_total
                .with_label_values(&[&report.kind, decision_label(event.decision)])
                .inc();
        }
    }

    /// Record an Outcome into typed counters + the apply duration
    /// histogram.
    pub fn record_outcome(&self, outcome: &Outcome) {
        let result = if outcome.failed.is_empty() && !outcome.applied.is_empty() {
            "applied"
        } else if outcome.applied.is_empty() && !outcome.failed.is_empty() {
            "failed"
        } else if !outcome.applied.is_empty() && !outcome.failed.is_empty() {
            "partial"
        } else {
            // Both empty — a NoOp-only plan that landed. Count as
            // a non-changing "applied" so operators see successful
            // reconciles.
            "applied"
        };
        self.apply_outcome_total
            .with_label_values(&[&outcome.kind, result])
            .inc();
        for ac in &outcome.applied {
            self.apply_resources_total
                .with_label_values(&[&outcome.kind, "applied"])
                .inc_by(0u64);
            let _ = ac; // already counted via outcome.applied.len() / actions
        }
        // Resource-level: one inc per applied + failed.
        self.apply_resources_total
            .with_label_values(&[&outcome.kind, "applied"])
            .inc_by(outcome.applied.len() as u64);
        self.apply_resources_total
            .with_label_values(&[&outcome.kind, "failed"])
            .inc_by(outcome.failed.len() as u64);

        let duration = (outcome.finished_at - outcome.started_at)
            .num_milliseconds()
            .max(0) as f64
            / 1000.0;
        self.apply_duration_seconds
            .with_label_values(&[&outcome.kind])
            .observe(duration);
    }

    /// Increment the in-flight gauge before an apply; decrement
    /// after. Pair these with the budget's semaphore so the gauge
    /// matches reality.
    pub fn apply_started(&self, kind: &str) {
        self.in_flight_applies.with_label_values(&[kind]).inc();
    }

    /// Pair with `apply_started`.
    pub fn apply_finished(&self, kind: &str) {
        self.in_flight_applies.with_label_values(&[kind]).dec();
    }
}

// ── Label helpers ─────────────────────────────────────────────────

fn action_label(a: magma_converge::Action) -> &'static str {
    match a {
        magma_converge::Action::Create  => "create",
        magma_converge::Action::Update  => "update",
        magma_converge::Action::Delete  => "delete",
        magma_converge::Action::Replace => "replace",
        magma_converge::Action::NoOp    => "noop",
    }
}

fn severity_label(s: ChangeSeverity) -> &'static str {
    match s {
        ChangeSeverity::Cosmetic   => "cosmetic",
        ChangeSeverity::Functional => "functional",
        ChangeSeverity::Critical   => "critical",
    }
}

fn decision_label(d: DriftDecision) -> &'static str {
    match d {
        DriftDecision::AutoCorrect          => "auto_correct",
        DriftDecision::AutoCorrectWithAlert => "auto_correct_with_alert",
        DriftDecision::RequireApproval      => "require_approval",
        DriftDecision::Refuse               => "refuse",
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_converge::{change, change_with_severity, Action, AppliedChange, FailedChange};
    use magma_drift::{classify, DriftPolicy};
    use prometheus::Encoder;
    use serde_json::json;

    fn fresh() -> (Registry, Metrics) {
        let registry = Registry::new();
        let metrics = Metrics::register(&registry).unwrap();
        (registry, metrics)
    }

    fn render(registry: &Registry) -> String {
        let encoder = prometheus::TextEncoder::new();
        let mfs = registry.gather();
        let mut buf = vec![];
        encoder.encode(&mfs, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn registration_succeeds() {
        let (_registry, _metrics) = fresh();
    }

    #[test]
    fn double_registration_in_same_registry_errors() {
        let registry = Registry::new();
        Metrics::register(&registry).unwrap();
        let second = Metrics::register(&registry);
        assert!(second.is_err());
    }

    #[test]
    fn record_plan_increments_typed_counters() {
        let (registry, metrics) = fresh();
        let plan = Plan::new("github_repo", vec![
            change("github_repo.a", Action::Create, None, Some(json!({}))),
            change("github_repo.b", Action::Update, Some(json!({})), Some(json!({}))),
            change("github_repo.c", Action::Delete, Some(json!({})), None),
            change("github_repo.d", Action::NoOp, None, None),
        ]);
        metrics.record_plan(&plan);

        let text = render(&registry);
        assert!(text.contains(r#"magma_plan_computed_total{kind="github_repo"} 1"#));
        assert!(text.contains(r#"magma_plan_changes_total{action="create",kind="github_repo"} 1"#));
        assert!(text.contains(r#"magma_plan_changes_total{action="update",kind="github_repo"} 1"#));
        assert!(text.contains(r#"magma_plan_changes_total{action="delete",kind="github_repo"} 1"#));
        assert!(text.contains(r#"magma_plan_changes_total{action="noop",kind="github_repo"} 1"#));
    }

    #[test]
    fn record_drift_emits_severity_and_decision_counters() {
        let (registry, metrics) = fresh();
        let plan = Plan::new("dns_record", vec![
            change_with_severity("dns_record:a", Action::Update, ChangeSeverity::Functional,
                Some(json!({})), Some(json!({}))),
            change_with_severity("dns_record:b", Action::Delete, ChangeSeverity::Critical,
                Some(json!({})), None),
        ]);
        let report = classify(&plan, &DriftPolicy::conservative_default());
        metrics.record_drift(&report);

        let text = render(&registry);
        // Severity counters
        assert!(text.contains(r#"magma_drift_classified_total{kind="dns_record",severity="functional"} 1"#));
        assert!(text.contains(r#"magma_drift_classified_total{kind="dns_record",severity="critical"} 1"#));
        // Decision counters
        assert!(text.contains(r#"magma_drift_decisions_total{decision="auto_correct_with_alert",kind="dns_record"} 1"#));
        assert!(text.contains(r#"magma_drift_decisions_total{decision="require_approval",kind="dns_record"} 1"#));
    }

    #[test]
    fn record_outcome_emits_result_and_duration() {
        let (registry, metrics) = fresh();
        let outcome = Outcome {
            plan_id:     magma_converge::PlanId("p1".into()),
            kind:        "helm_release".into(),
            applied:     vec![AppliedChange { address: "x".into(), action: Action::Create }],
            failed:      vec![],
            started_at:  chrono::Utc::now() - chrono::Duration::milliseconds(200),
            finished_at: chrono::Utc::now(),
        };
        metrics.record_outcome(&outcome);

        let text = render(&registry);
        assert!(text.contains(r#"magma_apply_outcome_total{kind="helm_release",result="applied"} 1"#));
        assert!(text.contains(r#"magma_apply_resources_total{kind="helm_release",status="applied"} 1"#));
        // Duration histogram observed at least once.
        assert!(text.contains(r#"magma_apply_duration_seconds_count{kind="helm_release"} 1"#));
    }

    #[test]
    fn outcome_with_failures_is_partial() {
        let (registry, metrics) = fresh();
        let outcome = Outcome {
            plan_id:     magma_converge::PlanId("p1".into()),
            kind:        "vault_policy".into(),
            applied:     vec![AppliedChange { address: "a".into(), action: Action::Create }],
            failed:      vec![FailedChange { address: "b".into(), action: Action::Update, error: "oops".into() }],
            started_at:  chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };
        metrics.record_outcome(&outcome);
        let text = render(&registry);
        assert!(text.contains(r#"magma_apply_outcome_total{kind="vault_policy",result="partial"} 1"#));
    }

    #[test]
    fn outcome_with_only_failures_is_failed() {
        let (registry, metrics) = fresh();
        let outcome = Outcome {
            plan_id:     magma_converge::PlanId("p1".into()),
            kind:        "terraform".into(),
            applied:     vec![],
            failed:      vec![FailedChange { address: "x".into(), action: Action::Create, error: "boom".into() }],
            started_at:  chrono::Utc::now(),
            finished_at: chrono::Utc::now(),
        };
        metrics.record_outcome(&outcome);
        let text = render(&registry);
        assert!(text.contains(r#"magma_apply_outcome_total{kind="terraform",result="failed"} 1"#));
    }

    #[test]
    fn in_flight_gauge_pairs_increment_and_decrement() {
        let (registry, metrics) = fresh();
        metrics.apply_started("inmemory_kv");
        metrics.apply_started("inmemory_kv");
        let text = render(&registry);
        assert!(text.contains(r#"magma_in_flight_applies{kind="inmemory_kv"} 2"#));

        metrics.apply_finished("inmemory_kv");
        let text2 = render(&registry);
        assert!(text2.contains(r#"magma_in_flight_applies{kind="inmemory_kv"} 1"#));
    }

    #[test]
    fn metric_names_match_helmworks_prometheus_rule_expectations() {
        // Locks in the contract with helmworks/charts/pleme-reconciler.
        // If a metric name changes here, the PrometheusRule
        // breaks silently in prod — this test fails first.
        let (registry, metrics) = fresh();
        let plan = Plan::new("test_kind", vec![
            change_with_severity("test_kind.x", Action::Update, ChangeSeverity::Critical,
                Some(json!({})), Some(json!({}))),
        ]);
        let report = classify(&plan, &DriftPolicy::conservative_default());
        metrics.record_drift(&report);
        let text = render(&registry);
        // pleme-reconciler.prometheusRule queries this exact metric name + labels.
        assert!(text.contains(r#"magma_drift_classified_total{kind="test_kind",severity="critical"} 1"#));
    }
}
