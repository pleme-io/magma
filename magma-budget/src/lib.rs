//! magma-budget — typed concurrency limits + retry policies.
//!
//! Production reconcilers need two things every operator
//! hand-rolls:
//!
//! 1. **Concurrency cap** — don't spam the cloud API with 100
//!    parallel applies. One semaphore at the engine level.
//! 2. **Retry policy** — transient API failures should retry with
//!    typed backoff, not fail the reconcile permanently.
//!
//! This crate packages both as typed wrappers around any
//! `Reconciler`. Wrap once; every call to that reconciler obeys
//! the budget + retry policy.

#![deny(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Semaphore;

use magma_converge::{ApplyMetrics, NoMetrics, Outcome, Plan, Reconciler, ReconcilerError};

// ── ConcurrencyLimit ──────────────────────────────────────────────

/// Caps concurrent `apply` calls against a wrapped reconciler.
/// Backed by `tokio::sync::Semaphore`.
#[derive(Clone)]
pub struct ConcurrencyLimit {
    semaphore: Arc<Semaphore>,
    max: usize,
}

impl ConcurrencyLimit {
    pub fn new(max: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max.max(1))),
            max,
        }
    }

    pub fn max(&self) -> usize {
        self.max
    }

    /// Currently-available permits (max - in_flight).
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

// ── RetryPolicy ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backoff {
    /// Wait the same duration between every retry.
    Constant { delay_ms: u64 },
    /// Each retry waits (n+1) * base_ms.
    Linear { base_ms: u64 },
    /// Each retry waits base_ms * 2^n, capped at max_ms.
    Exponential { base_ms: u64, max_ms: u64 },
}

impl Backoff {
    pub fn duration_for_attempt(&self, attempt: u32) -> Duration {
        let ms: u64 = match self {
            Backoff::Constant { delay_ms } => *delay_ms,
            Backoff::Linear { base_ms } => base_ms.saturating_mul(u64::from(attempt + 1)),
            Backoff::Exponential { base_ms, max_ms } => {
                let raw = base_ms.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX));
                raw.min(*max_ms)
            }
        };
        Duration::from_millis(ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff: Backoff,
    /// If true, `Validation` errors won't be retried (they're
    /// structural — retrying won't help).
    pub skip_validation_errors: bool,
}

impl RetryPolicy {
    /// Conservative default: 3 retries, exponential 100ms → 5s,
    /// skip Validation errors.
    pub fn conservative() -> Self {
        Self {
            max_retries: 3,
            backoff: Backoff::Exponential {
                base_ms: 100,
                max_ms: 5_000,
            },
            skip_validation_errors: true,
        }
    }

    /// No retries — pass-through. Useful for tests.
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            backoff: Backoff::Constant { delay_ms: 0 },
            skip_validation_errors: true,
        }
    }

    /// Decide whether an error is retryable under this policy.
    pub fn should_retry(&self, err: &ReconcilerError) -> bool {
        match err {
            ReconcilerError::Validation(_) if self.skip_validation_errors => false,
            ReconcilerError::Validation(_) => true,
            ReconcilerError::Transient(_) => true,
            // Apply / ComputePlan / ReadState may or may not be
            // transient — retry by default, the inner error string
            // tells the operator.
            ReconcilerError::Apply(_) => true,
            ReconcilerError::ComputePlan(_) => false, // deterministic; retry won't help
            ReconcilerError::ReadState(_) => true,
            ReconcilerError::Other(_) => true,
        }
    }
}

// ── BudgetedReconciler — the wrapper ──────────────────────────────

/// Wraps any `Reconciler` with a concurrency limit + retry policy.
/// Every call obeys both. Optional `metrics` handle (any
/// `ApplyMetrics` impl, including `magma_metrics::Metrics`) auto-
/// emits in_flight gauge ticks at apply boundaries.
pub struct BudgetedReconciler<R: Reconciler> {
    inner: R,
    concurrency: ConcurrencyLimit,
    retry: RetryPolicy,
    metrics: Arc<dyn ApplyMetrics>,
}

impl<R: Reconciler> BudgetedReconciler<R> {
    /// Build without instrumentation. Use `with_metrics` when you
    /// want auto-emitted in_flight gauges.
    pub fn new(inner: R, concurrency: ConcurrencyLimit, retry: RetryPolicy) -> Self {
        Self {
            inner,
            concurrency,
            retry,
            metrics: Arc::new(NoMetrics),
        }
    }

    /// Build with a metrics handle. Every `read_state` / `apply`
    /// call auto-emits `apply_started` / `apply_finished` ticks.
    pub fn with_metrics(
        inner: R,
        concurrency: ConcurrencyLimit,
        retry: RetryPolicy,
        metrics: Arc<dyn ApplyMetrics>,
    ) -> Self {
        Self {
            inner,
            concurrency,
            retry,
            metrics,
        }
    }

    /// Run an async closure with concurrency-limited semantics +
    /// retry + auto-emitted metrics ticks. Used internally for the
    /// trait methods that mutate.
    async fn with_budget<F, Fut, T>(&self, kind: &str, mut op: F) -> Result<T, ReconcilerError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, ReconcilerError>>,
    {
        let _permit = self
            .concurrency
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| ReconcilerError::Other(format!("semaphore closed: {e}")))?;

        // Bump in_flight on entry; decrement on every exit path
        // (success / err / retry-exhaustion) via the RAII guard.
        self.metrics.apply_started(kind);
        let _guard = InFlightGuard {
            metrics: Arc::clone(&self.metrics),
            kind: kind.to_string(),
        };

        let mut last_err: Option<ReconcilerError> = None;
        for attempt in 0..=self.retry.max_retries {
            match op().await {
                Ok(value) => return Ok(value),
                Err(e) => {
                    let should_retry = self.retry.should_retry(&e);
                    last_err = Some(e);
                    if !should_retry || attempt == self.retry.max_retries {
                        break;
                    }
                    let wait = self.retry.backoff.duration_for_attempt(attempt);
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ReconcilerError::Other("no attempts made".into())))
    }
}

/// RAII guard pairing `apply_started` with `apply_finished` so the
/// gauge decrements on every exit path (including panics + early
/// returns from retry exhaustion).
struct InFlightGuard {
    metrics: Arc<dyn ApplyMetrics>,
    kind: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.metrics.apply_finished(&self.kind);
    }
}

#[async_trait]
impl<R: Reconciler> Reconciler for BudgetedReconciler<R> {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        let kind = self.inner.kind();
        self.with_budget(kind, || self.inner.read_state()).await
    }

    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        // compute_plan is pure + synchronous — no budget, no metrics.
        self.inner.compute_plan(config, state)
    }

    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
        let kind = self.inner.kind();
        self.with_budget(kind, || self.inner.apply(plan)).await
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_converge::inmemory::InMemoryKvReconciler;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn backoff_constant() {
        let b = Backoff::Constant { delay_ms: 50 };
        assert_eq!(b.duration_for_attempt(0), Duration::from_millis(50));
        assert_eq!(b.duration_for_attempt(5), Duration::from_millis(50));
    }

    #[test]
    fn backoff_linear() {
        let b = Backoff::Linear { base_ms: 100 };
        assert_eq!(b.duration_for_attempt(0), Duration::from_millis(100));
        assert_eq!(b.duration_for_attempt(1), Duration::from_millis(200));
        assert_eq!(b.duration_for_attempt(2), Duration::from_millis(300));
    }

    #[test]
    fn backoff_exponential_capped() {
        let b = Backoff::Exponential {
            base_ms: 100,
            max_ms: 1_000,
        };
        assert_eq!(b.duration_for_attempt(0), Duration::from_millis(100));
        assert_eq!(b.duration_for_attempt(1), Duration::from_millis(200));
        assert_eq!(b.duration_for_attempt(2), Duration::from_millis(400));
        assert_eq!(b.duration_for_attempt(3), Duration::from_millis(800));
        // cap kicks in
        assert_eq!(b.duration_for_attempt(4), Duration::from_millis(1_000));
        assert_eq!(b.duration_for_attempt(10), Duration::from_millis(1_000));
    }

    #[test]
    fn policy_should_retry_classification() {
        let p = RetryPolicy::conservative();
        assert!(!p.should_retry(&ReconcilerError::Validation("x".into())));
        assert!(p.should_retry(&ReconcilerError::Transient("x".into())));
        assert!(p.should_retry(&ReconcilerError::Apply("x".into())));
        assert!(!p.should_retry(&ReconcilerError::ComputePlan("x".into())));
        assert!(p.should_retry(&ReconcilerError::ReadState("x".into())));
        assert!(p.should_retry(&ReconcilerError::Other("x".into())));
    }

    #[tokio::test]
    async fn pass_through_when_budget_uncontested() {
        let inner = InMemoryKvReconciler::new();
        let budgeted =
            BudgetedReconciler::new(inner, ConcurrencyLimit::new(4), RetryPolicy::none());

        let cfg = json!({ "a": 1 });
        let state = budgeted.read_state().await.unwrap();
        let plan = budgeted.compute_plan(&cfg, &state).unwrap();
        let outcome = budgeted.apply(&plan).await.unwrap();
        assert!(outcome.fully_succeeded());
    }

    #[tokio::test]
    async fn concurrency_limit_throttles_concurrent_applies() {
        // Wrap a reconciler that records observed peak in-flight count.
        use async_trait::async_trait;
        use magma_converge::{Action, AppliedChange};

        struct CountingReconciler {
            in_flight: AtomicUsize,
            peak: AtomicUsize,
        }

        #[async_trait]
        impl Reconciler for CountingReconciler {
            fn kind(&self) -> &'static str {
                "counting"
            }
            async fn read_state(&self) -> Result<Value, ReconcilerError> {
                Ok(json!({}))
            }
            fn compute_plan(&self, _: &Value, _: &Value) -> Result<Plan, ReconcilerError> {
                Ok(Plan::new("counting", vec![]))
            }
            async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
                let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(cur, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(Outcome {
                    plan_id: plan.id.clone(),
                    kind: "counting".into(),
                    applied: vec![AppliedChange {
                        address: "x".into(),
                        action: Action::NoOp,
                    }],
                    failed: vec![],
                    started_at: chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                })
            }
        }

        let inner = CountingReconciler {
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        };
        let budgeted = Arc::new(BudgetedReconciler::new(
            inner,
            ConcurrencyLimit::new(2),
            RetryPolicy::none(),
        ));

        // Spawn 10 concurrent applies.
        let plan = Plan::new("counting", vec![]);
        let mut tasks = vec![];
        for _ in 0..10 {
            let b = Arc::clone(&budgeted);
            let p = plan.clone();
            tasks.push(tokio::spawn(async move { b.apply(&p).await.unwrap() }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        // Peak in-flight must never exceed 2.
        let peak = budgeted.inner.peak.load(Ordering::SeqCst);
        assert!(
            peak <= 2,
            "concurrency limit violated: peak in-flight = {peak}"
        );
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_failures() {
        use async_trait::async_trait;
        use magma_converge::{Action, AppliedChange};

        struct FlakeyReconciler {
            attempts: AtomicUsize,
            fail_until: usize,
        }

        #[async_trait]
        impl Reconciler for FlakeyReconciler {
            fn kind(&self) -> &'static str {
                "flakey"
            }
            async fn read_state(&self) -> Result<Value, ReconcilerError> {
                Ok(json!({}))
            }
            fn compute_plan(&self, _: &Value, _: &Value) -> Result<Plan, ReconcilerError> {
                Ok(Plan::new("flakey", vec![]))
            }
            async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
                let n = self.attempts.fetch_add(1, Ordering::SeqCst);
                if n < self.fail_until {
                    return Err(ReconcilerError::Transient(format!("transient #{n}")));
                }
                Ok(Outcome {
                    plan_id: plan.id.clone(),
                    kind: "flakey".into(),
                    applied: vec![AppliedChange {
                        address: "x".into(),
                        action: Action::NoOp,
                    }],
                    failed: vec![],
                    started_at: chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                })
            }
        }

        let inner = FlakeyReconciler {
            attempts: AtomicUsize::new(0),
            fail_until: 2, // fail attempts 0+1, succeed on 2
        };
        let budgeted = BudgetedReconciler::new(
            inner,
            ConcurrencyLimit::new(1),
            RetryPolicy {
                max_retries: 3,
                backoff: Backoff::Constant { delay_ms: 1 },
                skip_validation_errors: true,
            },
        );

        let plan = Plan::new("flakey", vec![]);
        let outcome = budgeted.apply(&plan).await.unwrap();
        assert!(outcome.fully_succeeded());
        // 3 total attempts: 2 fail, 3rd succeeds.
        assert_eq!(budgeted.inner.attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_gives_up_after_max() {
        use async_trait::async_trait;

        struct AlwaysFailReconciler;
        #[async_trait]
        impl Reconciler for AlwaysFailReconciler {
            fn kind(&self) -> &'static str {
                "always_fail"
            }
            async fn read_state(&self) -> Result<Value, ReconcilerError> {
                Ok(json!({}))
            }
            fn compute_plan(&self, _: &Value, _: &Value) -> Result<Plan, ReconcilerError> {
                Ok(Plan::new("always_fail", vec![]))
            }
            async fn apply(&self, _: &Plan) -> Result<Outcome, ReconcilerError> {
                Err(ReconcilerError::Transient("nope".into()))
            }
        }

        let budgeted = BudgetedReconciler::new(
            AlwaysFailReconciler,
            ConcurrencyLimit::new(1),
            RetryPolicy {
                max_retries: 2,
                backoff: Backoff::Constant { delay_ms: 1 },
                skip_validation_errors: true,
            },
        );
        let result = budgeted.apply(&Plan::new("always_fail", vec![])).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validation_errors_skipped_when_policy_says_so() {
        use async_trait::async_trait;

        struct ValidationFailReconciler {
            attempts: AtomicUsize,
        }
        #[async_trait]
        impl Reconciler for ValidationFailReconciler {
            fn kind(&self) -> &'static str {
                "val_fail"
            }
            async fn read_state(&self) -> Result<Value, ReconcilerError> {
                Ok(json!({}))
            }
            fn compute_plan(&self, _: &Value, _: &Value) -> Result<Plan, ReconcilerError> {
                Ok(Plan::new("val_fail", vec![]))
            }
            async fn apply(&self, _: &Plan) -> Result<Outcome, ReconcilerError> {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                Err(ReconcilerError::Validation("bad config".into()))
            }
        }

        let inner = ValidationFailReconciler {
            attempts: AtomicUsize::new(0),
        };
        let budgeted = BudgetedReconciler::new(
            inner,
            ConcurrencyLimit::new(1),
            RetryPolicy {
                max_retries: 5,
                backoff: Backoff::Constant { delay_ms: 1 },
                skip_validation_errors: true,
            },
        );
        let _ = budgeted.apply(&Plan::new("val_fail", vec![])).await;
        // Validation error → no retry, only 1 attempt.
        assert_eq!(budgeted.inner.attempts.load(Ordering::SeqCst), 1);
    }
}
