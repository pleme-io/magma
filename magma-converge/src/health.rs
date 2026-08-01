//! Typed K8s-resource readiness — the canonical `HealthCheck<R>`
//! trait every reconciler that decides "is this resource ready?"
//! consumes. Composes with [`crate::Inventory`] +
//! [`crate::ResourceRef`] to produce typed `HealthReport`s.
//!
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III, P1.x (P1.5+).
//!
//! Subsumes FluxCD Kustomization's `healthChecks[]{kind,name,namespace}`
//! and `healthCheckExprs[]{kind,inProgress,failed,current}` (CEL)
//! patterns + the implicit "is this Deployment Ready?" logic that
//! today lives in lava-operator + engenho-controllers + tatara as
//! per-controller hand-rolls of kstatus.
//!
//! The trait is **generic over the resource type `R`** so adapters
//! bring in kube-rs (or any other K8s client) without polluting the
//! substrate core. The substrate ships:
//!
//! - `ReadyState` enum — 4 variants (`Ready` / `InProgress` / `Failed`
//!   / `Unknown`) mirroring kstatus's terminal classification
//! - `HealthCheck<R>` trait — pure-predicate shape
//! - `AlwaysReady` / `NeverReady` / `Closure(F)` reference impls
//! - `ChainedHealthCheck<R>` — composes per-ref typed checks; first
//!   non-`Ready` outcome wins (mirrors ChainedClassifier semantics)
//! - `HealthReport` — composes [`crate::Inventory`] + per-`ResourceRef`
//!   `ReadyState` into a typed apply-receipt-shaped record
//!
//! # Trait law
//!
//! For any `HealthCheck<R>` impl and any resource `r`:
//!
//!   `h.evaluate(r) == h.evaluate(r)`   (determinism)
//!
//! No I/O, no clock reads (consumer passes in any time-dependent
//! state via `r`). Pure value function — proptest-able.
//!
//! # Composition
//!
//! ```ignore
//! let inventory = Inventory::from_iter([deployment, service]);
//! let mut report = HealthReport::new();
//! for r in inventory.iter() {
//!     let state = my_checks.evaluate(&kube_get(r).await?);
//!     report.set(r.clone(), state);
//! }
//! match report.overall() {
//!     ReadyState::Ready => /* all green */,
//!     ReadyState::InProgress { reason } => requeue(short_interval),
//!     ReadyState::Failed { reason } => escalate(),
//!     ReadyState::Unknown => emit_warning(),
//! }
//! ```

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::inventory::ResourceRef;

/// Typed readiness classification. Mirrors kstatus's terminal
/// classification + the K8s ".status.conditions[Ready]" model.
///
/// `InProgress` and `Failed` carry an operator-facing `reason`
/// string (typed enough for operator display, free-form enough
/// to surface the K8s condition message verbatim).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
    gen_platform::OutcomeLattice,
)]
#[discriminant(method = "state", case = "kebab")]
#[outcome_lattice(trait_path = "crate::outcome::OutcomeLattice")]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ReadyState {
    /// Resource has reached its declared desired state.
    #[outcome(severity = 0, baseline)]
    Ready,
    /// Resource is converging but not yet ready (Deployment rolling
    /// out, Job running, etc).
    #[outcome(severity = 2)]
    InProgress { reason: String },
    /// Resource has reached a terminal failure (Pod CrashLoopBackOff,
    /// Helm release `failed`, etc).
    #[outcome(severity = 3)]
    Failed { reason: String },
    /// State can't be classified — no `.status` populated, custom
    /// resource without kstatus support, etc.
    #[outcome(severity = 1)]
    Unknown,
}

/// The canonical resource-readiness predicate. Generic over resource
/// type `R` so adapters bring in kube-rs (or any K8s client) without
/// polluting the substrate core.
///
/// `?Sized` on `R` lets the trait dispatch against `&dyn`-shaped
/// resources for type-erased pipelines.
pub trait HealthCheck<R: ?Sized>: Send + Sync {
    /// Determine the readiness state of `resource`. Pure function —
    /// no I/O, no clock reads.
    fn evaluate(&self, resource: &R) -> ReadyState;
}

/// Always returns `Ready`. For tests + resource kinds that are
/// trivially-ready (e.g. Namespaces, ConfigMaps without observed
/// generation tracking).
#[derive(Debug, Default, Copy, Clone)]
pub struct AlwaysReady;

impl<R: ?Sized> HealthCheck<R> for AlwaysReady {
    fn evaluate(&self, _resource: &R) -> ReadyState {
        ReadyState::Ready
    }
}

/// Always returns `Failed`. For tests + intentionally-blocked
/// resources.
#[derive(Debug, Default, Copy, Clone)]
pub struct NeverReady {
    pub reason: &'static str,
}

impl<R: ?Sized> HealthCheck<R> for NeverReady {
    fn evaluate(&self, _resource: &R) -> ReadyState {
        ReadyState::Failed {
            reason: self.reason.to_string(),
        }
    }
}

/// Wraps a closure as a HealthCheck. Convenient for ad-hoc test
/// checks and for prototyping per-resource predicates.
pub struct ClosureCheck<R: ?Sized, F>
where
    F: Fn(&R) -> ReadyState + Send + Sync,
{
    f: F,
    _phantom: std::marker::PhantomData<fn(&R)>,
}

impl<R: ?Sized, F> ClosureCheck<R, F>
where
    F: Fn(&R) -> ReadyState + Send + Sync,
{
    pub fn new(f: F) -> Self {
        Self {
            f,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R: ?Sized, F> HealthCheck<R> for ClosureCheck<R, F>
where
    F: Fn(&R) -> ReadyState + Send + Sync,
{
    fn evaluate(&self, resource: &R) -> ReadyState {
        (self.f)(resource)
    }
}

/// Compose multiple `HealthCheck<R>` impls. Iterates in declared
/// order; the **first non-Ready outcome wins** (mirrors
/// `ChainedClassifier`'s first-match semantics).
///
/// All checks pass ⇒ `Ready`. Any check returns InProgress / Failed /
/// Unknown ⇒ that outcome propagates. Order matters: if both an
/// InProgress and a Failed check would fire, the order of `with_check`
/// determines which one the consumer sees.
///
/// For aggregation across many resources (worst severity wins), use
/// `HealthReport::overall` instead.
pub struct ChainedHealthCheck<R: ?Sized> {
    checks: Vec<Arc<dyn HealthCheck<R>>>,
}

impl<R: ?Sized> ChainedHealthCheck<R> {
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Append a check. Returns self for fluent chaining.
    #[must_use]
    pub fn with_check<C>(mut self, check: C) -> Self
    where
        C: HealthCheck<R> + 'static,
    {
        self.checks.push(Arc::new(check));
        self
    }

    pub fn len(&self) -> usize {
        self.checks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }
}

impl<R: ?Sized> Default for ChainedHealthCheck<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: ?Sized> std::fmt::Debug for ChainedHealthCheck<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainedHealthCheck")
            .field("checks", &self.checks.len())
            .finish()
    }
}

impl<R: ?Sized> HealthCheck<R> for ChainedHealthCheck<R> {
    fn evaluate(&self, resource: &R) -> ReadyState {
        for check in &self.checks {
            let state = check.evaluate(resource);
            if !state.is_ready() {
                return state;
            }
        }
        ReadyState::Ready
    }
}

// ── HealthReport — per-ResourceRef readiness aggregation ──────────

/// Per-`ResourceRef` `ReadyState` map. The canonical apply-receipt-
/// shaped record for a typed inventory's health snapshot.
///
/// Composes with [`crate::Inventory`] — call `HealthReport::set` for
/// each `ResourceRef` in the inventory; call `overall` to get the
/// worst-severity outcome across all entries.
///
/// Internal storage is a sorted `Vec<(ResourceRef, ReadyState)>` so
/// the type serializes cleanly as a JSON array of pairs (JSON
/// requires string keys; `ResourceRef` is a struct). Lookups are
/// O(log n) via binary search; `set` is O(n) at insert time but the
/// typical inventory size is small (tens to low-hundreds per
/// Kustomization), and the sorted invariant keeps iteration in
/// canonical order without per-cycle re-sorting.
/// Canonical readiness report — `Aggregator<ResourceRef, ReadyState>`.
///
/// As of the Aggregator extraction (PATTERN-EXTRACTION.md Pattern 4),
/// HealthReport is a typed alias over the generic per-key outcome
/// aggregator. Existing API (set/get/len/is_empty/iter/overall) flows
/// through the generic; the only HealthReport-specific surface is
/// `counts()` (per-`ReadyState`-variant counter) which lives on
/// [`HealthReportExt`].
///
/// ```ignore
/// use magma_converge::{HealthReport, HealthReportExt, ReadyState};
/// let mut r = HealthReport::new();
/// r.set(some_ref, ReadyState::Ready);
/// let _counts = r.counts();        // via HealthReportExt
/// let _overall = r.overall();      // via Aggregator
/// ```
pub type HealthReport = crate::aggregator::Aggregator<ResourceRef, ReadyState>;

/// Extension methods specific to `HealthReport` (i.e. specialized to
/// `ReadyState`'s four variants).
pub trait HealthReportExt {
    /// Per-state count (`(ready, in_progress, failed, unknown)`).
    fn counts(&self) -> HealthCounts;
}

impl HealthReportExt for HealthReport {
    fn counts(&self) -> HealthCounts {
        let mut c = HealthCounts::default();
        for (_, state) in self.iter() {
            match state {
                ReadyState::Ready => c.ready += 1,
                ReadyState::InProgress { .. } => c.in_progress += 1,
                ReadyState::Failed { .. } => c.failed += 1,
                ReadyState::Unknown => c.unknown += 1,
            }
        }
        c
    }
}

/// Per-state count snapshot from a `HealthReport`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCounts {
    pub ready: usize,
    pub in_progress: usize,
    pub failed: usize,
    pub unknown: usize,
}

impl HealthCounts {
    pub fn total(&self) -> usize {
        self.ready + self.in_progress + self.failed + self.unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::OutcomeLattice;

    fn dep(ns: &str, name: &str) -> ResourceRef {
        ResourceRef::namespaced("apps", "v1", "Deployment", ns, name)
    }

    // ── ReadyState ─────────────────────────────────────────────────

    #[test]
    fn ready_state_predicates() {
        assert!(ReadyState::Ready.is_ready());
        assert!(!ReadyState::Ready.is_in_progress());

        let p = ReadyState::InProgress {
            reason: "rolling out".into(),
        };
        assert!(p.is_in_progress());
        assert!(!p.is_ready());

        let f = ReadyState::Failed {
            reason: "ImagePullBackOff".into(),
        };
        assert!(f.is_failed());
        assert!(!f.is_ready());

        assert!(ReadyState::Unknown.is_unknown());
    }

    #[test]
    fn ready_state_severity_order() {
        // Failed > InProgress > Unknown > Ready
        assert!(
            ReadyState::Failed { reason: "x".into() }.severity()
                > ReadyState::InProgress { reason: "x".into() }.severity()
        );
        assert!(
            ReadyState::InProgress { reason: "x".into() }.severity()
                > ReadyState::Unknown.severity()
        );
        assert!(ReadyState::Unknown.severity() > ReadyState::Ready.severity());
    }

    #[test]
    fn ready_state_state_discriminant() {
        assert_eq!(ReadyState::Ready.state(), "ready");
        assert_eq!(
            ReadyState::InProgress { reason: "x".into() }.state(),
            "in-progress"
        );
        assert_eq!(ReadyState::Failed { reason: "x".into() }.state(), "failed");
        assert_eq!(ReadyState::Unknown.state(), "unknown");
    }

    #[test]
    fn ready_state_serde_kebab_case() {
        let f = ReadyState::Failed {
            reason: "ImagePullBackOff".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        // Tag should be "failed" (kebab-case), not "Failed".
        assert!(json.contains("\"failed\""), "got {json:?}");
        let back: ReadyState = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);

        let ip = ReadyState::InProgress {
            reason: "rolling".into(),
        };
        let j2 = serde_json::to_string(&ip).unwrap();
        assert!(j2.contains("\"in-progress\""), "got {j2:?}");
    }

    // ── HealthCheck reference impls ────────────────────────────────

    #[test]
    fn always_ready_returns_ready() {
        let c = AlwaysReady;
        let r: i32 = 42;
        assert!(c.evaluate(&r).is_ready());
    }

    #[test]
    fn never_ready_returns_failed_with_reason() {
        let c = NeverReady {
            reason: "circuit breaker",
        };
        let r: i32 = 42;
        match c.evaluate(&r) {
            ReadyState::Failed { reason } => assert_eq!(reason, "circuit breaker"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn closure_check_runs_closure() {
        let c = ClosureCheck::new(|n: &i32| {
            if *n > 0 {
                ReadyState::Ready
            } else {
                ReadyState::Failed {
                    reason: format!("non-positive: {n}"),
                }
            }
        });
        assert!(c.evaluate(&5).is_ready());
        match c.evaluate(&-1) {
            ReadyState::Failed { reason } => assert!(reason.contains("non-positive")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // ── ChainedHealthCheck ─────────────────────────────────────────

    #[test]
    fn chained_empty_returns_ready() {
        let c: ChainedHealthCheck<i32> = ChainedHealthCheck::new();
        assert!(c.is_empty());
        assert!(c.evaluate(&42).is_ready());
    }

    #[test]
    fn chained_all_ready_returns_ready() {
        let c: ChainedHealthCheck<i32> = ChainedHealthCheck::new()
            .with_check(AlwaysReady)
            .with_check(AlwaysReady)
            .with_check(AlwaysReady);
        assert_eq!(c.len(), 3);
        assert!(c.evaluate(&42).is_ready());
    }

    #[test]
    fn chained_first_non_ready_wins() {
        // First non-Ready check determines the outcome.
        let c: ChainedHealthCheck<i32> = ChainedHealthCheck::new()
            .with_check(AlwaysReady)
            .with_check(NeverReady {
                reason: "first failure",
            })
            .with_check(NeverReady {
                reason: "second failure",
            });

        match c.evaluate(&42) {
            ReadyState::Failed { reason } => assert_eq!(reason, "first failure"),
            other => panic!("expected first Failed, got {other:?}"),
        }
    }

    #[test]
    fn chained_dyn_dispatch() {
        // Heterogeneous checks behind one chain.
        let in_prog = ClosureCheck::new(|_: &i32| ReadyState::InProgress {
            reason: "wait".into(),
        });
        let c: ChainedHealthCheck<i32> = ChainedHealthCheck::new()
            .with_check(AlwaysReady)
            .with_check(in_prog);
        assert!(c.evaluate(&42).is_in_progress());
    }

    // ── HealthReport ───────────────────────────────────────────────

    #[test]
    fn report_empty_overall_is_ready() {
        let r = HealthReport::new();
        assert!(r.is_empty());
        assert!(
            r.overall().is_ready(),
            "vacuous truth: no resources → Ready"
        );
        assert_eq!(r.counts().total(), 0);
    }

    #[test]
    fn report_all_ready_is_ready() {
        let mut r = HealthReport::new();
        r.set(dep("ns", "a"), ReadyState::Ready);
        r.set(dep("ns", "b"), ReadyState::Ready);
        assert!(r.overall().is_ready());
        assert_eq!(r.counts().ready, 2);
    }

    #[test]
    fn report_any_failed_aggregates_to_failed() {
        let mut r = HealthReport::new();
        r.set(dep("ns", "a"), ReadyState::Ready);
        r.set(
            dep("ns", "b"),
            ReadyState::Failed {
                reason: "broken".into(),
            },
        );
        r.set(dep("ns", "c"), ReadyState::Ready);

        match r.overall() {
            ReadyState::Failed { reason } => assert_eq!(reason, "broken"),
            other => panic!("expected Failed aggregate, got {other:?}"),
        }
    }

    #[test]
    fn report_in_progress_beats_unknown() {
        let mut r = HealthReport::new();
        r.set(dep("ns", "a"), ReadyState::Unknown);
        r.set(
            dep("ns", "b"),
            ReadyState::InProgress {
                reason: "rolling".into(),
            },
        );

        assert!(r.overall().is_in_progress());
    }

    #[test]
    fn report_failed_beats_in_progress_beats_unknown_beats_ready() {
        let mut r = HealthReport::new();
        r.set(dep("ns", "a"), ReadyState::Ready);
        r.set(dep("ns", "b"), ReadyState::Unknown);
        r.set(
            dep("ns", "c"),
            ReadyState::InProgress {
                reason: "rolling".into(),
            },
        );
        r.set(
            dep("ns", "d"),
            ReadyState::Failed {
                reason: "broken".into(),
            },
        );

        // Worst (Failed) wins.
        assert!(r.overall().is_failed());
    }

    #[test]
    fn report_counts_partition_total() {
        let mut r = HealthReport::new();
        r.set(dep("ns", "a"), ReadyState::Ready);
        r.set(dep("ns", "b"), ReadyState::Ready);
        r.set(
            dep("ns", "c"),
            ReadyState::InProgress {
                reason: "rolling".into(),
            },
        );
        r.set(dep("ns", "d"), ReadyState::Failed { reason: "x".into() });
        r.set(dep("ns", "e"), ReadyState::Unknown);

        let c = r.counts();
        assert_eq!(c.ready, 2);
        assert_eq!(c.in_progress, 1);
        assert_eq!(c.failed, 1);
        assert_eq!(c.unknown, 1);
        assert_eq!(c.total(), 5);
        assert_eq!(c.total(), r.len());
    }

    #[test]
    fn report_iter_in_canonical_resource_ref_order() {
        let mut r = HealthReport::new();
        r.set(dep("z-ns", "z"), ReadyState::Ready);
        r.set(dep("a-ns", "a"), ReadyState::Ready);
        r.set(dep("m-ns", "m"), ReadyState::Ready);

        let order: Vec<String> = r
            .iter()
            .map(|(rr, _)| rr.namespace.clone().unwrap_or_default())
            .collect();
        // BTreeMap iterates in sorted ResourceRef order; ResourceRef
        // sorts by (group, version, kind, namespace, name); all share
        // the same group+version+kind so namespace sort wins.
        assert_eq!(order, vec!["a-ns", "m-ns", "z-ns"]);
    }

    #[test]
    fn report_serde_round_trip() {
        let mut r = HealthReport::new();
        r.set(dep("ns", "a"), ReadyState::Ready);
        r.set(dep("ns", "b"), ReadyState::Failed { reason: "x".into() });
        let json = serde_json::to_string(&r).unwrap();
        let back: HealthReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── Composability ─────────────────────────────────────────────

    /// Demonstrate the canonical "iterate Inventory → evaluate per-
    /// ref → aggregate via HealthReport" flow.
    #[test]
    fn composes_inventory_check_and_report() {
        use crate::Inventory;
        use std::collections::BTreeMap;

        // A fake "resource" type for the test.
        struct FakeResource {
            ref_: ResourceRef,
            replicas_ready: u32,
            replicas_desired: u32,
        }

        let inventory = Inventory::from_iter([dep("ns", "a"), dep("ns", "b"), dep("ns", "c")]);

        let cluster_state: BTreeMap<ResourceRef, FakeResource> = [
            (
                dep("ns", "a"),
                FakeResource {
                    ref_: dep("ns", "a"),
                    replicas_ready: 3,
                    replicas_desired: 3,
                },
            ),
            (
                dep("ns", "b"),
                FakeResource {
                    ref_: dep("ns", "b"),
                    replicas_ready: 1,
                    replicas_desired: 3,
                },
            ),
            (
                dep("ns", "c"),
                FakeResource {
                    ref_: dep("ns", "c"),
                    replicas_ready: 0,
                    replicas_desired: 0,
                },
            ),
        ]
        .into_iter()
        .collect();

        let check = ClosureCheck::new(|r: &FakeResource| {
            if r.replicas_desired == 0 || r.replicas_ready == r.replicas_desired {
                ReadyState::Ready
            } else {
                ReadyState::InProgress {
                    reason: format!(
                        "{}/{} replicas ready ({})",
                        r.replicas_ready, r.replicas_desired, r.ref_
                    ),
                }
            }
        });

        let mut report = HealthReport::new();
        for r in inventory.iter() {
            let state = check.evaluate(&cluster_state[r]);
            report.set(r.clone(), state);
        }

        // 2 Ready, 1 InProgress.
        let c = report.counts();
        assert_eq!(c.ready, 2);
        assert_eq!(c.in_progress, 1);
        assert!(report.overall().is_in_progress());
    }
}
