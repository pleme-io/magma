use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

use magma_cty::DynamicValue;
use magma_plugin::provider::{
    PlannedChange, Provider, ProviderError, ProviderSchema, UnresponsiveCause,
};
use tokio::sync::watch;

const FAULT_CAP: usize = 64;
const ERROR_CAP: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RpcClass {
    Dial,
    Read,
    Mutate,
}

impl RpcClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dial => "dial",
            Self::Read => "read",
            Self::Mutate => "mutate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcDeadlines {
    pub dial: Duration,
    pub read: Duration,
    pub mutate: Duration,
}

impl Default for RpcDeadlines {
    fn default() -> Self {
        Self {
            dial: Duration::from_secs(120),
            read: Duration::from_secs(120),
            mutate: Duration::from_secs(1800),
        }
    }
}

impl RpcDeadlines {
    #[must_use]
    pub fn for_class(&self, class: RpcClass) -> Duration {
        match class {
            RpcClass::Dial => self.dial,
            RpcClass::Read => self.read,
            RpcClass::Mutate => self.mutate,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    pub provider: String,
    pub op: String,
    pub type_name: String,
    pub class: RpcClass,
    pub subject: Option<String>,
    pub elapsed: Duration,
    pub deadline: Duration,
}

impl std::fmt::Display for InFlight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}({}) for {}s",
            self.provider,
            self.op,
            self.subject.as_deref().unwrap_or(&self.type_name),
            self.elapsed.as_secs()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFault {
    pub provider: String,
    pub op: String,
    pub type_name: String,
    pub subject: Option<String>,
    pub cause: UnresponsiveCause,
}

impl std::fmt::Display for ProviderFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}({}): {}",
            self.provider,
            self.op,
            self.subject.as_deref().unwrap_or(&self.type_name),
            self.cause
        )
    }
}

struct Started {
    provider: String,
    op: String,
    type_name: String,
    class: RpcClass,
    subject: Option<String>,
    at: Instant,
    deadline: Duration,
}

pub struct ProgressBeacon {
    origin: Instant,
    last_progress_ms: AtomicU64,
    completed: AtomicU64,
    next_id: AtomicU64,
    in_flight: Mutex<BTreeMap<u64, Started>>,
    subject: Mutex<Option<String>>,
    faults: Mutex<VecDeque<ProviderFault>>,
    errors: Mutex<VecDeque<String>>,
}

impl Default for ProgressBeacon {
    fn default() -> Self {
        Self::new()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn push_capped<T>(q: &mut VecDeque<T>, cap: usize, v: T) {
    if q.len() >= cap {
        q.pop_front();
    }
    q.push_back(v);
}

impl ProgressBeacon {
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_progress_ms: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            next_id: AtomicU64::new(0),
            in_flight: Mutex::new(BTreeMap::new()),
            subject: Mutex::new(None),
            faults: Mutex::new(VecDeque::new()),
            errors: Mutex::new(VecDeque::new()),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub fn touch(&self) {
        self.last_progress_ms
            .store(self.now_ms(), Ordering::Release);
    }

    pub fn note_subject(&self, subject: impl Into<String>) {
        *lock(&self.subject) = Some(subject.into());
    }

    #[must_use]
    pub fn subject(&self) -> Option<String> {
        lock(&self.subject).clone()
    }

    #[must_use]
    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn last_progress(&self) -> Instant {
        self.origin + Duration::from_millis(self.last_progress_ms.load(Ordering::Acquire))
    }

    #[must_use]
    pub fn idle(&self) -> Duration {
        self.last_progress().elapsed()
    }

    #[must_use]
    pub fn in_flight(&self) -> Vec<InFlight> {
        lock(&self.in_flight)
            .values()
            .map(|s| InFlight {
                provider: s.provider.clone(),
                op: s.op.clone(),
                type_name: s.type_name.clone(),
                class: s.class,
                subject: s.subject.clone(),
                elapsed: s.at.elapsed(),
                deadline: s.deadline,
            })
            .collect()
    }

    #[must_use]
    pub fn faults(&self) -> Vec<ProviderFault> {
        lock(&self.faults).iter().cloned().collect()
    }

    #[must_use]
    pub fn recent_errors(&self) -> Vec<String> {
        lock(&self.errors).iter().cloned().collect()
    }

    pub fn record_fault(&self, fault: ProviderFault) {
        push_capped(&mut lock(&self.faults), FAULT_CAP, fault);
    }

    pub fn record_error(&self, text: impl Into<String>) {
        push_capped(&mut lock(&self.errors), ERROR_CAP, text.into());
    }

    fn begin(
        &self,
        provider: &str,
        op: &str,
        type_name: &str,
        class: RpcClass,
        deadline: Duration,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        let started = Started {
            provider: provider.to_string(),
            op: op.to_string(),
            type_name: type_name.to_string(),
            class,
            subject: self.subject(),
            at: Instant::now(),
            deadline,
        };
        lock(&self.in_flight).insert(id, started);
        id
    }

    fn end(&self, id: u64, answered: bool) {
        lock(&self.in_flight).remove(&id);
        if answered {
            self.completed.fetch_add(1, Ordering::AcqRel);
            self.touch();
        }
    }

    #[must_use]
    pub fn mutation_within_deadline(&self) -> bool {
        lock(&self.in_flight)
            .values()
            .any(|s| s.class == RpcClass::Mutate && s.at.elapsed() < s.deadline)
    }
}

pub struct RpcGuard {
    pub deadlines: RpcDeadlines,
    pub beacon: Arc<ProgressBeacon>,
}

impl RpcGuard {
    #[must_use]
    pub fn new(deadlines: RpcDeadlines, beacon: Arc<ProgressBeacon>) -> Self {
        Self { deadlines, beacon }
    }
}

pub type Abandonment = Arc<Mutex<Option<String>>>;

struct Meta {
    provider: String,
    guard: Arc<RpcGuard>,
    death: Option<watch::Receiver<Option<String>>>,
    abandoned: Abandonment,
}

async fn wait_for_death(death: Option<watch::Receiver<Option<String>>>) -> String {
    let Some(mut rx) = death else {
        return std::future::pending().await;
    };
    loop {
        let seen = rx.borrow_and_update().clone();
        if let Some(reason) = seen {
            return reason;
        }
        if rx.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

impl Meta {
    fn death_reason(&self) -> Option<String> {
        self.death.as_ref().and_then(|rx| rx.borrow().clone())
    }

    fn unresponsive(&self, op: &str, cause: UnresponsiveCause) -> ProviderError {
        ProviderError::Unresponsive {
            provider: self.provider.clone(),
            op: op.to_string(),
            cause,
        }
    }

    async fn run<T, F>(
        &self,
        class: RpcClass,
        op: &str,
        type_name: &str,
        fut: F,
    ) -> Result<T, ProviderError>
    where
        F: Future<Output = Result<T, ProviderError>>,
    {
        if let Some(earlier) = lock(&self.abandoned).clone() {
            return Err(self.unresponsive(op, UnresponsiveCause::Abandoned { earlier }));
        }
        if let Some(reason) = self.death_reason() {
            return Err(self.abandon(op, type_name, UnresponsiveCause::Exited { reason }));
        }
        let beacon = &self.guard.beacon;
        let deadline = self.guard.deadlines.for_class(class);
        let id = beacon.begin(&self.provider, op, type_name, class, deadline);
        let cause = tokio::select! {
            r = fut => {
                let died = self.death_reason().filter(|_| r.is_err());
                match died {
                    None => {
                        beacon.end(id, true);
                        if let Err(e) = &r {
                            beacon.record_error(format!("{}.{op}({type_name}): {e}", self.provider));
                        }
                        return r;
                    }
                    Some(reason) => UnresponsiveCause::Exited { reason },
                }
            }
            () = tokio::time::sleep(deadline) => UnresponsiveCause::DeadlineExceeded {
                deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            },
            reason = wait_for_death(self.death.clone()) => UnresponsiveCause::Exited { reason },
        };
        beacon.end(id, false);
        Err(self.abandon(op, type_name, cause))
    }

    fn abandon(&self, op: &str, type_name: &str, cause: UnresponsiveCause) -> ProviderError {
        let fault = ProviderFault {
            provider: self.provider.clone(),
            op: op.to_string(),
            type_name: type_name.to_string(),
            subject: self.guard.beacon.subject(),
            cause: cause.clone(),
        };
        tracing::error!(fault = %fault, "magma: provider unresponsive; abandoning this provider process");
        *lock(&self.abandoned) = Some(fault.to_string());
        self.guard.beacon.record_fault(fault);
        self.unresponsive(op, cause)
    }
}

pub struct GuardedProvider {
    inner: Box<dyn Provider>,
    meta: Meta,
}

impl GuardedProvider {
    #[must_use]
    pub fn new(
        inner: Box<dyn Provider>,
        provider: impl Into<String>,
        guard: Arc<RpcGuard>,
        death: Option<watch::Receiver<Option<String>>>,
    ) -> (Self, Abandonment) {
        let abandoned: Abandonment = Arc::new(Mutex::new(None));
        (
            Self {
                inner,
                meta: Meta {
                    provider: provider.into(),
                    guard,
                    death,
                    abandoned: Arc::clone(&abandoned),
                },
            },
            abandoned,
        )
    }
}

#[async_trait::async_trait]
impl Provider for GuardedProvider {
    async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
        let Self { inner, meta } = self;
        meta.run(RpcClass::Dial, "get_schema", "", inner.get_schema())
            .await
    }

    async fn configure(
        &mut self,
        config: &DynamicValue,
        terraform_version: &str,
    ) -> Result<(), ProviderError> {
        let Self { inner, meta } = self;
        meta.run(
            RpcClass::Dial,
            "configure",
            "",
            inner.configure(config, terraform_version),
        )
        .await
    }

    async fn plan_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        proposed_new_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<PlannedChange, ProviderError> {
        let Self { inner, meta } = self;
        meta.run(
            RpcClass::Read,
            "plan_resource_change",
            type_name,
            inner.plan_resource_change(type_name, prior_state, proposed_new_state, config),
        )
        .await
    }

    async fn apply_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        planned_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        let Self { inner, meta } = self;
        meta.run(
            RpcClass::Mutate,
            "apply_resource_change",
            type_name,
            inner.apply_resource_change(type_name, prior_state, planned_state, config),
        )
        .await
    }

    async fn read_resource(
        &mut self,
        type_name: &str,
        current_state: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        let Self { inner, meta } = self;
        meta.run(
            RpcClass::Read,
            "read_resource",
            type_name,
            inner.read_resource(type_name, current_state),
        )
        .await
    }

    async fn read_data_source(
        &mut self,
        type_name: &str,
        config: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        let Self { inner, meta } = self;
        meta.run(
            RpcClass::Read,
            "read_data_source",
            type_name,
            inner.read_data_source(type_name, config),
        )
        .await
    }

    async fn import_resource_state(
        &mut self,
        type_name: &str,
        id: &str,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        let Self { inner, meta } = self;
        meta.run(
            RpcClass::Read,
            "import_resource_state",
            type_name,
            inner.import_resource_state(type_name, id),
        )
        .await
    }

    async fn upgrade_resource_state(
        &mut self,
        type_name: &str,
        stored_version: i64,
        raw_json: &[u8],
    ) -> Result<DynamicValue, ProviderError> {
        let Self { inner, meta } = self;
        meta.run(
            RpcClass::Read,
            "upgrade_resource_state",
            type_name,
            inner.upgrade_resource_state(type_name, stored_version, raw_json),
        )
        .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StallPolicy {
    pub idle: Duration,
    pub tick: Duration,
}

impl Default for StallPolicy {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(300),
            tick: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "no provider progress for {}s (completed {completed} RPCs; in flight: {}; last subject: {}; faults: {})",
    idle.as_secs(),
    render_list(in_flight),
    subject.as_deref().unwrap_or("none"),
    render_list(faults)
)]
pub struct Stalled {
    pub idle: Duration,
    pub completed: u64,
    pub in_flight: Vec<InFlight>,
    pub subject: Option<String>,
    pub faults: Vec<ProviderFault>,
}

fn render_list<T: std::fmt::Display>(items: &[T]) -> String {
    if items.is_empty() {
        return "none".to_string();
    }
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

impl Stalled {
    #[must_use]
    pub fn of(beacon: &ProgressBeacon, idle: Duration) -> Self {
        Self {
            idle,
            completed: beacon.completed(),
            in_flight: beacon.in_flight(),
            subject: beacon.subject(),
            faults: beacon.faults(),
        }
    }
}

pub async fn supervise<T, F, L>(
    beacon: &ProgressBeacon,
    policy: StallPolicy,
    last_progress: L,
    fut: F,
) -> Result<T, Stalled>
where
    F: Future<Output = T>,
    L: Fn() -> Option<Instant>,
{
    beacon.touch();
    tokio::pin!(fut);
    let mut ticker = tokio::time::interval(policy.tick.max(Duration::from_millis(10)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            out = &mut fut => return Ok(out),
            _ = ticker.tick() => {
                let latest = last_progress().map_or(beacon.last_progress(), |o| o.max(beacon.last_progress()));
                let idle = latest.elapsed();
                if idle >= policy.idle && !beacon.mutation_within_deadline() {
                    return Err(Stalled::of(beacon, idle));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magma_cty::CtyType;

    enum Mode {
        Hang,
        Slow(Duration),
        Answer,
    }

    struct Fake {
        mode: Mode,
    }

    #[async_trait::async_trait]
    impl Provider for Fake {
        async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
            Err(ProviderError::NoNewState)
        }
        async fn configure(&mut self, _: &DynamicValue, _: &str) -> Result<(), ProviderError> {
            Ok(())
        }
        async fn plan_resource_change(
            &mut self,
            _: &str,
            _: &DynamicValue,
            _: &DynamicValue,
            _: &DynamicValue,
        ) -> Result<PlannedChange, ProviderError> {
            Err(ProviderError::NoNewState)
        }
        async fn apply_resource_change(
            &mut self,
            _: &str,
            _: &DynamicValue,
            _: &DynamicValue,
            _: &DynamicValue,
        ) -> Result<DynamicValue, ProviderError> {
            std::future::pending().await
        }
        async fn read_resource(
            &mut self,
            _: &str,
            _: &DynamicValue,
        ) -> Result<Option<DynamicValue>, ProviderError> {
            match self.mode {
                Mode::Hang => std::future::pending().await,
                Mode::Slow(d) => {
                    tokio::time::sleep(d).await;
                    Ok(None)
                }
                Mode::Answer => Ok(None),
            }
        }
        async fn read_data_source(
            &mut self,
            _: &str,
            _: &DynamicValue,
        ) -> Result<Option<DynamicValue>, ProviderError> {
            Ok(None)
        }
        async fn import_resource_state(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<DynamicValue>, ProviderError> {
            Ok(None)
        }
        async fn upgrade_resource_state(
            &mut self,
            _: &str,
            _: i64,
            _: &[u8],
        ) -> Result<DynamicValue, ProviderError> {
            Err(ProviderError::NoNewState)
        }
    }

    fn dv() -> DynamicValue {
        DynamicValue::from_json(&serde_json::Value::Null, &CtyType::String).unwrap()
    }

    fn guard(read: Duration) -> Arc<RpcGuard> {
        guard_with(read, Duration::from_secs(3600))
    }

    fn guard_with(read: Duration, mutate: Duration) -> Arc<RpcGuard> {
        Arc::new(RpcGuard::new(
            RpcDeadlines {
                dial: read,
                read,
                mutate,
            },
            Arc::new(ProgressBeacon::new()),
        ))
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn policy(idle: u64) -> StallPolicy {
        StallPolicy {
            idle: ms(idle),
            tick: ms(10),
        }
    }

    #[tokio::test]
    async fn a_hung_read_is_a_typed_deadline_error_and_abandons_the_provider() {
        let g = guard(ms(150));
        let (mut p, abandoned) = GuardedProvider::new(
            Box::new(Fake { mode: Mode::Hang }),
            "github",
            Arc::clone(&g),
            None,
        );
        g.beacon.note_subject("github_repository.a");
        let started = Instant::now();
        let err = p
            .read_resource("github_repository", &dv())
            .await
            .unwrap_err();
        assert!(started.elapsed() >= ms(150) && started.elapsed() < ms(2000));
        assert!(matches!(
            err,
            ProviderError::Unresponsive {
                cause: UnresponsiveCause::DeadlineExceeded { deadline_ms: 150 },
                ..
            }
        ));
        assert!(abandoned.lock().unwrap().is_some());
        let faults = g.beacon.faults();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].subject.as_deref(), Some("github_repository.a"));
        assert!(g.beacon.in_flight().is_empty());
        let again = p
            .read_resource("github_repository", &dv())
            .await
            .unwrap_err();
        assert!(matches!(
            again,
            ProviderError::Unresponsive {
                cause: UnresponsiveCause::Abandoned { .. },
                ..
            }
        ));
        assert!(!magma_plugin::provider::is_retryable(&again));
    }

    #[tokio::test]
    async fn a_provider_that_exits_mid_rpc_fails_at_once_not_at_the_deadline() {
        let g = guard(Duration::from_secs(3600));
        let (tx, rx) = watch::channel(None::<String>);
        let (mut p, _) = GuardedProvider::new(
            Box::new(Fake { mode: Mode::Hang }),
            "github",
            Arc::clone(&g),
            Some(rx),
        );
        let started = Instant::now();
        let state = dv();
        let call = p.read_resource("github_repository", &state);
        let kill = async {
            tokio::time::sleep(ms(50)).await;
            tx.send_replace(Some("provider process closed its stdout (exited)".into()));
        };
        let (err, ()) = tokio::join!(call, kill);
        assert!(started.elapsed() < ms(2000));
        match err.unwrap_err() {
            ProviderError::Unresponsive {
                cause: UnresponsiveCause::Exited { reason },
                ..
            } => assert!(reason.contains("exited")),
            other => panic!("expected Exited, got {other:?}"),
        }
        assert_eq!(g.beacon.faults().len(), 1);
    }

    #[tokio::test]
    async fn an_already_dead_provider_fails_the_next_call_immediately() {
        let g = guard(Duration::from_secs(3600));
        let (tx, rx) = watch::channel(None::<String>);
        tx.send_replace(Some("gone".into()));
        let (mut p, _) =
            GuardedProvider::new(Box::new(Fake { mode: Mode::Hang }), "github", g, Some(rx));
        let started = Instant::now();
        assert!(p.read_resource("t", &dv()).await.is_err());
        assert!(started.elapsed() < ms(500));
    }

    #[tokio::test]
    async fn a_slow_answer_inside_the_deadline_is_progress() {
        let g = guard(ms(500));
        let (mut p, abandoned) = GuardedProvider::new(
            Box::new(Fake {
                mode: Mode::Slow(ms(100)),
            }),
            "github",
            Arc::clone(&g),
            None,
        );
        assert!(p.read_resource("t", &dv()).await.unwrap().is_none());
        assert_eq!(g.beacon.completed(), 1);
        assert!(abandoned.lock().unwrap().is_none());
        assert!(g.beacon.idle() < ms(100));
    }

    #[tokio::test]
    async fn supervise_cancels_a_cycle_with_no_progress_within_the_idle_bound() {
        let beacon = ProgressBeacon::new();
        let started = Instant::now();
        let stalled = supervise(&beacon, policy(200), || None, std::future::pending::<()>())
            .await
            .unwrap_err();
        let waited = started.elapsed();
        assert!(waited >= ms(200) && waited < ms(2000), "{waited:?}");
        assert!(stalled.idle >= ms(200));
    }

    #[tokio::test]
    async fn supervise_reads_an_outside_progress_clock_too() {
        let beacon = ProgressBeacon::new();
        let outside = Arc::new(Mutex::new(Instant::now()));
        let o = Arc::clone(&outside);
        let bump = async move {
            for _ in 0..10 {
                tokio::time::sleep(ms(50)).await;
                *o.lock().unwrap() = Instant::now();
            }
            "done"
        };
        let out = supervise(
            &beacon,
            policy(200),
            || Some(*outside.lock().unwrap()),
            bump,
        )
        .await
        .unwrap();
        assert_eq!(out, "done");
    }

    #[tokio::test]
    async fn supervise_spares_a_cycle_that_keeps_answering() {
        let g = guard(ms(500));
        let (mut p, _) = GuardedProvider::new(
            Box::new(Fake {
                mode: Mode::Slow(ms(60)),
            }),
            "github",
            Arc::clone(&g),
            None,
        );
        let work = async {
            for _ in 0..8 {
                p.read_resource("t", &dv()).await.unwrap();
            }
            "done"
        };
        let out = supervise(&g.beacon, policy(200), || None, work)
            .await
            .unwrap();
        assert_eq!(out, "done");
    }

    #[tokio::test]
    async fn supervise_waits_out_a_mutation_inside_its_own_deadline() {
        let g = guard_with(ms(100), ms(600));
        let (mut p, _) = GuardedProvider::new(
            Box::new(Fake { mode: Mode::Answer }),
            "aws",
            Arc::clone(&g),
            None,
        );
        let started = Instant::now();
        let res = supervise(&g.beacon, policy(200), || None, async {
            p.apply_resource_change("aws_eks_cluster", &dv(), &dv(), &dv())
                .await
        })
        .await
        .unwrap();
        assert!(matches!(
            res,
            Err(ProviderError::Unresponsive {
                cause: UnresponsiveCause::DeadlineExceeded { .. },
                ..
            })
        ));
        assert!(started.elapsed() >= ms(600));
    }
}
