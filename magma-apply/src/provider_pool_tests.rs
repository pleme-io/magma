use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use magma_cty::CtyType;
use magma_types::ProviderInstance;

use super::*;

struct FakeProvider;

#[async_trait::async_trait]
impl Provider for FakeProvider {
    async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
        Ok(empty_schema())
    }
    async fn configure(&mut self, _: &DynamicValue, _: &str) -> Result<(), ProviderError> {
        Err(ProviderError::Transport("configure".into()))
    }
    async fn plan_resource_change(
        &mut self,
        _: &str,
        _: &DynamicValue,
        _: &DynamicValue,
        _: &DynamicValue,
    ) -> Result<PlannedChange, ProviderError> {
        Err(ProviderError::Transport("plan_resource_change".into()))
    }
    async fn apply_resource_change(
        &mut self,
        _: &str,
        _: &DynamicValue,
        _: &DynamicValue,
        _: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        Err(ProviderError::Transport("apply_resource_change".into()))
    }
    async fn read_resource(
        &mut self,
        _: &str,
        _: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        Err(ProviderError::Transport("read_resource".into()))
    }
    async fn read_data_source(
        &mut self,
        _: &str,
        _: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        Err(ProviderError::Transport("read_data_source".into()))
    }
    async fn import_resource_state(
        &mut self,
        _: &str,
        _: &str,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        Err(ProviderError::Transport("import_resource_state".into()))
    }
    async fn upgrade_resource_state(
        &mut self,
        _: &str,
        _: i64,
        _: &[u8],
    ) -> Result<DynamicValue, ProviderError> {
        Err(ProviderError::Transport("upgrade_resource_state".into()))
    }
}

fn empty_schema() -> ProviderSchema {
    ProviderSchema {
        provider_config: CtyType::Object(BTreeMap::new()),
        resources: BTreeMap::new(),
        data_sources: BTreeMap::new(),
        resource_versions: BTreeMap::new(),
    }
}

struct FakeTransport {
    crashed: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
}

impl ProviderTransport for FakeTransport {
    fn crash_summary(&self) -> Option<ProviderCrash> {
        self.crashed.load(Ordering::SeqCst).then(|| ProviderCrash {
            lines: vec!["panic: runtime error".to_string()],
            signal: Some(11),
        })
    }
    fn close_reason(&self) -> Option<String> {
        self.closed
            .load(Ordering::SeqCst)
            .then(|| "channel closed".to_string())
    }
}

#[derive(Default)]
struct FakeSpawner {
    spawned: AtomicUsize,
    fail: AtomicBool,
    processes: Mutex<Vec<(Arc<AtomicBool>, Arc<AtomicBool>)>>,
}

impl FakeSpawner {
    fn spawned(&self) -> usize {
        self.spawned.load(Ordering::SeqCst)
    }
    fn crash(&self, n: usize) {
        self.processes.lock().unwrap()[n]
            .0
            .store(true, Ordering::SeqCst);
    }
    fn close(&self, n: usize) {
        self.processes.lock().unwrap()[n]
            .1
            .store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl ProviderFactory for FakeSpawner {
    async fn dial(&self, _req: DialRequest<'_>) -> Result<LiveProvider, EngineError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(EngineError::Spawn("github".into(), "boom".into()));
        }
        self.spawned.fetch_add(1, Ordering::SeqCst);
        let crashed = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicBool::new(false));
        self.processes
            .lock()
            .unwrap()
            .push((Arc::clone(&crashed), Arc::clone(&closed)));
        Ok(LiveProvider {
            transport: Box::new(FakeTransport { crashed, closed }),
            conn: Box::new(FakeProvider),
            schema: empty_schema(),
        })
    }
}

fn config(max: usize, acquire_timeout_ms: u64) -> ProviderPoolConfig {
    ProviderPoolConfig {
        enabled: true,
        max_processes: NonZeroUsize::new(max).unwrap(),
        idle_ttl_secs: 300,
        acquire_timeout_ms,
    }
}

fn pool(spawner: &Arc<FakeSpawner>, cfg: ProviderPoolConfig) -> PooledProviderFactory {
    PooledProviderFactory::new(Arc::clone(spawner) as Arc<dyn ProviderFactory>, cfg)
        .with_version_resolver(Arc::new(|_| Some("6.2.1".to_string())))
}

fn github() -> ProviderInstance {
    ProviderInstance::default_instance("github").unwrap()
}

async fn checkout(pool: &PooledProviderFactory, token: &str) -> Result<LiveProvider, EngineError> {
    let instance = github();
    let config = serde_json::json!({ "token": token });
    pool.dial(DialRequest {
        workspace_dir: Path::new("/nonexistent"),
        terraform_version: "1.9.0",
        instance: &instance,
        config_json: &config,
    })
    .await
}

async fn lease(pool: &PooledProviderFactory, token: &str) -> LiveProvider {
    match checkout(pool, token).await {
        Ok(lp) => lp,
        Err(e) => panic!("checkout refused: {e}"),
    }
}

#[tokio::test]
async fn fifty_plans_of_one_key_start_one_process() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(4, 1_000));
    for _ in 0..50 {
        let mut lp = lease(&pool, "a").await;
        assert!(lp.provider_mut().get_schema().await.is_ok());
    }
    assert_eq!(spawner.spawned(), 1);
    assert_eq!(
        pool.stats(),
        PoolStats {
            live: 1,
            idle: 1,
            spawned: 1
        }
    );
}

#[tokio::test]
async fn a_held_lease_is_never_shared() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(4, 1_000));
    let first = lease(&pool, "a").await;
    let second = lease(&pool, "a").await;
    assert_eq!(spawner.spawned(), 2);
    drop((first, second));
    assert_eq!(pool.stats().idle, 2);
    let _third = lease(&pool, "a").await;
    assert_eq!(spawner.spawned(), 2);
}

#[tokio::test]
async fn another_config_digest_is_another_process() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(4, 1_000));
    drop(lease(&pool, "a").await);
    drop(lease(&pool, "b").await);
    drop(lease(&pool, "a").await);
    assert_eq!(spawner.spawned(), 2);
}

#[tokio::test]
async fn a_process_that_dies_while_leased_is_replaced() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(4, 1_000));
    let lp = lease(&pool, "a").await;
    assert!(lp.transport().crash_summary().is_none());
    assert!(lp.transport().close_reason().is_none());
    spawner.crash(0);
    assert!(lp.transport().crash_summary().is_some());
    drop(lp);
    assert_eq!(pool.stats().live, 0);
    let lp = lease(&pool, "a").await;
    assert!(lp.transport().close_reason().is_none());
    assert_eq!(spawner.spawned(), 2);
}

#[tokio::test]
async fn a_process_that_dies_while_idle_is_replaced_on_checkout() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(4, 1_000));
    drop(lease(&pool, "a").await);
    spawner.close(0);
    let lp = lease(&pool, "a").await;
    assert!(lp.transport().close_reason().is_none());
    assert_eq!(spawner.spawned(), 2);
    assert_eq!(pool.stats().live, 1);
}

#[tokio::test]
async fn the_bound_refuses_a_checkout_when_every_process_is_leased() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(2, 50));
    let _a = lease(&pool, "a").await;
    let _b = lease(&pool, "b").await;
    match checkout(&pool, "c").await {
        Ok(_) => panic!("a third process must not start past max_processes 2"),
        Err(EngineError::ProviderPoolExhausted {
            provider,
            max_processes,
            waited_ms,
        }) => {
            assert_eq!(provider, "github");
            assert_eq!(max_processes, 2);
            assert_eq!(waited_ms, 50);
        }
        Err(e) => panic!("wrong refusal: {e}"),
    }
    assert_eq!(spawner.spawned(), 2);
    assert_eq!(pool.stats().live, 2);
}

#[tokio::test]
async fn an_idle_process_of_another_key_is_evicted_at_the_bound() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(1, 50));
    drop(lease(&pool, "a").await);
    let _b = lease(&pool, "b").await;
    assert_eq!(spawner.spawned(), 2);
    assert_eq!(
        pool.stats(),
        PoolStats {
            live: 1,
            idle: 0,
            spawned: 2
        }
    );
}

#[tokio::test]
async fn a_waiting_checkout_proceeds_when_a_lease_returns() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = Arc::new(pool(&spawner, config(1, 5_000)));
    let held = lease(&pool, "a").await;
    let waiter = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move { checkout(&pool, "a").await.is_ok() })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiter.is_finished());
    drop(held);
    assert!(waiter.await.unwrap());
    assert_eq!(spawner.spawned(), 1);
}

#[tokio::test]
async fn an_idle_process_past_its_ttl_is_reaped() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(4, 1_000));
    drop(lease(&pool, "a").await);
    let now = Instant::now();
    assert_eq!(pool.reap_idle_at(now + Duration::from_secs(10)), 0);
    assert_eq!(pool.stats().live, 1);
    assert_eq!(pool.reap_idle_at(now + Duration::from_secs(301)), 1);
    assert_eq!(pool.stats().live, 0);
    drop(lease(&pool, "a").await);
    assert_eq!(spawner.spawned(), 2);
}

#[tokio::test]
async fn the_reaper_task_stops_idle_processes() {
    let spawner = Arc::new(FakeSpawner::default());
    let mut cfg = config(4, 1_000);
    cfg.idle_ttl_secs = 0;
    let pool = Arc::new(pool(&spawner, cfg));
    drop(lease(&pool, "a").await);
    let reaper = pool.spawn_reaper(Duration::from_millis(5));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(pool.stats().live, 0);
    drop(pool);
    tokio::time::timeout(Duration::from_secs(1), reaper)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_failed_dial_frees_its_reservation() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(1, 50));
    spawner.fail.store(true, Ordering::SeqCst);
    assert!(checkout(&pool, "a").await.is_err());
    assert_eq!(pool.stats().live, 0);
    spawner.fail.store(false, Ordering::SeqCst);
    drop(lease(&pool, "a").await);
    assert_eq!(spawner.spawned(), 1);
}

#[tokio::test]
async fn an_unresolved_version_is_not_pooled() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(1, 50)).with_version_resolver(Arc::new(|_| None));
    drop(lease(&pool, "a").await);
    drop(lease(&pool, "a").await);
    assert_eq!(spawner.spawned(), 2);
    assert_eq!(pool.stats().live, 0);
}

#[test]
fn the_pool_is_off_by_default_and_off_returns_the_inner_factory() {
    let parsed: ProviderPoolConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed, ProviderPoolConfig::default());
    assert!(!parsed.enabled);
    let inner: Arc<dyn ProviderFactory> = Arc::new(FakeSpawner::default());
    let chosen = parsed.factory(Arc::clone(&inner));
    assert_eq!(
        Arc::as_ptr(&chosen).cast::<()>(),
        Arc::as_ptr(&inner).cast::<()>()
    );
    let on = ProviderPoolConfig::enabled().factory(Arc::clone(&inner));
    assert_ne!(
        Arc::as_ptr(&on).cast::<()>(),
        Arc::as_ptr(&inner).cast::<()>()
    );
}

#[test]
fn a_zero_bound_and_an_unknown_field_are_refused() {
    assert!(serde_json::from_str::<ProviderPoolConfig>(r#"{"max_processes":0}"#).is_err());
    assert!(serde_json::from_str::<ProviderPoolConfig>(r#"{"max_procs":4}"#).is_err());
}

#[test]
fn the_defaults_are_off_eight_processes_five_minutes_one_minute() {
    let d = ProviderPoolConfig::default();
    assert!(!d.enabled);
    assert_eq!(d.max_processes.get(), 8);
    assert_eq!(d.idle_ttl_secs, 300);
    assert_eq!(d.acquire_timeout_ms, 60_000);
}

#[tokio::test]
async fn a_dead_idle_slot_is_skipped_and_uncounted_on_take() {
    let spawner = Arc::new(FakeSpawner::default());
    let mut st = State::default();
    for _ in 0..2 {
        let lp = spawner
            .dial(DialRequest {
                workspace_dir: Path::new("/nonexistent"),
                terraform_version: "1.9.0",
                instance: &github(),
                config_json: &serde_json::json!({}),
            })
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        st.live += 1;
        st.idle.entry(key()).or_default().push(Slot {
            conn: lp.conn,
            transport: Arc::from(lp.transport),
            schema: lp.schema,
            idle_since: Instant::now(),
        });
    }
    spawner.crash(1);
    let mut dead = Vec::new();
    assert!(st.take_alive(&key(), &mut dead).is_some());
    assert_eq!(dead.len(), 1);
    assert_eq!(st.live, 1);
    assert!(st.idle.is_empty());
}

fn key() -> PoolKey {
    PoolKey {
        provider: "github".into(),
        version: "6.2.1".into(),
        config_digest: "d".into(),
        terraform_version: "1.9.0".into(),
    }
}

#[tokio::test]
async fn a_waiter_gets_room_when_a_leased_process_dies() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = Arc::new(pool(&spawner, config(1, 5_000)));
    let held = lease(&pool, "a").await;
    let waiter = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move { checkout(&pool, "b").await.is_ok() })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiter.is_finished());
    spawner.crash(0);
    drop(held);
    assert!(waiter.await.unwrap());
    assert_eq!(spawner.spawned(), 2);
    assert_eq!(pool.stats().live, 1);
}

#[tokio::test]
async fn every_provider_call_reaches_the_pooled_process() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(1, 50));
    let mut lp = lease(&pool, "a").await;
    let p = lp.provider_mut();
    let v = DynamicValue::from_json(&serde_json::Value::Null, &CtyType::String).unwrap();
    let mut seen = Vec::new();
    let mut note = |r: Result<(), ProviderError>| seen.push(r.unwrap_err().to_string());
    note(p.configure(&v, "1.9.0").await);
    note(p.plan_resource_change("t", &v, &v, &v).await.map(|_| ()));
    note(p.apply_resource_change("t", &v, &v, &v).await.map(|_| ()));
    note(p.read_resource("t", &v).await.map(|_| ()));
    note(p.read_data_source("t", &v).await.map(|_| ()));
    note(p.import_resource_state("t", "id").await.map(|_| ()));
    note(p.upgrade_resource_state("t", 0, b"{}").await.map(|_| ()));
    for (got, want) in seen.iter().zip([
        "configure",
        "plan_resource_change",
        "apply_resource_change",
        "read_resource",
        "read_data_source",
        "import_resource_state",
        "upgrade_resource_state",
    ]) {
        assert!(got.contains(want), "{got} does not name {want}");
    }
    assert_eq!(seen.len(), 7);
}

#[tokio::test]
async fn a_closed_channel_is_seen_through_the_lease_and_not_returned() {
    let spawner = Arc::new(FakeSpawner::default());
    let pool = pool(&spawner, config(2, 50));
    let lp = lease(&pool, "a").await;
    spawner.close(0);
    assert_eq!(
        lp.transport().close_reason().as_deref(),
        Some("channel closed")
    );
    drop(lp);
    assert_eq!(pool.stats().live, 0);
}
