use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use magma_cty::DynamicValue;
use magma_plugin::ProviderCrash;
use magma_plugin::provider::{PlannedChange, Provider, ProviderError, ProviderSchema};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::engine::{DialRequest, EngineError, LiveProvider, ProviderFactory, ProviderTransport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPoolConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "ProviderPoolConfig::default_max_processes")]
    pub max_processes: NonZeroUsize,
    #[serde(default = "ProviderPoolConfig::default_idle_ttl_secs")]
    pub idle_ttl_secs: u64,
    #[serde(default = "ProviderPoolConfig::default_acquire_timeout_ms")]
    pub acquire_timeout_ms: u64,
}

impl ProviderPoolConfig {
    fn default_max_processes() -> NonZeroUsize {
        NonZeroUsize::new(8).unwrap_or(NonZeroUsize::MIN)
    }
    fn default_idle_ttl_secs() -> u64 {
        300
    }
    fn default_acquire_timeout_ms() -> u64 {
        60_000
    }

    #[must_use]
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn factory(&self, inner: Arc<dyn ProviderFactory>) -> Arc<dyn ProviderFactory> {
        if self.enabled {
            Arc::new(PooledProviderFactory::new(inner, self.clone()))
        } else {
            inner
        }
    }

    fn idle_ttl(&self) -> Duration {
        Duration::from_secs(self.idle_ttl_secs)
    }

    fn acquire_timeout(&self) -> Duration {
        Duration::from_millis(self.acquire_timeout_ms)
    }
}

impl Default for ProviderPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_processes: Self::default_max_processes(),
            idle_ttl_secs: Self::default_idle_ttl_secs(),
            acquire_timeout_ms: Self::default_acquire_timeout_ms(),
        }
    }
}

pub type ProviderVersionResolver = Arc<dyn Fn(&DialRequest<'_>) -> Option<String> + Send + Sync>;

#[must_use]
pub fn located_binary_version() -> ProviderVersionResolver {
    Arc::new(|req: &DialRequest<'_>| {
        magma_providers::locate_provider(req.workspace_dir, req.instance.name())
            .ok()
            .map(|p| p.display().to_string())
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PoolKey {
    pub provider: String,
    pub version: String,
    pub config_digest: String,
    pub terraform_version: String,
}

impl PoolKey {
    fn of(req: &DialRequest<'_>, version: String) -> Self {
        let bytes = serde_json::to_vec(req.config_json).unwrap_or_default();
        Self {
            provider: req.instance.name().to_string(),
            version,
            config_digest: blake3::hash(&bytes).to_hex().to_string(),
            terraform_version: req.terraform_version.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    pub live: usize,
    pub idle: usize,
    pub spawned: u64,
}

struct Slot {
    conn: Box<dyn Provider>,
    transport: Arc<dyn ProviderTransport>,
    schema: ProviderSchema,
    idle_since: Instant,
}

impl Slot {
    fn alive(&self) -> bool {
        is_alive(self.transport.as_ref())
    }
}

fn is_alive(transport: &dyn ProviderTransport) -> bool {
    transport.crash_summary().is_none() && transport.close_reason().is_none()
}

#[derive(Default)]
struct State {
    idle: HashMap<PoolKey, Vec<Slot>>,
    live: usize,
}

impl State {
    fn idle_count(&self) -> usize {
        self.idle.values().map(Vec::len).sum()
    }

    fn take_alive(&mut self, key: &PoolKey, dead: &mut Vec<Slot>) -> Option<Slot> {
        let slots = self.idle.get_mut(key)?;
        let mut found = None;
        while let Some(slot) = slots.pop() {
            if slot.alive() {
                found = Some(slot);
                break;
            }
            self.live -= 1;
            dead.push(slot);
        }
        if slots.is_empty() {
            self.idle.remove(key);
        }
        found
    }

    fn evict_oldest(&mut self) -> Option<Slot> {
        let key = self
            .idle
            .iter()
            .filter_map(|(k, v)| v.first().map(|s| (k.clone(), s.idle_since)))
            .min_by_key(|(_, t)| *t)
            .map(|(k, _)| k)?;
        let slots = self.idle.get_mut(&key)?;
        let slot = slots.remove(0);
        if slots.is_empty() {
            self.idle.remove(&key);
        }
        Some(slot)
    }

    fn reap(&mut self, now: Instant, ttl: Duration) -> Vec<Slot> {
        let mut reaped = Vec::new();
        self.idle.retain(|_, slots| {
            let (keep, gone): (Vec<Slot>, Vec<Slot>) = slots
                .drain(..)
                .partition(|s| s.alive() && now.saturating_duration_since(s.idle_since) <= ttl);
            reaped.extend(gone);
            *slots = keep;
            !slots.is_empty()
        });
        self.live -= reaped.len();
        reaped
    }
}

struct Shared {
    config: ProviderPoolConfig,
    state: Mutex<State>,
    freed: Notify,
    spawned: AtomicU64,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn give_back(&self, key: PoolKey, slot: Slot) {
        let dead = {
            let mut st = self.lock();
            if slot.alive() {
                st.idle.entry(key).or_default().push(slot);
                None
            } else {
                st.live -= 1;
                Some(slot)
            }
        };
        drop(dead);
        self.freed.notify_waiters();
    }

    fn release_reservation(&self) {
        self.lock().live -= 1;
        self.freed.notify_waiters();
    }
}

enum Plan {
    Lease(Slot),
    Dial(Option<Slot>),
    Wait,
}

pub struct PooledProviderFactory {
    inner: Arc<dyn ProviderFactory>,
    resolve_version: ProviderVersionResolver,
    shared: Arc<Shared>,
}

impl PooledProviderFactory {
    #[must_use]
    pub fn new(inner: Arc<dyn ProviderFactory>, config: ProviderPoolConfig) -> Self {
        Self {
            inner,
            resolve_version: located_binary_version(),
            shared: Arc::new(Shared {
                config,
                state: Mutex::new(State::default()),
                freed: Notify::new(),
                spawned: AtomicU64::new(0),
            }),
        }
    }

    #[must_use]
    pub fn with_version_resolver(mut self, resolve: ProviderVersionResolver) -> Self {
        self.resolve_version = resolve;
        self
    }

    #[must_use]
    pub fn stats(&self) -> PoolStats {
        let st = self.shared.lock();
        PoolStats {
            live: st.live,
            idle: st.idle_count(),
            spawned: self.shared.spawned.load(Ordering::SeqCst),
        }
    }

    pub fn reap_idle_at(&self, now: Instant) -> usize {
        let reaped = self.shared.lock().reap(now, self.shared.config.idle_ttl());
        reaped.len()
    }

    pub fn reap_idle(&self) -> usize {
        self.reap_idle_at(Instant::now())
    }

    pub fn spawn_reaper(self: &Arc<Self>, every: Duration) -> tokio::task::JoinHandle<()> {
        let pool: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let Some(pool) = pool.upgrade() else { break };
                pool.reap_idle();
            }
        })
    }

    fn plan(&self, key: &PoolKey) -> Plan {
        let mut dead = Vec::new();
        let plan = {
            let mut st = self.shared.lock();
            if let Some(slot) = st.take_alive(key, &mut dead) {
                Plan::Lease(slot)
            } else if st.live < self.shared.config.max_processes.get() {
                st.live += 1;
                Plan::Dial(None)
            } else if let Some(evicted) = st.evict_oldest() {
                Plan::Dial(Some(evicted))
            } else {
                Plan::Wait
            }
        };
        drop(dead);
        plan
    }

    fn lease(&self, key: PoolKey, slot: Slot) -> LiveProvider {
        let schema = slot.schema.clone();
        LiveProvider {
            transport: Box::new(SharedTransport(Arc::clone(&slot.transport))),
            conn: Box::new(Leased {
                key: Some(key),
                slot: Some(slot),
                pool: Arc::downgrade(&self.shared),
            }),
            schema,
        }
    }
}

#[async_trait::async_trait]
impl ProviderFactory for PooledProviderFactory {
    async fn dial(&self, req: DialRequest<'_>) -> Result<LiveProvider, EngineError> {
        let Some(version) = (self.resolve_version)(&req) else {
            return self.inner.dial(req).await;
        };
        let key = PoolKey::of(&req, version);
        self.reap_idle();
        let deadline = tokio::time::Instant::now() + self.shared.config.acquire_timeout();
        loop {
            let freed = self.shared.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            match self.plan(&key) {
                Plan::Lease(slot) => return Ok(self.lease(key, slot)),
                Plan::Dial(evicted) => {
                    drop(evicted);
                    return match self.inner.dial(req).await {
                        Ok(lp) => {
                            self.shared.spawned.fetch_add(1, Ordering::SeqCst);
                            let slot = Slot {
                                conn: lp.conn,
                                transport: Arc::from(lp.transport),
                                schema: lp.schema,
                                idle_since: Instant::now(),
                            };
                            Ok(self.lease(key, slot))
                        }
                        Err(e) => {
                            self.shared.release_reservation();
                            Err(e)
                        }
                    };
                }
                Plan::Wait => {
                    if tokio::time::timeout_at(deadline, freed).await.is_err() {
                        return Err(EngineError::ProviderPoolExhausted {
                            provider: key.provider,
                            max_processes: self.shared.config.max_processes.get(),
                            waited_ms: self.shared.config.acquire_timeout_ms,
                        });
                    }
                }
            }
        }
    }
}

struct SharedTransport(Arc<dyn ProviderTransport>);

impl ProviderTransport for SharedTransport {
    fn crash_summary(&self) -> Option<ProviderCrash> {
        self.0.crash_summary()
    }
    fn close_reason(&self) -> Option<String> {
        self.0.close_reason()
    }
}

struct Leased {
    key: Option<PoolKey>,
    slot: Option<Slot>,
    pool: Weak<Shared>,
}

impl Leased {
    fn conn(&mut self) -> Result<&mut Box<dyn Provider>, ProviderError> {
        self.slot
            .as_mut()
            .map(|s| &mut s.conn)
            .ok_or_else(|| ProviderError::Transport("pooled provider already returned".into()))
    }
}

impl Drop for Leased {
    fn drop(&mut self) {
        let (Some(key), Some(mut slot)) = (self.key.take(), self.slot.take()) else {
            return;
        };
        let Some(pool) = self.pool.upgrade() else {
            return;
        };
        slot.idle_since = Instant::now();
        pool.give_back(key, slot);
    }
}

#[async_trait::async_trait]
impl Provider for Leased {
    async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
        self.conn()?.get_schema().await
    }

    async fn configure(
        &mut self,
        config: &DynamicValue,
        terraform_version: &str,
    ) -> Result<(), ProviderError> {
        self.conn()?.configure(config, terraform_version).await
    }

    async fn plan_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        proposed_new_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<PlannedChange, ProviderError> {
        self.conn()?
            .plan_resource_change(type_name, prior_state, proposed_new_state, config)
            .await
    }

    async fn apply_resource_change(
        &mut self,
        type_name: &str,
        prior_state: &DynamicValue,
        planned_state: &DynamicValue,
        config: &DynamicValue,
    ) -> Result<DynamicValue, ProviderError> {
        self.conn()?
            .apply_resource_change(type_name, prior_state, planned_state, config)
            .await
    }

    async fn read_resource(
        &mut self,
        type_name: &str,
        current_state: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        self.conn()?.read_resource(type_name, current_state).await
    }

    async fn read_data_source(
        &mut self,
        type_name: &str,
        config: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        self.conn()?.read_data_source(type_name, config).await
    }

    async fn import_resource_state(
        &mut self,
        type_name: &str,
        id: &str,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        self.conn()?.import_resource_state(type_name, id).await
    }

    async fn upgrade_resource_state(
        &mut self,
        type_name: &str,
        stored_version: i64,
        raw_json: &[u8],
    ) -> Result<DynamicValue, ProviderError> {
        self.conn()?
            .upgrade_resource_state(type_name, stored_version, raw_json)
            .await
    }
}

#[cfg(test)]
#[path = "provider_pool_tests.rs"]
mod tests;
