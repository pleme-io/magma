use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use magma_apply::engine::{
    ApplyContext, ReadConcurrency, RefreshOptions, RefreshScope, RoutingProviderFactory,
    affected_addresses, refresh_then_plan_with,
};
use magma_cty::{CtyType, DynamicValue};
use magma_plugin::provider::{PlannedChange, Provider, ProviderError, ProviderSchema};
use magma_types::{
    Action, Coverage, InstanceStatus, ModulePath, Plan, ProviderReference, ResourceAddress,
    ResourceKind, ResourceTypeId, State, StateInstance, StateResource,
};

const FIXTURE: usize = 2_000;
const LATENCY: Duration = Duration::from_millis(5);

#[derive(Clone)]
struct SlowReads {
    reads: Arc<AtomicUsize>,
    forkable: bool,
}

fn implied() -> CtyType {
    CtyType::Object(BTreeMap::from([
        ("name".to_string(), CtyType::String),
        ("description".to_string(), CtyType::String),
    ]))
}

#[async_trait::async_trait]
impl Provider for SlowReads {
    async fn get_schema(&mut self) -> Result<ProviderSchema, ProviderError> {
        Ok(ProviderSchema {
            provider_config: CtyType::Object(BTreeMap::new()),
            resources: BTreeMap::from([("github_repository".to_string(), implied())]),
            data_sources: BTreeMap::new(),
            resource_versions: BTreeMap::new(),
        })
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
        Err(ProviderError::NoNewState)
    }
    async fn read_resource(
        &mut self,
        _: &str,
        current: &DynamicValue,
    ) -> Result<Option<DynamicValue>, ProviderError> {
        tokio::time::sleep(LATENCY).await;
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(Some(current.clone()))
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
    fn fork(&self) -> Option<Box<dyn Provider>> {
        self.forkable.then(|| Box::new(self.clone()) as Box<dyn Provider>)
    }
}

fn address(name: &str) -> ResourceAddress {
    ResourceAddress {
        module: ModulePath::root(),
        kind: ResourceKind::Managed,
        type_id: ResourceTypeId("github_repository".into()),
        name: name.into(),
        key: None,
    }
}

fn repo(i: usize) -> String {
    let mut s = String::from("repo_");
    s.push_str(&i.to_string());
    s
}

fn fixture(n: usize, edited: Option<usize>) -> (magma_config::Config, State) {
    let mut resources = serde_json::Map::new();
    let mut rows = Vec::with_capacity(n);
    for i in 0..n {
        let name = repo(i);
        let description = if edited == Some(i) { "edited" } else { "d" };
        resources.insert(
            name.clone(),
            serde_json::json!({ "name": name.clone(), "description": description }),
        );
        rows.push(StateResource {
            address: address(&name),
            provider: ProviderReference {
                source: "integrations/github".into(),
                name: "github".into(),
                alias: None,
            },
            instances: vec![StateInstance {
                index_key: None,
                schema_version: 0,
                attributes: serde_json::json!({ "name": name, "description": "d" }),
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
        resources: rows,
    };
    (cfg, state)
}

struct Run {
    plan: Plan,
    reads: usize,
    elapsed: Duration,
}

async fn run(edited: Option<usize>, options: RefreshOptions, forkable: bool) -> Run {
    let (cfg, mut state) = fixture(FIXTURE, edited);
    let reads = Arc::new(AtomicUsize::new(0));
    let provider = SlowReads {
        reads: reads.clone(),
        forkable,
    };
    let factory = RoutingProviderFactory::new()
        .with_native("github", move || Box::new(provider.clone()) as Box<dyn Provider>);
    let td = tempfile::tempdir().expect("tempdir");
    let ctx = ApplyContext::new(td.path().to_path_buf()).with_provider_factory(Arc::new(factory));
    let started = Instant::now();
    let (plan, report) = refresh_then_plan_with(&cfg, &mut state, Some(&ctx), options)
        .await
        .expect("plan computes");
    let elapsed = started.elapsed();
    let report = report.expect("a context produces a report");
    assert_eq!(report.kept_on_error, 0);
    assert_eq!(state.resources.len(), FIXTURE);
    Run {
        plan,
        reads: reads.load(Ordering::SeqCst),
        elapsed,
    }
}

fn changes(plan: &Plan) -> usize {
    plan.resource_changes
        .iter()
        .filter(|c| c.action != Action::NoOp)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_concurrent_reads_beat_sequential_on_two_thousand_resources() {
    let sequential = run(
        None,
        RefreshOptions {
            scope: RefreshScope::Full,
            concurrency: ReadConcurrency::Sequential,
        },
        true,
    )
    .await;
    let concurrent = run(None, RefreshOptions::default(), true).await;
    eprintln!(
        "full refresh of {FIXTURE}: sequential {:?}, bounded(8) {:?}",
        sequential.elapsed, concurrent.elapsed
    );
    assert_eq!(sequential.reads, FIXTURE);
    assert_eq!(concurrent.reads, FIXTURE);
    assert_eq!(changes(&sequential.plan), 0);
    assert_eq!(changes(&concurrent.plan), 0);
    assert_eq!(
        sequential.plan.observation.coverage(),
        concurrent.plan.observation.coverage()
    );
    assert!(concurrent.elapsed * 4 < sequential.elapsed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_provider_that_cannot_fork_reads_sequentially() {
    let run = run(None, RefreshOptions::default(), false).await;
    assert_eq!(run.reads, FIXTURE);
    assert_eq!(changes(&run.plan), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_resource_spec_change_reads_only_that_resource() {
    let full = run(Some(7), RefreshOptions::default(), true).await;
    let affected = run(
        Some(7),
        RefreshOptions {
            scope: RefreshScope::Affected,
            concurrency: ReadConcurrency::default(),
        },
        true,
    )
    .await;
    eprintln!(
        "one changed address of {FIXTURE}: full {:?} ({} reads), affected {:?} ({} reads)",
        full.elapsed, full.reads, affected.elapsed, affected.reads
    );
    assert_eq!(affected.reads, 1);
    assert_eq!(changes(&full.plan), 1);
    assert_eq!(changes(&affected.plan), 1);
    assert_eq!(affected.plan.observation.coverage(), Coverage::Partial);
    assert_eq!(full.plan.observation.coverage(), Coverage::Complete);
}

#[test]
fn dependents_of_a_changed_address_are_affected_transitively() {
    let (cfg, state) = fixture(4, Some(0));
    let plan = magma_plan::plan(&cfg, &state).expect("plan computes");
    let mut json = serde_json::to_value(&plan).expect("plan serializes");
    let refs = [
        (1, "${github_repository.repo_0.name}"),
        (2, "${github_repository.repo_1.name}"),
    ];
    if let Some(changes) = json["resource_changes"].as_array_mut() {
        for c in changes.iter_mut() {
            for (i, r) in refs {
                if c["address"]["name"] == serde_json::json!(repo(i)) {
                    c["after"]["description"] = serde_json::json!(r);
                }
            }
        }
    }
    let plan: Plan = serde_json::from_value(json).expect("plan deserializes");
    let got = affected_addresses(&plan);
    assert!(got.contains(&address(&repo(0))));
    assert!(got.contains(&address(&repo(1))));
    assert!(got.contains(&address(&repo(2))));
    assert!(!got.contains(&address(&repo(3))));
}
