//! `DnsRecordReconciler` — declarative DNS record reconciler.
//! Demonstrates the "list-then-diff with composite primary key"
//! API style (Cloudflare, Route53, Porkbun all fit).
//!
//! A record's identity = `(zone, name, type)`. Updates replace the
//! `value` + `ttl`. Adding the same name+type with a different
//! value triggers an update; adding a record with a new name or
//! type triggers a create.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Action, AppliedChange, ChangeSeverity, Outcome, Plan, Reconciler, ReconcilerError,
    build_outcome, change_with_severity,
};

// ── Typed record shape ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordKey {
    pub zone: String,
    pub name: String,
    /// "A", "CNAME", "MX", "TXT", …
    pub r#type: String,
}

impl RecordKey {
    /// Address encoding uses `:` as separator since DNS zones and
    /// names commonly contain `.` characters. `dns_record:<zone>:<name>:<type>`.
    pub fn address(&self) -> String {
        format!(
            "dns_record:{}:{}:{}",
            self.zone,
            self.name,
            self.r#type.to_lowercase()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordValue {
    pub value: String,
    pub ttl: u32,
    /// Whether the record routes through the provider's proxy
    /// (Cloudflare orange-cloud, Route53 alias targets, etc.).
    #[serde(default)]
    pub proxied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub key: RecordKey,
    pub value: RecordValue,
}

// ── Client abstraction ────────────────────────────────────────────

#[async_trait]
pub trait DnsClient: Send + Sync {
    async fn list_records(&self) -> Result<Vec<Record>, String>;
    async fn create_record(&self, r: &Record) -> Result<(), String>;
    async fn update_record(&self, r: &Record) -> Result<(), String>;
    async fn delete_record(&self, k: &RecordKey) -> Result<(), String>;
}

#[derive(Default)]
pub struct MockDnsClient {
    state: Mutex<HashMap<RecordKey, RecordValue>>,
}

impl MockDnsClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_records(records: Vec<Record>) -> Self {
        let map: HashMap<_, _> = records.into_iter().map(|r| (r.key, r.value)).collect();
        Self {
            state: Mutex::new(map),
        }
    }

    pub fn snapshot(&self) -> HashMap<RecordKey, RecordValue> {
        self.state.lock().unwrap().clone()
    }
}

#[async_trait]
impl DnsClient for MockDnsClient {
    async fn list_records(&self) -> Result<Vec<Record>, String> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| Record {
                key: k.clone(),
                value: v.clone(),
            })
            .collect())
    }
    async fn create_record(&self, r: &Record) -> Result<(), String> {
        self.state
            .lock()
            .unwrap()
            .insert(r.key.clone(), r.value.clone());
        Ok(())
    }
    async fn update_record(&self, r: &Record) -> Result<(), String> {
        self.state
            .lock()
            .unwrap()
            .insert(r.key.clone(), r.value.clone());
        Ok(())
    }
    async fn delete_record(&self, k: &RecordKey) -> Result<(), String> {
        self.state.lock().unwrap().remove(k);
        Ok(())
    }
}

// ── Reconciler ────────────────────────────────────────────────────

pub struct DnsRecordReconciler<C: DnsClient> {
    client: C,
}

impl<C: DnsClient> DnsRecordReconciler<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
    pub fn client(&self) -> &C {
        &self.client
    }
}

/// Severity: most DNS changes are functional; CNAME re-pointing
/// affects routing → critical when value swaps. Keep simple:
/// updates default to Functional, but a change that swaps a CNAME
/// target is Critical (production traffic pointed elsewhere).
fn dns_severity(action: Action, k: &RecordKey) -> ChangeSeverity {
    match action {
        Action::Delete | Action::Replace => ChangeSeverity::Critical,
        Action::Create => ChangeSeverity::Functional,
        Action::Update if k.r#type.to_uppercase() == "CNAME" => ChangeSeverity::Critical,
        Action::Update => ChangeSeverity::Functional,
        Action::NoOp => ChangeSeverity::Cosmetic,
    }
}

#[async_trait]
impl<C: DnsClient> Reconciler for DnsRecordReconciler<C> {
    fn kind(&self) -> &'static str {
        "dns_record"
    }

    async fn read_state(&self) -> Result<Value, ReconcilerError> {
        let records = self
            .client
            .list_records()
            .await
            .map_err(ReconcilerError::ReadState)?;
        serde_json::to_value(records).map_err(|e| ReconcilerError::ReadState(e.to_string()))
    }

    fn compute_plan(&self, config: &Value, state: &Value) -> Result<Plan, ReconcilerError> {
        let desired_vec: Vec<Record> = serde_json::from_value(config.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("config: {e}")))?;
        let current_vec: Vec<Record> = serde_json::from_value(state.clone())
            .map_err(|e| ReconcilerError::ComputePlan(format!("state: {e}")))?;

        // Index by composite key.
        let desired: HashMap<RecordKey, RecordValue> =
            desired_vec.into_iter().map(|r| (r.key, r.value)).collect();
        let current: HashMap<RecordKey, RecordValue> =
            current_vec.into_iter().map(|r| (r.key, r.value)).collect();

        let mut all_keys: Vec<RecordKey> = desired.keys().chain(current.keys()).cloned().collect();
        all_keys.sort_by_key(|k| (k.zone.clone(), k.name.clone(), k.r#type.clone()));
        all_keys.dedup();

        let mut changes = vec![];
        for key in all_keys {
            let address = key.address();
            match (current.get(&key), desired.get(&key)) {
                (None, Some(v)) => changes.push(change_with_severity(
                    address,
                    Action::Create,
                    dns_severity(Action::Create, &key),
                    None,
                    Some(serde_json::to_value(v).unwrap()),
                )),
                (Some(v), None) => changes.push(change_with_severity(
                    address,
                    Action::Delete,
                    dns_severity(Action::Delete, &key),
                    Some(serde_json::to_value(v).unwrap()),
                    None,
                )),
                (Some(a), Some(b)) if a != b => changes.push(change_with_severity(
                    address,
                    Action::Update,
                    dns_severity(Action::Update, &key),
                    Some(serde_json::to_value(a).unwrap()),
                    Some(serde_json::to_value(b).unwrap()),
                )),
                _ => {}
            }
        }

        Ok(Plan::new(self.kind(), changes))
    }

    async fn apply(&self, plan: &Plan) -> Result<Outcome, ReconcilerError> {
        let started_at = Utc::now();
        let mut applied = vec![];
        let mut failed = vec![];

        for c in &plan.changes {
            let res: Result<(), String> = match c.action {
                Action::Create | Action::Update | Action::Replace => {
                    let r: Result<Record, String> = c
                        .after
                        .as_ref()
                        .ok_or_else(|| "missing after".to_string())
                        .and_then(|v| {
                            // The `after` payload from compute_plan is the
                            // RecordValue. Combine with the address-derived
                            // key (we re-parse the address to recover it).
                            let value: RecordValue = serde_json::from_value(v.clone())
                                .map_err(|e| format!("decode after: {e}"))?;
                            let key = parse_address(&c.address)
                                .ok_or_else(|| format!("bad address: {}", c.address))?;
                            Ok(Record { key, value })
                        });
                    match r {
                        Ok(rec) => {
                            if matches!(c.action, Action::Create) {
                                self.client.create_record(&rec).await
                            } else {
                                self.client.update_record(&rec).await
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
                Action::Delete => match parse_address(&c.address) {
                    Some(key) => self.client.delete_record(&key).await,
                    None => Err(format!("bad address: {}", c.address)),
                },
                Action::NoOp => continue,
            };
            match res {
                Ok(()) => applied.push(AppliedChange {
                    address: c.address.clone(),
                    action: c.action,
                }),
                Err(e) => failed.push(crate::FailedChange {
                    address: c.address.clone(),
                    action: c.action,
                    error: e,
                }),
            }
        }

        Ok(build_outcome(plan, applied, failed, started_at))
    }
}

/// `dns_record:<zone>:<name>:<type>` → `RecordKey`. The `:`
/// separator avoids ambiguity with dot-containing zones/names.
fn parse_address(addr: &str) -> Option<RecordKey> {
    let rest = addr.strip_prefix("dns_record:")?;
    let parts: Vec<&str> = rest.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    Some(RecordKey {
        zone: parts[0].to_string(),
        name: parts[1].to_string(),
        r#type: parts[2].to_uppercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(zone: &str, name: &str, ty: &str, value: &str) -> Record {
        Record {
            key: RecordKey {
                zone: zone.into(),
                name: name.into(),
                r#type: ty.into(),
            },
            value: RecordValue {
                value: value.into(),
                ttl: 300,
                proxied: false,
            },
        }
    }

    #[tokio::test]
    async fn create_plan_for_new_record() {
        let r = DnsRecordReconciler::new(MockDnsClient::new());
        let config = serde_json::to_value(vec![rec("ex.com", "api", "A", "1.2.3.4")]).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].action, Action::Create);
    }

    #[tokio::test]
    async fn apply_creates_record() {
        let r = DnsRecordReconciler::new(MockDnsClient::new());
        let want = rec("ex.com", "api", "A", "1.2.3.4");
        let config = serde_json::to_value(vec![want.clone()]).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        let outcome = r.apply(&plan).await.unwrap();
        assert!(outcome.fully_succeeded());
        let live = r.client().snapshot();
        assert_eq!(live.get(&want.key), Some(&want.value));
    }

    #[tokio::test]
    async fn cname_update_is_critical_severity() {
        let initial = vec![rec("ex.com", "www", "CNAME", "old.target.")];
        let r = DnsRecordReconciler::new(MockDnsClient::with_records(initial));
        let config =
            serde_json::to_value(vec![rec("ex.com", "www", "CNAME", "new.target.")]).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.change_count(), 1);
        assert_eq!(plan.changes[0].action, Action::Update);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Critical);
    }

    #[tokio::test]
    async fn a_record_update_is_functional_severity() {
        let initial = vec![rec("ex.com", "api", "A", "1.1.1.1")];
        let r = DnsRecordReconciler::new(MockDnsClient::with_records(initial));
        let config = serde_json::to_value(vec![rec("ex.com", "api", "A", "2.2.2.2")]).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Functional);
    }

    #[tokio::test]
    async fn delete_for_removed_record() {
        let initial = vec![rec("ex.com", "old", "A", "1.1.1.1")];
        let r = DnsRecordReconciler::new(MockDnsClient::with_records(initial));
        let config = serde_json::to_value(Vec::<Record>::new()).unwrap();
        let state = r.read_state().await.unwrap();
        let plan = r.compute_plan(&config, &state).unwrap();
        assert_eq!(plan.changes[0].action, Action::Delete);
        assert_eq!(plan.changes[0].severity, ChangeSeverity::Critical);
    }

    #[test]
    fn parse_address_round_trips() {
        let key = RecordKey {
            zone: "ex.com".into(),
            name: "api".into(),
            r#type: "A".into(),
        };
        let addr = key.address();
        let parsed = parse_address(&addr).unwrap();
        assert_eq!(parsed.zone, key.zone);
        assert_eq!(parsed.name, key.name);
        assert_eq!(parsed.r#type, key.r#type);
    }
}
