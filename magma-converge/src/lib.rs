//! magma-converge — universal state-convergence substrate.
//!
//! One typed `Reconciler` trait that fits any declarative API.
//! Terraform/OpenTofu is one shape. Kubernetes is another. The same
//! diff-then-apply pattern lives behind dozens of APIs we already
//! touch: GitHub, DNS, Helm, Slack, PagerDuty, Datadog, Grafana,
//! Linear, Stripe, Vault, Auth0, …
//!
//! Every reconciler obeys the same trait laws (see `tests/laws`).
//! Every reconciler shares typed `Plan` / `Outcome` / `Change`
//! shapes so downstream consumers (drift classification,
//! attestation, K8s events) don't care which kind produced them.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md`.

#![deny(unsafe_code)]

pub mod aggregator;
pub mod apply;
pub mod artifact;
pub mod backend_error;
pub mod blobstore;
pub mod condition;
pub mod decision;
pub mod dns;
pub mod drift;
pub mod engine;
pub mod github;
pub mod health;
pub mod helm;
pub mod inmemory;
pub mod inventory;
pub mod manifest;
pub mod meta;
pub mod outcome;
pub mod policy;
pub mod refspec;
pub mod selector;
pub mod terraform;
pub mod validate;
pub mod vault;
pub mod webhook;

pub use aggregator::Aggregator;
pub use apply::{ApplyCounts, ApplyDiff, ApplyOutcome, ApplyReport, ApplyStatus};
pub use artifact::{Artifact, ArtifactDigest, DigestAlgo, DigestError, Provenance};
pub use backend_error::BackendError;
pub use blobstore::{BlobMetadata, BlobStoreBackend, BlobStoreError, InMemoryBlobStore};
pub use condition::{Condition, ConditionSet, ConditionStatus};
pub use decision::Decision;
pub use drift::DriftPolicy;
pub use engine::ConvergeEngine;
pub use health::{
    AlwaysReady, ChainedHealthCheck, ClosureCheck, HealthCheck, HealthCounts, HealthReport,
    HealthReportExt, NeverReady, ReadyState,
};
pub use inventory::{Inventory, InventoryDiff, ResourceRef};
pub use manifest::{Manifest, TypeMeta};
pub use meta::{ObjectMeta, OwnerReference};
pub use outcome::{OutcomeLattice, best_of, worst_of};
pub use policy::CascadePolicy;
pub use refspec::{RefSpec, RefSpecParseError};
pub use selector::{LabelSelector, LabelSelectorOperator, LabelSelectorRequirement};
pub use validate::{Validate, Violation};
pub use webhook::{
    HeaderTokenValidator, NoOpValidator, WebhookError, WebhookEvent, WebhookKind, WebhookRequest,
    WebhookValidator,
};

// == Convergence trait + typed border: RE-HOMED to shigoto-types ======
//
// The Reconciler trait + its Plan/Outcome/Change/Action/PlanId/Severity/
// AppliedChange/FailedChange/ReconcilerError/ApplyMetrics border + the
// build_outcome/change/change_with_severity helpers were lifted VERBATIM to
// lightweight shigoto-types::converge (2026-06-05, theory/CONVERGENCE-ADOPTION.md)
// -- the third leg of the CascadePolicy/Decision re-home arc. The border is
// serde-only, so lightweight controllers adopt the trait without dragging
// magma's IaC closure (tonic/rustls/aws-lc-rs/gen-platform). Re-exported here so
// magma_converge::{Reconciler,Plan,Outcome,...} + the engine/terraform/github/dns/
// vault/helm/inmemory impls are byte-for-byte untouched -- identical shim shape to
// the sibling decision.rs / policy.rs re-exports.
pub use shigoto_types::converge::{
    Action, AppliedChange, ApplyMetrics, Change, ChangeSeverity, FailedChange, NoMetrics, Outcome,
    Plan, PlanId, Reconciler, ReconcilerError, SharedReconciler, build_outcome, change,
    change_with_severity,
};
