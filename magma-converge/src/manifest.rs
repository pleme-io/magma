//! Typed K8s object wrapper — the canonical `Manifest<Spec, Status>`
//! primitive that combines [`TypeMeta`], [`crate::ObjectMeta`], typed
//! `spec`, and typed `status` into one value.
//!
//! Capstone of the K8s object stack:
//!
//! - [`crate::ResourceRef`]    — identity (GVKNN tuple)
//! - [`crate::ObjectMeta`]     — metadata (labels, annotations, finalizers,
//!                                ownerReferences, …)
//! - [`crate::ConditionSet`]   — status conditions
//! - [`crate::LabelSelector`]  — selection
//! - **`Manifest<Spec, Status>`** — typed object wrapper combining
//!                                  apiVersion + kind + metadata + spec + status
//!
//! Wire format is **byte-identical to K8s JSON**:
//!
//! ```yaml
//! apiVersion: apps/v1
//! kind: Deployment
//! metadata:
//!   name: nginx
//!   namespace: default
//!   labels: { app: nginx }
//! spec:
//!   replicas: 3
//!   ...
//! status:
//!   readyReplicas: 3
//!   ...
//! ```
//!
//! Achieved via `#[serde(flatten)]` on `TypeMeta` so `apiVersion` +
//! `kind` sit at the top level alongside `metadata` / `spec` / `status`.
//!
//! # Generic over Spec + Status
//!
//! `Manifest<S, T = serde_json::Value>` is generic over both the spec
//! type AND the status type. Default `Status = serde_json::Value`
//! covers the common case where a controller cares about typed Spec
//! but reads Status opaquely. Controllers that own the full type
//! (write Status) specialize both generics.
//!
//! `Manifest<MyCRSpec, MyCRStatus>` is the typed CR shape every
//! pleme-io controller works with. The substrate never depends on
//! kube-rs; adapters convert at the API boundary via `From`/`Into`.

use serde::{Deserialize, Serialize};

use crate::inventory::ResourceRef;
use crate::meta::ObjectMeta;

/// K8s `TypeMeta` — the `apiVersion` + `kind` pair every K8s object
/// carries at the top level. Wire format matches K8s exactly via
/// camelCase.
///
/// `apiVersion` follows the `<group>/<version>` form for non-core
/// API groups (e.g. `"apps/v1"`, `"networking.k8s.io/v1"`) and the
/// `<version>` form for the core group (`"v1"`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeMeta {
    pub api_version: String,
    pub kind: String,
}

impl TypeMeta {
    /// Construct from (api_version, kind).
    pub fn new(api_version: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            api_version: api_version.into(),
            kind: kind.into(),
        }
    }

    /// Construct from (group, version, kind). `group` may be empty
    /// for the core API group; the resulting `api_version` is just
    /// `<version>` in that case.
    pub fn from_gvk(
        group: impl AsRef<str>,
        version: impl AsRef<str>,
        kind: impl Into<String>,
    ) -> Self {
        let group = group.as_ref();
        let version = version.as_ref();
        let api_version = if group.is_empty() {
            version.to_string()
        } else {
            format!("{group}/{version}")
        };
        Self {
            api_version,
            kind: kind.into(),
        }
    }

    /// Parse the group from `api_version`. Returns `""` for the
    /// core group (when `api_version` has no `/` separator).
    pub fn group(&self) -> &str {
        self.api_version
            .split_once('/')
            .map(|(g, _)| g)
            .unwrap_or("")
    }

    /// Parse the version from `api_version`. Always returns the
    /// portion after `/` (or the whole `api_version` for the core
    /// group).
    pub fn version(&self) -> &str {
        self.api_version
            .split_once('/')
            .map(|(_, v)| v)
            .unwrap_or(self.api_version.as_str())
    }

    /// `true` when this TypeMeta is in the core API group (`apiVersion`
    /// has no `/` separator).
    pub fn is_core(&self) -> bool {
        !self.api_version.contains('/')
    }
}

/// Typed K8s object wrapper — combines `TypeMeta` (flattened),
/// `ObjectMeta` (metadata), typed `spec`, and typed `status` (default
/// `serde_json::Value` for controllers that don't own the status
/// type).
///
/// Wire format is byte-identical to K8s JSON via `#[serde(flatten)]`
/// on `type_meta` so `apiVersion` + `kind` sit at the top level
/// alongside `metadata` / `spec` / `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest<S, T = serde_json::Value> {
    /// Flattens into top-level `apiVersion` + `kind` per K8s wire format.
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    /// `metadata` block.
    pub metadata: ObjectMeta,

    /// Typed `spec`.
    pub spec: S,

    /// Typed `status` — `None` when the object hasn't been observed
    /// by its controller yet (status not populated).
    #[serde(default = "default_none", skip_serializing_if = "Option::is_none")]
    pub status: Option<T>,
}

fn default_none<T>() -> Option<T> {
    None
}

impl<S, T> Manifest<S, T> {
    /// Construct from (apiVersion, kind, ObjectMeta, spec). No status.
    pub fn new(
        api_version: impl Into<String>,
        kind: impl Into<String>,
        metadata: ObjectMeta,
        spec: S,
    ) -> Self {
        Self {
            type_meta: TypeMeta::new(api_version, kind),
            metadata,
            spec,
            status: None,
        }
    }

    /// Construct from (group, version, kind, ObjectMeta, spec). No status.
    pub fn from_gvk(
        group: impl AsRef<str>,
        version: impl AsRef<str>,
        kind: impl Into<String>,
        metadata: ObjectMeta,
        spec: S,
    ) -> Self {
        Self {
            type_meta: TypeMeta::from_gvk(group, version, kind),
            metadata,
            spec,
            status: None,
        }
    }

    /// Set the typed status. Returns self for chaining.
    #[must_use]
    pub fn with_status(mut self, status: T) -> Self {
        self.status = Some(status);
        self
    }

    /// `true` when this object has been observed by its controller
    /// (status is populated).
    pub fn has_status(&self) -> bool {
        self.status.is_some()
    }

    /// Build a [`ResourceRef`] for this object using its TypeMeta +
    /// ObjectMeta. Bridges metadata-only primitives to identity-bearing
    /// primitives via the typed TypeMeta.
    pub fn to_resource_ref(&self) -> ResourceRef {
        self.metadata.to_resource_ref(
            self.type_meta.group(),
            self.type_meta.version(),
            &self.type_meta.kind,
        )
    }

    /// Convenience: the object's name.
    pub fn name(&self) -> &str {
        &self.metadata.name
    }

    /// Convenience: the object's namespace (empty for cluster-scoped).
    pub fn namespace(&self) -> &str {
        &self.metadata.namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    // A typed spec + status to demonstrate the generic shape.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DeploymentSpec {
        replicas: u32,
        image: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DeploymentStatus {
        ready_replicas: u32,
        observed_generation: i64,
    }

    fn meta() -> ObjectMeta {
        ObjectMeta::namespaced("nginx", "default").with_label("app", "nginx")
    }

    fn spec() -> DeploymentSpec {
        DeploymentSpec {
            replicas: 3,
            image: "nginx:1.25".into(),
        }
    }

    // ── TypeMeta ──────────────────────────────────────────────────

    #[test]
    fn type_meta_new_sets_api_version_and_kind() {
        let t = TypeMeta::new("apps/v1", "Deployment");
        assert_eq!(t.api_version, "apps/v1");
        assert_eq!(t.kind, "Deployment");
    }

    #[test]
    fn from_gvk_with_group() {
        let t = TypeMeta::from_gvk("apps", "v1", "Deployment");
        assert_eq!(t.api_version, "apps/v1");
        assert_eq!(t.kind, "Deployment");
    }

    #[test]
    fn from_gvk_core_group_emits_version_only() {
        let t = TypeMeta::from_gvk("", "v1", "Pod");
        assert_eq!(t.api_version, "v1", "core group: no group prefix");
        assert_eq!(t.kind, "Pod");
    }

    #[test]
    fn group_version_parsing_with_group() {
        let t = TypeMeta::new("apps/v1", "Deployment");
        assert_eq!(t.group(), "apps");
        assert_eq!(t.version(), "v1");
        assert!(!t.is_core());
    }

    #[test]
    fn group_version_parsing_core_group() {
        let t = TypeMeta::new("v1", "Pod");
        assert_eq!(t.group(), "");
        assert_eq!(t.version(), "v1");
        assert!(t.is_core());
    }

    #[test]
    fn group_version_parsing_complex_group() {
        // Multi-segment group like "networking.k8s.io/v1".
        let t = TypeMeta::new("networking.k8s.io/v1", "NetworkPolicy");
        assert_eq!(t.group(), "networking.k8s.io");
        assert_eq!(t.version(), "v1");
        assert!(!t.is_core());
    }

    #[test]
    fn type_meta_serde_camelcase() {
        let t = TypeMeta::new("apps/v1", "Deployment");
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"apiVersion\":\"apps/v1\""), "got {json:?}");
        assert!(json.contains("\"kind\":\"Deployment\""));
        assert!(!json.contains("api_version"));
    }

    #[test]
    fn type_meta_round_trip() {
        let t = TypeMeta::new("apps/v1", "Deployment");
        let json = serde_json::to_string(&t).unwrap();
        let back: TypeMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    // ── Manifest construction + bridges ───────────────────────────

    #[test]
    fn manifest_new_constructs_with_no_status() {
        let m: Manifest<DeploymentSpec> = Manifest::new("apps/v1", "Deployment", meta(), spec());
        assert_eq!(m.type_meta.api_version, "apps/v1");
        assert_eq!(m.type_meta.kind, "Deployment");
        assert_eq!(m.metadata.name, "nginx");
        assert_eq!(m.spec, spec());
        assert!(m.status.is_none());
        assert!(!m.has_status());
    }

    #[test]
    fn manifest_from_gvk_constructs_typed_api_version() {
        let m: Manifest<DeploymentSpec> =
            Manifest::from_gvk("apps", "v1", "Deployment", meta(), spec());
        assert_eq!(m.type_meta.api_version, "apps/v1");
    }

    #[test]
    fn manifest_with_status_sets_typed_status() {
        let m = Manifest::<DeploymentSpec, DeploymentStatus>::from_gvk(
            "apps",
            "v1",
            "Deployment",
            meta(),
            spec(),
        )
        .with_status(DeploymentStatus {
            ready_replicas: 3,
            observed_generation: 5,
        });

        assert!(m.has_status());
        assert_eq!(m.status.as_ref().unwrap().ready_replicas, 3);
    }

    #[test]
    fn manifest_to_resource_ref_namespaced() {
        let m: Manifest<DeploymentSpec> =
            Manifest::from_gvk("apps", "v1", "Deployment", meta(), spec());
        let r = m.to_resource_ref();
        assert_eq!(r.group, "apps");
        assert_eq!(r.version, "v1");
        assert_eq!(r.kind, "Deployment");
        assert_eq!(r.namespace.as_deref(), Some("default"));
        assert_eq!(r.name, "nginx");
    }

    #[test]
    fn manifest_to_resource_ref_cluster_scoped_when_no_namespace() {
        let m: Manifest<DeploymentSpec> = Manifest::from_gvk(
            "apiextensions.k8s.io",
            "v1",
            "CustomResourceDefinition",
            ObjectMeta::new("widgets.example.io"),
            spec(),
        );
        let r = m.to_resource_ref();
        assert!(r.is_cluster_scoped());
        assert!(r.namespace.is_none());
        assert_eq!(r.name, "widgets.example.io");
    }

    #[test]
    fn manifest_to_resource_ref_core_group() {
        let m: Manifest<DeploymentSpec> = Manifest::from_gvk(
            "",
            "v1",
            "Pod",
            ObjectMeta::namespaced("mypod", "default"),
            spec(),
        );
        let r = m.to_resource_ref();
        assert_eq!(r.group, "", "core group must propagate as empty string");
        assert_eq!(r.version, "v1");
        assert_eq!(r.kind, "Pod");
    }

    #[test]
    fn name_and_namespace_accessors() {
        let m: Manifest<DeploymentSpec> = Manifest::new("apps/v1", "Deployment", meta(), spec());
        assert_eq!(m.name(), "nginx");
        assert_eq!(m.namespace(), "default");
    }

    // ── Manifest wire format ──────────────────────────────────────

    #[test]
    fn manifest_serde_flattens_type_meta_at_top_level() {
        let m: Manifest<DeploymentSpec> =
            Manifest::from_gvk("apps", "v1", "Deployment", meta(), spec());
        let json = serde_json::to_string(&m).unwrap();
        // apiVersion + kind MUST sit at top level (flattened).
        assert!(json.contains("\"apiVersion\":\"apps/v1\""), "got {json:?}");
        assert!(json.contains("\"kind\":\"Deployment\""));
        // metadata + spec are siblings of apiVersion/kind.
        assert!(json.contains("\"metadata\":"));
        assert!(json.contains("\"spec\":"));
        // typeMeta envelope MUST NOT appear (flatten).
        assert!(!json.contains("typeMeta"));
        assert!(!json.contains("type_meta"));
    }

    #[test]
    fn manifest_serde_omits_status_when_none() {
        let m: Manifest<DeploymentSpec> =
            Manifest::from_gvk("apps", "v1", "Deployment", meta(), spec());
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("\"status\""), "got {json:?}");
    }

    #[test]
    fn manifest_serde_emits_status_when_some() {
        let m = Manifest::<DeploymentSpec, DeploymentStatus>::from_gvk(
            "apps",
            "v1",
            "Deployment",
            meta(),
            spec(),
        )
        .with_status(DeploymentStatus {
            ready_replicas: 3,
            observed_generation: 5,
        });
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"readyReplicas\":3"));
    }

    #[test]
    fn manifest_round_trip_with_status() {
        let m = Manifest::<DeploymentSpec, DeploymentStatus>::from_gvk(
            "apps",
            "v1",
            "Deployment",
            meta(),
            spec(),
        )
        .with_status(DeploymentStatus {
            ready_replicas: 3,
            observed_generation: 5,
        });

        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest<DeploymentSpec, DeploymentStatus> = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn manifest_round_trip_without_status() {
        let m: Manifest<DeploymentSpec> =
            Manifest::from_gvk("apps", "v1", "Deployment", meta(), spec());

        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest<DeploymentSpec> = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn manifest_deserializes_real_k8s_payload() {
        // A real-world K8s Deployment payload should parse via the
        // typed Spec + opaque (serde_json::Value) Status.
        let payload = r#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "nginx",
                "namespace": "default",
                "uid": "abc-123",
                "labels": {"app": "nginx"}
            },
            "spec": {
                "replicas": 3,
                "image": "nginx:1.25"
            },
            "status": {
                "readyReplicas": 3,
                "observedGeneration": 5,
                "conditions": []
            }
        }"#;

        let m: Manifest<DeploymentSpec> = serde_json::from_str(payload).unwrap();
        assert_eq!(m.type_meta.api_version, "apps/v1");
        assert_eq!(m.spec.replicas, 3);
        assert_eq!(m.spec.image, "nginx:1.25");
        assert_eq!(m.metadata.uid, "abc-123");
        // Status is opaque (serde_json::Value) — we don't decode it
        // when the controller doesn't care.
        assert!(m.status.is_some());
    }

    #[test]
    fn manifest_with_fully_typed_status_decodes_payload() {
        // Same payload, controller owns the Status type.
        let payload = r#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "nginx", "namespace": "default"},
            "spec": {"replicas": 3, "image": "nginx:1.25"},
            "status": {"readyReplicas": 2, "observedGeneration": 7}
        }"#;

        let m: Manifest<DeploymentSpec, DeploymentStatus> = serde_json::from_str(payload).unwrap();
        let status = m.status.as_ref().unwrap();
        assert_eq!(status.ready_replicas, 2);
        assert_eq!(status.observed_generation, 7);
    }

    // ── Composition + bridges ─────────────────────────────────────

    #[test]
    fn manifest_composes_with_label_selector_via_metadata() {
        use crate::LabelSelector;

        let m: Manifest<DeploymentSpec> = Manifest::from_gvk(
            "apps",
            "v1",
            "Deployment",
            meta(), // has label app=nginx
            spec(),
        );

        let sel = LabelSelector::from_label("app", "nginx");
        assert!(sel.matches(&m.metadata.labels));

        let sel2 = LabelSelector::from_label("app", "redis");
        assert!(!sel2.matches(&m.metadata.labels));
    }
}
