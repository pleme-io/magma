//! Typed K8s object metadata — the canonical `ObjectMeta` +
//! `OwnerReference` primitives every controller reads + writes.
//!
//! Completes the typed K8s object stack:
//!
//! - [`crate::ResourceRef`] — identity (GVKNN tuple)
//! - **`ObjectMeta`** — metadata (labels, annotations, finalizers,
//!   ownerReferences, uid, generation, …)
//! - [`crate::ConditionSet`] — status (typed conditions)
//! - [`crate::LabelSelector`] — selection (matches against
//!   `ObjectMeta::labels`)
//!
//! Wire format is **byte-identical to K8s metav1.ObjectMeta +
//! metav1.OwnerReference** JSON via `#[serde(rename_all = "camelCase")]`
//! + `skip_serializing_if = "..."` on every optional field so the
//! serialized form matches what the K8s API server produces.
//!
//! The substrate stays kube-rs-free; adapters convert to/from
//! `k8s_openapi::api::core::v1::ObjectMeta` at the API boundary via
//! a derive or hand-written `From`/`Into`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::inventory::ResourceRef;

/// Reference to an owner object (used in `ObjectMeta.ownerReferences`).
/// Mirrors `metav1.OwnerReference` byte-for-byte.
///
/// `controller: Some(true)` marks this as the **controller** owner —
/// the singular owner that the controller-runtime considers
/// authoritative for cascading deletes. Per K8s spec, at most one
/// owner reference per object may carry `controller: Some(true)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerReference {
    /// API version of the referent (e.g. `"apps/v1"`).
    pub api_version: String,
    /// Kind of the referent (e.g. `"Deployment"`).
    pub kind: String,
    /// Name of the referent.
    pub name: String,
    /// UID of the referent.
    pub uid: String,
    /// `true` when this owner is the controller. K8s allows at most
    /// one controller owner per object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    /// `true` when GC should block deletion of the owner until this
    /// object is also deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_owner_deletion: Option<bool>,
}

impl OwnerReference {
    /// Construct a minimal owner reference (no controller / block-
    /// owner-deletion flags). Use `with_controller` and
    /// `with_block_owner_deletion` to opt in.
    pub fn new(
        api_version: impl Into<String>,
        kind: impl Into<String>,
        name: impl Into<String>,
        uid: impl Into<String>,
    ) -> Self {
        Self {
            api_version: api_version.into(),
            kind: kind.into(),
            name: name.into(),
            uid: uid.into(),
            controller: None,
            block_owner_deletion: None,
        }
    }

    /// Mark this owner reference as the controller (`controller: Some(true)`).
    #[must_use]
    pub fn with_controller(mut self) -> Self {
        self.controller = Some(true);
        self
    }

    /// Opt this owner reference into GC blocking (`blockOwnerDeletion: Some(true)`).
    #[must_use]
    pub fn with_block_owner_deletion(mut self) -> Self {
        self.block_owner_deletion = Some(true);
        self
    }

    /// `true` when this owner reference is marked as the controller.
    /// Matches K8s `controller-runtime`'s `IsControlledBy` semantics.
    pub fn is_controller(&self) -> bool {
        self.controller.unwrap_or(false)
    }
}

/// Typed K8s metav1.ObjectMeta — every object's metadata block.
///
/// Wire format is byte-identical to K8s metav1.ObjectMeta JSON. All
/// optional fields use `skip_serializing_if = "..."` so the emitted
/// form matches what the K8s API server produces for an object
/// without the optional field set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Object name. REQUIRED for most kinds; the empty string
    /// signals "use `generateName`" workflows.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,

    /// Server-side prefix for generated names. K8s appends a random
    /// suffix when `name` is empty + `generate_name` is set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub generate_name: String,

    /// Namespace. Empty for cluster-scoped resources.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,

    /// Server-assigned UID. Populated by the API server, never set
    /// by clients.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,

    /// Server-managed resource version (etag for optimistic
    /// concurrency).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resource_version: String,

    /// Server-incremented generation; bumps on every spec update.
    /// Compared against `status.observedGeneration` to detect
    /// "controller has seen this generation."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,

    /// Object creation timestamp. Populated by the API server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<DateTime<Utc>>,

    /// When the object is targeted for deletion. Set by the API
    /// server when a delete request arrives + the object has
    /// finalizers blocking removal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_timestamp: Option<DateTime<Utc>>,

    /// Object labels. Composed with [`crate::LabelSelector::matches`]
    /// for selection.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,

    /// Object annotations. Free-form operator-readable metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,

    /// Finalizers that block object deletion until the named
    /// controllers remove them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finalizers: Vec<String>,

    /// Owner references. At most one entry may carry
    /// `controller: Some(true)` per K8s spec.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

impl ObjectMeta {
    /// New metadata with just a name (namespace empty → cluster-scoped
    /// or to-be-defaulted).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// New metadata for a namespaced resource.
    pub fn namespaced(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            ..Default::default()
        }
    }

    /// Fluent label setter.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Fluent annotation setter.
    #[must_use]
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }

    /// Fluent finalizer adder.
    #[must_use]
    pub fn with_finalizer(mut self, f: impl Into<String>) -> Self {
        self.finalizers.push(f.into());
        self
    }

    /// Fluent owner-reference adder.
    #[must_use]
    pub fn with_owner_reference(mut self, o: OwnerReference) -> Self {
        self.owner_references.push(o);
        self
    }

    /// `true` when the object is targeted for deletion (deletion
    /// timestamp set by the API server). Controllers MUST treat
    /// terminating objects as read-only except for finalizer
    /// removal.
    pub fn is_terminating(&self) -> bool {
        self.deletion_timestamp.is_some()
    }

    /// `true` when the named finalizer is present.
    pub fn has_finalizer(&self, name: &str) -> bool {
        self.finalizers.iter().any(|f| f == name)
    }

    /// Add a finalizer if not already present. Returns `true` if it
    /// was newly added.
    pub fn add_finalizer(&mut self, name: impl Into<String>) -> bool {
        let s = name.into();
        if self.has_finalizer(&s) {
            false
        } else {
            self.finalizers.push(s);
            true
        }
    }

    /// Remove the named finalizer. Returns `true` if it was present.
    pub fn remove_finalizer(&mut self, name: &str) -> bool {
        let before = self.finalizers.len();
        self.finalizers.retain(|f| f != name);
        before != self.finalizers.len()
    }

    /// The singular controller owner reference (if any).
    pub fn controller(&self) -> Option<&OwnerReference> {
        self.owner_references.iter().find(|o| o.is_controller())
    }

    /// `true` when this object is controlled by the given owner UID.
    pub fn is_controlled_by(&self, owner_uid: &str) -> bool {
        self.controller().map(|c| c.uid == owner_uid).unwrap_or(false)
    }

    /// Build a [`ResourceRef`] from this metadata + the given GVK.
    ///
    /// This is the typed bridge between [`ObjectMeta`] (which carries
    /// metadata only) and [`ResourceRef`] (which carries identity
    /// + GVK). Use when you have an object's `(group, version, kind)`
    /// in hand from your typed `TypeMeta` border.
    pub fn to_resource_ref(
        &self,
        group: impl Into<String>,
        version: impl Into<String>,
        kind: impl Into<String>,
    ) -> ResourceRef {
        if self.namespace.is_empty() {
            ResourceRef::cluster_scoped(group, version, kind, &self.name)
        } else {
            ResourceRef::namespaced(group, version, kind, &self.namespace, &self.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LabelSelector;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    // ── OwnerReference ─────────────────────────────────────────────

    #[test]
    fn owner_reference_minimal_omits_controller_and_block_flags() {
        let o = OwnerReference::new("apps/v1", "Deployment", "owner", "uid-1");
        assert!(!o.is_controller());
        let json = serde_json::to_string(&o).unwrap();
        // Controller / blockOwnerDeletion are None → skipped.
        assert!(!json.contains("\"controller\""));
        assert!(!json.contains("\"blockOwnerDeletion\""));
    }

    #[test]
    fn owner_reference_with_controller_emits_flag() {
        let o = OwnerReference::new("apps/v1", "Deployment", "owner", "uid-1")
            .with_controller();
        assert!(o.is_controller());
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"controller\":true"));
    }

    #[test]
    fn owner_reference_with_block_owner_deletion() {
        let o = OwnerReference::new("apps/v1", "Deployment", "owner", "uid-1")
            .with_block_owner_deletion();
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"blockOwnerDeletion\":true"));
    }

    #[test]
    fn owner_reference_camelcase_wire_format() {
        let o = OwnerReference::new("apps/v1", "Deployment", "owner", "uid-1")
            .with_controller()
            .with_block_owner_deletion();
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"apiVersion\":\"apps/v1\""));
        assert!(json.contains("\"kind\":\"Deployment\""));
        assert!(!json.contains("api_version"));
        assert!(!json.contains("block_owner_deletion"));
    }

    #[test]
    fn owner_reference_deserializes_real_k8s_payload() {
        let payload = r#"{
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "name": "my-deploy",
            "uid": "abc-123",
            "controller": true,
            "blockOwnerDeletion": false
        }"#;
        let o: OwnerReference = serde_json::from_str(payload).unwrap();
        assert_eq!(o.api_version, "apps/v1");
        assert_eq!(o.kind, "Deployment");
        assert_eq!(o.name, "my-deploy");
        assert_eq!(o.uid, "abc-123");
        assert!(o.is_controller());
        assert_eq!(o.block_owner_deletion, Some(false));
    }

    #[test]
    fn owner_reference_round_trip() {
        let o = OwnerReference::new("apps/v1", "Deployment", "owner", "uid-1")
            .with_controller()
            .with_block_owner_deletion();
        let json = serde_json::to_string(&o).unwrap();
        let back: OwnerReference = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    // ── ObjectMeta basics ──────────────────────────────────────────

    #[test]
    fn object_meta_new_sets_just_name() {
        let m = ObjectMeta::new("my-object");
        assert_eq!(m.name, "my-object");
        assert!(m.namespace.is_empty());
        assert!(m.labels.is_empty());
    }

    #[test]
    fn object_meta_namespaced_constructor() {
        let m = ObjectMeta::namespaced("my-object", "kube-system");
        assert_eq!(m.name, "my-object");
        assert_eq!(m.namespace, "kube-system");
    }

    #[test]
    fn object_meta_fluent_builders() {
        let m = ObjectMeta::namespaced("my-deploy", "default")
            .with_label("app", "nginx")
            .with_label("tier", "frontend")
            .with_annotation("kubectl.kubernetes.io/last-applied-configuration", "{}")
            .with_finalizer("foreground-cascading-deletion")
            .with_owner_reference(
                OwnerReference::new("apps/v1", "ReplicaSet", "rs-1", "uid-rs1")
                    .with_controller(),
            );

        assert_eq!(m.labels.len(), 2);
        assert_eq!(m.annotations.len(), 1);
        assert_eq!(m.finalizers.len(), 1);
        assert_eq!(m.owner_references.len(), 1);
    }

    // ── ObjectMeta serde wire format ───────────────────────────────

    #[test]
    fn object_meta_camelcase_keys() {
        let mut m = ObjectMeta::namespaced("x", "ns");
        m.resource_version = "12345".into();
        m.generation = Some(7);
        m.creation_timestamp = Some(ts(1000));

        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"resourceVersion\""), "got {json:?}");
        assert!(json.contains("\"creationTimestamp\""), "got {json:?}");
        // Snake-case form must NOT appear.
        assert!(!json.contains("resource_version"));
        assert!(!json.contains("creation_timestamp"));
    }

    #[test]
    fn object_meta_skips_empty_fields() {
        let m = ObjectMeta::new("just-name");
        let json = serde_json::to_string(&m).unwrap();
        // Only "name" should be present.
        assert!(json.contains("\"name\":\"just-name\""));
        assert!(!json.contains("\"namespace\""));
        assert!(!json.contains("\"uid\""));
        assert!(!json.contains("\"labels\""));
        assert!(!json.contains("\"annotations\""));
        assert!(!json.contains("\"ownerReferences\""));
    }

    #[test]
    fn object_meta_serializes_minimal_form() {
        let m = ObjectMeta::default();
        let json = serde_json::to_string(&m).unwrap();
        // Fully-default ObjectMeta serializes as `{}`.
        assert_eq!(json, "{}");
    }

    #[test]
    fn object_meta_deserializes_real_k8s_payload() {
        let payload = r#"{
            "name": "my-deploy",
            "namespace": "default",
            "uid": "abc-123",
            "resourceVersion": "98765",
            "generation": 5,
            "creationTimestamp": "2026-05-28T12:00:00Z",
            "labels": {"app": "nginx"},
            "annotations": {"key": "value"},
            "finalizers": ["foregroundDeletion"],
            "ownerReferences": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "rs-1",
                    "uid": "uid-rs1",
                    "controller": true
                }
            ]
        }"#;
        let m: ObjectMeta = serde_json::from_str(payload).unwrap();

        assert_eq!(m.name, "my-deploy");
        assert_eq!(m.namespace, "default");
        assert_eq!(m.uid, "abc-123");
        assert_eq!(m.generation, Some(5));
        assert_eq!(m.labels.get("app").map(|s| s.as_str()), Some("nginx"));
        assert_eq!(m.finalizers, vec!["foregroundDeletion".to_string()]);
        assert_eq!(m.owner_references.len(), 1);
        assert!(m.owner_references[0].is_controller());
    }

    #[test]
    fn object_meta_round_trip_compound() {
        let m = ObjectMeta::namespaced("my-deploy", "default")
            .with_label("app", "nginx")
            .with_annotation("note", "test")
            .with_finalizer("foregroundDeletion")
            .with_owner_reference(
                OwnerReference::new("apps/v1", "RS", "rs-1", "uid-rs1").with_controller(),
            );

        let json = serde_json::to_string(&m).unwrap();
        let back: ObjectMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // ── Termination + finalizer semantics ──────────────────────────

    #[test]
    fn is_terminating_true_when_deletion_timestamp_set() {
        let mut m = ObjectMeta::new("x");
        assert!(!m.is_terminating());
        m.deletion_timestamp = Some(ts(2000));
        assert!(m.is_terminating());
    }

    #[test]
    fn has_finalizer_finds_by_name() {
        let m = ObjectMeta::new("x")
            .with_finalizer("foregroundDeletion")
            .with_finalizer("my-controller.example.io/cleanup");
        assert!(m.has_finalizer("foregroundDeletion"));
        assert!(m.has_finalizer("my-controller.example.io/cleanup"));
        assert!(!m.has_finalizer("nonexistent"));
    }

    #[test]
    fn add_finalizer_idempotent() {
        let mut m = ObjectMeta::new("x");
        assert!(m.add_finalizer("foo"));
        assert!(!m.add_finalizer("foo"), "second add returns false");
        assert_eq!(m.finalizers.len(), 1);
    }

    #[test]
    fn remove_finalizer_returns_presence() {
        let mut m = ObjectMeta::new("x").with_finalizer("foo");
        assert!(m.remove_finalizer("foo"));
        assert!(m.finalizers.is_empty());
        assert!(!m.remove_finalizer("foo"), "second remove returns false");
    }

    // ── Controller semantics ───────────────────────────────────────

    #[test]
    fn controller_returns_singular_controller_owner() {
        let m = ObjectMeta::new("x")
            .with_owner_reference(OwnerReference::new(
                "v1",
                "ConfigMap",
                "non-ctrl",
                "uid-cm",
            ))
            .with_owner_reference(
                OwnerReference::new("apps/v1", "RS", "rs-1", "uid-rs1").with_controller(),
            );

        let ctrl = m.controller().expect("expected controller");
        assert_eq!(ctrl.uid, "uid-rs1");
    }

    #[test]
    fn controller_none_when_no_owner_marked() {
        let m = ObjectMeta::new("x").with_owner_reference(OwnerReference::new(
            "v1",
            "ConfigMap",
            "owner",
            "uid-cm",
        ));
        assert!(m.controller().is_none());
    }

    #[test]
    fn is_controlled_by_matches_controller_uid() {
        let m = ObjectMeta::new("x").with_owner_reference(
            OwnerReference::new("apps/v1", "RS", "rs-1", "uid-rs1").with_controller(),
        );
        assert!(m.is_controlled_by("uid-rs1"));
        assert!(!m.is_controlled_by("uid-other"));
    }

    #[test]
    fn is_controlled_by_false_when_no_controller_set() {
        let m = ObjectMeta::new("x").with_owner_reference(OwnerReference::new(
            "v1",
            "ConfigMap",
            "owner",
            "uid-cm",
        ));
        assert!(!m.is_controlled_by("uid-cm"));
    }

    // ── ResourceRef bridge ─────────────────────────────────────────

    #[test]
    fn to_resource_ref_namespaced() {
        let m = ObjectMeta::namespaced("nginx", "default");
        let r = m.to_resource_ref("apps", "v1", "Deployment");
        assert_eq!(r.group, "apps");
        assert_eq!(r.version, "v1");
        assert_eq!(r.kind, "Deployment");
        assert_eq!(r.namespace.as_deref(), Some("default"));
        assert_eq!(r.name, "nginx");
    }

    #[test]
    fn to_resource_ref_cluster_scoped_when_no_namespace() {
        let m = ObjectMeta::new("widgets.example.io");
        let r = m.to_resource_ref("apiextensions.k8s.io", "v1", "CustomResourceDefinition");
        assert!(r.is_cluster_scoped());
        assert!(r.namespace.is_none());
        assert_eq!(r.name, "widgets.example.io");
    }

    // ── Composition with LabelSelector ─────────────────────────────

    #[test]
    fn label_selector_matches_object_meta_labels() {
        let m = ObjectMeta::new("nginx")
            .with_label("app", "nginx")
            .with_label("tier", "frontend");

        let selector = LabelSelector::from_label("app", "nginx");
        assert!(selector.matches(&m.labels));

        let strict = LabelSelector::new()
            .with_label("app", "nginx")
            .with_label("tier", "frontend");
        assert!(strict.matches(&m.labels));

        let too_strict = LabelSelector::new()
            .with_label("app", "nginx")
            .with_label("tier", "backend");
        assert!(!too_strict.matches(&m.labels));
    }
}
