//! Typed blob-store backend dispatch — the canonical `BlobStoreBackend`
//! trait every fleet-wide object-store consumer reads against.
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III, P1.4.
//!
//! Subsumes the hand-rolled "which cloud's blob API?" dispatch that
//! recurs in FluxCD's Bucket controller (`provider: generic|aws|gcp|azure`)
//! plus the implicit per-backend handling in our own substrate's
//! image/artifact fetch paths.
//!
//! The trait factors three orthogonal concerns:
//!
//! 1. **Operations** — `get` / `put` / `list` / `delete` / `head`.
//!    Five typed methods cover every observed object-store use case.
//! 2. **Backends** — `InMemoryBlobStore` ships here as the canonical
//!    test impl + concurrency reference. Production backends (S3,
//!    GCS, Azure, OCI registry, filesystem) live in their own crates
//!    and impl `BlobStoreBackend`.
//! 3. **Metadata** — `BlobMetadata` carries content_type + size +
//!    etag + last_modified. Composes with [`crate::Artifact<T>`] so a
//!    backend `get` can produce a typed `Artifact<Vec<u8>>`.
//!
//! # Trait laws
//!
//! 1. `put(p, b); get(p) == Ok(b)` for any path + bytes — what you
//!    put is what you get.
//! 2. `delete(p); get(p) == Err(NotFound(p))` — delete removes.
//! 3. `list(prefix)` returns every path whose key starts with `prefix`,
//!    in arbitrary order. Caller sorts if order matters.
//! 4. `head(p)` returns metadata without bytes — the byte-count is
//!    authoritative even if the consumer doesn't read.
//! 5. Concurrent `put`/`get`/`delete` of the same path serialize
//!    atomically (the in-memory impl uses `Mutex`; production
//!    backends rely on the underlying API's atomicity guarantees).
//!
//! # Composition
//!
//! ```ignore
//! let backend: &dyn BlobStoreBackend = &my_s3_client;
//! let bytes = backend.get("path/to/blob").await?;
//! let artifact = Artifact::new(
//!     ArtifactDigest::new(DigestAlgo::Blake3, blake3_hex(&bytes))?,
//!     Provenance::new(backend.url(), RefSpec::Name("path/to/blob".into()), digest, Utc::now()),
//!     bytes,
//! );
//! ```

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Per-blob metadata. Returned by `head` + `put`, included in `list`.
/// Mirrors the cross-cloud-common subset of object-store metadata
/// (S3, GCS, Azure all expose these five fields under different names).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// Object key / path within the backend.
    pub path: String,
    /// Content size in bytes.
    pub size: u64,
    /// Backend-provided content type (MIME-shape). Empty when unknown.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// Backend-provided ETag (S3) / Generation (GCS) / ETag (Azure).
    /// Used for conditional fetches; empty when the backend doesn't
    /// expose one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// Last-modified timestamp. Backends without one set this to the
    /// put-time.
    pub last_modified: DateTime<Utc>,
}

impl BlobMetadata {
    pub fn new(path: impl Into<String>, size: u64, last_modified: DateTime<Utc>) -> Self {
        Self {
            path: path.into(),
            size,
            content_type: String::new(),
            etag: String::new(),
            last_modified,
        }
    }

    #[must_use]
    pub fn with_content_type(mut self, ct: impl Into<String>) -> Self {
        self.content_type = ct.into();
        self
    }

    #[must_use]
    pub fn with_etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = etag.into();
        self
    }
}

/// Errors any `BlobStoreBackend` impl can return. Backends MUST
/// normalize their native errors into one of these variants so
/// callers can match without per-backend conditionals.
#[derive(Debug, thiserror::Error)]
pub enum BlobStoreError {
    /// Object at `path` doesn't exist.
    #[error("blob not found at {path:?}")]
    NotFound { path: String },

    /// Caller lacks permission to perform the operation.
    #[error("permission denied for {op:?} on {path:?}: {detail}")]
    PermissionDenied {
        op: &'static str,
        path: String,
        detail: String,
    },

    /// Transient backend failure — caller should retry per the
    /// `Classifier<&str, FailureKind>::Transient` pattern.
    #[error("transient backend error for {op:?} on {path:?}: {detail}")]
    Transient {
        op: &'static str,
        path: String,
        detail: String,
    },

    /// Permanent backend failure — caller should not retry. Operator
    /// must investigate (misconfig, invalid bucket, etc.).
    #[error("permanent backend error for {op:?} on {path:?}: {detail}")]
    Permanent {
        op: &'static str,
        path: String,
        detail: String,
    },
}

impl BlobStoreError {
    /// `true` for `Transient` errors — caller may retry.
    pub fn is_retryable(&self) -> bool {
        matches!(self, BlobStoreError::Transient { .. })
    }

    /// Variant discriminant string for metrics labels.
    pub fn kind(&self) -> &'static str {
        match self {
            BlobStoreError::NotFound { .. } => "not_found",
            BlobStoreError::PermissionDenied { .. } => "permission_denied",
            BlobStoreError::Transient { .. } => "transient",
            BlobStoreError::Permanent { .. } => "permanent",
        }
    }
}

/// Canonical blob-store backend trait. Implementations live in their
/// own crates (S3, GCS, Azure, OCI, filesystem); this crate ships
/// the trait + `InMemoryBlobStore` reference impl + tests.
///
/// `Send + Sync` bound so a `Arc<dyn BlobStoreBackend>` can be shared
/// across reconcile workers. `'static` bound so impls can hold owned
/// connection clients.
#[async_trait]
pub trait BlobStoreBackend: Send + Sync + 'static {
    /// Stable backend name for metrics / audit logs. Each impl picks
    /// its name (`"s3"`, `"gcs"`, `"azure"`, `"oci"`, `"filesystem"`,
    /// `"memory"`).
    fn backend(&self) -> &'static str;

    /// Read object bytes at `path`. NotFound when path doesn't exist.
    async fn get(&self, path: &str) -> Result<Vec<u8>, BlobStoreError>;

    /// Write `bytes` to `path`. Returns metadata of the written object.
    /// Overwrites existing content at `path`.
    async fn put(&self, path: &str, bytes: Vec<u8>) -> Result<BlobMetadata, BlobStoreError>;

    /// List metadata for every object whose path starts with `prefix`.
    /// Order is backend-specific; callers sort if order matters.
    async fn list(&self, prefix: &str) -> Result<Vec<BlobMetadata>, BlobStoreError>;

    /// Delete the object at `path`. NotFound when path doesn't exist.
    async fn delete(&self, path: &str) -> Result<(), BlobStoreError>;

    /// Metadata-only fetch — no bytes transferred. Used by reconcilers
    /// that just want to check existence / etag / size.
    async fn head(&self, path: &str) -> Result<BlobMetadata, BlobStoreError>;
}

// ── InMemoryBlobStore — canonical test impl + concurrency reference ─

/// In-memory blob store backed by a `Mutex<BTreeMap>`. Ships in this
/// crate as the canonical test impl + reference for how concurrent
/// access serializes through the typed trait.
///
/// NOT a production backend — every byte lives in RAM. Use S3/GCS/
/// Azure/etc. crates that impl `BlobStoreBackend` for real workloads.
pub struct InMemoryBlobStore {
    entries: Mutex<BTreeMap<String, (Vec<u8>, BlobMetadata)>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the current entry count for assertions.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("InMemoryBlobStore mutex poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryBlobStore {
    fn default() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }
}

impl std::fmt::Debug for InMemoryBlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryBlobStore")
            .field("entries", &self.len())
            .finish()
    }
}

#[async_trait]
impl BlobStoreBackend for InMemoryBlobStore {
    fn backend(&self) -> &'static str {
        "memory"
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>, BlobStoreError> {
        let g = self
            .entries
            .lock()
            .expect("InMemoryBlobStore mutex poisoned");
        g.get(path)
            .map(|(b, _)| b.clone())
            .ok_or_else(|| BlobStoreError::NotFound {
                path: path.to_string(),
            })
    }

    async fn put(&self, path: &str, bytes: Vec<u8>) -> Result<BlobMetadata, BlobStoreError> {
        let meta = BlobMetadata::new(path, bytes.len() as u64, Utc::now());
        let mut g = self
            .entries
            .lock()
            .expect("InMemoryBlobStore mutex poisoned");
        g.insert(path.to_string(), (bytes, meta.clone()));
        Ok(meta)
    }

    async fn list(&self, prefix: &str) -> Result<Vec<BlobMetadata>, BlobStoreError> {
        let g = self
            .entries
            .lock()
            .expect("InMemoryBlobStore mutex poisoned");
        let v: Vec<_> = g
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, (_, m))| m.clone())
            .collect();
        Ok(v)
    }

    async fn delete(&self, path: &str) -> Result<(), BlobStoreError> {
        let mut g = self
            .entries
            .lock()
            .expect("InMemoryBlobStore mutex poisoned");
        g.remove(path)
            .ok_or_else(|| BlobStoreError::NotFound {
                path: path.to_string(),
            })
            .map(|_| ())
    }

    async fn head(&self, path: &str) -> Result<BlobMetadata, BlobStoreError> {
        let g = self
            .entries
            .lock()
            .expect("InMemoryBlobStore mutex poisoned");
        g.get(path)
            .map(|(_, m)| m.clone())
            .ok_or_else(|| BlobStoreError::NotFound {
                path: path.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn store() -> InMemoryBlobStore {
        InMemoryBlobStore::new()
    }

    // ── BlobMetadata ───────────────────────────────────────────────

    #[test]
    fn metadata_builder_chain() {
        let m = BlobMetadata::new("k", 42, Utc::now())
            .with_content_type("application/json")
            .with_etag("abc-123");
        assert_eq!(m.path, "k");
        assert_eq!(m.size, 42);
        assert_eq!(m.content_type, "application/json");
        assert_eq!(m.etag, "abc-123");
    }

    #[test]
    fn metadata_serde_omits_empty_optional_strings() {
        let m = BlobMetadata::new("k", 0, Utc::now());
        let json = serde_json::to_string(&m).unwrap();
        // content_type + etag are empty; serde should skip them.
        assert!(!json.contains("\"content_type\""));
        assert!(!json.contains("\"etag\""));
        let back: BlobMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // ── BlobStoreError classification ──────────────────────────────

    #[test]
    fn error_retryable_only_for_transient() {
        let nf = BlobStoreError::NotFound { path: "x".into() };
        let pd = BlobStoreError::PermissionDenied {
            op: "get",
            path: "x".into(),
            detail: "no creds".into(),
        };
        let tr = BlobStoreError::Transient {
            op: "get",
            path: "x".into(),
            detail: "5xx".into(),
        };
        let pm = BlobStoreError::Permanent {
            op: "get",
            path: "x".into(),
            detail: "bucket gone".into(),
        };

        assert!(!nf.is_retryable());
        assert!(!pd.is_retryable());
        assert!(tr.is_retryable());
        assert!(!pm.is_retryable());
    }

    #[test]
    fn error_kind_discriminant() {
        assert_eq!(
            BlobStoreError::NotFound { path: "x".into() }.kind(),
            "not_found"
        );
        assert_eq!(
            BlobStoreError::PermissionDenied {
                op: "get",
                path: "x".into(),
                detail: String::new(),
            }
            .kind(),
            "permission_denied"
        );
        assert_eq!(
            BlobStoreError::Transient {
                op: "get",
                path: "x".into(),
                detail: String::new(),
            }
            .kind(),
            "transient"
        );
        assert_eq!(
            BlobStoreError::Permanent {
                op: "get",
                path: "x".into(),
                detail: String::new(),
            }
            .kind(),
            "permanent"
        );
    }

    // ── InMemoryBlobStore trait law conformance ────────────────────

    #[tokio::test]
    async fn backend_name_is_memory() {
        let s = store();
        assert_eq!(s.backend(), "memory");
    }

    #[tokio::test]
    async fn put_then_get_returns_bytes() {
        let s = store();
        let bytes = vec![0u8, 1, 2, 3];
        s.put("foo/bar", bytes.clone()).await.unwrap();

        let got = s.get("foo/bar").await.unwrap();
        assert_eq!(got, bytes);
    }

    #[tokio::test]
    async fn put_overwrites() {
        let s = store();
        s.put("k", vec![1]).await.unwrap();
        s.put("k", vec![2, 3]).await.unwrap();
        assert_eq!(s.get("k").await.unwrap(), vec![2, 3]);
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let s = store();
        let err = s.get("missing").await.unwrap_err();
        assert!(matches!(err, BlobStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn head_returns_metadata_without_bytes() {
        let s = store();
        s.put("k", vec![1, 2, 3]).await.unwrap();
        let m = s.head("k").await.unwrap();
        assert_eq!(m.path, "k");
        assert_eq!(m.size, 3);
    }

    #[tokio::test]
    async fn head_missing_returns_not_found() {
        let s = store();
        let err = s.head("missing").await.unwrap_err();
        assert!(matches!(err, BlobStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_removes_object() {
        let s = store();
        s.put("k", vec![1]).await.unwrap();
        assert!(s.delete("k").await.is_ok());

        let err = s.get("k").await.unwrap_err();
        assert!(matches!(err, BlobStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_missing_returns_not_found() {
        let s = store();
        let err = s.delete("missing").await.unwrap_err();
        assert!(matches!(err, BlobStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn list_returns_only_prefix_matches() {
        let s = store();
        s.put("a/1", vec![]).await.unwrap();
        s.put("a/2", vec![]).await.unwrap();
        s.put("b/1", vec![]).await.unwrap();

        let v = s.list("a/").await.unwrap();
        assert_eq!(v.len(), 2);
        let paths: Vec<_> = v.iter().map(|m| m.path.as_str()).collect();
        assert!(paths.contains(&"a/1"));
        assert!(paths.contains(&"a/2"));
        assert!(!paths.contains(&"b/1"));
    }

    #[tokio::test]
    async fn list_empty_prefix_returns_everything() {
        let s = store();
        s.put("x", vec![]).await.unwrap();
        s.put("y/z", vec![]).await.unwrap();

        let v = s.list("").await.unwrap();
        assert_eq!(v.len(), 2);
    }

    #[tokio::test]
    async fn list_no_match_returns_empty() {
        let s = store();
        s.put("a", vec![]).await.unwrap();
        let v = s.list("nope/").await.unwrap();
        assert!(v.is_empty());
    }

    /// The canonical put→get round-trip law: what you put is what you get.
    #[tokio::test]
    async fn law_put_then_get_returns_same_bytes() {
        let s = store();
        for (path, bytes) in [
            ("empty", vec![]),
            ("one", vec![42]),
            ("nul-bytes", vec![0, 0, 0, 0]),
            ("nested/deeply/path", vec![255, 254, 253]),
        ] {
            s.put(path, bytes.clone()).await.unwrap();
            let got = s.get(path).await.unwrap();
            assert_eq!(got, bytes, "round-trip failed for path={path:?}");
        }
    }

    /// The delete→get law: deletion removes the object.
    #[tokio::test]
    async fn law_delete_then_get_returns_not_found() {
        let s = store();
        s.put("k", vec![1]).await.unwrap();
        s.delete("k").await.unwrap();
        let err = s.get("k").await.unwrap_err();
        assert!(matches!(err, BlobStoreError::NotFound { .. }));
    }

    /// Test that any impl of the trait can be hidden behind dyn dispatch.
    #[tokio::test]
    async fn dyn_dispatch_works() {
        let s: Arc<dyn BlobStoreBackend> = Arc::new(InMemoryBlobStore::new());
        s.put("k", vec![1, 2]).await.unwrap();
        assert_eq!(s.get("k").await.unwrap(), vec![1, 2]);
        assert_eq!(s.backend(), "memory");
    }

    /// Composability with Artifact<T> + Provenance + RefSpec — the
    /// canonical "backend fetches → typed Artifact" flow.
    #[tokio::test]
    async fn composes_with_artifact() {
        use crate::{Artifact, ArtifactDigest, DigestAlgo, Provenance, RefSpec};

        let s: Arc<dyn BlobStoreBackend> = Arc::new(InMemoryBlobStore::new());
        s.put("releases/v1.tar.gz", vec![1, 2, 3]).await.unwrap();

        let bytes = s.get("releases/v1.tar.gz").await.unwrap();
        // Caller computes the digest (e.g. via blake3 crate or tameshi);
        // here we use a placeholder.
        let placeholder_hex: String = std::iter::repeat('a').take(64).collect();
        let digest = ArtifactDigest::new(DigestAlgo::Blake3, placeholder_hex).unwrap();
        let provenance = Provenance::new(
            "s3://my-bucket/releases/v1.tar.gz",
            RefSpec::Name("releases/v1.tar.gz".into()),
            "v1.tar.gz",
            Utc::now(),
        );
        let artifact = Artifact::new(digest, provenance, bytes);

        assert_eq!(artifact.payload, vec![1, 2, 3]);
    }
}
