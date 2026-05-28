//! Typed content-addressed artifact — the canonical `Artifact<T>`
//! every fleet-wide fetcher/publisher consumes.
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III, P1.1.
//!
//! Subsumes FluxCD's per-CR `artifact { url, revision, digest, size,
//! lastUpdateTime }` block (GitRepository, OCIRepository,
//! HelmRepository, Bucket all carry it) by lifting the shape into
//! a typed primitive that:
//!
//! - Carries the **payload** as `T` (typed — not opaque bytes)
//! - Names a **content-addressed digest** (BLAKE3 by default, with
//!   typed algorithm tag for future flexibility)
//! - Records **provenance** — source URL + the typed `RefSpec` it was
//!   fetched at + the resolved revision + fetched-at timestamp
//!
//! The primitive is the typed shape; **digest computation lives at
//! the caller**. tameshi/sekiban already canonicalize the BLAKE3
//! computation pipeline; this primitive is the typed border every
//! reconciler reads + writes against.
//!
//! # Composition
//!
//! - `Provenance.ref_spec` is the [`crate::RefSpec`] enum (shipped
//!   in P1.0). One typed surface across "what ref" and "what
//!   artifact was produced by that ref."
//! - `Artifact<Inventory<Ref>>` will be the canonical shape for
//!   Kustomization-style apply outputs (P1.3).
//! - `Artifact<HelmReleaseDelta>` will carry the typed Helm release
//!   transition (P1.8).
//!
//! # Freshness
//!
//! `Artifact::is_fresh(age_limit, now)` returns whether the artifact
//! is within `age_limit` of `now` — used by reconcilers to decide
//! whether to re-fetch. The clock is passed in (no `Utc::now()` call
//! inside the primitive) so the type stays pure.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::refspec::RefSpec;

/// Content-addressed digest algorithm. Default is BLAKE3 — the
/// canonical algorithm across pleme-io's tameshi attestation chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgo {
    /// BLAKE3 — canonical default; tameshi chain uses this everywhere.
    Blake3,
    /// SHA-256 — provided for FluxCD compatibility (Flux uses SHA-256
    /// for artifact revisions); operators consuming Flux interop can
    /// produce SHA-256 digests when needed.
    Sha256,
    /// SHA-512 — for systems that mandate longer hashes.
    Sha512,
}

impl Default for DigestAlgo {
    fn default() -> Self {
        Self::Blake3
    }
}

impl DigestAlgo {
    /// Expected hex-string length for this algorithm's output.
    /// BLAKE3 / SHA-256 = 64 chars; SHA-512 = 128 chars.
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Blake3 | Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

/// Content-addressed digest — algorithm tag + hex-encoded hash.
/// The primitive stores the result; computation lives at the caller
/// (tameshi/sekiban for BLAKE3, openssl/ring/sha2 for SHA family).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDigest {
    pub algo: DigestAlgo,
    /// Hex-encoded digest. MUST be lowercase + exact length for the
    /// algorithm (see [`DigestAlgo::hex_len`]).
    pub hex: String,
}

impl ArtifactDigest {
    /// Construct + validate. Returns Err if `hex` isn't lowercase
    /// hex of the algorithm's expected length.
    pub fn new(algo: DigestAlgo, hex: impl Into<String>) -> Result<Self, DigestError> {
        let hex = hex.into();
        if hex.len() != algo.hex_len() {
            return Err(DigestError::WrongLength {
                algo,
                expected: algo.hex_len(),
                got: hex.len(),
            });
        }
        if !hex
            .chars()
            .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return Err(DigestError::NotLowercaseHex(hex));
        }
        Ok(Self { algo, hex })
    }

    /// Construct without validation. For internal use + tests where
    /// the digest is known-good.
    pub fn unchecked(algo: DigestAlgo, hex: impl Into<String>) -> Self {
        Self {
            algo,
            hex: hex.into(),
        }
    }

    /// Pleme-io standard form: `"<algo>:<hex>"` (e.g. `"blake3:abc..."`).
    /// Mirrors OCI image-reference convention so artifacts pulled from
    /// OCI registries can reuse the digest string verbatim.
    pub fn to_oci_form(&self) -> String {
        format!("{}:{}", self.algo.name(), self.hex)
    }
}

impl std::fmt::Display for ArtifactDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_oci_form())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("digest hex has wrong length for {algo:?}: expected {expected}, got {got}")]
    WrongLength {
        algo: DigestAlgo,
        expected: usize,
        got: usize,
    },
    #[error("digest hex must be lowercase 0-9/a-f; got {0:?}")]
    NotLowercaseHex(String),
}

/// Provenance — where did this artifact come from?
///
/// Composes [`RefSpec`] (the typed git/OCI/object-store reference)
/// with the source URL, the resolved revision (after the reconciler
/// dereferences a floating ref like `Branch("main")` into a commit
/// SHA), and the fetched-at timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Source URL (e.g. `"https://github.com/foo/bar"`).
    pub source_url: String,
    /// The typed reference the operator declared.
    pub ref_spec: RefSpec,
    /// The concrete revision the reconciler resolved `ref_spec` to
    /// (e.g. a commit SHA for `Branch("main")` or an OCI digest for
    /// `Tag("v1.2.3")`). For immutable variants (`Commit`, `Digest`)
    /// this matches `ref_spec.value()`.
    pub resolved_revision: String,
    /// When the artifact was fetched.
    pub fetched_at: DateTime<Utc>,
}

impl Provenance {
    pub fn new(
        source_url: impl Into<String>,
        ref_spec: RefSpec,
        resolved_revision: impl Into<String>,
        fetched_at: DateTime<Utc>,
    ) -> Self {
        Self {
            source_url: source_url.into(),
            ref_spec,
            resolved_revision: resolved_revision.into(),
            fetched_at,
        }
    }
}

/// Typed content-addressed artifact. Carries the typed payload `T`,
/// a content-addressed digest, and provenance.
///
/// Two artifacts are "the same artifact" iff they share an
/// `ArtifactDigest`. Provenance can differ (same content fetched
/// from a mirror or at a different time) without changing identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact<T> {
    pub digest: ArtifactDigest,
    pub provenance: Provenance,
    pub payload: T,
}

impl<T> Artifact<T> {
    pub fn new(digest: ArtifactDigest, provenance: Provenance, payload: T) -> Self {
        Self {
            digest,
            provenance,
            payload,
        }
    }

    /// `true` when the artifact was fetched within `age_limit` of `now`.
    /// Used by reconcilers to decide whether the in-memory artifact is
    /// fresh enough to skip a re-fetch.
    ///
    /// Defensive against clock skew: `fetched_at > now` returns
    /// `false` (never reports a future-fetched artifact as fresh).
    pub fn is_fresh(&self, age_limit: Duration, now: DateTime<Utc>) -> bool {
        let fetched = self.provenance.fetched_at;
        if fetched > now {
            return false;
        }
        let elapsed = now.signed_duration_since(fetched);
        let limit = match chrono::Duration::from_std(age_limit) {
            Ok(d) => d,
            Err(_) => return true, // limit larger than chrono can represent
        };
        elapsed <= limit
    }

    /// `true` when the digest matches another artifact's digest —
    /// they represent the same content. Provenance may differ.
    pub fn content_eq<U>(&self, other: &Artifact<U>) -> bool {
        self.digest == other.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn hex64(c: char) -> String {
        // Build a 64-char string of a single hex digit, useful for
        // tests that don't care about the exact bytes — only that
        // the digest is well-formed.
        std::iter::repeat(c).take(64).collect()
    }

    fn provenance() -> Provenance {
        Provenance::new(
            "https://github.com/example/repo",
            RefSpec::Branch("main".into()),
            "a1b2c3d4e5f6789012345678901234567890abcd",
            t(1000),
        )
    }

    fn digest_blake3_aaa() -> ArtifactDigest {
        ArtifactDigest::new(DigestAlgo::Blake3, hex64('a')).unwrap()
    }

    // ── DigestAlgo + ArtifactDigest ────────────────────────────────

    #[test]
    fn digest_algo_default_is_blake3() {
        assert_eq!(DigestAlgo::default(), DigestAlgo::Blake3);
    }

    #[test]
    fn digest_algo_hex_lengths() {
        assert_eq!(DigestAlgo::Blake3.hex_len(), 64);
        assert_eq!(DigestAlgo::Sha256.hex_len(), 64);
        assert_eq!(DigestAlgo::Sha512.hex_len(), 128);
    }

    #[test]
    fn digest_validates_length() {
        // Too short
        let r = ArtifactDigest::new(DigestAlgo::Blake3, "abc");
        assert!(matches!(r, Err(DigestError::WrongLength { .. })));

        // Right length
        let r = ArtifactDigest::new(DigestAlgo::Blake3, hex64('a'));
        assert!(r.is_ok());

        // SHA-512 length
        let long: String = std::iter::repeat('a').take(128).collect();
        assert!(ArtifactDigest::new(DigestAlgo::Sha512, long).is_ok());
    }

    #[test]
    fn digest_rejects_uppercase_and_non_hex() {
        let upper: String = std::iter::repeat('A').take(64).collect();
        let r = ArtifactDigest::new(DigestAlgo::Blake3, upper);
        assert!(matches!(r, Err(DigestError::NotLowercaseHex(_))));

        let bad: String = std::iter::repeat('z').take(64).collect();
        let r = ArtifactDigest::new(DigestAlgo::Blake3, bad);
        assert!(matches!(r, Err(DigestError::NotLowercaseHex(_))));
    }

    #[test]
    fn digest_oci_form_round_trip() {
        let d = digest_blake3_aaa();
        let s = d.to_oci_form();
        assert!(s.starts_with("blake3:"));
        assert_eq!(s, format!("blake3:{}", hex64('a')));
        assert_eq!(d.to_string(), s);
    }

    #[test]
    fn digest_unchecked_skips_validation() {
        // Useful for tests + internal use where bytes are known-good.
        let d = ArtifactDigest::unchecked(DigestAlgo::Blake3, "short");
        assert_eq!(d.hex, "short");
    }

    #[test]
    fn digest_serde_round_trip() {
        let d = digest_blake3_aaa();
        let json = serde_json::to_string(&d).unwrap();
        let back: ArtifactDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
        // Algo serializes lowercase.
        assert!(json.contains("\"blake3\""));
    }

    // ── Provenance ─────────────────────────────────────────────────

    #[test]
    fn provenance_composes_ref_spec() {
        let p = provenance();
        assert_eq!(p.source_url, "https://github.com/example/repo");
        match &p.ref_spec {
            RefSpec::Branch(b) => assert_eq!(b, "main"),
            other => panic!("expected Branch, got {other:?}"),
        }
    }

    #[test]
    fn provenance_serde_round_trip() {
        let p = provenance();
        let json = serde_json::to_string(&p).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // ── Artifact<T> ────────────────────────────────────────────────

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TarballBytes(Vec<u8>);

    #[test]
    fn artifact_is_fresh_within_limit() {
        let a = Artifact::new(digest_blake3_aaa(), provenance(), TarballBytes(vec![1, 2, 3]));
        // fetched_at = 1000; now = 1300; limit = 600s → fresh
        assert!(a.is_fresh(Duration::from_secs(600), t(1300)));
    }

    #[test]
    fn artifact_is_not_fresh_past_limit() {
        let a = Artifact::new(digest_blake3_aaa(), provenance(), TarballBytes(vec![1, 2, 3]));
        // fetched_at = 1000; now = 2000; limit = 600s → stale
        assert!(!a.is_fresh(Duration::from_secs(600), t(2000)));
    }

    #[test]
    fn artifact_is_fresh_exactly_at_limit() {
        let a = Artifact::new(digest_blake3_aaa(), provenance(), TarballBytes(vec![1]));
        // fetched_at = 1000; now = 1600; limit = 600s → boundary: fresh
        assert!(a.is_fresh(Duration::from_secs(600), t(1600)));
    }

    #[test]
    fn artifact_clock_skew_returns_not_fresh() {
        // now < fetched_at → defensive: not fresh, never reports a
        // future-fetched artifact as cached.
        let a = Artifact::new(digest_blake3_aaa(), provenance(), TarballBytes(vec![1]));
        assert!(!a.is_fresh(Duration::from_secs(99_999), t(500)));
    }

    #[test]
    fn artifact_content_eq_compares_digest_only() {
        let a1 = Artifact::new(digest_blake3_aaa(), provenance(), TarballBytes(vec![1]));

        // Same digest, different provenance (mirror), different payload type.
        let mut prov2 = provenance();
        prov2.source_url = "https://mirror.example.com/repo".into();
        let a2 = Artifact::new(digest_blake3_aaa(), prov2, vec![1u8, 2, 3]);

        assert!(a1.content_eq(&a2), "same digest → content_eq");

        // Different digest → not content_eq.
        let other_digest = ArtifactDigest::new(DigestAlgo::Blake3, hex64('b')).unwrap();
        let a3 = Artifact::new(other_digest, provenance(), TarballBytes(vec![1]));
        assert!(!a1.content_eq(&a3));
    }

    #[test]
    fn artifact_serde_round_trip() {
        let a = Artifact::new(digest_blake3_aaa(), provenance(), TarballBytes(vec![1, 2, 3, 4]));
        let json = serde_json::to_string(&a).unwrap();
        let back: Artifact<TarballBytes> = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn artifact_payload_typed_not_opaque_bytes() {
        // Demonstrates the generic-payload value of Artifact<T>: the
        // payload is typed at the source-controller layer, not opaque
        // bytes. FluxCD's `artifact` block hides this; Artifact<T>
        // exposes it.

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct HelmChart {
            name: String,
            version: String,
        }

        let a = Artifact::new(
            digest_blake3_aaa(),
            provenance(),
            HelmChart {
                name: "nginx".into(),
                version: "1.2.3".into(),
            },
        );

        assert_eq!(a.payload.name, "nginx");
        assert_eq!(a.payload.version, "1.2.3");
    }
}
