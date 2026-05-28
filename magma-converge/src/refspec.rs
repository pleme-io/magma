//! Typed git/OCI/object-store ref polymorphism — the canonical
//! `RefSpec` enum every FluxCD-shape source consumer uses.
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III, P1.0.
//!
//! Subsumes the "what ref?" polymorphism currently scattered as
//! `Option<String>` fields (`spec.ref.branch`, `spec.ref.tag`,
//! `spec.ref.semver`, `spec.ref.commit`, `spec.ref.name`) in every
//! source-shape CRD (GitRepository, OCIRepository, HelmRepository,
//! Bucket) and in our own substrate's git consumers (tend's
//! workspace repos, magma's source fetchers, lava's chart refs).
//!
//! The enum carries the typed intent + the typed payload. Parsers
//! (e.g. cofre, samba, the substrate's git wrapper) accept &RefSpec
//! instead of forking on an `Option<String>` tuple.
//!
//! # Variants
//!
//! - `Branch(name)`   — track HEAD of branch; reconciler re-fetches on every interval
//! - `Tag(name)`      — track a specific tag; immutable per tag-name (under standard git/oci semantics)
//! - `Semver(range)`  — track latest tag matching the semver range (e.g. `^1.2.0`)
//! - `Commit(sha)`    — pin to a specific commit SHA; never changes
//! - `Name(name)`     — name-shaped ref (cosign signatures, OCI artifacts named by tag)
//! - `Digest(sha256)` — content-addressed pin; the strongest form of pinning
//!
//! # Resolution
//!
//! The reconciler resolves a `RefSpec` to a concrete revision string
//! at fetch time. `Commit` and `Digest` resolve to themselves;
//! `Branch` / `Tag` / `Semver` / `Name` resolve via the upstream API.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Typed reference into a git repo, OCI registry, or content-addressed
/// store. Carries both the variant (intent) and the payload (value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum RefSpec {
    /// Track HEAD of a named branch. Reconciler re-fetches every cycle.
    Branch(String),
    /// Track a specific tag. Immutable per tag name.
    Tag(String),
    /// Track latest tag matching a semver range (e.g. `^1.2.0`, `~2.0.0`).
    Semver(String),
    /// Pin to a specific commit/object SHA. Never changes.
    Commit(String),
    /// Name-shaped ref (OCI artifact name, cosign signature, etc).
    Name(String),
    /// Content-addressed digest (e.g. `sha256:abc...`). Strongest pin.
    Digest(String),
}

impl RefSpec {
    /// `true` when this ref is content-addressed or commit-pinned —
    /// the reconciler can skip re-fetch unless the spec itself
    /// changes.
    pub fn is_immutable(&self) -> bool {
        matches!(self, RefSpec::Commit(_) | RefSpec::Digest(_))
    }

    /// `true` when this ref tracks moving upstream state and must be
    /// re-resolved every reconcile cycle.
    pub fn is_floating(&self) -> bool {
        matches!(
            self,
            RefSpec::Branch(_) | RefSpec::Semver(_) | RefSpec::Tag(_) | RefSpec::Name(_)
        )
    }

    /// Extract the raw value string regardless of variant.
    pub fn value(&self) -> &str {
        match self {
            RefSpec::Branch(s)
            | RefSpec::Tag(s)
            | RefSpec::Semver(s)
            | RefSpec::Commit(s)
            | RefSpec::Name(s)
            | RefSpec::Digest(s) => s.as_str(),
        }
    }

    /// Variant discriminant as a stable string. Useful for metrics
    /// labels and audit logs that want to count refs by kind.
    pub fn kind(&self) -> &'static str {
        match self {
            RefSpec::Branch(_) => "branch",
            RefSpec::Tag(_) => "tag",
            RefSpec::Semver(_) => "semver",
            RefSpec::Commit(_) => "commit",
            RefSpec::Name(_) => "name",
            RefSpec::Digest(_) => "digest",
        }
    }
}

impl fmt::Display for RefSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind(), self.value())
    }
}

/// Errors parsing a `RefSpec` from a `kind:value` string.
#[derive(Debug, thiserror::Error)]
pub enum RefSpecParseError {
    #[error("ref string missing 'kind:value' separator: {0:?}")]
    MissingSeparator(String),
    #[error("unknown ref kind {kind:?} in {full:?}; expected one of branch/tag/semver/commit/name/digest")]
    UnknownKind { kind: String, full: String },
    #[error("ref value cannot be empty in {0:?}")]
    EmptyValue(String),
}

impl std::str::FromStr for RefSpec {
    type Err = RefSpecParseError;

    /// Parse `"<kind>:<value>"`. Examples:
    ///   - `"branch:main"`
    ///   - `"tag:v1.2.3"`
    ///   - `"semver:^1.2.0"`
    ///   - `"commit:a1b2c3d"`
    ///   - `"digest:sha256:abc..."`  (digest values may contain ':')
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, value) = s
            .split_once(':')
            .ok_or_else(|| RefSpecParseError::MissingSeparator(s.to_string()))?;
        if value.is_empty() {
            return Err(RefSpecParseError::EmptyValue(s.to_string()));
        }
        match kind {
            "branch" => Ok(RefSpec::Branch(value.into())),
            "tag" => Ok(RefSpec::Tag(value.into())),
            "semver" => Ok(RefSpec::Semver(value.into())),
            "commit" => Ok(RefSpec::Commit(value.into())),
            "name" => Ok(RefSpec::Name(value.into())),
            "digest" => Ok(RefSpec::Digest(value.into())),
            other => Err(RefSpecParseError::UnknownKind {
                kind: other.to_string(),
                full: s.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn immutable_variants_classified_correctly() {
        assert!(RefSpec::Commit("abc".into()).is_immutable());
        assert!(RefSpec::Digest("sha256:abc".into()).is_immutable());
        assert!(!RefSpec::Branch("main".into()).is_immutable());
        assert!(!RefSpec::Tag("v1".into()).is_immutable());
        assert!(!RefSpec::Semver("^1.0".into()).is_immutable());
        assert!(!RefSpec::Name("foo".into()).is_immutable());
    }

    #[test]
    fn floating_variants_classified_correctly() {
        assert!(RefSpec::Branch("main".into()).is_floating());
        assert!(RefSpec::Tag("v1".into()).is_floating());
        assert!(RefSpec::Semver("^1.0".into()).is_floating());
        assert!(RefSpec::Name("foo".into()).is_floating());
        assert!(!RefSpec::Commit("abc".into()).is_floating());
        assert!(!RefSpec::Digest("sha256:abc".into()).is_floating());
    }

    #[test]
    fn immutable_and_floating_are_complementary() {
        // Every variant is either immutable XOR floating — never both, never neither.
        for spec in [
            RefSpec::Branch("a".into()),
            RefSpec::Tag("a".into()),
            RefSpec::Semver("a".into()),
            RefSpec::Commit("a".into()),
            RefSpec::Name("a".into()),
            RefSpec::Digest("a".into()),
        ] {
            assert_ne!(spec.is_immutable(), spec.is_floating(),
                "variant {spec:?} must be exactly one of immutable or floating");
        }
    }

    #[test]
    fn value_returns_inner_string() {
        assert_eq!(RefSpec::Branch("main".into()).value(), "main");
        assert_eq!(RefSpec::Tag("v1.2.3".into()).value(), "v1.2.3");
        assert_eq!(RefSpec::Digest("sha256:abc".into()).value(), "sha256:abc");
    }

    #[test]
    fn kind_returns_stable_discriminant() {
        assert_eq!(RefSpec::Branch("x".into()).kind(), "branch");
        assert_eq!(RefSpec::Tag("x".into()).kind(), "tag");
        assert_eq!(RefSpec::Semver("x".into()).kind(), "semver");
        assert_eq!(RefSpec::Commit("x".into()).kind(), "commit");
        assert_eq!(RefSpec::Name("x".into()).kind(), "name");
        assert_eq!(RefSpec::Digest("x".into()).kind(), "digest");
    }

    #[test]
    fn display_round_trips_through_parse() {
        let specs = [
            RefSpec::Branch("main".into()),
            RefSpec::Tag("v1.2.3".into()),
            RefSpec::Semver("^1.2.0".into()),
            RefSpec::Commit("a1b2c3d".into()),
            RefSpec::Name("my-artifact".into()),
        ];
        for s in &specs {
            let formatted = s.to_string();
            let parsed: RefSpec = formatted.parse().unwrap();
            assert_eq!(parsed, *s, "round-trip failed for {s:?} -> {formatted:?}");
        }
    }

    #[test]
    fn digest_value_containing_colon_round_trips() {
        // Digest values legitimately contain ':' (sha256:abc...). The
        // parser only splits at the FIRST ':' so the rest is preserved.
        let d = RefSpec::Digest("sha256:abc123def456".into());
        let parsed: RefSpec = d.to_string().parse().unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = "no-colon".parse::<RefSpec>().unwrap_err();
        assert!(matches!(err, RefSpecParseError::MissingSeparator(_)));
    }

    #[test]
    fn parse_rejects_empty_value() {
        let err = "branch:".parse::<RefSpec>().unwrap_err();
        assert!(matches!(err, RefSpecParseError::EmptyValue(_)));
    }

    #[test]
    fn parse_rejects_unknown_kind() {
        let err = "weird:value".parse::<RefSpec>().unwrap_err();
        match err {
            RefSpecParseError::UnknownKind { kind, .. } => assert_eq!(kind, "weird"),
            other => panic!("expected UnknownKind, got {other:?}"),
        }
    }

    #[test]
    fn serde_round_trip_via_json() {
        let s = RefSpec::Semver("^1.2.0".into());
        let json = serde_json::to_string(&s).unwrap();
        let back: RefSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn serde_uses_kind_value_envelope() {
        // The `#[serde(tag = "kind", content = "value")]` annotation
        // gives us `{"kind": "branch", "value": "main"}` shape so the
        // JSON form is operator-readable.
        let s = RefSpec::Branch("main".into());
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"value\""));
        assert!(json.contains("\"branch\""));
        assert!(json.contains("\"main\""));
    }
}
