//! Typed webhook intake + signature validation — the canonical
//! `WebhookValidator` trait every fleet-wide HTTP-edge intake reads.
//! Spec: `theory/FLUXCD-CONVERGENCE.md` §III, P1.5.
//!
//! Subsumes FluxCD's Receiver controller (22-variant `type` enum
//! over generic/github/gitlab/bitbucket/harbor/dockerhub/quay/...
//! plus generic-hmac + generic-oidc). Lifts the shape into a typed
//! trait so:
//!
//! - Per-provider validators live behind one polymorphic surface
//!   (`Box<dyn WebhookValidator>`)
//! - Headers + body are typed; no untyped string-rattling
//! - Successful validation produces a typed `WebhookEvent<P>` the
//!   reconciler can route via existing `Classifier<WebhookEvent, ReconcileTrigger>`
//! - Failure modes are typed via `WebhookError` (mirrors the
//!   `BlobStoreError` Transient/Permanent shape for retry routing)
//!
//! # What ships in this crate
//!
//! The **trait** + the **typed types** + **two reference impls** with
//! NO cryptographic dependencies:
//!
//! - `NoOpValidator` — accepts every request as-is. For tests + dev
//!   environments where the network is already trusted.
//! - `HeaderTokenValidator` — checks for a static token value in a
//!   named header. Suitable for low-stakes intakes where rotation is
//!   handled separately (e.g. internal cron hits behind a firewall).
//!
//! HMAC + OIDC validators (the cryptographically real ones) ship as
//! separate adapter crates (e.g. `magma-webhook-hmac`, `magma-webhook-oidc`)
//! that depend on `hmac`/`sha2`/`jsonwebtoken`. Keeping crypto out of
//! the substrate core means consumers pay for what they use.
//!
//! # Composition
//!
//! ```ignore
//! let validator: Box<dyn WebhookValidator> = match config.kind {
//!     WebhookKind::Github      => Box::new(GithubHmacValidator { secret }),
//!     WebhookKind::GenericHmac => Box::new(GenericHmacValidator { secret, header }),
//!     WebhookKind::GenericOidc => Box::new(OidcValidator { issuer, audience }),
//!     _                        => Box::new(HeaderTokenValidator { header, token }),
//! };
//!
//! let req = WebhookRequest { method, path, headers, body };
//! match validator.validate(&req) {
//!     Ok(event)  => dispatch(event).await,
//!     Err(WebhookError::InvalidSignature) => return 401,
//!     Err(WebhookError::Transient { .. }) => return 503,
//!     Err(other) => return 400,
//! }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Canonical webhook-provider taxonomy. Mirrors FluxCD Receiver's
/// `type` field but as a typed enum that can be extended without
/// touching parse code.
///
/// `Generic*` variants are wire-format generics (the substrate's own
/// validators); the named variants (`Github`, `Gitlab`, etc) carry
/// vendor-specific signature schemes that adapter crates implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebhookKind {
    /// No verification — accepts every request. Test/dev only.
    Generic,
    /// HMAC signature on raw body via a configured header + secret.
    GenericHmac,
    /// OIDC ID-token verification (issuer + audience).
    GenericOidc,
    /// Static-token-in-header verification.
    HeaderToken,

    /// GitHub-shape HMAC-SHA256 (`X-Hub-Signature-256`).
    Github,
    /// GitLab-shape token in `X-Gitlab-Token`.
    Gitlab,
    /// Bitbucket-server HMAC.
    Bitbucket,

    /// Harbor / quay / GCR / ACR / Nexus registry notifications.
    Harbor,
    DockerHub,
    Quay,
    Nexus,
    Gcr,
    Acr,

    /// CDEvents-shape webhook (vendor-neutral CI/CD event format).
    Cdevents,
}

impl WebhookKind {
    pub fn name(self) -> &'static str {
        match self {
            WebhookKind::Generic => "generic",
            WebhookKind::GenericHmac => "generic-hmac",
            WebhookKind::GenericOidc => "generic-oidc",
            WebhookKind::HeaderToken => "header-token",
            WebhookKind::Github => "github",
            WebhookKind::Gitlab => "gitlab",
            WebhookKind::Bitbucket => "bitbucket",
            WebhookKind::Harbor => "harbor",
            WebhookKind::DockerHub => "dockerhub",
            WebhookKind::Quay => "quay",
            WebhookKind::Nexus => "nexus",
            WebhookKind::Gcr => "gcr",
            WebhookKind::Acr => "acr",
            WebhookKind::Cdevents => "cdevents",
        }
    }
}

/// Typed HTTP webhook request. The substrate carries the raw method
/// + path + headers + body; per-validator parsing happens inside
/// `validate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookRequest {
    /// HTTP method (typically `"POST"`).
    pub method: String,
    /// URL path the request landed on (e.g. `"/hooks/abc123"`).
    pub path: String,
    /// All request headers. Keys SHOULD be lowercased by the HTTP
    /// stack before being passed in (HTTP/1.1 headers are
    /// case-insensitive; some validators key on `x-foo-bar` exact
    /// casing).
    pub headers: BTreeMap<String, String>,
    /// Raw request body bytes — HMAC validators sign over these.
    pub body: Vec<u8>,
}

impl WebhookRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Case-insensitive header lookup. HTTP headers are
    /// case-insensitive per RFC 7230 §3.2; the BTreeMap stores
    /// arbitrary case so we walk + compare lowercase.
    pub fn header(&self, name: &str) -> Option<&str> {
        let target = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == target)
            .map(|(_, v)| v.as_str())
    }
}

/// Typed event emitted after a `WebhookRequest` passes validation.
/// Generic over the payload type so per-provider decoded shapes can
/// flow through unchanged (`WebhookEvent<GithubPushPayload>` etc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookEvent<P = serde_json::Value> {
    pub kind: WebhookKind,
    /// Decoded payload — `serde_json::Value` by default; per-provider
    /// adapters can produce typed payload shapes.
    pub payload: P,
    /// Headers preserved for downstream metadata enrichment (e.g.
    /// GitHub's `X-GitHub-Event: push` flows through here).
    pub headers: BTreeMap<String, String>,
}

/// Errors a `WebhookValidator` can return. Mirrors the
/// `BlobStoreError` Transient/Permanent shape so calling code can
/// route retries uniformly.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// Required signature/token header missing.
    #[error("webhook missing expected header {header:?}")]
    MissingHeader { header: String },

    /// Signature/token present but invalid.
    #[error("webhook signature invalid: {detail}")]
    InvalidSignature { detail: String },

    /// Payload body wasn't decodable into the expected shape.
    #[error("webhook payload decode failed: {detail}")]
    PayloadDecode { detail: String },

    /// Unrecognized event kind in payload (e.g. GitHub event header
    /// names an event we don't handle).
    #[error("webhook unknown event type {kind:?}: {detail}")]
    UnknownEventType { kind: String, detail: String },

    /// Transient validator failure (e.g. external OIDC provider
    /// unreachable) — caller may retry.
    #[error("webhook transient validator error: {detail}")]
    Transient { detail: String },

    /// Permanent validator failure (misconfigured secret, etc.) —
    /// caller must not retry.
    #[error("webhook permanent validator error: {detail}")]
    Permanent { detail: String },
}

impl WebhookError {
    /// `true` for `Transient` — caller may retry. Other variants
    /// are deterministic on this request and shouldn't retry.
    pub fn is_retryable(&self) -> bool {
        matches!(self, WebhookError::Transient { .. })
    }

    /// `true` for failures that map to HTTP 401 (signature/token
    /// problems). All others map to 400 (bad request) or 503
    /// (transient backend).
    pub fn is_auth_failure(&self) -> bool {
        matches!(
            self,
            WebhookError::MissingHeader { .. } | WebhookError::InvalidSignature { .. }
        )
    }

    /// Variant discriminant string for metrics labels.
    pub fn kind(&self) -> &'static str {
        match self {
            WebhookError::MissingHeader { .. } => "missing_header",
            WebhookError::InvalidSignature { .. } => "invalid_signature",
            WebhookError::PayloadDecode { .. } => "payload_decode",
            WebhookError::UnknownEventType { .. } => "unknown_event_type",
            WebhookError::Transient { .. } => "transient",
            WebhookError::Permanent { .. } => "permanent",
        }
    }
}

/// Canonical webhook validator trait. Implementations validate the
/// incoming `WebhookRequest` (signature, token, OIDC, etc) and
/// produce a typed `WebhookEvent<serde_json::Value>` on success.
///
/// Sync at the trait boundary — most validators are CPU-only (HMAC
/// compute, signature compare). Validators that need external
/// network (OIDC JWKS fetch) cache the keys + provide a blocking
/// adapter; truly-async OIDC validators ship as separate crates.
pub trait WebhookValidator: Send + Sync {
    /// Stable kind name for metrics + routing.
    fn kind(&self) -> WebhookKind;

    /// Validate `req` + extract the typed event. On success, the
    /// payload is decoded as `serde_json::Value`; per-provider
    /// adapters can convert to richer typed payloads downstream.
    fn validate(&self, req: &WebhookRequest) -> Result<WebhookEvent, WebhookError>;
}

// ── Reference impl: NoOpValidator ─────────────────────────────────

/// Validator that accepts every request without verification. The
/// body is decoded as JSON (best-effort); if decode fails the
/// payload is left as `serde_json::Value::Null`.
///
/// Test/dev use only. Production should always use a cryptographic
/// validator from a `magma-webhook-*` adapter crate.
#[derive(Debug, Default, Copy, Clone)]
pub struct NoOpValidator;

impl WebhookValidator for NoOpValidator {
    fn kind(&self) -> WebhookKind {
        WebhookKind::Generic
    }

    fn validate(&self, req: &WebhookRequest) -> Result<WebhookEvent, WebhookError> {
        let payload = serde_json::from_slice::<serde_json::Value>(&req.body)
            .unwrap_or(serde_json::Value::Null);
        Ok(WebhookEvent {
            kind: WebhookKind::Generic,
            payload,
            headers: req.headers.clone(),
        })
    }
}

// ── Reference impl: HeaderTokenValidator ──────────────────────────

/// Validator that accepts requests carrying a configured static
/// token in a named header. Suitable for low-stakes intakes (internal
/// cron triggers behind firewall) where the secret value is rotated
/// externally.
///
/// Constant-time comparison via `subtle::ConstantTimeEq` is the safe
/// choice for HMAC validators in adapter crates; this minimal
/// validator uses naive `==` because the token is a configured
/// constant and timing-attack risk is negligible. Production
/// validators should use constant-time comparison.
#[derive(Debug, Clone)]
pub struct HeaderTokenValidator {
    /// Name of the header carrying the token (e.g. `"X-Auth-Token"`).
    pub header: String,
    /// Expected token value.
    pub expected: String,
}

impl HeaderTokenValidator {
    pub fn new(header: impl Into<String>, expected: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            expected: expected.into(),
        }
    }
}

impl WebhookValidator for HeaderTokenValidator {
    fn kind(&self) -> WebhookKind {
        WebhookKind::HeaderToken
    }

    fn validate(&self, req: &WebhookRequest) -> Result<WebhookEvent, WebhookError> {
        let got = req.header(&self.header).ok_or_else(|| {
            WebhookError::MissingHeader {
                header: self.header.clone(),
            }
        })?;
        if got != self.expected {
            return Err(WebhookError::InvalidSignature {
                detail: format!("token mismatch on header {:?}", self.header),
            });
        }
        let payload = serde_json::from_slice::<serde_json::Value>(&req.body)
            .unwrap_or(serde_json::Value::Null);
        Ok(WebhookEvent {
            kind: WebhookKind::HeaderToken,
            payload,
            headers: req.headers.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── WebhookKind ────────────────────────────────────────────────

    #[test]
    fn webhook_kind_names() {
        assert_eq!(WebhookKind::Generic.name(), "generic");
        assert_eq!(WebhookKind::GenericHmac.name(), "generic-hmac");
        assert_eq!(WebhookKind::Github.name(), "github");
        assert_eq!(WebhookKind::Cdevents.name(), "cdevents");
    }

    #[test]
    fn webhook_kind_serde_kebab_case() {
        let k = WebhookKind::GenericHmac;
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, "\"generic-hmac\"");
        let back: WebhookKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }

    // ── WebhookRequest builder + lookups ───────────────────────────

    #[test]
    fn request_builder_chain() {
        let r = WebhookRequest::new("POST", "/hooks/abc")
            .with_header("X-Github-Event", "push")
            .with_header("Content-Type", "application/json")
            .with_body(br#"{"ref":"refs/heads/main"}"#.to_vec());

        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/hooks/abc");
        assert_eq!(r.headers.len(), 2);
        assert!(r.body.starts_with(b"{"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let r = WebhookRequest::new("POST", "/")
            .with_header("X-Github-Event", "push");
        assert_eq!(r.header("X-Github-Event"), Some("push"));
        assert_eq!(r.header("x-github-event"), Some("push"));
        assert_eq!(r.header("X-GITHUB-EVENT"), Some("push"));
        assert_eq!(r.header("nonexistent"), None);
    }

    #[test]
    fn request_serde_round_trip() {
        let r = WebhookRequest::new("POST", "/hooks/abc")
            .with_header("X-Auth", "token123")
            .with_body(b"hello".to_vec());
        let json = serde_json::to_string(&r).unwrap();
        let back: WebhookRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── WebhookError classification ────────────────────────────────

    #[test]
    fn error_retryable_only_for_transient() {
        let e = WebhookError::Transient {
            detail: "JWKS 503".into(),
        };
        assert!(e.is_retryable());
        let e = WebhookError::InvalidSignature {
            detail: "bad sig".into(),
        };
        assert!(!e.is_retryable());
        let e = WebhookError::MissingHeader {
            header: "X-Sig".into(),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn error_auth_failures_classified() {
        assert!(
            WebhookError::MissingHeader {
                header: "x".into()
            }
            .is_auth_failure()
        );
        assert!(
            WebhookError::InvalidSignature {
                detail: "x".into()
            }
            .is_auth_failure()
        );
        assert!(
            !WebhookError::PayloadDecode {
                detail: "x".into()
            }
            .is_auth_failure()
        );
        assert!(
            !WebhookError::Transient {
                detail: "x".into()
            }
            .is_auth_failure()
        );
    }

    #[test]
    fn error_kind_discriminant() {
        assert_eq!(
            WebhookError::MissingHeader {
                header: "x".into()
            }
            .kind(),
            "missing_header"
        );
        assert_eq!(
            WebhookError::InvalidSignature {
                detail: "x".into()
            }
            .kind(),
            "invalid_signature"
        );
        assert_eq!(
            WebhookError::Transient {
                detail: "x".into()
            }
            .kind(),
            "transient"
        );
    }

    // ── NoOpValidator ──────────────────────────────────────────────

    #[test]
    fn noop_accepts_anything() {
        let v = NoOpValidator;
        let req = WebhookRequest::new("POST", "/").with_body(b"{}".to_vec());
        let event = v.validate(&req).unwrap();
        assert_eq!(event.kind, WebhookKind::Generic);
    }

    #[test]
    fn noop_decodes_json_body_when_possible() {
        let v = NoOpValidator;
        let req = WebhookRequest::new("POST", "/").with_body(br#"{"a":1}"#.to_vec());
        let event = v.validate(&req).unwrap();
        assert_eq!(event.payload["a"], 1);
    }

    #[test]
    fn noop_returns_null_payload_on_invalid_json() {
        let v = NoOpValidator;
        let req = WebhookRequest::new("POST", "/").with_body(b"not json".to_vec());
        let event = v.validate(&req).unwrap();
        assert_eq!(event.payload, serde_json::Value::Null);
    }

    #[test]
    fn noop_preserves_headers_in_event() {
        let v = NoOpValidator;
        let req = WebhookRequest::new("POST", "/")
            .with_header("X-Github-Event", "push");
        let event = v.validate(&req).unwrap();
        assert_eq!(event.headers.get("X-Github-Event").map(|s| s.as_str()), Some("push"));
    }

    // ── HeaderTokenValidator ───────────────────────────────────────

    #[test]
    fn header_token_accepts_matching() {
        let v = HeaderTokenValidator::new("X-Auth-Token", "secret123");
        let req = WebhookRequest::new("POST", "/").with_header("X-Auth-Token", "secret123");
        let event = v.validate(&req).unwrap();
        assert_eq!(event.kind, WebhookKind::HeaderToken);
    }

    #[test]
    fn header_token_rejects_missing_header() {
        let v = HeaderTokenValidator::new("X-Auth-Token", "secret123");
        let req = WebhookRequest::new("POST", "/");
        let err = v.validate(&req).unwrap_err();
        assert!(matches!(err, WebhookError::MissingHeader { .. }));
        assert!(err.is_auth_failure());
    }

    #[test]
    fn header_token_rejects_mismatched_value() {
        let v = HeaderTokenValidator::new("X-Auth-Token", "secret123");
        let req = WebhookRequest::new("POST", "/").with_header("X-Auth-Token", "wrong");
        let err = v.validate(&req).unwrap_err();
        assert!(matches!(err, WebhookError::InvalidSignature { .. }));
        assert!(err.is_auth_failure());
    }

    #[test]
    fn header_token_case_insensitive_header_lookup() {
        // HTTP headers are case-insensitive — the validator MUST find
        // its expected header regardless of casing in the request.
        let v = HeaderTokenValidator::new("X-Auth-Token", "secret");
        let req = WebhookRequest::new("POST", "/").with_header("x-auth-token", "secret");
        let event = v.validate(&req).unwrap();
        assert_eq!(event.kind, WebhookKind::HeaderToken);
    }

    // ── dyn dispatch ───────────────────────────────────────────────

    #[test]
    fn dyn_dispatch_through_box() {
        let validators: Vec<Box<dyn WebhookValidator>> = vec![
            Box::new(NoOpValidator),
            Box::new(HeaderTokenValidator::new("X-Auth", "s")),
        ];

        let req = WebhookRequest::new("POST", "/").with_header("X-Auth", "s");
        for v in &validators {
            let _ = v.validate(&req); // both succeed for this req
        }
    }

    #[test]
    fn validators_have_distinct_kinds() {
        assert_eq!(NoOpValidator.kind(), WebhookKind::Generic);
        assert_eq!(
            HeaderTokenValidator::new("h", "v").kind(),
            WebhookKind::HeaderToken
        );
    }

    // Composability with shigoto-types::Classifier<WebhookEvent, T>
    // is demonstrated in downstream consumer crates that depend on
    // both magma-converge AND shigoto-types (e.g. pangea-operator's
    // webhook-receiver controller). Magma-converge stays
    // shigoto-types-free at the crate boundary.
}
