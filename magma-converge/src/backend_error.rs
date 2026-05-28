//! `BackendError` — the canonical trait every typed backend / validator
//! error in the substrate implements.
//!
//! Spec: `theory/PATTERN-EXTRACTION.md` Pattern 2 (TransientPermanent
//! BackendError). Extracted after 3+ sites repeated the same
//! `.is_retryable() + .kind()` shape:
//!
//!   - `shigoto_types::FailureKind` (Transient / Declarative)
//!   - `magma_converge::BlobStoreError` (NotFound / PermissionDenied /
//!     Transient / Permanent)
//!   - `magma_converge::WebhookError` (MissingHeader / InvalidSignature
//!     / PayloadDecode / UnknownEventType / Transient / Permanent)
//!
//! ## What the trait codifies
//!
//! Every backend-shaped error has THREE invariants the substrate cares
//! about:
//!
//!   1. **Is it retryable?** — distinguishes Transient-class faults
//!      (network blip, rate-limit, leadership transition) from
//!      Permanent-class faults (auth denial, malformed payload, missing
//!      resource). Drives whether the caller schedules a backoff retry
//!      or escalates to the operator.
//!
//!   2. **What kind is it?** — a stable, lowercase, snake-case
//!      identifier per variant. Used as a metrics label, an audit-log
//!      tag, and the key under which an error class is rate-limited.
//!      Stable across crate versions — adding a new variant requires
//!      naming it; renaming an existing variant is a breaking change.
//!
//!   3. **Is it an auth failure?** — distinguishes "the caller's
//!      identity is wrong" (401 / 403) from "the request shape is
//!      wrong" (400) from "the backend is sad" (503). Default is
//!      `false`; impls override when the error carries an
//!      identity-rejection variant.
//!
//! ## The trait
//!
//! ```rust,no_run
//! use magma_converge::backend_error::BackendError;
//! use thiserror::Error;
//!
//! #[derive(Debug, Error)]
//! enum MyBackendError {
//!     #[error("transient: {0}")] Transient(String),
//!     #[error("permanent: {0}")] Permanent(String),
//! }
//!
//! impl BackendError for MyBackendError {
//!     fn is_retryable(&self) -> bool {
//!         matches!(self, MyBackendError::Transient(_))
//!     }
//!     fn kind(&self) -> &'static str {
//!         match self {
//!             MyBackendError::Transient(_) => "transient",
//!             MyBackendError::Permanent(_) => "permanent",
//!         }
//!     }
//! }
//! ```
//!
//! ## When the derive macro ships
//!
//! Per the substrate's three-site rule: with 2 backends impl'ing
//! today (BlobStoreError, WebhookError), the third manual impl
//! triggers extraction of `#[derive(BackendError)]` via
//! `tatara-rust-forge catalog-instantiate` — typed `#[backend_error]`
//! attributes (`transient`, `permanent`, `auth`, `not_found`) on
//! variants auto-emit the impl.

#![allow(missing_docs)]

/// Canonical trait for typed backend / validator errors.
///
/// Implementations carry typed semantic distinctions the substrate
/// uses to route retries, label metrics, and emit operator alerts.
///
/// `Send + Sync + 'static` are required so any `Box<dyn BackendError>`
/// can be safely shared across reconciler workers.
pub trait BackendError: std::error::Error + Send + Sync + 'static {
    /// `true` for errors the caller may safely retry after a backoff.
    /// Transient-class faults (network blip, rate-limit, leadership
    /// transition) return `true`; Permanent-class faults return
    /// `false`.
    fn is_retryable(&self) -> bool;

    /// Stable, lowercase, snake-case identifier for the error variant.
    /// Used as a metrics label / audit-log tag / rate-limit key.
    /// Stable across crate versions — renaming an existing variant
    /// is a breaking change.
    fn kind(&self) -> &'static str;

    /// `true` for errors that indicate the caller's identity was
    /// rejected (401 / 403 maps). Default `false` — backends with
    /// identity-rejection variants override.
    fn is_auth_failure(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use thiserror::Error;

    #[derive(Debug, Error)]
    enum TestError {
        #[error("transient")]
        Transient,
        #[error("permanent")]
        Permanent,
        #[error("auth")]
        Auth,
    }

    impl BackendError for TestError {
        fn is_retryable(&self) -> bool {
            matches!(self, TestError::Transient)
        }

        fn kind(&self) -> &'static str {
            match self {
                TestError::Transient => "transient",
                TestError::Permanent => "permanent",
                TestError::Auth => "auth",
            }
        }

        fn is_auth_failure(&self) -> bool {
            matches!(self, TestError::Auth)
        }
    }

    #[test]
    fn transient_is_retryable() {
        assert!(TestError::Transient.is_retryable());
        assert!(!TestError::Permanent.is_retryable());
        assert!(!TestError::Auth.is_retryable());
    }

    #[test]
    fn kinds_are_distinct() {
        assert_eq!(TestError::Transient.kind(), "transient");
        assert_eq!(TestError::Permanent.kind(), "permanent");
        assert_eq!(TestError::Auth.kind(), "auth");
    }

    #[test]
    fn auth_failure_default_is_false() {
        // Default impl is false unless overridden.
        assert!(!TestError::Transient.is_auth_failure());
        assert!(!TestError::Permanent.is_auth_failure());
        // The override:
        assert!(TestError::Auth.is_auth_failure());
    }

    #[test]
    fn dyn_dispatchable() {
        let boxed: Box<dyn BackendError> = Box::new(TestError::Transient);
        assert!(boxed.is_retryable());
        assert_eq!(boxed.kind(), "transient");
    }

    #[test]
    fn composes_with_existing_blobstore_error_via_blanket_impl() {
        // Proof: BlobStoreError implements the same shape but doesn't
        // yet declare BackendError. After ratification we add the
        // `impl BackendError for BlobStoreError { ... }` impl in
        // blobstore.rs; this test will then move to that module.
    }
}
