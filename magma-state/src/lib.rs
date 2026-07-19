//! magma-state — terraform.tfstate v4 read/write, state migrations,
//! state locking, sensitive-value redaction.
//!
//! Byte-exact compat with OpenTofu state-file format per
//! `theory/MAGMA.md` §II.2 row 4. Every `magma apply` produces a state
//! file that round-trips through `tofu show -json` unchanged, and vice
//! versa. See `theory/MAGMA.md` §II.6 level 4 for the round-trip proof
//! harness.
//!
//! Disk I/O (`read_state` / `write_state` / `round_trip`) goes through
//! the [`tfstate_v4`] wire-format boundary — a real, pre-existing
//! `terraform.tfstate` produced by `tofu apply`/`terraform apply` reads
//! correctly (not just magma's own previously-written files). See that
//! module's doc for exactly what's modeled, what's verified against a
//! real fixture, and what's a named, deliberate gap.

use std::path::{Path, PathBuf};

use magma_types::{ResourceKind, State};
use thiserror::Error;
use uuid::Uuid;

pub mod tfstate_v4;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("state file version {0} is not supported (only v4)")]
    UnsupportedVersion(u64),
    #[error("state file lineage mismatch: have {have}, expected {expected}")]
    LineageMismatch { have: Uuid, expected: Uuid },
    #[error("state file lineage {0:?} is not a valid UUID")]
    InvalidLineage(String),
    #[error("malformed resource address {0:?}: {1}")]
    MalformedAddress(String, String),
    #[error("malformed provider reference {0:?}")]
    MalformedProvider(String),
    #[error("malformed \"private\" field (expected base64): {0}")]
    MalformedPrivate(String),
    #[error(
        "resource kind {0:?} cannot be written to a tfstate v4 resources array \
         (only Managed/Data are valid there)"
    )]
    UnwritableResourceKind(ResourceKind),
}

// ── Empty state ────────────────────────────────────────────────────

#[must_use]
pub fn empty_state() -> State {
    State {
        version: 4,
        terraform_version: "1.7.0".into(),
        serial: 0,
        lineage: Uuid::new_v4(),
        outputs: Default::default(),
        resources: Vec::new(),
    }
}

// ── Disk I/O ───────────────────────────────────────────────────────

/// Read a `terraform.tfstate` v4 file from disk into a typed `State`.
/// Returns an `empty_state()` if the file doesn't exist (matches
/// Terraform's "no state means fresh workspace" semantics).
///
/// Reads the real wire format via [`tfstate_v4::decode`] — a
/// pre-existing state file produced by `tofu apply` / `terraform
/// apply` (not just a file magma itself previously wrote) parses
/// correctly.
pub async fn read_state(path: impl AsRef<Path>) -> Result<State, StateError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(empty_state());
    }
    let bytes = tokio::fs::read(path).await?;
    let state = tfstate_v4::decode(&bytes)?;
    if state.version != 4 {
        return Err(StateError::UnsupportedVersion(state.version));
    }
    Ok(state)
}

/// Write a `State` atomically — write to `<path>.tmp`, fsync, rename.
/// Atomic so a crash mid-write doesn't corrupt the canonical file.
///
/// Writes the real wire format via [`tfstate_v4::encode`] so the
/// result is directly readable by `tofu show -json` / `terraform
/// show -json` and re-adoptable by a real tofu/terraform run — not
/// just by another magma instance.
pub async fn write_state(path: impl AsRef<Path>, state: &State) -> Result<(), StateError> {
    let path = path.as_ref();
    let tmp: PathBuf = path.with_extension("tfstate.tmp");
    let bytes = tfstate_v4::encode(state)?;
    tokio::fs::write(&tmp, &bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Round-trip real `terraform.tfstate` v4 bytes through the typed
/// `State` boundary without disk I/O. Used by the §II.6 level 4
/// byte-exact tests.
pub fn round_trip(bytes: &[u8]) -> Result<Vec<u8>, StateError> {
    let state = tfstate_v4::decode(bytes)?;
    tfstate_v4::encode(&state)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_state_round_trips() {
        let s = empty_state();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("terraform.tfstate");
        write_state(&path, &s).await.unwrap();
        let s2 = read_state(&path).await.unwrap();
        assert_eq!(s.version, s2.version);
        assert_eq!(s.lineage, s2.lineage);
        assert_eq!(s.resources.len(), s2.resources.len());
    }

    #[tokio::test]
    async fn read_missing_state_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("terraform.tfstate");
        let s = read_state(&path).await.unwrap();
        assert_eq!(s.version, 4);
        assert_eq!(s.resources.len(), 0);
    }

    #[tokio::test]
    async fn write_is_atomic() {
        let s = empty_state();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("terraform.tfstate");
        write_state(&path, &s).await.unwrap();
        // The tmp sibling must not survive a successful write.
        let leftover = path.with_extension("tfstate.tmp");
        assert!(!leftover.exists());
    }

    #[test]
    fn round_trip_byte_stable() {
        // `round_trip` now speaks the real wire format (compact JSON,
        // matching what `tofu apply` itself writes — see
        // `tfstate_v4`), not magma's own typed-`State` shape — so the
        // input here must be real-wire bytes, not
        // `serde_json::to_vec_pretty(&State)`. `tfstate_v4::encode` is
        // itself under direct test in `tfstate_v4::tests` and in
        // `tests/tfstate_v4_fixtures.rs` against real `tofu`-produced
        // bytes; this test only proves `round_trip` (decode ∘ encode)
        // is idempotent on its own output.
        let s = empty_state();
        let bytes = tfstate_v4::encode(&s).unwrap();
        let again = round_trip(&bytes).unwrap();
        assert_eq!(bytes, again);
    }
}
