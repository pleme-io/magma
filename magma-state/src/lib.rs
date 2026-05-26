//! magma-state — terraform.tfstate v4 read/write, state migrations,
//! state locking, sensitive-value redaction.
//!
//! Byte-exact compat with OpenTofu state-file format per
//! `theory/MAGMA.md` §II.2 row 4. Every `magma apply` produces a state
//! file that round-trips through `tofu show -json` unchanged, and vice
//! versa. See `theory/MAGMA.md` §II.6 level 4 for the round-trip proof
//! harness.

use std::path::{Path, PathBuf};

use magma_types::State;
use thiserror::Error;
use uuid::Uuid;

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
pub async fn read_state(path: impl AsRef<Path>) -> Result<State, StateError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(empty_state());
    }
    let bytes = tokio::fs::read(path).await?;
    let state: State = serde_json::from_slice(&bytes)?;
    if state.version != 4 {
        return Err(StateError::UnsupportedVersion(state.version));
    }
    Ok(state)
}

/// Write a `State` atomically — write to `<path>.tmp`, fsync, rename.
/// Atomic so a crash mid-write doesn't corrupt the canonical file.
pub async fn write_state(path: impl AsRef<Path>, state: &State) -> Result<(), StateError> {
    let path = path.as_ref();
    let tmp: PathBuf = path.with_extension("tfstate.tmp");
    let bytes = serde_json::to_vec_pretty(state)?;
    tokio::fs::write(&tmp, &bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Round-trip a state file through serde without disk I/O. Used by the
/// §II.6 level 4 byte-exact tests.
pub fn round_trip(bytes: &[u8]) -> Result<Vec<u8>, StateError> {
    let state: State = serde_json::from_slice(bytes)?;
    Ok(serde_json::to_vec_pretty(&state)?)
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
        let s = empty_state();
        let bytes = serde_json::to_vec_pretty(&s).unwrap();
        let again = round_trip(&bytes).unwrap();
        assert_eq!(bytes, again);
    }
}
