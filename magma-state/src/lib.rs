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

/// Write `bytes` to `path` as a file created with mode 0600, off the
/// runtime's worker threads.
///
/// **Why 0600 is load-bearing here.** A tfstate file records
/// provider-marked sensitive attributes *in the clear* — the
/// `"sensitive_attributes"` list names them, it does not encrypt them —
/// so the file's permission bits are the only thing the format offers
/// between a rendered password and every other local user. This creates
/// the file at 0600 in the same `open(2)` that creates it
/// ([`cofre_fs::write_secret`]) rather than writing first and chmod'ing
/// after, so there is no interval during which the state is readable by
/// anyone else. It also refuses to write through a symlink pre-planted
/// at the path.
///
/// `cofre_fs::write_secret` is synchronous and `fsync`s, so it runs on a
/// blocking thread rather than stalling an async worker.
///
/// Callers that want the write to be *atomic* should aim this at a
/// temporary path and `rename(2)` it into place — `rename` preserves the
/// mode, so the canonical file inherits the 0600.
///
/// # Errors
/// The underlying `io::Error`, or a join failure wrapped as one.
pub async fn write_secret_file(path: PathBuf, bytes: Vec<u8>) -> Result<(), StateError> {
    tokio::task::spawn_blocking(move || cofre_fs::write_secret(&path, &bytes, 0o600))
        .await
        .map_err(std::io::Error::other)??;
    Ok(())
}

/// Write a `State` atomically — write to `<path>.tmp`, fsync, rename.
/// Atomic so a crash mid-write doesn't corrupt the canonical file.
///
/// Writes the real wire format via [`tfstate_v4::encode`] so the
/// result is directly readable by `tofu show -json` / `terraform
/// show -json` and re-adoptable by a real tofu/terraform run — not
/// just by another magma instance.
///
/// The temp file is created 0600 via [`write_secret_file`]; `rename`
/// carries that mode onto the canonical path. See that function for why
/// the mode is the only protection a tfstate has.
pub async fn write_state(path: impl AsRef<Path>, state: &State) -> Result<(), StateError> {
    let path = path.as_ref();
    let tmp: PathBuf = path.with_extension("tfstate.tmp");
    let bytes = tfstate_v4::encode(state)?;
    write_secret_file(tmp.clone(), bytes).await?;
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

    /// The canonical state file must land at 0600, not at the default
    /// 0666-minus-umask a plain `fs::write` produces.
    ///
    /// This asserts the property magma owns — that the mode set on the
    /// temp file survives `rename(2)` onto the real path. It does NOT
    /// re-prove that the mode came from `open(2)` rather than a later
    /// chmod; that is cofre-fs's property and is tested there under a
    /// cleared umask.
    #[tokio::test]
    async fn written_state_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let s = empty_state();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("terraform.tfstate");
        write_state(&path, &s).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "tfstate holds sensitive attributes in plaintext; the mode is the \
             only protection — got {mode:o}"
        );
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
