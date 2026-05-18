//! magma-backend — Backend trait + impls (local / s3 / http / consul /
//! kubernetes / postgres / azurerm / gcs / remote).
//!
//! Each impl handles state read / write / lock / unlock against its
//! particular backing store. Lock semantics match OpenTofu's behavior
//! on the same backend exactly (DynamoDB / GCS object-lock / Consul
//! session / Postgres advisory / etc.).
//!
//! M0 ships the LocalBackend; S3 follows in M1.

use std::path::PathBuf;

use async_trait::async_trait;
use magma_types::State;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("state is already locked by {holder} ({id})")]
    AlreadyLocked { id: String, holder: String },
    #[error("lock id mismatch: have {have:?}, expected {expected:?}")]
    LockIdMismatch { have: String, expected: String },
    #[error("backend feature not implemented: {0}")]
    NotImplemented(String),
}

// ── Lock id ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockId(pub String);

impl LockId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for LockId {
    fn default() -> Self { Self::new() }
}

// ── Backend trait ──────────────────────────────────────────────────

#[async_trait]
pub trait Backend: Send + Sync {
    async fn read_state(&self) -> Result<State, BackendError>;
    async fn write_state(&self, state: &State) -> Result<(), BackendError>;
    async fn lock(&self) -> Result<LockId, BackendError>;
    async fn unlock(&self, lock_id: &LockId) -> Result<(), BackendError>;
}

// ── LocalBackend ──────────────────────────────────────────────────

/// File-backed Backend. The state file lives at `<dir>/terraform.tfstate`;
/// the lock at `<dir>/terraform.tfstate.lock`.
#[derive(Debug, Clone)]
pub struct LocalBackend {
    state_path: PathBuf,
    lock_path:  PathBuf,
}

impl LocalBackend {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir: PathBuf = dir.into();
        Self {
            state_path: dir.join("terraform.tfstate"),
            lock_path:  dir.join("terraform.tfstate.lock"),
        }
    }

    pub fn state_path(&self) -> &PathBuf { &self.state_path }
    pub fn lock_path(&self)  -> &PathBuf { &self.lock_path }
}

#[async_trait]
impl Backend for LocalBackend {
    async fn read_state(&self) -> Result<State, BackendError> {
        if !self.state_path.exists() {
            return Ok(empty_state_inline());
        }
        let bytes = tokio::fs::read(&self.state_path).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn write_state(&self, state: &State) -> Result<(), BackendError> {
        let tmp = self.state_path.with_extension("tfstate.tmp");
        let bytes = serde_json::to_vec_pretty(state)?;
        if let Some(parent) = self.state_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &self.state_path).await?;
        Ok(())
    }

    async fn lock(&self) -> Result<LockId, BackendError> {
        // Best-effort exclusive create — fails if the lock file exists.
        if self.lock_path.exists() {
            let existing = tokio::fs::read_to_string(&self.lock_path)
                .await
                .unwrap_or_default();
            let info: LockInfo = serde_json::from_str(&existing)
                .unwrap_or_else(|_| LockInfo { id: "unknown".into(), holder: "unknown".into() });
            return Err(BackendError::AlreadyLocked {
                id: info.id,
                holder: info.holder,
            });
        }
        let id = LockId::new();
        let info = LockInfo {
            id:     id.0.clone(),
            holder: std::env::var("USER").unwrap_or_else(|_| "magma".into()),
        };
        if let Some(parent) = self.lock_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&self.lock_path, serde_json::to_vec_pretty(&info)?).await?;
        Ok(id)
    }

    async fn unlock(&self, lock_id: &LockId) -> Result<(), BackendError> {
        if !self.lock_path.exists() {
            return Ok(());
        }
        let bytes = tokio::fs::read(&self.lock_path).await?;
        let info: LockInfo = serde_json::from_slice(&bytes)?;
        if info.id != lock_id.0 {
            return Err(BackendError::LockIdMismatch {
                have:     lock_id.0.clone(),
                expected: info.id,
            });
        }
        tokio::fs::remove_file(&self.lock_path).await?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LockInfo {
    id:     String,
    holder: String,
}

fn empty_state_inline() -> State {
    State {
        version:           4,
        terraform_version: "1.7.0".into(),
        serial:            0,
        lineage:           Uuid::new_v4(),
        outputs:           Default::default(),
        resources:         Vec::new(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn local_backend_round_trips_empty_state() {
        let dir = tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_path_buf());
        let s = backend.read_state().await.unwrap();
        assert_eq!(s.version, 4);
        backend.write_state(&s).await.unwrap();
        let s2 = backend.read_state().await.unwrap();
        assert_eq!(s.lineage, s2.lineage);
    }

    #[tokio::test]
    async fn local_backend_lock_unlock() {
        let dir = tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_path_buf());
        let id = backend.lock().await.unwrap();
        let err = backend.lock().await.unwrap_err();
        assert!(matches!(err, BackendError::AlreadyLocked { .. }));
        backend.unlock(&id).await.unwrap();
        // Re-lock should succeed after unlock.
        let _ = backend.lock().await.unwrap();
    }

    #[tokio::test]
    async fn unlock_wrong_id_errs() {
        let dir = tempdir().unwrap();
        let backend = LocalBackend::new(dir.path().to_path_buf());
        let _id = backend.lock().await.unwrap();
        let bogus = LockId("not-the-real-id".into());
        let err = backend.unlock(&bogus).await.unwrap_err();
        assert!(matches!(err, BackendError::LockIdMismatch { .. }));
    }
}
