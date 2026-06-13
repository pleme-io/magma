//! [`PgRegistry`] — the Postgres registry resolver (§III, §IV tier 1),
//! gated behind the `postgres` feature so the crate compiles without a
//! live database or libpq.
//!
//! Resolves a provider binary from the `magma_providers` table (see
//! `migrations/001_providers_table.sql`), keyed by `(source, version,
//! os, arch)`. On a hit it:
//!
//! 1. reads `(binary, content_hash)`;
//! 2. **BLAKE3-verifies** the binary against the recorded `content_hash`
//!    — a mismatch is [`RegistryError::ContentHashMismatch`], never a
//!    silently-loaded plugin;
//! 3. **materializes** the binary to a per-coordinate exec cache path
//!    under `cache_dir` and returns a [`ProviderHandle`] pointing at it.
//!
//! Per §III the binary's durable home is Postgres; the cache path is a
//! transient materialized exec reach (the one sanctioned filesystem
//! touch), not storage.
//!
//! Queries use runtime SQL (`sqlx::query_as`), **not** the compile-time
//! `query!` macros — so building the crate needs no `DATABASE_URL` and
//! no live Postgres. The schema contract lives in the migration file.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sqlx::PgPool;
use sqlx::Row;

use crate::{ProviderHandle, ProviderInfo, ProviderRegistry, RegistryError};

impl From<sqlx::Error> for RegistryError {
    fn from(e: sqlx::Error) -> Self {
        RegistryError::Backend(e.to_string())
    }
}

/// A registry backed by a Postgres `magma_providers` table. Holds a
/// connection pool + the directory under which materialized binaries
/// are cached for go-plugin to `exec`.
#[derive(Debug, Clone)]
pub struct PgRegistry {
    pool: PgPool,
    cache_dir: PathBuf,
}

impl PgRegistry {
    /// Construct from a live pool + the exec-cache directory. The
    /// cache directory is created on first materialization if absent.
    #[must_use]
    pub fn new(pool: PgPool, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            cache_dir: cache_dir.into(),
        }
    }

    /// The exec-cache path for one provider coordinate:
    /// `<cache_dir>/<source-with-/→_>/<version>/<os>_<arch>/terraform-provider-<name>`.
    fn cache_path(&self, source: &str, version: &str, os: &str, arch: &str) -> PathBuf {
        let name = source.rsplit('/').next().unwrap_or(source);
        let flat_source = source.replace('/', "_");
        self.cache_dir
            .join(flat_source)
            .join(version)
            .join(format!("{os}_{arch}"))
            .join(format!("terraform-provider-{name}"))
    }

    /// Materialize `bytes` to `path` as a 0o755 executable, creating
    /// parent dirs. Idempotent: an existing file is overwritten.
    fn materialize(path: &std::path::Path, bytes: &[u8]) -> Result<(), RegistryError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::File::create(path)?;
        f.write_all(bytes)?;
        f.flush()?;
        let mut perms = f.metadata()?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms)?;
        Ok(())
    }
}

/// Row shape SELECTed from `magma_providers`.
struct ProviderRow {
    binary: Vec<u8>,
    content_hash: String,
}

#[async_trait::async_trait]
impl ProviderRegistry for PgRegistry {
    async fn resolve(
        &self,
        source: &str,
        version: &str,
        os: &str,
        arch: &str,
    ) -> Result<Option<ProviderHandle>, RegistryError> {
        let row = sqlx::query(
            "SELECT binary, content_hash FROM magma_providers \
             WHERE source = $1 AND version = $2 AND os = $3 AND arch = $4",
        )
        .bind(source)
        .bind(version)
        .bind(os)
        .bind(arch)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let row = ProviderRow {
            binary: row.try_get::<Vec<u8>, _>("binary")?,
            content_hash: row.try_get::<String, _>("content_hash")?,
        };

        // BLAKE3-verify BEFORE materializing to an exec path — a
        // tampered/corrupt blob is rejected, never spawned.
        let actual = crate::blake3_hex(&row.binary);
        if actual != row.content_hash {
            return Err(RegistryError::ContentHashMismatch {
                provider: source.to_string(),
                version: version.to_string(),
                os: os.to_string(),
                arch: arch.to_string(),
                expected: row.content_hash,
                actual,
            });
        }

        let path = self.cache_path(source, version, os, arch);
        Self::materialize(&path, &row.binary)?;

        let info = ProviderInfo::new(source, version, os, arch, row.content_hash);
        Ok(Some(ProviderHandle::with_info(path, info)))
    }
}
