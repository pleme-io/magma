//! [`PgRegistry`] — the Postgres registry resolver (§III, §IV tier 1),
//! gated behind the `postgres` feature so the crate compiles without a
//! live database or libpq.
//!
//! Resolves a provider binary from the `magma_meta.providers` table,
//! keyed by `(source, version, platform)`. On a hit it:
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
//! no live Postgres.
//!
//! ── ★ THE SCHEMA IS ENSURED HERE, NOT IN A `migrations/` DIRECTORY ────
//! There used to be a `migrations/001_providers_table.sql` that **nothing
//! ever executed** — it was referenced only from a doc comment, so
//! `resolve` would have failed with `relation "magma_providers" does not
//! exist` on the first real call. Deleted, and replaced with
//! [`PgRegistry::ensure_schema`].
//!
//! That follows the house pattern rather than inventing one:
//! `theory/MAGMA-POSTGRES-LIFECYCLE.md` §1 chose `sqlx_embedded` **over** a
//! `migrations/*.sql` directory, and pangea-operator's `ArtifactStore`
//! (`pangea_meta.artifacts` — the same BYTEA + content-hash shape this
//! table mirrors) does exactly this: `CREATE SCHEMA/TABLE IF NOT EXISTS`,
//! lazily self-healed behind an `AtomicBool` and re-runnable as an
//! explicit one-shot.
//!
//! **This is an interim owner, and it is worth saying so.** The fleet rule
//! is that every schema concern is a `keifu::Change` through one renderer
//! and one applier. keifu was extracted for exactly that
//! (`pleme-io/shinka` → `keifu-core`), but it cannot be consumed here yet:
//! shinka is a PRIVATE repo, magma is PUBLIC, and the publish path is
//! deliberately withheld for private sources. When keifu-core lands in a
//! public home, [`ensure_schema`] is the seam that swaps — the table shape
//! below is already what the changeset will render.
//!
//! ── SCHEMA, and one deliberate deviation from the spec ────────────────
//! `theory/MAGMA-PROVIDER-PLANE.md` §III declares `protocol INT NOT NULL`.
//! It is **nullable** here. The tfplugin protocol version is discovered
//! from the go-plugin handshake at load (`magma-apply` engine.rs), so the
//! column is a RECORD of what was seen, never the source of truth — and a
//! `NOT NULL` would make it impossible to seed a row from a Nix-baked
//! mirror, where the binary has not been run and the protocol is genuinely
//! unknown. A column that forces a guess is worse than one that admits it.

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
    /// Has the schema been ensured on this pool yet?
    ///
    /// `Arc` so clones share one flag — the ensure is per-DATABASE, not
    /// per-handle, and a clone that re-ran it would be pure noise. Ordering
    /// is `Relaxed` deliberately: the DDL itself is `IF NOT EXISTS`, so a
    /// race between two tasks costs one redundant statement, never a
    /// conflict. The flag is an optimisation, not a lock.
    ensured: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// The table this registry resolves against, qualified. Spec §III.
pub(crate) const PROVIDERS_TABLE: &str = "magma_meta.providers";

impl PgRegistry {
    /// Construct from a live pool + the exec-cache directory. The
    /// cache directory is created on first materialization if absent.
    #[must_use]
    pub fn new(pool: PgPool, cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            cache_dir: cache_dir.into(),
            ensured: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Terraform's platform spelling for an `(os, arch)` pair: `linux_amd64`.
    ///
    /// The [`ProviderRegistry`] trait takes `os` and `arch` separately
    /// because that is what a caller naturally has; the TABLE keys on the
    /// joined form because that is what terraform, the registry protocol and
    /// the release artifacts all use. Joining here keeps the seam honest in
    /// both directions instead of forcing one convention on the other.
    #[must_use]
    pub fn platform_of(os: &str, arch: &str) -> String {
        format!("{os}_{arch}")
    }

    /// Create the schema + table if absent. Idempotent, safe to call
    /// concurrently, and safe to call on a database that already has them.
    ///
    /// # Errors
    /// [`RegistryError::Backend`] if the DDL cannot be applied — e.g. the
    /// role cannot `CREATE`.
    pub async fn ensure_schema(&self) -> Result<(), RegistryError> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS magma_meta")
            .execute(&self.pool)
            .await?;
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {PROVIDERS_TABLE} (
                 source        TEXT        NOT NULL,
                 version       TEXT        NOT NULL,
                 platform      TEXT        NOT NULL,
                 protocol      INT,
                 content_hash  CHAR(64)    NOT NULL,
                 binary        BYTEA       NOT NULL,
                 fetched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                 PRIMARY KEY (source, version, platform)
             )"
        ))
        .execute(&self.pool)
        .await?;
        self.ensured
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Seed the registry from a Nix-baked mirror — the bake's demotion from
    /// mechanism to seed (spec §II, §VI).
    ///
    /// Idempotent by construction: the key is a content coordinate, and a
    /// row already at that coordinate is left alone (`ON CONFLICT DO
    /// NOTHING`). Re-seeding on every boot is therefore free, which is what
    /// makes it safe to call unconditionally rather than gating it on a
    /// "have we seeded?" flag that could itself be wrong.
    ///
    /// Reads coordinates from the PATH — see [`crate::mirror`] — so adding a
    /// provider to the image is a one-line flake edit with no manifest to
    /// keep in sync.
    ///
    /// # Errors
    /// [`RegistryError::Backend`] if the schema cannot be ensured or a row
    /// cannot be written; [`RegistryError::Io`] if a binary cannot be read.
    pub async fn seed_from_mirror(
        &self,
        root: &std::path::Path,
    ) -> Result<crate::SeedReport, RegistryError> {
        self.ensure_ready().await?;

        let entries = crate::mirror::scan(root);
        let mut report = crate::SeedReport {
            scanned: entries.len(),
            ..Default::default()
        };

        for e in entries {
            let bytes = std::fs::read(&e.path)?;
            let hash = crate::blake3_hex(&bytes);
            // The hash is computed HERE from the bytes being stored, so the
            // row is self-consistent by construction — `resolve` re-verifies
            // on the way out, and the two can only disagree if the row was
            // changed by something other than this path.
            let done = sqlx::query(&format!(
                "INSERT INTO {PROVIDERS_TABLE}
                     (source, version, platform, content_hash, binary)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (source, version, platform) DO NOTHING"
            ))
            .bind(&e.source)
            .bind(&e.version)
            .bind(&e.platform)
            .bind(&hash)
            .bind(&bytes)
            .execute(&self.pool)
            .await?;

            if done.rows_affected() == 0 {
                report.already_present += 1;
            } else {
                report.inserted += 1;
            }
        }

        Ok(report)
    }

    /// Ensure once, then get out of the way.
    ///
    /// Lazy rather than constructor-time because `new` is sync and infallible
    /// and should stay that way; and self-healing rather than one-shot because
    /// a registry whose database was reset mid-life should recover on its next
    /// call instead of failing until the process restarts. Same shape as
    /// pangea-operator's `ArtifactStore::ensure_ready`.
    async fn ensure_ready(&self) -> Result<(), RegistryError> {
        if self.ensured.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        self.ensure_schema().await
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
        // The table has to exist before the first SELECT can miss rather
        // than error. A missing relation is not a "no such provider" — it is
        // a broken deployment, and conflating the two would make the chain
        // fall through to the dir tier and report a clean miss.
        self.ensure_ready().await?;

        let row = sqlx::query(&format!(
            "SELECT binary, content_hash FROM {PROVIDERS_TABLE} \
             WHERE source = $1 AND version = $2 AND platform = $3"
        ))
        .bind(source)
        .bind(version)
        .bind(Self::platform_of(os, arch))
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
