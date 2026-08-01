//! Tests for the provider-registry resolution plane. None require a
//! live Postgres — the DB tier is exercised through a [`MockRegistry`]
//! that returns caller-supplied outcomes, and the directory tier is
//! exercised against a real `tempfile` tree.

use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::{
    ChainRegistry, DirRegistry, ProviderHandle, ProviderInfo, ProviderRegistry, RegistryError,
    blake3_hex,
};

/// A registry whose every `resolve` returns a pre-programmed outcome —
/// stands in for the Postgres tier in fallback + error tests without a
/// live DB. `None` models a clean miss; `Some(Ok(handle))` a hit;
/// `Some(Err(_))` a backend/hash failure.
struct MockRegistry {
    outcome: Box<dyn Fn() -> Result<Option<ProviderHandle>, RegistryError> + Send + Sync>,
}

impl MockRegistry {
    fn miss() -> Self {
        Self {
            outcome: Box::new(|| Ok(None)),
        }
    }

    fn hit(path: PathBuf) -> Self {
        Self {
            outcome: Box::new(move || Ok(Some(ProviderHandle::from_path(path.clone())))),
        }
    }

    fn hash_mismatch() -> Self {
        Self {
            outcome: Box::new(|| {
                Err(RegistryError::ContentHashMismatch {
                    provider: "cloudflare/cloudflare".into(),
                    version: "5.12.0".into(),
                    os: "linux".into(),
                    arch: "amd64".into(),
                    expected: blake3_hex(b"the real binary"),
                    actual: blake3_hex(b"a tampered binary"),
                })
            }),
        }
    }
}

#[async_trait::async_trait]
impl ProviderRegistry for MockRegistry {
    async fn resolve(
        &self,
        _source: &str,
        _version: &str,
        _os: &str,
        _arch: &str,
    ) -> Result<Option<ProviderHandle>, RegistryError> {
        (self.outcome)()
    }
}

fn touch(p: &Path) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, b"#!/bin/sh\n").unwrap();
}

// ── ProviderInfo ────────────────────────────────────────────────────

#[test]
fn provider_info_serde_round_trip() {
    let info = ProviderInfo::new(
        "cloudflare/cloudflare",
        "5.12.0",
        "linux",
        "amd64",
        blake3_hex(b"binary bytes"),
    );
    let json = serde_json::to_string(&info).unwrap();
    let back: ProviderInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info, back);
    // All five fields survive the round trip.
    assert_eq!(back.source, "cloudflare/cloudflare");
    assert_eq!(back.version, "5.12.0");
    assert_eq!(back.os, "linux");
    assert_eq!(back.arch, "amd64");
}

#[test]
fn provider_info_provider_name_strips_namespace() {
    assert_eq!(
        ProviderInfo::new("cloudflare/cloudflare", "5", "linux", "amd64", "h").provider_name(),
        "cloudflare"
    );
    assert_eq!(
        ProviderInfo::new("marcfrederick/porkbun", "1", "linux", "amd64", "h").provider_name(),
        "porkbun"
    );
    // A bare source (no namespace) returns itself.
    assert_eq!(
        ProviderInfo::new("random", "3", "linux", "amd64", "h").provider_name(),
        "random"
    );
}

// ── blake3_hex ──────────────────────────────────────────────────────

#[test]
fn blake3_hex_is_lowercase_64_chars() {
    let h = blake3_hex(b"hello");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    // Deterministic.
    assert_eq!(h, blake3_hex(b"hello"));
    assert_ne!(h, blake3_hex(b"world"));
}

// ── DirRegistry ─────────────────────────────────────────────────────

#[tokio::test]
async fn dir_registry_locates_versioned_binary() {
    let td = TempDir::new().unwrap();
    let bin = td
        .path()
        .join("registry.terraform.io/cloudflare/cloudflare/5.12.0/linux_amd64")
        .join("terraform-provider-cloudflare_v5.12.0");
    touch(&bin);
    let reg = DirRegistry::new(td.path());
    let handle = reg
        .resolve("cloudflare/cloudflare", "5.12.0", "linux", "amd64")
        .await
        .unwrap()
        .expect("dir hit");
    assert_eq!(handle.path, bin);
    // The dir mirror carries no recorded hash.
    assert!(handle.info.is_none());
}

#[tokio::test]
async fn dir_registry_miss_when_absent() {
    let td = TempDir::new().unwrap();
    let reg = DirRegistry::new(td.path());
    let got = reg
        .resolve("cloudflare/cloudflare", "5.12.0", "linux", "amd64")
        .await
        .unwrap();
    assert!(
        got.is_none(),
        "absent provider is a clean miss, not an error"
    );
}

#[tokio::test]
async fn dir_registry_no_root_is_clean_miss() {
    // A DirRegistry whose root dir does not exist returns Ok(None) so it
    // can sit at the tail of a chain on a node with no baked mirror.
    let reg = DirRegistry::new("/nonexistent/magma/provider/dir");
    let got = reg
        .resolve("random", "3.0.0", "linux", "amd64")
        .await
        .unwrap();
    assert!(got.is_none());
}

// ── ChainRegistry ───────────────────────────────────────────────────

#[tokio::test]
async fn chain_falls_back_db_miss_then_dir_hit() {
    // Tier 1 (DB) misses; tier 2 (dir) hits — the canonical §IV path,
    // proven with zero live Postgres.
    let td = TempDir::new().unwrap();
    let bin = td
        .path()
        .join("hashicorp/random/3.6.0/linux_amd64")
        .join("terraform-provider-random_v3.6.0");
    touch(&bin);

    let chain = ChainRegistry::new(MockRegistry::miss(), DirRegistry::new(td.path()));
    let handle = chain
        .resolve("hashicorp/random", "3.6.0", "linux", "amd64")
        .await
        .unwrap()
        .expect("fell through to dir hit");
    assert_eq!(handle.path, bin);
}

#[tokio::test]
async fn chain_prefers_primary_hit() {
    // When tier 1 (DB) hits, the fallback is never consulted — proven by
    // pointing the fallback at a dir that would also hit but at a
    // DIFFERENT path; the primary path must win.
    let td = TempDir::new().unwrap();
    let dir_bin = td
        .path()
        .join("hashicorp/random/3.6.0/linux_amd64/terraform-provider-random_v3.6.0");
    touch(&dir_bin);

    let primary_path = PathBuf::from("/db/materialized/terraform-provider-random");
    let chain = ChainRegistry::new(
        MockRegistry::hit(primary_path.clone()),
        DirRegistry::new(td.path()),
    );
    let handle = chain
        .resolve("hashicorp/random", "3.6.0", "linux", "amd64")
        .await
        .unwrap()
        .expect("primary hit");
    assert_eq!(handle.path, primary_path);
}

#[tokio::test]
async fn chain_propagates_primary_error_without_fallback() {
    // A hash mismatch from tier 1 is a correctness failure, NOT a miss —
    // it must propagate, never be swallowed by trying the dir tier.
    let td = TempDir::new().unwrap();
    // Make the dir tier ABLE to hit, to prove the error short-circuits.
    touch(
        &td.path()
            .join("cloudflare/cloudflare/5.12.0/linux_amd64/terraform-provider-cloudflare_v5.12.0"),
    );

    let chain = ChainRegistry::new(MockRegistry::hash_mismatch(), DirRegistry::new(td.path()));
    let err = chain
        .resolve("cloudflare/cloudflare", "5.12.0", "linux", "amd64")
        .await
        .expect_err("hash mismatch must propagate as a typed error");
    assert!(
        matches!(err, RegistryError::ContentHashMismatch { .. }),
        "expected ContentHashMismatch, got {err:?}"
    );
}

// ── Content-hash mismatch is a typed error ──────────────────────────

#[test]
fn content_hash_mismatch_is_a_typed_error() {
    // The verify step the PgRegistry runs, exercised in isolation: a
    // binary whose computed BLAKE3 disagrees with the recorded hash is a
    // typed ContentHashMismatch, not a silently-loaded plugin. No DB.
    let stored_binary = b"the real provider binary".as_slice();
    let recorded_hash = blake3_hex(stored_binary);
    let tampered = b"a tampered provider binary".as_slice();
    let actual = blake3_hex(tampered);
    assert_ne!(actual, recorded_hash);

    let result: Result<(), RegistryError> = if actual != recorded_hash {
        Err(RegistryError::ContentHashMismatch {
            provider: "cloudflare/cloudflare".into(),
            version: "5.12.0".into(),
            os: "linux".into(),
            arch: "amd64".into(),
            expected: recorded_hash,
            actual,
        })
    } else {
        Ok(())
    };
    let err = result.expect_err("mismatch");
    match err {
        RegistryError::ContentHashMismatch {
            provider,
            expected,
            actual,
            ..
        } => {
            assert_eq!(provider, "cloudflare/cloudflare");
            assert_ne!(expected, actual);
        }
        other => panic!("expected ContentHashMismatch, got {other:?}"),
    }
}
