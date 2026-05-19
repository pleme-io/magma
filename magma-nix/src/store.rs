//! In-memory content-addressed store (M8.3 destination).
//!
//! Replaces `/nix/store` for Pangea workspaces. Every entry is
//! keyed by BLAKE3 of its content; retrieval is BLAKE3 verification.
//! No daemon, no disk; the store lives in an `Arc<RwLock<HashMap>>`
//! for the operator process lifetime.

use std::collections::HashMap;

use crate::{NixError, Result};

/// One store entry — opaque byte payload keyed by BLAKE3 hash.
pub struct StoreEntry {
    pub hash:  String,
    pub bytes: Vec<u8>,
}

/// In-memory store. M8.3 lands the Mutex<HashMap> impl.
#[derive(Default)]
pub struct Store {
    _entries: HashMap<String, Vec<u8>>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, _bytes: &[u8]) -> Result<String> {
        Err(NixError::Store(
            "M8.3 store not yet implemented — see theory/MAGMA-AS-PLATFORM.md".into(),
        ))
    }

    pub fn get(&self, _hash: &str) -> Result<Option<&Vec<u8>>> {
        Ok(None)
    }
}
