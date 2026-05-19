//! In-memory blob cache, BLAKE3-keyed (M3 destination).
//!
//! Stores fetched gem tarballs by content hash so repeat-resolutions
//! across workspaces share bytes. LRU eviction with operator-tunable
//! capacity.

use crate::Result;

/// Cache handle. M3 backs this with a Mutex<HashMap<String, Vec<u8>>>;
/// later versions plug LRU eviction + async eviction policies.
pub struct BlobCache {
    /// Capacity in bytes (M3+ uses this for eviction).
    pub capacity_bytes: usize,
}

impl BlobCache {
    pub fn new(capacity_bytes: usize) -> Self {
        Self { capacity_bytes }
    }

    /// Look up a blob by BLAKE3 hash.
    ///
    /// M3 implementation TBD.
    pub fn get(&self, _hash: &str) -> Option<Vec<u8>> {
        None
    }

    /// Insert a blob; returns the BLAKE3 hash.
    ///
    /// M3 implementation TBD.
    pub fn put(&self, bytes: &[u8]) -> Result<String> {
        Ok(hex::encode(blake3::hash(bytes).as_bytes()))
    }
}
