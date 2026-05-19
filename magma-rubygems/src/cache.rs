//! In-memory blob cache, BLAKE3-keyed (M3 — in-process cache landed).
//!
//! Stores fetched gem tarballs by content hash so repeat-resolutions
//! across workspaces share bytes. Concurrent-safe; future M3.x adds
//! LRU eviction + capacity-bounded eviction policies.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::Result;

/// Concurrent-safe in-memory blob cache keyed by BLAKE3 hex hash.
/// `capacity_bytes` is informational today; M3.x wires LRU eviction
/// once the fetcher generates real load.
pub struct BlobCache {
    pub capacity_bytes: usize,
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl BlobCache {
    /// Create a fresh blob cache with a target byte capacity.
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Look up a blob by BLAKE3 hex hash. Returns the bytes if
    /// cached; None otherwise.
    pub fn get(&self, hash: &str) -> Option<Vec<u8>> {
        self.inner.lock().ok()?.get(hash).cloned()
    }

    /// Insert a blob; returns the BLAKE3 hex hash that keys it.
    /// Re-inserting an identical blob is idempotent.
    pub fn put(&self, bytes: &[u8]) -> Result<String> {
        let hash = hex::encode(blake3::hash(bytes).as_bytes());
        if let Ok(mut map) = self.inner.lock() {
            map.insert(hash.clone(), bytes.to_vec());
        }
        Ok(hash)
    }

    /// Count of cached blobs. Useful for observability.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_returns_hex_hash() {
        let cache = BlobCache::new(0);
        let hash = cache.put(b"hello").unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn get_returns_inserted_blob() {
        let cache = BlobCache::new(0);
        let hash = cache.put(b"hello").unwrap();
        let got = cache.get(&hash).unwrap();
        assert_eq!(got, b"hello");
    }

    #[test]
    fn miss_returns_none() {
        let cache = BlobCache::new(0);
        assert!(cache.get("ffff").is_none());
    }

    #[test]
    fn duplicate_put_is_idempotent() {
        let cache = BlobCache::new(0);
        let h1 = cache.put(b"hello").unwrap();
        let h2 = cache.put(b"hello").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(cache.len(), 1);
    }
}
