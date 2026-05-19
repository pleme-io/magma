//! fetchurl / fetchTarball with BLAKE3 + sha256 attestation
//! (M8.4 destination).

use crate::{NixError, Result};

/// Fetch a URL into the store, verifying against an expected hash.
pub async fn fetch_url(_url: &str, _expected_sha256: &str) -> Result<Vec<u8>> {
    Err(NixError::Fetch(
        "M8.4 fetcher not yet implemented — see theory/MAGMA-AS-PLATFORM.md".into(),
    ))
}
