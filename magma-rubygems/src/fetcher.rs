//! Async gem fetcher — typed source dispatch (M3 destination).
//!
//! Pulls gem tarballs from typed `Source` variants. Rate-limit
//! aware via samba (per theory/RATE-LIMITED-CONSUMERS.md). Stores
//! fetched bytes in `cache` for the materialize stage.

use crate::{Result, RubygemsError, source::Source};

/// Fetch the tarball bytes for one (name, version) pair from a
/// typed Source. Returns the raw `.gem` bytes.
///
/// M3 implementation TBD.
pub async fn fetch_tarball(_name: &str, _version: &str, _source: &Source) -> Result<Vec<u8>> {
    Err(RubygemsError::Fetch(
        "M3 not yet started — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}
