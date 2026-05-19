//! Native-extension compilation orchestration (M4 destination).
//!
//! Some gems ship C source that compiles to `.so` at install time
//! (nokogiri, sqlite3, …). magma-rubygems either:
//!
//! 1. Delegates to system `cc`/`clang` + writes the result into
//!    the VirtualGemTree, OR
//! 2. Looks up a pre-built per-(version, platform) attestation
//!    from a magma-attest registry and skips compile entirely.
//!
//! M4 lands #1; M4.x evaluates #2 once pre-built attestations are
//! plumbed through tameshi.

use crate::Result;

/// Build the native extension for one gem in the closure.
///
/// M4 implementation TBD.
pub async fn build_extension(_gem_name: &str, _gem_dir: &std::path::Path) -> Result<()> {
    Ok(()) // M4 stub — no-op succeeds so M3 fetch can land first.
}
