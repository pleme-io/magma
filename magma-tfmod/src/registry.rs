//! Terraform registry client — downloads modules from typed sources.

use crate::{ModuleSource, Result, TfModError};

/// Download the module tarball for a typed source. Returns raw
/// bytes (caller passes to the HCL2 parser).
///
/// M9.1 implementation TBD.
pub async fn download(_source: &ModuleSource) -> Result<Vec<u8>> {
    Err(TfModError::Registry(
        "M9.1 registry client not yet implemented".into(),
    ))
}
