//! HCL2 parser — extracts variables + outputs + required_providers
//! from a Terraform module's `.tf` files.
//!
//! Out of scope: full HCL2 expression evaluation. We only extract
//! the typed surface (variable blocks, output blocks, terraform
//! block).

use crate::{ModuleSchema, ModuleSource, Result, TfModError};

/// Parse a Terraform module tarball into a typed `ModuleSchema`.
///
/// M9.2 implementation TBD.
pub fn parse_module(_source: ModuleSource, _bytes: &[u8]) -> Result<ModuleSchema> {
    Err(TfModError::Parse(
        "M9.2 HCL2 parser not yet implemented".into(),
    ))
}
