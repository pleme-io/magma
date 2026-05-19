//! Emit Pangea Ruby DSL code from a typed `ModuleSchema`.
//!
//! Output: a `Pangea::Architectures::<Name>` Ruby module that
//! wraps the TF module's surface as a callable Pangea primitive.
//! Composable in Ruby DSL alongside hand-written architectures.

use crate::{ModuleSchema, Result, TfModError};

/// Emit Pangea Ruby code for the given `ModuleSchema`. The output
/// is a complete `.rb` file ready to be added to a pangea-*
/// provider gem.
///
/// M9.3 implementation TBD.
pub fn emit_pangea_module(_schema: &ModuleSchema) -> Result<String> {
    Err(TfModError::Codegen(
        "M9.3 Pangea codegen not yet implemented".into(),
    ))
}
