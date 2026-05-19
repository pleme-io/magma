//! `*.gemspec` parser (M1 destination).

use crate::{Result, RubygemsError, Spec};

/// Parse a gemspec source string into a typed `Spec`.
///
/// M1 implementation TBD.
pub fn parse(_source: &str) -> Result<Spec> {
    Err(RubygemsError::GemspecParse(
        "M1 not yet started — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}
