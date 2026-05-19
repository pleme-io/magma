//! Gemfile DSL parser (M1 destination).
//!
//! Parses the narrow Ruby DSL bundler accepts: `source`, `ruby`,
//! `gem`, `group`, `gemspec`, `git_source`, `platform`. Refuses
//! arbitrary Ruby — if a Gemfile embeds `eval` or other dynamic
//! constructs the parser returns an error (Pangea workspaces don't
//! use these).

use crate::{manifest::Manifest, Result, RubygemsError};

/// Parse a Gemfile source string into a typed `Manifest`.
///
/// M1 implementation TBD.
pub fn parse(_source: &str) -> Result<Manifest> {
    Err(RubygemsError::GemfileParse(
        "M1 not yet started — see theory/MAGMA-RUBYGEMS.md".into(),
    ))
}
