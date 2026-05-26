//! Typed Gemfile manifest (M1 destination).

use serde::{Deserialize, Serialize};

/// Pinned Ruby version + interpreter family. M1 populates this
/// from `Gemfile`'s `ruby` directive + Pangea's `.ruby-version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RubyVersion {
    pub version: String,
    /// Interpreter family — "mri" (default), "jruby", "truffleruby".
    #[serde(default = "default_interpreter")]
    pub interpreter: String,
}

fn default_interpreter() -> String {
    "mri".into()
}

/// One dependency entry from the Gemfile DSL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    /// Version constraint expression: `~> 1.2`, `>= 2.0, < 3`, etc.
    pub requirement: Option<String>,
    /// Source override for this gem. None = inherit `Manifest::sources`.
    pub source: Option<crate::source::Source>,
    /// Dependency groups (`:development`, `:test`, `:default`).
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Typed image of a parsed Gemfile. M1 populates fields from
/// `gemfile_parser::parse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub ruby: RubyVersion,
    pub deps: Vec<Dependency>,
    pub sources: Vec<crate::source::Source>,
    /// Path-style "gemspec" directives that import a sibling gem's spec.
    #[serde(default)]
    pub gemspec_paths: Vec<String>,
}
