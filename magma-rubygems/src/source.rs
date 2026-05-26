//! Typed source enum — every gem comes from one of these origins.

use serde::{Deserialize, Serialize};

/// Where a gem comes from. Closed over the variants Pangea Ruby
/// uses today; bundler's `:platforms` is encoded inline as a
/// platform-constraint refinement, not a separate variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// Canonical default — fetch from rubygems.org (or a mirror).
    RubyGemsOrg {
        /// Mirror URL; None = the default `https://rubygems.org/`.
        mirror_url: Option<String>,
    },
    /// Git-sourced gem with explicit ref pinning.
    Git {
        url: String,
        /// Branch, tag, or full SHA. Tags + SHAs are preferred for
        /// determinism; branch refs only resolve at fetch-time.
        reference: String,
    },
    /// Path-sourced gem (sibling crate in the same workspace).
    Path { dir: std::path::PathBuf },
}

impl Source {
    /// Canonical rubygems.org default — used when the Gemfile
    /// omits a source for a dep.
    pub fn default_rubygems() -> Self {
        Self::RubyGemsOrg { mirror_url: None }
    }
}
