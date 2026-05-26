//! Typed source for a Pangea repository — where the operator
//! pulls workspace declarations from.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Where a Pangea repository lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// Local directory — already on disk, no Git fetch needed.
    /// Used for development + tests + when the operator
    /// pre-clones into its working dir.
    Local { path: PathBuf },
    /// Any `git clone`-able URL with a typed ref pinning.
    Git {
        url: String,
        /// Branch / tag / full SHA. Tags + SHAs are deterministic;
        /// branch refs resolve at fetch-time.
        #[serde(default = "default_main")]
        reference: String,
    },
    /// GitHub-specific source — enables future webhook + PR
    /// preview features (M5+M6).
    GitHub {
        owner: String,
        repo: String,
        #[serde(default = "default_main")]
        reference: String,
    },
}

fn default_main() -> String {
    "main".into()
}

impl Source {
    /// Materialize the source to a local directory the operator
    /// can scan. For Local, returns the path as-is. For Git /
    /// GitHub, M1 clones into the provided `work_dir`; today
    /// (M0) returns NotImplemented for those variants.
    pub fn materialize(&self, _work_dir: &std::path::Path) -> Result<PathBuf, SourceError> {
        match self {
            Source::Local { path } => {
                if !path.exists() {
                    return Err(SourceError::NotFound(path.clone()));
                }
                Ok(path.clone())
            }
            Source::Git { .. } | Source::GitHub { .. } => Err(SourceError::NotImplemented(
                "Git/GitHub materialization lands in magma-repo M1".into(),
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source path not found: {0:?}")]
    NotFound(PathBuf),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_source_materialize_returns_path() {
        let tmp = tempfile::tempdir().unwrap();
        let src = Source::Local {
            path: tmp.path().to_path_buf(),
        };
        let materialized = src.materialize(std::path::Path::new("/tmp/work")).unwrap();
        assert_eq!(materialized, tmp.path());
    }

    #[test]
    fn missing_local_path_errors() {
        let src = Source::Local {
            path: "/this/does/not/exist".into(),
        };
        assert!(src.materialize(std::path::Path::new("/tmp")).is_err());
    }

    #[test]
    fn git_source_not_implemented_yet() {
        let src = Source::Git {
            url: "https://github.com/x/y".into(),
            reference: "main".into(),
        };
        assert!(matches!(
            src.materialize(std::path::Path::new("/tmp")),
            Err(SourceError::NotImplemented(_)),
        ));
    }

    #[test]
    fn source_round_trips_through_serde() {
        let s1 = Source::GitHub {
            owner: "pleme-io".into(),
            repo: "pangea-architectures".into(),
            reference: "main".into(),
        };
        let json = serde_json::to_string(&s1).unwrap();
        let s2: Source = serde_json::from_str(&json).unwrap();
        assert_eq!(s1, s2);
    }
}
