//! magma — Rust-native Pangea-Ruby-first OpenTofu-compatible IaC executor.
//!
//! Umbrella crate; re-exports the public surface from the workspace's
//! typed primitives. See `theory/MAGMA.md` for the canonical
//! specification. Consumers pull from `magma::*`, not from individual
//! sub-crates.
//!
//! Input layer: Pangea Ruby DSL (in-process via magnus + `pangea-ruby-eval`)
//! and Terraform JSON (Pangea's rendered output). Magma never reads `.tf`
//! files — HCL parsing is intentionally out of scope per
//! `theory/MAGMA.md` §II.1.

pub use magma_apply as apply;
pub use magma_attest as attest;
pub use magma_backend as backend;
pub use magma_config as config;
pub use magma_graph as graph;
pub use magma_mcp as mcp;
pub use magma_pangea as pangea;
pub use magma_plan as plan;
pub use magma_plugin as plugin;
pub use magma_protocol as protocol;
pub use magma_providers as providers;
pub use magma_state as state;
pub use magma_types as types;
