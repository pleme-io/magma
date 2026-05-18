//! magma-providers — provider discovery, download, lock-file round-trip,
//! OpenTofu + Terraform registry protocols.
//!
//! Resolves providers from the lock file (`.terraform.lock.hcl`), the user
//! plugin cache (`~/.terraform.d/plugin-cache/`), and the configured
//! registries. Registry client is generated from the OpenTofu registry's
//! OpenAPI spec via forge-gen (per `theory/MAGMA.md` §II.7 strict-standards row).
