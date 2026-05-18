# magma

> Pangea declares the supercontinent's shape; magma is the molten executive force that realizes it on cloud substrate.

The Rust-native OpenTofu-compatible IaC executor for pleme-io. gRPC plugin protocol v5/v6 + `terraform.tfstate` v4 + `.terraform.lock.hcl` + HCL2 + full CLI surface, byte-exact compat with the existing Terraform / OpenTofu provider ecosystem; internals shikumi-typed end to end, apply engine shigoto-scheduled, plans tameshi-attested via BLAKE3, ships as a WASI module.

**Status:** Draft v1, pre-implementation (M0 in flight). The destination doc — [`pleme-io/theory/MAGMA.md`](https://github.com/pleme-io/theory/blob/main/MAGMA.md) — is canonical; read it before touching this repo.

**Repo docs:**
- [`CLAUDE.md`](./CLAUDE.md) — agent-facing repo guide (architecture, build, anti-patterns)
- [`theory/MAGMA.md`](https://github.com/pleme-io/theory/blob/main/MAGMA.md) — destination, typed surface, compatibility contract, phases, alignment

## Quick start

```bash
cargo build --workspace
cargo test  --workspace

nix build                # release build via substrate's crate2nix
nix flake check          # hermetic build + tests
```

## License

MIT.
