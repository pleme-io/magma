# magma

> Pangea declares the supercontinent's shape; magma is the molten executive force that realizes it on cloud substrate.

The Rust-native OpenTofu-compatible IaC executor for pleme-io. It speaks the
gRPC plugin protocol v5/v6, reads and writes `terraform.tfstate` v4, and
consumes `.terraform.lock.hcl` — so it drives **unmodified, real Terraform and
OpenTofu provider binaries**. Internals are shikumi-typed end to end, the apply
engine is shigoto-scheduled, plans are tameshi-attested via BLAKE3, and it ships
as a WASI module.

**What it accepts as input, precisely.** magma consumes **Terraform JSON** and
**Pangea Ruby in-process**. It does **not** parse HCL2 — there is no HCL parser
in the workspace, `magma-tfmod`'s `parse_module` returns *"M9.2 HCL2 parser not
yet implemented"*, and the binary's own capability manifest emits
`"input_formats_excluded": ["hcl2"]`. So magma runs **machine-generated**
configuration — which is what pangea emits — and **cannot today be pointed at a
hand-written Terraform estate.** State backends are `local` and in-memory; S3 is
planned for M1.

> Corrected 2026-08-30: this paragraph listed HCL2 among the supported inputs
> and described magma as byte-exact compatible without qualifying *with what*.
> The provider-ecosystem compatibility is real and differentially tested against
> genuine provider binaries; the config-format claim was not.

**Status: working executor, bounded scope.** 69,106 lines, 1,334 tests, a
verified go-plugin handshake with mTLS and gRPC against real provider binaries,
and a schema oracle run against the real `terraform-provider-random` Go binary
that caught a genuine bug. It is the sole executor on pleme-io's own pangea
stack. It is **not** a drop-in `terraform` replacement, and the input-format
paragraph above is why. The destination doc —
[`pleme-io/theory/MAGMA.md`](https://github.com/pleme-io/theory/blob/main/MAGMA.md)
— is canonical; read it before touching this repo.

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
