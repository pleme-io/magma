# magma — Rust-native OpenTofu-compatible IaC executor

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section.
>
> **Destination doc:** [`pleme-io/theory/MAGMA.md`](https://github.com/pleme-io/theory/blob/main/MAGMA.md). Read it before touching anything load-bearing — typed surface in §III, plugin protocol in §IV, compatibility contract in §II.2, test corpus in §II.6, substrate integration in §II.7, anti-patterns in §IX.

The execution layer of pleme-io's Pillar 5 (IaC declaration → execution). Pangea declares the supercontinent's shape; magma is the molten executive force that realizes it on cloud substrate. Pairs with `forja` (forge — CI/CD metal-shaping); `tear` is the session manager, not this.

## Architecture

```
magma (workspace root)
├── magma-types        — Plan, Resource, ResourceAddress, Action, Diff, State, …
├── magma-pangea       — Pangea Ruby DSL in-process evaluator (CRuby via magnus +
│                       pangea-ruby-eval) + Terraform JSON reader. Canonical M0 input.
├── magma-config       — Terraform JSON → typed Config; narrow ${resource.attribute}
│                       interpolation resolver. No HCL parser.
├── magma-protocol     — tfplugin5/6.proto bindings via prost-build + tonic-build
├── magma-plugin       — go-plugin handshake, mTLS bootstrap, gRPC client lifecycle
├── magma-providers    — Provider discovery, download, lock-file, registry
├── magma-state        — terraform.tfstate v4 read/write, state migrations, locking
├── magma-backend      — Backend trait + LocalBackend impl (S3 follows M1)
├── magma-graph        — Resource DAG (petgraph) + Kahn-style wave planning
├── magma-plan         — Plan algorithm: Config × State → []Action (typed shigoto::Job)
├── magma-apply        — Apply engine: shigoto::Scheduler over provider RPC
├── magma-attest       — BLAKE3 over plans; tameshi receipts; tabeliao registry
├── magma-mcp          — MCP server (JSON-RPC 2.0). 14 typed tools, destructive gating.
├── magma-cli          — Binary; drop-in `terraform`/`tofu` compat (argv[0] + TF env
│                       vars) + native magma subcommands + `magma mcp` launcher
├── magma-test         — Compat test harness + mock_provider bin for integration
└── magma              — Umbrella crate; re-exports the public surface
```

**No HCL parser.** Magma reads two input shapes only: Pangea Ruby (in-process via magnus, the canonical M0 path) and Terraform JSON (the fallback). Per [`theory/MAGMA.md` §I, §II.1, §IX](https://github.com/pleme-io/theory/blob/main/MAGMA.md). Operators with raw-HCL workflows render to JSON via `terraform-config-inspect` first or migrate to Pangea Ruby.

Phases M0–M5 in [`theory/MAGMA.md` §VI](https://github.com/pleme-io/theory/blob/main/MAGMA.md#vi-phases--the-path-down-from-destination). M0 (≈4 months) ships in-process Pangea-Ruby evaluation + JSON executor + drop-in CLI compat + MCP skeleton + Tier 1 providers passing all 5 test levels.

## Four interfaces (theory/MAGMA.md §II.8)

| Interface | Surface | Status |
|---|---|---|
| Drop-in CLI compat | `argv[0]` → terraform/tofu mode; TF_* env vars; matching exit codes | ✓ M0 |
| Native typed CLI | `magma <subcommand>`; `--json` everywhere; native additions (`mcp`, `daemon`, `watch`, `attest`, `config`, `flow`) | ✓ M0 |
| MCP server | `magma mcp`; JSON-RPC 2.0; 14 typed tools; destructive gating | ✓ M0 (skeleton) |
| Rust library | `cargo add magma`; consumers compose typed values directly | ✓ M0 |

## In-memory pipelines + shigoto work-graph (§II.9)

Pangea Ruby evaluates in-process; rendered architecture never touches disk in the in-memory chain. Every operation surfaces as a typed `shigoto::Job`; flows authored as `(defmagma-flow …)` compile to a `shigoto::Dag`. Cross-workspace chaining passes typed values through Rust, not state files through S3.

## Compatibility contract (§II.2)

| Surface | Format | Source of truth |
|---|---|---|
| Provider protocol | gRPC; tfplugin5/6.proto | OpenTofu `internal/tfplugin{5,6}/` |
| State file | JSON, schema version 4 | OpenTofu `internal/states/statefile/` |
| Lock file | HCL, `.terraform.lock.hcl` | OpenTofu `internal/depsfile/` |
| HCL2 syntax | full HCL2 spec | hashicorp/hcl/v2 |
| CLI | `init/plan/apply/destroy/state/import/workspace/output/show/refresh/taint/force-unlock/get/fmt/validate/console` | OpenTofu `cmd/opentofu/` |
| Function library | 150+ built-ins, exact semantics | OpenTofu `internal/lang/funcs/` |

Byte-exactness is the gate — see [`theory/MAGMA.md` §II.6](https://github.com/pleme-io/theory/blob/main/MAGMA.md#ii6-test-corpus--the-proof-of-compatibility) for the proof harness.

## Build

```bash
cargo build --workspace            # debug build
cargo test  --workspace            # unit + integration tests
cargo fmt   --all -- --check       # formatting gate
cargo clippy --workspace -- -D warnings  # lint gate (workspace.lints applied)

nix build                          # release build via substrate's crate2nix
nix flake check                    # hermetic build + tests + checks
nix run .#regenerate               # regenerate Cargo.nix after Cargo.toml changes
```

## Substrate integration

This repo follows the canonical pleme-io patterns; no escape hatches (§II.7):

| Primitive | How magma uses it |
|---|---|
| `substrate/lib/rust-workspace-release-flake.nix` | `flake.nix` — one import, no hand-rolled build glue |
| `substrate/lib/module-trio.nix` | NixOS + home-manager + darwin modules auto-emitted from `module = { … }` in flake.nix |
| `shikumi` | All config structs; `~/.config/magma/magma.yaml` materialized from typed groups |
| `tatara-lisp` | `(defmagma-module …)`, `(defmagma-resource …)` surface (M0.1) |
| `shigoto` | Apply engine consumes `shigoto::Scheduler`; resource DAG is `shigoto::Dag` |
| `tameshi` | BLAKE3 attestation chain over plans (`magma-attest`) |
| `cofre` | Provider credentials, attestation keys (zero plaintext through magma) |
| `nix-ast` | HCL emission goes through typed `HclValue` AST (`magma fmt`) |
| `pleme-actions` | (TBD) CI workflows migrate to `pleme-io/rust-ci-action@v1` once published |

## Per-crate notes

- **magma-protocol** vendors `tfplugin5.proto` + `tfplugin6.proto` in `magma-protocol/proto/` from OpenTofu's `internal/tfplugin{5,6}/`. `build.rs` invokes `tonic-build` to emit Rust gRPC client stubs at compile time. Do not hand-write protobuf or gRPC code anywhere else (per §IX anti-patterns).
- **magma-plugin** owns the go-plugin handshake (stdout parsing + mTLS bootstrap + subprocess lifecycle). Exposes `Plugin::spawn(binary, magic_cookie, accepted_protocols) -> Result<Plugin>` and a typed `Provider` trait.
- **magma-types** is consumed by every other crate; no upstream deps beyond `serde` + `chrono` + `uuid` + `thiserror` + `schemars`. Keep it small.
- **magma-cli** depends on `magma` (umbrella) + `clap`; logic stays in the typed crates.

## NixOS / home-manager surface

The module trio in `flake.nix` produces `services.magma` (NixOS), `blackmatter.components.magma` (home-manager — operator workstations), and a darwin counterpart. See [`theory/MAGMA.md` §II.7](https://github.com/pleme-io/theory/blob/main/MAGMA.md#ii7-pleme-io-substrate-integration) for the full option surface. Module options expand mechanically as the typed schema grows — never hand-edit `nix/*-module.nix`; instead extend the `shikumiTypedGroups` block in `flake.nix`.

## Anti-patterns (see also theory/MAGMA.md §IX)

- Shelling out to `tofu`/`terraform` from anywhere inside magma
- Hand-written gRPC clients for tfplugin5/6 (must go through `magma-protocol`)
- `format!()` of HCL syntax (must go through `magma-hcl`'s typed `HclValue` AST)
- Inline state-file mutation (must go through `magma-state`'s typed API)
- Custom plan executors per provider (one apply engine; one set of typed primitives)
- `skip-<primitive>:` markers on magma's own implementation — magma must adopt every applicable primitive without escape hatches
