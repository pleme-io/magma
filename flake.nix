{
  description = "magma — the Rust-native OpenTofu-compatible IaC executor. gRPC plugin protocol v5/v6 + terraform.tfstate v4 + .terraform.lock.hcl + HCL2 + full CLI surface; byte-exact compat with existing providers; internals shikumi-typed end to end, apply engine shigoto-scheduled, plans tameshi-attested via BLAKE3, ships as a WASI module. Pangea declares the supercontinent's shape; magma is the molten executive force that realizes it on cloud substrate. Spec: theory/MAGMA.md.";

  inputs = {
    nixpkgs.url     = "github:nixos/nixpkgs?ref=nixos-25.11";
    crate2nix.url   = "github:nix-community/crate2nix";
    flake-utils.url = "github:numtide/flake-utils";
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    crate2nix,
    flake-utils,
    substrate,
  }:
    (import "${substrate}/lib/rust-workspace-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils;
    }) {
      toolName    = "magma";
      packageName = "magma-cli";
      src         = self;
      repo        = "pleme-io/magma";

      # ── Substrate module trio: emits nixosModules.default +
      # ── homeManagerModules.default + darwinModules.default.
      # ── Per MAGMA.md §II.7 "Pleme-io substrate integration":
      # ──   - services.magma  (NixOS — per-workspace systemd units)
      # ──   - programs.magma  (home-manager — operator config)
      # ──   - blackmatter.components.magma (opinionated bundle)
      module = {
        description = "magma — Rust-native OpenTofu-compatible IaC executor";
        hmNamespace = "blackmatter.components";

        # System daemon: cluster-side workspace-watcher service.
        # `magma daemon` watches /etc/magma/workspaces/*/ and runs
        # plan on change; per-workspace systemd units come from the
        # `workspaces` option below.
        withSystemDaemon  = true;
        daemonSubcommand  = "daemon";

        # User daemon: operator-side workspace watcher.
        # `magma watch` runs as a launchd agent / systemd user unit on
        # the operator's workstation.
        withUserDaemon         = true;
        userDaemonSubcommand   = "watch";

        # Shikumi YAML config at ~/.config/magma/magma.yaml.
        withShikumiConfig = true;

        # Typed config groups — auto-generated NixOS option declarations.
        # Per "what extensive means concretely" (MAGMA.md §II.7) —
        # options expand mechanically from the typed schema, never
        # hand-edited.
        shikumiTypedGroups = {
          general = {
            default_backend = {
              type        = "str";
              default     = "s3://pleme-dev-terraform-state";
              description = "Default Terraform backend URL when a workspace omits it.";
            };
            providers_cache_dir = {
              type        = "str";
              default     = "~/.local/share/magma/plugins";
              description = "Per-user provider plugin cache directory; survives upgrades.";
            };
            lockfile_mode = {
              type        = "str";
              default     = "strict";
              description = "Provider lockfile enforcement mode: strict | permissive | bootstrap.";
            };
            attestation_enable = {
              type        = "bool";
              default     = true;
              description = "Emit tameshi BLAKE3 attestation receipts for every plan + apply.";
            };
          };
          telemetry = {
            enable = {
              type        = "bool";
              default     = false;
              description = "Forward structured logs + metrics to the local Vector ingest socket (per pleme-io observability stack).";
            };
            vector_socket = {
              type        = "str";
              default     = "/run/vector/magma.sock";
              description = "Path to the Vector ingest Unix domain socket.";
            };
          };
          # Dual-backend selection — per theory/MAGMA.md §II.11.
          # Pangea Ruby and substrate's pangea-arch-workspace.nix consult
          # this when picking between tofu and magma. magma is the
          # selectable default once the operator opts in fleet-wide;
          # individual workspaces can still override via pangea.yml.
          backend = {
            selection = {
              type        = "str";
              default     = "tofu";
              description = "Default executor for Pangea workspaces: tofu | magma. See theory/MAGMA.md §II.11.";
            };
            require_in_memory_pipeline = {
              type        = "bool";
              default     = false;
              description = "Require in-memory workspace chains (§II.9). When true, magma is the only viable backend.";
            };
            require_workspace_chains = {
              type        = "bool";
              default     = false;
              description = "Require typed WorkspaceChain DAG support (§II.9).";
            };
          };
        };

        # Bespoke escape-hatch options — workspaces + accounts registries.
        # These are richer than the typed-group shape supports today;
        # expand into shikumiTypedGroups once the schema for nested
        # registries lands in substrate's module-trio.
        extraHmOptions = {
          workspaces = nixpkgs.lib.mkOption {
            type        = nixpkgs.lib.types.attrsOf nixpkgs.lib.types.attrs;
            default     = { };
            description = ''
              Workspace registry. Each entry produces a magma-workspace@<name>
              systemd unit (on NixOS via services.magma) and an operator-side
              path watcher (on home-manager via programs.magma).

              Example:
                workspaces.seph-vpc = {
                  path = "/etc/magma/workspaces/seph-vpc";
                  backend = "s3://pleme-dev-terraform-state/pangea/seph-vpc";
                  autoApprove = false;
                  attestation.enable = true;
                };
            '';
          };
          accounts = nixpkgs.lib.mkOption {
            type        = nixpkgs.lib.types.attrsOf nixpkgs.lib.types.attrs;
            default     = { };
            description = ''
              Per-account credential references. Each entry maps an account
              name to a provider + credentials reference (cofre path).

              Example:
                accounts."example-development" = {
                  provider = "aws";
                  credentials = config.cofre.refs."aws/example-development";
                };
            '';
          };
        };

        extraHmConfigFn = { cfg, lib, ... }:
          lib.mkIf (cfg.workspaces != { } || cfg.accounts != { }) {
            services.magma.settings = {
              inherit (cfg) workspaces accounts;
            };
          };
      };
    };
}
