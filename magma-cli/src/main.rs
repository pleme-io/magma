//! magma — CLI binary entry point.
//!
//! Four interfaces per `theory/MAGMA.md` §II.8:
//! 1. **Drop-in CLI compat** — when invoked as `terraform`/`tofu`,
//!    magma honors the TF env vars, exit codes, and output formats.
//! 2. **Native typed CLI** — when invoked as `magma`, the pleme-io
//!    surface with extra subcommands (`mcp`, `daemon`, `watch`,
//!    `attest`, `config`, `flow`).
//! 3. **MCP server** — `magma mcp` launches the JSON-RPC 2.0 server.
//! 4. **Rust library** — consumers `cargo add magma`; this binary is
//!    a façade over the typed library surface.
//!
//! Per `theory/MAGMA.md` §VI.M3 (Full CLI parity), every Terraform
//! flag + exit code must match upstream. M0 ships the load-bearing
//! subset (init/plan/apply/destroy + daemon/watch + mcp).

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use magma::backend::Backend as _;
use magma::pangea::WorkspaceLoader as _;

// ── Drop-in compat: argv[0] sensing ────────────────────────────────

/// Which CLI mode magma is running in. Determined from `argv[0]`'s
/// basename per `theory/MAGMA.md` §II.8 interface 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeMode {
    /// Invoked as `terraform` or `terraform-*`. Match upstream
    /// stdout/stderr/exit-code format verbatim.
    TerraformCompat,
    /// Invoked as `tofu` or `tofu-*`. Same as TerraformCompat for the
    /// surfaces magma implements; the small post-fork divergences
    /// (e.g. `tofu encryption`) opt into native magma behavior.
    OpenTofuCompat,
    /// Invoked as `magma` or anything else. Native typed surface
    /// (clap-derived, structured JSON via `--json`, native
    /// subcommands available).
    MagmaNative,
}

fn detect_mode() -> InvokeMode {
    let argv0 = env::args().next().unwrap_or_default();
    let basename = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("magma")
        .to_lowercase();

    // env override for testing: MAGMA_INVOKE_AS=terraform forces compat
    if let Ok(forced) = env::var("MAGMA_INVOKE_AS") {
        return match forced.as_str() {
            "terraform" => InvokeMode::TerraformCompat,
            "tofu" => InvokeMode::OpenTofuCompat,
            _ => InvokeMode::MagmaNative,
        };
    }

    if basename.starts_with("terraform") {
        InvokeMode::TerraformCompat
    } else if basename.starts_with("tofu") {
        InvokeMode::OpenTofuCompat
    } else {
        InvokeMode::MagmaNative
    }
}

#[cfg(test)]
fn is_compat_mode(m: InvokeMode) -> bool {
    matches!(m, InvokeMode::TerraformCompat | InvokeMode::OpenTofuCompat)
}

// ── TF_* environment variable inventory ───────────────────────────

/// Snapshot of Terraform / OpenTofu environment variables magma
/// honors when running in compat mode (and respects in native mode
/// when set). Per `theory/MAGMA.md` §II.2 row 15.
#[derive(Debug, Default, Clone)]
struct TfEnv {
    /// `TF_VAR_<name>` → variable value (name lower-cased per Terraform).
    pub vars: std::collections::HashMap<String, String>,
    /// `TF_DATA_DIR` — working data dir (default `.terraform`).
    pub data_dir: Option<PathBuf>,
    /// `TF_LOG` — log level: TRACE/DEBUG/INFO/WARN/ERROR/JSON/off.
    pub log_level: Option<String>,
    /// `TF_LOG_PATH` — log file.
    pub log_path: Option<PathBuf>,
    /// `TF_INPUT` — false/0/no disables interactive prompts.
    pub input_enabled: bool,
    /// `TF_IN_AUTOMATION` — any non-empty value is CI mode.
    pub in_automation: bool,
    /// `TF_WORKSPACE` — active workspace name.
    pub workspace: Option<String>,
    /// `TF_PLUGIN_CACHE_DIR` — provider plugin cache directory.
    pub plugin_cache_dir: Option<PathBuf>,
    /// `TF_TOKEN_<host>` — registry auth tokens (host is host-encoded).
    pub registry_tokens: std::collections::HashMap<String, String>,
    /// `TF_CLI_ARGS_<subcommand>` — extra args per subcommand.
    pub cli_args: std::collections::HashMap<String, String>,
}

fn capture_tf_env() -> TfEnv {
    let mut e = TfEnv {
        input_enabled: true,
        ..Default::default()
    };
    for (k, v) in env::vars() {
        match k.as_str() {
            "TF_DATA_DIR" => e.data_dir = Some(PathBuf::from(v)),
            "TF_LOG" => e.log_level = Some(v),
            "TF_LOG_PATH" => e.log_path = Some(PathBuf::from(v)),
            "TF_INPUT" => {
                let lower = v.to_lowercase();
                e.input_enabled = !(lower == "false" || lower == "0" || lower == "no");
            }
            "TF_IN_AUTOMATION" => e.in_automation = !v.is_empty(),
            "TF_WORKSPACE" => e.workspace = Some(v),
            "TF_PLUGIN_CACHE_DIR" => e.plugin_cache_dir = Some(PathBuf::from(v)),
            _ => {
                if let Some(name) = k.strip_prefix("TF_VAR_") {
                    e.vars.insert(name.to_lowercase(), v);
                } else if let Some(host) = k.strip_prefix("TF_TOKEN_") {
                    e.registry_tokens.insert(host.to_string(), v);
                } else if let Some(sub) = k.strip_prefix("TF_CLI_ARGS_") {
                    e.cli_args.insert(sub.to_lowercase(), v);
                }
            }
        }
    }
    e
}

// ── Output mode ────────────────────────────────────────────────────

/// `MAGMA_OUTPUT=native` (or `--magma-native`) opts into pleme-io's
/// structured-JSON stream. Default in compat mode is Terraform-style
/// plain text; default in native mode is also plain text unless
/// `--json` is passed (per Terraform's per-subcommand convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    TerraformPlain,
    MagmaNative,
}

fn detect_output_mode(invoke: InvokeMode) -> OutputMode {
    match env::var("MAGMA_OUTPUT").as_deref() {
        Ok("native") => OutputMode::MagmaNative,
        Ok("terraform" | "plain") => OutputMode::TerraformPlain,
        _ => match invoke {
            InvokeMode::MagmaNative => OutputMode::TerraformPlain,
            _ => OutputMode::TerraformPlain,
        },
    }
}

// ── clap surface ──────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "magma",
    version,
    about = "Rust-native Pangea-Ruby-first OpenTofu-compatible IaC executor",
    long_about = "Pangea declares the supercontinent's shape; magma is the molten executive force that realizes it on cloud substrate. See theory/MAGMA.md for the destination spec.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Subcommand. Omit for version + welcome banner.
    #[command(subcommand)]
    cmd: Option<Command>,

    /// Detailed exit code: `plan` returns 2 if changes are pending.
    /// Mirrors `terraform plan -detailed-exitcode`.
    #[arg(long, global = true)]
    detailed_exitcode: bool,

    /// Structured JSON output. Available on subcommands that support it
    /// (matches `terraform <subcommand> -json`).
    #[arg(long, global = true)]
    json: bool,

    /// Force pleme-io structured output mode (overrides MAGMA_OUTPUT env).
    #[arg(long, global = true)]
    magma_native: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    // ── Terraform / OpenTofu surface ──────────────────────────────
    /// Initialize a workspace — download providers, build lock file.
    Init(InitArgs),
    /// Compute a plan against current state.
    Plan(PlanArgs),
    /// Apply a plan to the cloud substrate.
    Apply(ApplyArgs),
    /// Destroy all managed resources.
    Destroy(DestroyArgs),
    /// Inspect or mutate state.
    #[command(subcommand)]
    State(StateCommand),
    /// Import an existing resource into state.
    Import,
    /// Manage workspaces.
    #[command(subcommand)]
    Workspace(WorkspaceCommand),
    /// Print an output value.
    Output,
    /// Show the current state or a saved plan.
    Show,
    /// Refresh state from the cloud.
    Refresh,
    /// Mark a resource as tainted (force re-create).
    Taint,
    /// Force-unlock state.
    ForceUnlock,
    /// Get / update modules.
    Get,
    /// Format HCL files. (No-op in magma — see theory/MAGMA.md §IX.)
    Fmt,
    /// Validate config + state.
    Validate,
    /// Interactive evaluator console.
    Console,

    // ── Native magma additions (per theory/MAGMA.md §II.8 interface 2) ──
    /// Start the MCP server on stdin/stdout (or TCP if --port is set).
    Mcp(McpArgs),
    /// Run as the system-side workspace-watcher daemon (NixOS services.magma).
    Daemon,
    /// Run as the operator-side workspace watcher (HM programs.magma).
    Watch,
    /// Attestation: verify a tameshi receipt against a stored plan.
    #[command(subcommand)]
    Attest(AttestCommand),
    /// Manipulate ~/.config/magma/magma.yaml (typed shikumi config).
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Execute a tatara-lisp DAG of magma operations (§II.9).
    Flow(FlowArgs),
    /// Print a typed JSON capability manifest — consumed by Pangea Ruby's
    /// backend auto-discovery to probe magma's abilities at runtime.
    /// Per `theory/MAGMA.md` §II.11.
    Capabilities,
    /// Verify any Pangea-rendered workspace through magma's typed
    /// pipeline. Reusable from Ruby rspec, CI, bash — anywhere a JSON
    /// report on "does magma plan this workspace cleanly?" is needed.
    #[command(subcommand)]
    Fixture(FixtureCommand),
    /// Atomic typed state-organization migration. Moves resources
    /// between workspaces' state files without recreate. Consumes a
    /// typed `MigrationPlan` JSON; emits a `MigrationReceipt` JSON
    /// with BLAKE3 hashes pre/post. Per
    /// `theory/PANGEA-MAGMA-ORCHESTRATION.md` §III.3 + §V.
    Migrate(MigrateArgs),
    /// Split: move a subset of one workspace's resources into a new
    /// workspace. Thin wrapper over `magma migrate` for the case where
    /// the target state file is empty.
    Split(SplitArgs),
    /// Merge: move every resource from one workspace into another.
    /// Thin wrapper over `magma migrate` for the case where every
    /// source address is moved over verbatim.
    Merge(MergeArgs),

    /// Pangea Ruby gem operations — in-memory bundler+bundix
    /// replacement. Parses Gemfile / Gemfile.lock, emits gemset.nix,
    /// attests the gem closure with BLAKE3.
    #[command(subcommand)]
    Rubygems(RubygemsCommand),
}

#[derive(Subcommand, Debug)]
enum RubygemsCommand {
    /// Parse a Gemfile.lock + emit gemset.nix to stdout. Replaces
    /// the `bundix` subprocess for Pangea workspace flakes.
    GemsetFromLock(RubygemsFileArgs),
    /// Parse a Gemfile.lock + print the BLAKE3 attestation hex.
    /// The attestation is order-independent over the resolved
    /// gem closure; identical closures hash to the same value
    /// regardless of bundler's emission order.
    AttestLock(RubygemsFileArgs),
    /// Parse a Gemfile + emit the typed Manifest as JSON.
    ParseGemfile(RubygemsFileArgs),
    /// Parse a Gemfile.lock + emit the typed Lockfile as JSON.
    ParseLock(RubygemsFileArgs),
    /// Parse a *.gemspec + emit the typed GemSpec as JSON.
    ParseGemspec(RubygemsFileArgs),
    /// Compute the nix-base32 sha256 hash of a file (the format
    /// nix-prefetch-url emits + `fetchurl` accepts). Used to fill
    /// the M3-pending sha256 placeholders in gemset.nix.
    NixHashSha256(RubygemsFileArgs),
}

#[derive(Args, Debug)]
struct RubygemsFileArgs {
    /// Path to the Gemfile / Gemfile.lock. Defaults to stdin if "-".
    #[arg(default_value = "-")]
    path: String,
}

#[derive(Subcommand, Debug)]
enum FixtureCommand {
    /// Verify a single workspace (directory or single `.tf.json` file).
    Verify(FixtureVerifyArgs),
    /// Verify every `.tf.json` under a directory; emit aggregate JSON.
    VerifyDir(FixtureVerifyDirArgs),
    /// Run the full universal substrate law battery against a
    /// workspace. Architecture composition + workspace lifecycle
    /// laws — fails fast with a JSON report on the first broken
    /// law. Use this from CI / pangea-operator preflight / Ruby
    /// rspec to assert the universal substrate contracts.
    LawBattery(FixtureVerifyArgs),
    /// Run the law battery over every `.tf.json` under a directory.
    /// Aggregate JSON report; exit 1 if any workspace violated a
    /// law. Designed for CI gates over fleet workspaces.
    LawBatteryDir(FixtureVerifyDirArgs),
}

#[derive(clap::Args, Debug)]
struct FixtureVerifyArgs {
    path: PathBuf,
}

#[derive(clap::Args, Debug)]
struct FixtureVerifyDirArgs {
    dir: PathBuf,
}

#[derive(clap::Args, Debug)]
struct MigrateArgs {
    /// Path to the typed MigrationPlan JSON (see
    /// `magma_migrate::MigrationPlan`). Pass `-` to read from stdin.
    plan: PathBuf,
    /// Override `dry_run` flag in the plan (force preview).
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct SplitArgs {
    /// Source workspace name.
    #[arg(long)]
    from: String,
    /// Source state file path.
    #[arg(long)]
    from_state: PathBuf,
    /// Target workspace name.
    #[arg(long)]
    to: String,
    /// Target state file path (need not yet exist).
    #[arg(long)]
    to_state: PathBuf,
    /// Resource addresses to split out (repeatable).
    #[arg(long = "resource")]
    resources: Vec<String>,
    /// Preview only — do not write either state file.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args, Debug)]
struct MergeArgs {
    /// Source workspace name.
    #[arg(long)]
    from: String,
    /// Source state file path.
    #[arg(long)]
    from_state: PathBuf,
    /// Target workspace name.
    #[arg(long)]
    to: String,
    /// Target state file path (need not yet exist).
    #[arg(long)]
    to_state: PathBuf,
    /// Preview only — do not write either state file.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args, Debug, Default)]
struct InitArgs {
    /// Workspace directory (default: current dir).
    #[arg(default_value = ".")]
    dir: PathBuf,
    /// Skip provider downloads — useful for offline tests.
    #[arg(long)]
    no_download: bool,
}

#[derive(clap::Args, Debug, Default)]
struct PlanArgs {
    #[arg(default_value = ".")]
    dir: PathBuf,
    /// Variables (`-var name=value`); also reads `TF_VAR_*` env vars.
    #[arg(long = "var")]
    vars: Vec<String>,
    /// Variable files (`.tfvars`).
    #[arg(long = "var-file")]
    var_files: Vec<PathBuf>,
    /// Write the plan to a file (consumed later by `magma apply -plan-id`).
    #[arg(short = 'o', long)]
    out: Option<PathBuf>,
    /// Path to a `.tlisp` lava architecture. When set, bypasses the
    /// workspace-on-disk path entirely and synthesizes via magma-lava.
    /// The state is still read from the workspace dir (or in-memory
    /// empty state when --tlisp-state-dir is unset).
    ///
    /// Requires the `tlisp` feature (off by default — see magma-cli's
    /// Cargo.toml for why). Without it this flag does not exist and clap
    /// rejects it as unknown.
    #[cfg(feature = "tlisp")]
    #[arg(long)]
    tlisp: Option<PathBuf>,
    /// Repeatable `key=value` binding for the .tlisp architecture's
    /// `:inputs` slot. Required for any architecture whose interface
    /// declares non-optional inputs.
    #[cfg(feature = "tlisp")]
    #[arg(long = "tlisp-binding", value_name = "KEY=VALUE")]
    tlisp_bindings: Vec<String>,
    /// Optional typed-interface gate name. Validated against bundled
    /// interfaces via lava-architectures.
    #[cfg(feature = "tlisp")]
    #[arg(long)]
    tlisp_gate: Option<String>,
    /// Refresh state against real providers before planning — Terraform's
    /// implicit plan-time refresh (`ReadResource` against every state
    /// instance), which catches drift from changes made outside magma
    /// (a resource deleted or edited in the console). On by default,
    /// matching Terraform; pass `--refresh false` to plan against the
    /// state exactly as last written (the pre-refresh behavior). Requires
    /// provider binaries to be locatable (`magma init`, or
    /// `$MAGMA_PROVIDER_DIR`) — when they aren't, refresh safely degrades
    /// to a no-op (never drops state on uncertainty) and planning
    /// proceeds unchanged.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    refresh: bool,
}

#[derive(clap::Args, Debug, Default)]
struct ApplyArgs {
    #[arg(default_value = ".")]
    dir: PathBuf,
    /// Apply a previously-computed plan by its BLAKE3 PlanId.
    #[arg(long)]
    plan_id: Option<String>,
    /// Skip the interactive approval prompt (Terraform's `-auto-approve`).
    #[arg(long)]
    auto_approve: bool,
    /// Path to a `.tlisp` lava architecture. Same semantics as
    /// `plan --tlisp`, including the `tlisp` feature requirement.
    #[cfg(feature = "tlisp")]
    #[arg(long)]
    tlisp: Option<PathBuf>,
    /// Repeatable `key=value` binding.
    #[cfg(feature = "tlisp")]
    #[arg(long = "tlisp-binding", value_name = "KEY=VALUE")]
    tlisp_bindings: Vec<String>,
    /// Optional typed-interface gate name.
    #[cfg(feature = "tlisp")]
    #[arg(long)]
    tlisp_gate: Option<String>,
    /// Same as `plan --refresh` — on by default. See [`PlanArgs::refresh`].
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    refresh: bool,
}

#[derive(clap::Args, Debug, Default)]
struct DestroyArgs {
    #[arg(default_value = ".")]
    dir: PathBuf,
    #[arg(long)]
    auto_approve: bool,
}

#[derive(Subcommand, Debug)]
enum StateCommand {
    List,
    Show {
        address: String,
    },
    Mv {
        from: String,
        to: String,
    },
    Rm {
        address: String,
    },
    /// Replace a provider in state (e.g. fork migration).
    ReplaceProvider {
        from: String,
        to: String,
    },
}

#[derive(Subcommand, Debug)]
enum WorkspaceCommand {
    Show,
    List,
    New { name: String },
    Select { name: String },
    Delete { name: String },
}

#[derive(clap::Args, Debug, Default)]
struct McpArgs {
    /// TCP port (default: stdin/stdout transport per MCP standard).
    #[arg(long)]
    port: Option<u16>,
}

#[derive(Subcommand, Debug)]
enum AttestCommand {
    /// Verify a receipt against a stored plan.
    Verify { plan_id: String },
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    Get {
        key: String,
    },
    Set {
        key: String,
        value: String,
    },
    /// Open the config file in $EDITOR.
    Edit,
}

#[derive(clap::Args, Debug, Default)]
struct FlowArgs {
    /// Path to a tatara-lisp DAG file (`.lisp` or `.tatara`).
    flow: PathBuf,
}

// ── Entry point ───────────────────────────────────────────────────

fn main() -> ExitCode {
    let invoke = detect_mode();
    let tf_env = capture_tf_env();
    let output = detect_output_mode(invoke);

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("TF_LOG")
                .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // One tokio runtime for the whole process — every async subcommand
    // dispatches into it instead of spawning its own. Replaces the
    // 9-cmd duplication that had `tokio::runtime::Runtime::new()?
    // .block_on(...)` repeated in each handler.
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("magma: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let result = runtime.block_on(run(cli, invoke, output, tf_env));
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("magma: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli, invoke: InvokeMode, output: OutputMode, tf_env: TfEnv) -> Result<u8> {
    let _ = (output, &tf_env);

    let Some(cmd) = cli.cmd else {
        print_banner(invoke);
        return Ok(0);
    };

    match cmd {
        Command::Init(args) => cmd_init(args),
        Command::Plan(args) => cmd_plan(args, cli.detailed_exitcode).await,
        Command::Apply(args) => cmd_apply(args).await,
        Command::Destroy(args) => cmd_destroy(args).await,
        Command::State(s) => cmd_state(s).await,
        Command::Import => stub("import"),
        Command::Workspace(w) => cmd_workspace(w),
        Command::Output => stub("output"),
        Command::Show => stub("show"),
        Command::Refresh => stub("refresh"),
        Command::Taint => stub("taint"),
        Command::ForceUnlock => stub("force-unlock"),
        Command::Get => stub("get"),
        Command::Fmt => cmd_fmt(),
        Command::Validate => stub("validate"),
        Command::Console => stub("console"),
        Command::Mcp(args) => cmd_mcp(args),
        Command::Daemon => stub("daemon"),
        Command::Watch => stub("watch"),
        Command::Attest(a) => cmd_attest(a),
        Command::Config(c) => cmd_config(c),
        Command::Flow(args) => cmd_flow(args).await,
        Command::Capabilities => cmd_capabilities(),
        Command::Fixture(cmd) => cmd_fixture(cmd).await,
        Command::Migrate(args) => cmd_migrate(args).await,
        Command::Split(args) => cmd_split(args).await,
        Command::Merge(args) => cmd_merge(args).await,
        Command::Rubygems(cmd) => cmd_rubygems(cmd).await,
    }
}

async fn cmd_rubygems(cmd: RubygemsCommand) -> Result<u8> {
    use std::io::Read;
    let read_input = |args: &RubygemsFileArgs| -> Result<String> {
        if args.path == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        } else {
            Ok(std::fs::read_to_string(&args.path)?)
        }
    };

    match cmd {
        RubygemsCommand::GemsetFromLock(args) => {
            let source = read_input(&args)?;
            let lock = magma_rubygems::lockfile::parse(&source)
                .map_err(|e| anyhow::anyhow!("parse Gemfile.lock: {e}"))?;
            let text = magma_rubygems::nix::emit_gemset(&lock)
                .map_err(|e| anyhow::anyhow!("emit gemset.nix: {e}"))?;
            print!("{text}");
            Ok(0)
        }
        RubygemsCommand::AttestLock(args) => {
            let source = read_input(&args)?;
            let lock = magma_rubygems::lockfile::parse(&source)
                .map_err(|e| anyhow::anyhow!("parse Gemfile.lock: {e}"))?;
            let attestation = magma_rubygems::attestation::attest_lockfile(&lock);
            println!("{attestation}");
            Ok(0)
        }
        RubygemsCommand::ParseGemfile(args) => {
            let source = read_input(&args)?;
            let manifest = magma_rubygems::gemfile_parser::parse(&source)
                .map_err(|e| anyhow::anyhow!("parse Gemfile: {e}"))?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
            Ok(0)
        }
        RubygemsCommand::ParseLock(args) => {
            let source = read_input(&args)?;
            let lock = magma_rubygems::lockfile::parse(&source)
                .map_err(|e| anyhow::anyhow!("parse Gemfile.lock: {e}"))?;
            println!("{}", serde_json::to_string_pretty(&lock)?);
            Ok(0)
        }
        RubygemsCommand::ParseGemspec(args) => {
            let source = read_input(&args)?;
            let spec = magma_rubygems::gemspec_parser::parse(&source)
                .map_err(|e| anyhow::anyhow!("parse gemspec: {e}"))?;
            println!("{}", serde_json::to_string_pretty(&spec)?);
            Ok(0)
        }
        RubygemsCommand::NixHashSha256(args) => {
            let bytes = if args.path == "-" {
                use std::io::Read;
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            } else {
                std::fs::read(&args.path)?
            };
            println!("{}", magma_rubygems::nixhash::sha256_nix(&bytes));
            Ok(0)
        }
    }
}

async fn cmd_fixture(cmd: FixtureCommand) -> Result<u8> {
    match cmd {
        FixtureCommand::Verify(args) => {
            let harness = magma_arch_test::WorkspaceTestHarness::new(args.path.clone());
            match harness.verify().await {
                Ok(report) => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    Ok(0)
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path":   args.path,
                            "status": "failed",
                            "error":  e.to_string(),
                        }))?,
                    );
                    Ok(1)
                }
            }
        }
        FixtureCommand::VerifyDir(args) => match magma_arch_test::verify_directory(&args.dir).await
        {
            Ok(agg) => {
                println!("{}", serde_json::to_string_pretty(&agg)?);
                Ok(if agg.failed == 0 { 0 } else { 1 })
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "dir":    args.dir,
                        "status": "failed",
                        "error":  e.to_string(),
                    }))?,
                );
                Ok(1)
            }
        },
        FixtureCommand::LawBattery(args) => {
            let harness = magma_arch_test::WorkspaceTestHarness::new(args.path.clone());
            match harness.assert_all_substrate_laws().await {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path":   args.path,
                            "status": "passed",
                            "laws":   ["architecture::assert_all_laws", "workspace::assert_all_laws"],
                            "report": report,
                        }))?,
                    );
                    Ok(0)
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "path":   args.path,
                            "status": "violated",
                            "error":  e.to_string(),
                        }))?,
                    );
                    Ok(1)
                }
            }
        }
        FixtureCommand::LawBatteryDir(args) => {
            match magma_arch_test::run_law_battery_directory(&args.dir).await {
                Ok(agg) => {
                    println!("{}", serde_json::to_string_pretty(&agg)?);
                    Ok(if agg.failed == 0 { 0 } else { 1 })
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "dir":    args.dir,
                            "status": "failed",
                            "error":  e.to_string(),
                        }))?,
                    );
                    Ok(1)
                }
            }
        }
    }
}

fn cmd_capabilities() -> Result<u8> {
    // Typed JSON capability manifest — the canonical Pangea-Ruby
    // auto-discovery surface per theory/MAGMA.md §II.11.
    let mcp_tools: Vec<String> = magma::mcp::tool_specs()
        .into_iter()
        .map(|t| t.name)
        .collect();

    let manifest = serde_json::json!({
        "tool":               "magma",
        "version":            env!("CARGO_PKG_VERSION"),
        "schema_version":     1,
        "supported_protocols": ["tfplugin5", "tfplugin6"],
        "input_formats":      ["pangea-ruby-inprocess", "terraform-json"],
        "input_formats_excluded": ["hcl2"],
        "backends":           ["local", "s3 (planned M1)"],
        "subcommands": [
            "init", "plan", "apply", "destroy",
            "state", "import", "workspace", "output", "show",
            "refresh", "taint", "force-unlock", "get", "fmt",
            "validate", "console",
            // Native magma additions:
            "mcp", "daemon", "watch", "attest", "config", "flow",
            "capabilities",
        ],
        "interfaces": {
            "drop_in_cli":   { "argv0_modes": ["terraform", "tofu", "magma"] },
            "native_cli":    { "json_flag": true },
            "mcp":           { "transport": "stdin-stdout-jsonrpc2", "tools": mcp_tools.len() },
            "library":       { "umbrella_crate": "magma" }
        },
        "mcp_tools":          mcp_tools,
        "env_vars_honored": [
            "TF_VAR_*", "TF_DATA_DIR", "TF_LOG", "TF_LOG_PATH",
            "TF_CLI_ARGS_*", "TF_INPUT", "TF_IN_AUTOMATION",
            "TF_TOKEN_*", "TF_PLUGIN_CACHE_DIR", "TF_WORKSPACE",
            "MAGMA_OUTPUT", "MAGMA_INVOKE_AS"
        ],
        "exit_codes": {
            "0": "success",
            "1": "error",
            "2": "plan: changes pending (-detailed-exitcode)"
        },
        "workspace_primitive_supported": true,
        "workspace_chain_supported":     true,
        "in_memory_pipeline_supported":  true,
        "shigoto_job_wrapping": "planned (M1)"
    });
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(0)
}

fn print_banner(invoke: InvokeMode) {
    match invoke {
        InvokeMode::TerraformCompat => {
            println!(
                "Terraform v1.5-compat (magma {})",
                env!("CARGO_PKG_VERSION")
            );
            println!("Run `terraform --help` for usage.");
        }
        InvokeMode::OpenTofuCompat => {
            println!("OpenTofu v1.7-compat (magma {})", env!("CARGO_PKG_VERSION"));
            println!("Run `tofu --help` for usage.");
        }
        InvokeMode::MagmaNative => {
            println!(
                "magma {} — Rust-native Pangea-Ruby-first IaC executor",
                env!("CARGO_PKG_VERSION"),
            );
            println!("See `magma --help` and theory/MAGMA.md for the destination spec.");
        }
    }
}

// ── Per-subcommand stubs (M0; full impl wires in M0.x → M3) ──────

fn stub(name: &str) -> Result<u8> {
    eprintln!("magma {name}: not yet implemented (M0 in flight — see theory/MAGMA.md §VI)");
    Ok(1)
}

fn cmd_init(args: InitArgs) -> Result<u8> {
    eprintln!(
        "magma init: workspace {:?} (no-download={})",
        args.dir, args.no_download
    );
    // M0: verify workspace shape; provider download lands in M0.x via magma-providers registry client.
    use magma::pangea::WorkspaceShape;
    let shape = WorkspaceShape::discover(&args.dir)
        .map_err(|e| anyhow::anyhow!("workspace discovery: {e}"))?;
    match shape {
        WorkspaceShape::PangeaRuby { ruby_files, .. } => {
            println!(
                "magma init: PangeaRuby workspace ({} .rb files)",
                ruby_files.len()
            );
        }
        WorkspaceShape::TerraformJson { json_files, .. } => {
            println!(
                "magma init: TerraformJson workspace ({} .tf.json files)",
                json_files.len()
            );
        }
    }
    Ok(0)
}

/// Discover → load → parse → read state. Every async cmd_* that
/// operates on a Pangea-rendered workspace shares this prelude;
/// keeping it in one helper means future load-bearing changes
/// (e.g. caching, multi-file workspace support) land in one place.
/// The triple every command needs before it can plan: parsed config, the
/// state backend, and the state itself. Named so the two ways of
/// producing it (rendered terraform.json on disk, or tlisp synthesis)
/// have one shared return type.
type LoadedWorkspace = (
    magma::config::Config,
    magma::backend::LocalBackend,
    magma::types::State,
);

/// `plan` and `apply` resolve their workspace identically, and both have
/// to gate the tlisp arm on the `tlisp` feature. Generating the accessor
/// states that gate exactly ONCE instead of copying the same `#[cfg]`
/// pair into each command — the duplication that would otherwise drift
/// the moment a third command grows a `--tlisp`.
macro_rules! impl_loaded_workspace {
    ($($args:ty),+ $(,)?) => { $(
        impl $args {
            #[cfg(feature = "tlisp")]
            async fn load_workspace(&self) -> Result<LoadedWorkspace> {
                match &self.tlisp {
                    Some(path) => {
                        synthesize_via_tlisp(
                            path,
                            &self.tlisp_bindings,
                            self.tlisp_gate.as_deref(),
                            &self.dir,
                        )
                        .await
                    }
                    None => load_workspace_and_state(&self.dir).await,
                }
            }

            /// Without the `tlisp` feature there is no second source to
            /// choose between — the flags do not exist, so this is not a
            /// fallback, it is the only path.
            #[cfg(not(feature = "tlisp"))]
            async fn load_workspace(&self) -> Result<LoadedWorkspace> {
                load_workspace_and_state(&self.dir).await
            }
        }
    )+ };
}

impl_loaded_workspace!(PlanArgs, ApplyArgs);

/// Synthesize a tlisp-sourced workspace. State still comes from
/// `state_dir`'s local backend, so plan/apply work the same way they
/// do with rendered terraform.json sources.
#[cfg(feature = "tlisp")]
async fn synthesize_via_tlisp(
    tlisp_path: &std::path::Path,
    bindings: &[String],
    gate: Option<&str>,
    state_dir: &std::path::Path,
) -> Result<(
    magma::config::Config,
    magma::backend::LocalBackend,
    magma::types::State,
)> {
    let mut typed_bindings: indexmap::IndexMap<String, magma_lava::Binding> =
        indexmap::IndexMap::new();
    for kv in bindings {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--tlisp-binding must be KEY=VALUE: `{kv}`"))?;
        typed_bindings.insert(k.to_string(), magma_lava::Binding::Scalar(v.to_string()));
    }
    let source = magma_lava::LavaSource::Path {
        path: tlisp_path.to_path_buf(),
    };
    let plan = magma_lava::synthesize_source(&source, &typed_bindings, gate)
        .map_err(|e| anyhow::anyhow!("magma-lava synthesize: {e}"))?;
    let cfg = magma::config::Config::from_json(plan.terraform_json)
        .map_err(|e| anyhow::anyhow!("parse synthesized terraform.json: {e}"))?;
    let backend = magma::backend::LocalBackend::new(state_dir.to_path_buf());
    let state = backend
        .read_state()
        .await
        .map_err(|e| anyhow::anyhow!("read state: {e}"))?;
    Ok((cfg, backend, state))
}

async fn load_workspace_and_state(
    dir: &std::path::Path,
) -> Result<(
    magma::config::Config,
    magma::backend::LocalBackend,
    magma::types::State,
)> {
    let shape = magma::pangea::WorkspaceShape::discover(dir)
        .map_err(|e| anyhow::anyhow!("discover: {e}"))?;
    let loaded = magma::pangea::TerraformJsonLoader
        .load(shape)
        .await
        .map_err(|e| anyhow::anyhow!("load: {e}"))?;
    let cfg = magma::config::Config::from_json(loaded.rendered)
        .map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    let backend = magma::backend::LocalBackend::new(dir.to_path_buf());
    let state = backend
        .read_state()
        .await
        .map_err(|e| anyhow::anyhow!("read state: {e}"))?;
    Ok((cfg, backend, state))
}

/// Surface a plan-time [`magma::apply::engine::RefreshReport`] to the
/// operator — shared by `cmd_plan` + `cmd_apply` so the two entry points
/// report drift identically. Silent only when the refresh was genuinely
/// clean AND found nothing to report.
///
/// The loud arm is not decoration. This function used to return early
/// whenever `refreshed`/`dropped_*`/`suppressed_mass_drop` were all zero —
/// which is EXACTLY the shape of a refresh in which every `ReadResource`
/// failed (`kept_on_error = N`, everything else 0). The one case where
/// magma knows nothing was the one case it said nothing about, and the
/// operator read the silence as "clean".
fn report_refresh(report: &magma::apply::engine::RefreshReport) {
    let observation = report.observation();
    let coverage = observation.coverage();
    if !coverage.supports_in_sync_claim() {
        // Blind / Partial / Unrefreshed — say so before anything else,
        // because everything downstream of here is about to look like a
        // clean plan.
        eprintln!(
            "magma: plan-time refresh is {coverage} — {} of {} state instance(s) could not be \
             read from the provider. This plan's `before` side is REMEMBERED state, not \
             observed reality; an empty change set here is NOT evidence that anything matches.",
            report.kept_on_error,
            observation.counts().probed(),
        );
    }
    let changed = report.refreshed > 0
        || report.dropped_instances > 0
        || report.dropped_resources > 0
        || report.suppressed_mass_drop > 0;
    if !changed {
        return;
    }
    eprintln!(
        "magma: plan-time refresh — {} instance(s) updated from the real world, \
         {} confirmed gone ({} resource(s) dropped from state), \
         {} suppressed as a mass-drop anomaly (systemic read failure, not genuine drift)",
        report.refreshed,
        report.dropped_instances,
        report.dropped_resources,
        report.suppressed_mass_drop,
    );
}

async fn cmd_plan(args: PlanArgs, detailed: bool) -> Result<u8> {
    let (cfg, backend, mut state) = args.load_workspace().await?;
    let refresh_ctx = args
        .refresh
        .then(|| magma::apply::engine::ApplyContext::new(args.dir.clone()));
    let (plan, refresh_report) =
        magma::apply::engine::refresh_then_plan(&cfg, &mut state, refresh_ctx.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("plan: {e}"))?;
    if let Some(report) = &refresh_report {
        report_refresh(report);
        // Terraform parity: a plan-time refresh persists the refreshed
        // state to the backend even though `plan` itself makes no other
        // change — so a later `plan`/`apply` never re-discovers the same
        // drift from scratch.
        backend
            .write_state(&state)
            .await
            .map_err(|e| anyhow::anyhow!("write refreshed state: {e}"))?;
    }
    let summary = serde_json::json!({
        "plan_id":          hex::encode(plan.id.0),
        "created_at":       plan.created_at,
        "resource_changes": plan.resource_changes.len(),
        "changes":          plan.resource_changes,
        // How much of the above is real. A `--json` consumer must be able
        // to answer "was this observed?" from the machine-readable output,
        // never from stderr.
        "observation":      plan.observation,
        "verdict":          plan.drift_verdict(),
    });
    if let Some(out) = args.out {
        tokio::fs::write(&out, serde_json::to_vec_pretty(&plan)?).await?;
        eprintln!("plan written to {}", out.display());
    } else {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    }
    // `Read` is excluded alongside `NoOp`: this drives the --detailed exit
    // code (2 = "there are changes"), and a data-source lookup is not a change.
    // Counting reads here would make ANY workspace containing a `data` block
    // report drift forever, which is exactly the false positive `--detailed`
    // exists to avoid. See Plan::change_count for the same correction.
    let has_changes = plan.resource_changes.iter().any(|c| {
        !matches!(
            c.action,
            magma::types::Action::NoOp | magma::types::Action::Read
        )
    });
    Ok(if detailed && has_changes { 2 } else { 0 })
}

async fn cmd_apply(args: ApplyArgs) -> Result<u8> {
    let (cfg, backend, mut state) = args.load_workspace().await?;
    let refresh_ctx = args
        .refresh
        .then(|| magma::apply::engine::ApplyContext::new(args.dir.clone()));
    let (plan, refresh_report) =
        magma::apply::engine::refresh_then_plan(&cfg, &mut state, refresh_ctx.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("plan: {e}"))?;
    if let Some(report) = &refresh_report {
        report_refresh(report);
        // Persist the refresh even if the operator declines to apply below
        // (Terraform parity — see the matching comment in `cmd_plan`).
        backend
            .write_state(&state)
            .await
            .map_err(|e| anyhow::anyhow!("write refreshed state: {e}"))?;
    }

    if !args.auto_approve {
        eprintln!(
            "magma apply: would apply {} resource changes. Re-run with --auto-approve to proceed.",
            plan.resource_changes.len(),
        );
        return Ok(0);
    }

    let outcome =
        magma::apply::run_plan(&plan, &mut state).map_err(|e| anyhow::anyhow!("apply: {e}"))?;
    backend
        .write_state(&state)
        .await
        .map_err(|e| anyhow::anyhow!("write state: {e}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "plan_id":     hex::encode(outcome.plan_id.0),
            "applied":     outcome.applied.len(),
            "failed":      outcome.failed.len(),
            "started_at":  outcome.started_at,
            "finished_at": outcome.finished_at,
        }))?,
    );
    Ok(if outcome.failed.is_empty() { 0 } else { 1 })
}

async fn cmd_destroy(args: DestroyArgs) -> Result<u8> {
    use magma::types::{Action, ChangeReason, Plan as TPlan, PlanId, ResourceChange};

    let backend = magma::backend::LocalBackend::new(args.dir.clone());
    let mut state = backend
        .read_state()
        .await
        .map_err(|e| anyhow::anyhow!("read state: {e}"))?;
    let resource_changes: Vec<ResourceChange> = state
        .resources
        .iter()
        .map(|r| ResourceChange {
            address: r.address.clone(),
            action: Action::Delete,
            before: r.instances.first().map(|i| i.attributes.clone()),
            after: None,
            reasons: vec![ChangeReason::DeletedResource],
        })
        .collect();
    let plan = TPlan {
        id: PlanId([0u8; 32]),
        created_at: chrono::Utc::now(),
        config_root: args.dir.clone(),
        variables: Default::default(),
        resource_changes,
        output_changes: vec![],
        // `destroy` synthesizes a delete-everything plan straight from
        // state without a refresh, so the honest record is "nothing was
        // observed".
        observation: magma::types::Observation::unrefreshed(),
    };

    if !args.auto_approve {
        eprintln!(
            "magma destroy: would destroy {} resources. Re-run with --auto-approve to proceed.",
            plan.resource_changes.len(),
        );
        return Ok(0);
    }
    let outcome =
        magma::apply::run_plan(&plan, &mut state).map_err(|e| anyhow::anyhow!("apply: {e}"))?;
    backend
        .write_state(&state)
        .await
        .map_err(|e| anyhow::anyhow!("write state: {e}"))?;
    eprintln!("magma destroy: removed {} resources", outcome.applied.len());
    Ok(if outcome.failed.is_empty() { 0 } else { 1 })
}

async fn cmd_state(cmd: StateCommand) -> Result<u8> {
    let backend = magma::backend::LocalBackend::new(std::env::current_dir()?);
    let state = backend
        .read_state()
        .await
        .map_err(|e| anyhow::anyhow!("read state: {e}"))?;
    match cmd {
        StateCommand::List => {
            for r in &state.resources {
                println!(
                    "{}.{}{}",
                    r.address.type_id.0,
                    r.address.name,
                    match &r.address.key {
                        Some(k) => format!(" [{k:?}]"),
                        None => String::new(),
                    },
                );
            }
            Ok(0)
        }
        StateCommand::Show { address } => {
            let found = state
                .resources
                .iter()
                .find(|r| format!("{}.{}", r.address.type_id.0, r.address.name) == address);
            match found {
                Some(r) => {
                    println!("{}", serde_json::to_string_pretty(r)?);
                    Ok(0)
                }
                None => {
                    eprintln!("magma state show: address {address} not found in state");
                    Ok(1)
                }
            }
        }
        StateCommand::Mv { .. } => stub("state mv"),
        StateCommand::Rm { .. } => stub("state rm"),
        StateCommand::ReplaceProvider { .. } => stub("state replace-provider"),
    }
}

fn cmd_workspace(cmd: WorkspaceCommand) -> Result<u8> {
    match cmd {
        WorkspaceCommand::Show => {
            println!("default");
            Ok(0)
        }
        WorkspaceCommand::List => {
            println!("* default");
            Ok(0)
        }
        WorkspaceCommand::New { .. } => stub("workspace new"),
        WorkspaceCommand::Select { .. } => stub("workspace select"),
        WorkspaceCommand::Delete { .. } => stub("workspace delete"),
    }
}

fn cmd_fmt() -> Result<u8> {
    // magma does NOT parse HCL (theory/MAGMA.md §I, §IX). `magma fmt`
    // is a no-op that returns success — operators who relied on
    // `terraform fmt` against Pangea-rendered JSON output didn't need
    // it anyway (the JSON renderer emits canonical output).
    eprintln!("magma fmt: no-op (magma never reads HCL — see theory/MAGMA.md §IX)");
    Ok(0)
}

fn cmd_mcp(args: McpArgs) -> Result<u8> {
    eprintln!("magma mcp: starting MCP server (port={:?})", args.port);
    eprintln!("[stub] M0.x: wire JSON-RPC 2.0 dispatch via magma-mcp::dispatch");
    let _specs = magma::mcp::tool_specs();
    eprintln!(
        "(magma-mcp registered {} typed tools)",
        magma::mcp::tool_specs().len()
    );
    Ok(0)
}

fn cmd_attest(cmd: AttestCommand) -> Result<u8> {
    match cmd {
        AttestCommand::Verify { plan_id } => {
            eprintln!("magma attest verify: plan_id={plan_id}");
            stub("attest verify")
        }
    }
}

fn cmd_config(cmd: ConfigCommand) -> Result<u8> {
    match cmd {
        ConfigCommand::Get { key } => {
            eprintln!("magma config get: {key}");
            stub("config get")
        }
        ConfigCommand::Set { key, value } => {
            eprintln!("magma config set: {key}={value}");
            stub("config set")
        }
        ConfigCommand::Edit => stub("config edit"),
    }
}

async fn cmd_flow(args: FlowArgs) -> Result<u8> {
    // Flow file shape (typed JSON; tatara-lisp `.lisp` / `.tatara` /
    // `.scm` extensions compile to the same JSON via magma-tatara):
    //
    //   { "workspaces": [...], "edges": [...], "optimization": {...} }
    //
    //   (deforch :name "seph"
    //     :workspaces ((:name "vpc"     :dir "workspaces/seph-vpc")
    //                  (:name "cluster" :dir "workspaces/seph-cluster"))
    //     :edges ((:from "vpc" :from-output "vpc_id"
    //              :to   "cluster" :to-input "vpc_id"))
    //     :optimization (:strategy "parallel_by_tier" :max-concurrency 4))
    //
    // magma loads + plans each workspace in topological order; output
    // values from the rendered JSON flow downstream per declared
    // edges. The actual engine lives in magma-flow; this handler just
    // parses + delegates.

    let bytes = tokio::fs::read(&args.flow).await?;
    let is_lisp = args
        .flow
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s == "lisp" || s == "tatara" || s == "scm")
        .unwrap_or(false);
    let flow: magma_flow::FlowFile = if is_lisp {
        let source = std::str::from_utf8(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid UTF-8 in lisp source: {e}"))?;
        let value =
            magma_tatara::parse_deforch(source).map_err(|e| anyhow::anyhow!("lisp parse: {e}"))?;
        serde_json::from_value(value)?
    } else {
        serde_json::from_slice(&bytes)?
    };
    let report = magma_flow::run(&flow)
        .await
        .map_err(|e| anyhow::anyhow!("flow run: {e}"))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(0)
}

// ── Migration / split / merge ──────────────────────────────────────

async fn cmd_migrate(args: MigrateArgs) -> Result<u8> {
    let raw = if args.plan.as_os_str() == "-" {
        use tokio::io::AsyncReadExt as _;
        let mut buf = Vec::new();
        tokio::io::stdin().read_to_end(&mut buf).await?;
        buf
    } else {
        tokio::fs::read(&args.plan).await?
    };
    let mut plan: magma_migrate::MigrationPlan = serde_json::from_slice(&raw)
        .map_err(|e| anyhow::anyhow!("parse MigrationPlan JSON: {e}"))?;
    if args.dry_run {
        plan.dry_run = true;
    }
    let receipt = magma_migrate::run(plan)
        .await
        .map_err(|e| anyhow::anyhow!("migrate: {e}"))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(0)
}

/// Build a typed MigrationPlan from CLI args + a list of resource
/// moves. Shared by `cmd_split` and `cmd_merge` to keep the plan
/// shape in one place.
fn migration_plan(
    from_name: String,
    from_state: PathBuf,
    to_name: String,
    to_state: PathBuf,
    moves: Vec<magma_migrate::ResourceMove>,
    dry_run: bool,
) -> magma_migrate::MigrationPlan {
    magma_migrate::MigrationPlan {
        from: magma_migrate::WorkspaceRef {
            name: from_name,
            state_path: from_state,
        },
        to: magma_migrate::WorkspaceRef {
            name: to_name,
            state_path: to_state,
        },
        moves,
        preserve: magma_migrate::PreserveFlags::default(),
        dry_run,
    }
}

async fn cmd_split(args: SplitArgs) -> Result<u8> {
    if args.resources.is_empty() {
        anyhow::bail!("magma split: at least one --resource is required");
    }
    let moves: Vec<magma_migrate::ResourceMove> = args
        .resources
        .iter()
        .map(|addr| magma_migrate::ResourceMove {
            source_address: addr.clone(),
            target_address: addr.clone(),
        })
        .collect();
    let plan = migration_plan(
        args.from,
        args.from_state,
        args.to,
        args.to_state,
        moves,
        args.dry_run,
    );
    let receipt = magma_migrate::run(plan)
        .await
        .map_err(|e| anyhow::anyhow!("split: {e}"))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(0)
}

async fn cmd_merge(args: MergeArgs) -> Result<u8> {
    // Load the source state to enumerate every resource address; the
    // plan-builder is `magma merge` itself — operators don't need to
    // hand-author the address list.
    let bytes = tokio::fs::read(&args.from_state)
        .await
        .map_err(|e| anyhow::anyhow!("read {:?}: {e}", args.from_state))?;
    let from_state_json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("parse source state JSON: {e}"))?;
    let resources = from_state_json
        .get("resources")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow::anyhow!("source state has no resources array"))?;
    let mut moves: Vec<magma_migrate::ResourceMove> = Vec::new();
    for r in resources {
        let kind = r
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("resource missing `type`"))?;
        let name = r
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("resource missing `name`"))?;
        let addr = format!("{kind}.{name}");
        moves.push(magma_migrate::ResourceMove {
            source_address: addr.clone(),
            target_address: addr,
        });
    }
    let plan = migration_plan(
        args.from,
        args.from_state,
        args.to,
        args.to_state,
        moves,
        args.dry_run,
    );
    let receipt = magma_migrate::run(plan)
        .await
        .map_err(|e| anyhow::anyhow!("merge: {e}"))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(0)
}

// topological_order moved to magma-flow crate.

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_mode_via_env_override() {
        unsafe {
            env::set_var("MAGMA_INVOKE_AS", "terraform");
            assert_eq!(detect_mode(), InvokeMode::TerraformCompat);
            env::set_var("MAGMA_INVOKE_AS", "tofu");
            assert_eq!(detect_mode(), InvokeMode::OpenTofuCompat);
            env::set_var("MAGMA_INVOKE_AS", "magma");
            assert_eq!(detect_mode(), InvokeMode::MagmaNative);
            env::remove_var("MAGMA_INVOKE_AS");
        }
    }

    #[test]
    fn is_compat_mode_basic() {
        assert!(is_compat_mode(InvokeMode::TerraformCompat));
        assert!(is_compat_mode(InvokeMode::OpenTofuCompat));
        assert!(!is_compat_mode(InvokeMode::MagmaNative));
    }
}
