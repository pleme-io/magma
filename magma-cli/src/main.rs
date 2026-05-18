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
use clap::{Parser, Subcommand};
use magma::pangea::WorkspaceLoader as _;
use magma::backend::Backend as _;

mod tatara_lite;

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
            "TF_DATA_DIR"         => e.data_dir = Some(PathBuf::from(v)),
            "TF_LOG"              => e.log_level = Some(v),
            "TF_LOG_PATH"         => e.log_path = Some(PathBuf::from(v)),
            "TF_INPUT"            => {
                let lower = v.to_lowercase();
                e.input_enabled = !(lower == "false" || lower == "0" || lower == "no");
            }
            "TF_IN_AUTOMATION"    => e.in_automation = !v.is_empty(),
            "TF_WORKSPACE"        => e.workspace = Some(v),
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
    disable_help_subcommand = true,
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
}

#[derive(Subcommand, Debug)]
enum FixtureCommand {
    /// Verify a single workspace (directory or single `.tf.json` file).
    Verify(FixtureVerifyArgs),
    /// Verify every `.tf.json` under a directory; emit aggregate JSON.
    VerifyDir(FixtureVerifyDirArgs),
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
    Show { address: String },
    Mv   { from: String, to: String },
    Rm   { address: String },
    /// Replace a provider in state (e.g. fork migration).
    ReplaceProvider { from: String, to: String },
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
    Get { key: String },
    Set { key: String, value: String },
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
    let result = run(cli, invoke, output, tf_env);
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("magma: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(
    cli: Cli,
    invoke: InvokeMode,
    output: OutputMode,
    tf_env: TfEnv,
) -> Result<u8> {
    let _ = (output, &tf_env);

    let Some(cmd) = cli.cmd else {
        print_banner(invoke);
        return Ok(0);
    };

    match cmd {
        Command::Init(args)    => cmd_init(args),
        Command::Plan(args)    => cmd_plan(args, cli.detailed_exitcode),
        Command::Apply(args)   => cmd_apply(args),
        Command::Destroy(args) => cmd_destroy(args),
        Command::State(s)      => cmd_state(s),
        Command::Import        => stub("import"),
        Command::Workspace(w)  => cmd_workspace(w),
        Command::Output        => stub("output"),
        Command::Show          => stub("show"),
        Command::Refresh       => stub("refresh"),
        Command::Taint         => stub("taint"),
        Command::ForceUnlock   => stub("force-unlock"),
        Command::Get           => stub("get"),
        Command::Fmt           => cmd_fmt(),
        Command::Validate      => stub("validate"),
        Command::Console       => stub("console"),
        Command::Mcp(args)     => cmd_mcp(args),
        Command::Daemon        => stub("daemon"),
        Command::Watch         => stub("watch"),
        Command::Attest(a)     => cmd_attest(a),
        Command::Config(c)     => cmd_config(c),
        Command::Flow(args)    => cmd_flow(args),
        Command::Capabilities  => cmd_capabilities(),
        Command::Fixture(cmd)  => cmd_fixture(cmd),
        Command::Migrate(args) => cmd_migrate(args),
        Command::Split(args)   => cmd_split(args),
        Command::Merge(args)   => cmd_merge(args),
    }
}

fn cmd_fixture(cmd: FixtureCommand) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        match cmd {
            FixtureCommand::Verify(args) => {
                let harness = magma_arch_test::WorkspaceTestHarness::new(args.path.clone());
                match harness.verify().await {
                    Ok(report) => {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                        Ok::<u8, anyhow::Error>(0)
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
            FixtureCommand::VerifyDir(args) => {
                match magma_arch_test::verify_directory(&args.dir).await {
                    Ok(agg) => {
                        println!("{}", serde_json::to_string_pretty(&agg)?);
                        Ok::<u8, anyhow::Error>(if agg.failed == 0 { 0 } else { 1 })
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
    })
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
            println!("Terraform v1.5-compat (magma {})", env!("CARGO_PKG_VERSION"));
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
    eprintln!("magma init: workspace {:?} (no-download={})", args.dir, args.no_download);
    // M0: verify workspace shape; provider download lands in M0.x via magma-providers registry client.
    use magma::pangea::WorkspaceShape;
    let shape = WorkspaceShape::discover(&args.dir)
        .map_err(|e| anyhow::anyhow!("workspace discovery: {e}"))?;
    match shape {
        WorkspaceShape::PangeaRuby { ruby_files, .. } => {
            println!("magma init: PangeaRuby workspace ({} .rb files)", ruby_files.len());
        }
        WorkspaceShape::TerraformJson { json_files, .. } => {
            println!("magma init: TerraformJson workspace ({} .tf.json files)", json_files.len());
        }
    }
    Ok(0)
}

fn cmd_plan(args: PlanArgs, detailed: bool) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let shape = magma::pangea::WorkspaceShape::discover(&args.dir)
            .map_err(|e| anyhow::anyhow!("discover: {e}"))?;
        let loaded = magma::pangea::TerraformJsonLoader
            .load(shape)
            .await
            .map_err(|e| anyhow::anyhow!("load: {e}"))?;
        let cfg = magma::config::Config::from_json(loaded.rendered)
            .map_err(|e| anyhow::anyhow!("parse: {e}"))?;
        // Read state via LocalBackend (workspace dir holds .terraform/terraform.tfstate).
        let backend = magma::backend::LocalBackend::new(args.dir.clone());
        let state = backend.read_state().await
            .map_err(|e| anyhow::anyhow!("read state: {e}"))?;
        let plan = magma::plan::plan(&cfg, &state)
            .map_err(|e| anyhow::anyhow!("plan: {e}"))?;
        // Pretty-print.
        let summary = serde_json::json!({
            "plan_id":          hex::encode(plan.id.0),
            "created_at":       plan.created_at,
            "resource_changes": plan.resource_changes.len(),
            "changes":          plan.resource_changes,
        });
        if let Some(out) = args.out {
            tokio::fs::write(&out, serde_json::to_vec_pretty(&plan)?).await?;
            eprintln!("plan written to {}", out.display());
        } else {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        // -detailed-exitcode: 0 if no changes, 2 if changes pending.
        let has_changes = plan
            .resource_changes
            .iter()
            .any(|c| !matches!(c.action, magma::types::Action::NoOp));
        if detailed && has_changes {
            return Ok::<u8, anyhow::Error>(2);
        }
        Ok::<u8, anyhow::Error>(0)
    })
}

fn cmd_apply(args: ApplyArgs) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let shape = magma::pangea::WorkspaceShape::discover(&args.dir)
            .map_err(|e| anyhow::anyhow!("discover: {e}"))?;
        let loaded = magma::pangea::TerraformJsonLoader
            .load(shape)
            .await
            .map_err(|e| anyhow::anyhow!("load: {e}"))?;
        let cfg = magma::config::Config::from_json(loaded.rendered)
            .map_err(|e| anyhow::anyhow!("parse: {e}"))?;
        let backend = magma::backend::LocalBackend::new(args.dir.clone());
        let mut state = backend.read_state().await
            .map_err(|e| anyhow::anyhow!("read state: {e}"))?;
        let plan = magma::plan::plan(&cfg, &state)
            .map_err(|e| anyhow::anyhow!("plan: {e}"))?;

        if !args.auto_approve {
            eprintln!("magma apply: would apply {} resource changes. Re-run with --auto-approve to proceed.", plan.resource_changes.len());
            return Ok(0);
        }

        let outcome = magma::apply::run_plan(&plan, &mut state)
            .map_err(|e| anyhow::anyhow!("apply: {e}"))?;
        backend.write_state(&state).await
            .map_err(|e| anyhow::anyhow!("write state: {e}"))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "plan_id": hex::encode(outcome.plan_id.0),
                "applied": outcome.applied.len(),
                "failed":  outcome.failed.len(),
                "started_at":  outcome.started_at,
                "finished_at": outcome.finished_at,
            }))?,
        );
        Ok::<u8, anyhow::Error>(if outcome.failed.is_empty() { 0 } else { 1 })
    })
}

fn cmd_destroy(args: DestroyArgs) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let backend = magma::backend::LocalBackend::new(args.dir.clone());
        let mut state = backend.read_state().await
            .map_err(|e| anyhow::anyhow!("read state: {e}"))?;
        // Synthesize a destroy plan: every state resource → Delete.
        use magma::types::{Action, ChangeReason, Plan as TPlan, PlanId, ResourceChange};
        let resource_changes: Vec<ResourceChange> = state
            .resources
            .iter()
            .map(|r| ResourceChange {
                address: r.address.clone(),
                action:  Action::Delete,
                before:  r.instances.first().map(|i| i.attributes.clone()),
                after:   None,
                reasons: vec![ChangeReason::DeletedResource],
            })
            .collect();
        let plan = TPlan {
            id:               PlanId([0u8; 32]),
            created_at:       chrono::Utc::now(),
            config_root:      args.dir.clone(),
            variables:        Default::default(),
            resource_changes,
            output_changes:   vec![],
        };

        if !args.auto_approve {
            eprintln!("magma destroy: would destroy {} resources. Re-run with --auto-approve to proceed.", plan.resource_changes.len());
            return Ok(0);
        }
        let outcome = magma::apply::run_plan(&plan, &mut state)
            .map_err(|e| anyhow::anyhow!("apply: {e}"))?;
        backend.write_state(&state).await
            .map_err(|e| anyhow::anyhow!("write state: {e}"))?;
        eprintln!("magma destroy: removed {} resources", outcome.applied.len());
        Ok::<u8, anyhow::Error>(if outcome.failed.is_empty() { 0 } else { 1 })
    })
}

fn cmd_state(cmd: StateCommand) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let backend = magma::backend::LocalBackend::new(std::env::current_dir()?);
        let state = backend.read_state().await
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
                Ok::<u8, anyhow::Error>(0)
            }
            StateCommand::Show { address } => {
                let found = state.resources.iter().find(|r| {
                    format!("{}.{}", r.address.type_id.0, r.address.name) == address
                });
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
            StateCommand::Mv   { .. }       => stub("state mv"),
            StateCommand::Rm   { .. }       => stub("state rm"),
            StateCommand::ReplaceProvider{..} => stub("state replace-provider"),
        }
    })
}

fn cmd_workspace(cmd: WorkspaceCommand) -> Result<u8> {
    match cmd {
        WorkspaceCommand::Show           => { println!("default"); Ok(0) }
        WorkspaceCommand::List           => { println!("* default"); Ok(0) }
        WorkspaceCommand::New { .. }     => stub("workspace new"),
        WorkspaceCommand::Select { .. }  => stub("workspace select"),
        WorkspaceCommand::Delete { .. }  => stub("workspace delete"),
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
    eprintln!("(magma-mcp registered {} typed tools)", magma::mcp::tool_specs().len());
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
        ConfigCommand::Get  { key }            => { eprintln!("magma config get: {key}");  stub("config get") }
        ConfigCommand::Set  { key, value }     => { eprintln!("magma config set: {key}={value}"); stub("config set") }
        ConfigCommand::Edit                    => stub("config edit"),
    }
}

fn cmd_flow(args: FlowArgs) -> Result<u8> {
    // Flow file shape (typed JSON; tatara-lisp .lisp surface compiles
    // to this same shape in M0.7):
    //
    // {
    //   "workspaces": [
    //     { "name": "vpc",     "dir": "workspaces/seph-vpc" },
    //     { "name": "cluster", "dir": "workspaces/seph-cluster" }
    //   ],
    //   "edges": [
    //     { "from": "vpc", "from_output": "vpc_id",
    //       "to":   "cluster", "to_input":  "vpc_id" }
    //   ],
    //   "optimization": {
    //     "strategy":        "parallel_by_tier",
    //     "max_concurrency": 4,
    //     "retries":         { "max": 2, "backoff_ms": 500 }
    //   }
    // }
    //
    // Tatara-lisp surface (M0.7 minimal — `.lisp` / `.tatara` extension):
    //
    //   (deforch :name "seph"
    //     :workspaces (
    //       (:name "vpc"     :dir "workspaces/seph-vpc")
    //       (:name "cluster" :dir "workspaces/seph-cluster")
    //     )
    //     :edges (
    //       (:from "vpc" :from-output "vpc_id"
    //        :to   "cluster" :to-input "vpc_id")
    //     )
    //     :optimization (:strategy "parallel_by_tier"
    //                    :max-concurrency 4))
    //
    // Each workspace dir is a Pangea-rendered Terraform JSON workspace.
    // magma loads + plans each in topological order; output values are
    // taken from the `output` block of each workspace's rendered JSON
    // and flow downstream per the declared edges. M0 ships the
    // plan-only orchestration; per-workspace apply lands alongside
    // typed cross-workspace state.

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let bytes = tokio::fs::read(&args.flow).await?;
        let is_lisp = args.flow.extension()
            .and_then(|s| s.to_str())
            .map(|s| s == "lisp" || s == "tatara" || s == "scm")
            .unwrap_or(false);
        let flow: FlowFile = if is_lisp {
            let source = std::str::from_utf8(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid UTF-8 in lisp source: {e}"))?;
            let value = tatara_lite::parse_deforch(source)
                .map_err(|e| anyhow::anyhow!("lisp parse: {e}"))?;
            serde_json::from_value(value)?
        } else {
            serde_json::from_slice(&bytes)?
        };
        let order = topological_order(&flow)?;
        let mut outputs_so_far: std::collections::HashMap<String, serde_json::Value> =
            std::collections::HashMap::new();
        let mut summaries: Vec<serde_json::Value> = vec![];

        for workspace in order {
            let entry = flow
                .workspaces
                .iter()
                .find(|w| w.name == workspace)
                .ok_or_else(|| anyhow::anyhow!("flow references unknown workspace: {workspace}"))?;
            let shape = magma::pangea::WorkspaceShape::discover(&entry.dir)
                .map_err(|e| anyhow::anyhow!("discover {}: {e}", entry.name))?;
            let loaded = magma::pangea::TerraformJsonLoader
                .load(shape)
                .await
                .map_err(|e| anyhow::anyhow!("load {}: {e}", entry.name))?;
            let cfg = magma::config::Config::from_json(loaded.rendered.clone())
                .map_err(|e| anyhow::anyhow!("parse {}: {e}", entry.name))?;
            let backend = magma::backend::LocalBackend::new(entry.dir.clone());
            let state = backend
                .read_state()
                .await
                .map_err(|e| anyhow::anyhow!("read state {}: {e}", entry.name))?;
            let plan = magma::plan::plan(&cfg, &state)
                .map_err(|e| anyhow::anyhow!("plan {}: {e}", entry.name))?;

            // Extract this workspace's outputs from the rendered JSON's
            // `output` block (Pangea-rendered).
            let mut workspace_outputs: std::collections::HashMap<String, serde_json::Value> =
                std::collections::HashMap::new();
            for (out_name, decl) in &cfg.outputs {
                workspace_outputs.insert(out_name.clone(), decl.value.clone());
            }
            // Cross-workspace edges: upstream → downstream input flow.
            for edge in flow
                .edges
                .iter()
                .filter(|e| e.from == entry.name)
            {
                if let Some(v) = workspace_outputs.get(&edge.from_output) {
                    outputs_so_far.insert(
                        format!("{}.{}", edge.to, edge.to_input),
                        v.clone(),
                    );
                }
            }

            summaries.push(serde_json::json!({
                "workspace": entry.name,
                "plan_id":   hex::encode(plan.id.0),
                "changes":   plan.resource_changes.len(),
                "outputs":   workspace_outputs,
            }));
        }

        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "workspaces":     summaries,
                "propagated":     outputs_so_far,
            }))?,
        );
        Ok::<u8, anyhow::Error>(0)
    })
}

#[derive(serde::Deserialize)]
struct FlowFile {
    workspaces: Vec<FlowWorkspace>,
    #[serde(default)]
    edges:      Vec<FlowEdge>,
    /// Optional typed orchestration hints. M0.4 plumbed; honored once
    /// `magma flow run` lands its shigoto-wrapped apply path. The
    /// current plan-only path is sequential regardless of hints.
    #[serde(default)]
    #[allow(dead_code)]
    optimization: Option<OptimizationHints>,
}

#[derive(serde::Deserialize, Clone, Debug)]
#[allow(dead_code)]
struct OptimizationHints {
    #[serde(default)]
    strategy:         Option<String>,
    #[serde(default)]
    max_concurrency:  Option<usize>,
    #[serde(default)]
    retries:          Option<OptimizationRetries>,
    #[serde(default)]
    timeout_ms:       Option<u64>,
}

#[derive(serde::Deserialize, Clone, Debug)]
#[allow(dead_code)]
struct OptimizationRetries {
    #[serde(default)]
    max:        Option<u32>,
    #[serde(default)]
    backoff_ms: Option<u64>,
}

#[derive(serde::Deserialize, Clone)]
struct FlowWorkspace {
    name: String,
    dir:  std::path::PathBuf,
}

#[derive(serde::Deserialize, Clone)]
struct FlowEdge {
    from:        String,
    from_output: String,
    to:          String,
    to_input:    String,
}

// ── Migration / split / merge ──────────────────────────────────────

fn cmd_migrate(args: MigrateArgs) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
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
        Ok::<u8, anyhow::Error>(0)
    })
}

fn cmd_split(args: SplitArgs) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
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
        let plan = magma_migrate::MigrationPlan {
            from: magma_migrate::WorkspaceRef {
                name:       args.from,
                state_path: args.from_state,
            },
            to: magma_migrate::WorkspaceRef {
                name:       args.to,
                state_path: args.to_state,
            },
            moves,
            preserve: magma_migrate::PreserveFlags::default(),
            dry_run:  args.dry_run,
        };
        let receipt = magma_migrate::run(plan)
            .await
            .map_err(|e| anyhow::anyhow!("split: {e}"))?;
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok::<u8, anyhow::Error>(0)
    })
}

fn cmd_merge(args: MergeArgs) -> Result<u8> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        // Load the source state to enumerate every resource address; the
        // plan-builder is `magma merge` itself — operators don't need to
        // hand-author the address list.
        let bytes = tokio::fs::read(&args.from_state).await
            .map_err(|e| anyhow::anyhow!("read {:?}: {e}", args.from_state))?;
        let from_state: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parse source state JSON: {e}"))?;
        let resources = from_state
            .get("resources")
            .and_then(|r| r.as_array())
            .ok_or_else(|| anyhow::anyhow!("source state has no resources array"))?;
        let mut moves: Vec<magma_migrate::ResourceMove> = Vec::new();
        for r in resources {
            let kind = r.get("type").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("resource missing `type`"))?;
            let name = r.get("name").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("resource missing `name`"))?;
            let addr = format!("{kind}.{name}");
            moves.push(magma_migrate::ResourceMove {
                source_address: addr.clone(),
                target_address: addr,
            });
        }
        let plan = magma_migrate::MigrationPlan {
            from: magma_migrate::WorkspaceRef {
                name:       args.from,
                state_path: args.from_state,
            },
            to: magma_migrate::WorkspaceRef {
                name:       args.to,
                state_path: args.to_state,
            },
            moves,
            preserve: magma_migrate::PreserveFlags::default(),
            dry_run:  args.dry_run,
        };
        let receipt = magma_migrate::run(plan)
            .await
            .map_err(|e| anyhow::anyhow!("merge: {e}"))?;
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok::<u8, anyhow::Error>(0)
    })
}

fn topological_order(flow: &FlowFile) -> Result<Vec<String>> {
    use std::collections::{HashMap, HashSet, VecDeque};
    let mut indegree: HashMap<String, usize> = flow
        .workspaces
        .iter()
        .map(|w| (w.name.clone(), 0))
        .collect();
    for edge in &flow.edges {
        if !indegree.contains_key(&edge.to) {
            anyhow::bail!("flow edge references unknown workspace: {}", edge.to);
        }
        *indegree.entry(edge.to.clone()).or_insert(0) += 1;
    }
    let mut queue: VecDeque<String> = indegree
        .iter()
        .filter(|&(_, &d)| d == 0)
        .map(|(n, _)| n.clone())
        .collect();
    let mut order: Vec<String> = vec![];
    let mut visited: HashSet<String> = HashSet::new();
    while let Some(n) = queue.pop_front() {
        if !visited.insert(n.clone()) {
            continue;
        }
        order.push(n.clone());
        for edge in flow.edges.iter().filter(|e| e.from == n) {
            if let Some(d) = indegree.get_mut(&edge.to) {
                *d = d.saturating_sub(1);
                if *d == 0 {
                    queue.push_back(edge.to.clone());
                }
            }
        }
    }
    if order.len() < flow.workspaces.len() {
        anyhow::bail!("flow has a cycle");
    }
    Ok(order)
}

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
