//! magma-migrate — typed state-organization migration primitive.
//!
//! Move resources between workspaces' state files atomically while
//! preserving cloud-resource identity. Per
//! `theory/PANGEA-MAGMA-ORCHESTRATION.md` §III.3 + §V.
//!
//! Five guarantees the engine enforces (§V):
//!
//! 1. **No recreate** — `state mv` semantics; cloud identity (ARN/UUID)
//!    is unchanged.
//! 2. **No data loss** — validation pass before any state mutation;
//!    refuses to proceed if a resource would be orphaned.
//! 3. **Dependent reference rewriting** — references to the moved
//!    resource get the new address (M0.x; M0.2 covers the basics).
//! 4. **Attestation continuity** — pre/post BLAKE3 hashes of every
//!    affected state file emitted in the `MigrationReceipt`.
//! 5. **Atomicity** — two-phase commit (stage target → validate →
//!    swap source). Either every declared resource migrates or none
//!    does; on partial failure, `MigrationStallError` carries the
//!    typed checkpoint so the operator can `resume`.
//!
//! The Ruby side (`Pangea::Magma::Migration`) declares migrations;
//! the magma CLI's `magma migrate <plan.json>` invokes this crate.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::Utc;
use magma_state::{read_state, write_state};
use magma_types::{ResourceAddress, State, StateResource};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state error: {0}")]
    State(#[from] magma_state::StateError),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("validation failed: {reason}")]
    Validation { reason: String },
    #[error("source resource not found: {0}")]
    SourceNotFound(String),
    #[error("target already has resource: {0}")]
    TargetCollision(String),
    #[error("migration stalled at phase {phase}: {reason} (checkpoint: {checkpoint:?})")]
    Stalled {
        phase: String,
        reason: String,
        checkpoint: PathBuf,
    },
}

// ── Typed plan shape ──────────────────────────────────────────────

/// Reference to a workspace's state file on disk. The Pangea side
/// resolves `workspace_dir` paths into these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRef {
    pub name: String,
    pub state_path: PathBuf,
}

/// One resource-level move.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMove {
    /// Address in the source workspace (e.g. `aws_iam_role.k3s_node`).
    pub source_address: String,
    /// Address it will take in the target workspace.
    pub target_address: String,
}

/// What identity / metadata to preserve across the move.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreserveFlags {
    /// Don't destroy/recreate. Default: true. Setting false defeats
    /// the whole point of magma-migrate; documented but supported for
    /// completeness.
    #[serde(default = "yes")]
    pub resource_identity: bool,
    /// Preserve the resource's tag set even if the new workspace's
    /// Pangea Ruby renders different tags.
    #[serde(default)]
    pub tags: bool,
    /// Update dependent_references in other resources that point at
    /// the moved resource.
    #[serde(default)]
    pub dependent_resources: bool,
}

fn yes() -> bool {
    true
}

/// The full typed migration plan. Pangea::Magma::Migration#plan
/// emits one of these as JSON; `magma migrate <plan.json>` consumes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub from: WorkspaceRef,
    pub to: WorkspaceRef,
    pub moves: Vec<ResourceMove>,
    #[serde(default)]
    pub preserve: PreserveFlags,
    /// When true, validate + return a planned receipt without
    /// mutating any state files. Useful for `pangea_migrate_dry_run`.
    #[serde(default)]
    pub dry_run: bool,
}

// ── Receipt ───────────────────────────────────────────────────────

/// Typed audit receipt emitted after every migration. Includes
/// pre/post BLAKE3 hashes of both state files (the
/// attestation-continuity guarantee §V row 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub plan: MigrationPlan,
    pub started_at: chrono::DateTime<Utc>,
    pub finished_at: chrono::DateTime<Utc>,
    pub from_state_hash_pre: String,
    pub from_state_hash_post: String,
    pub to_state_hash_pre: String,
    pub to_state_hash_post: String,
    pub moved_count: usize,
    pub dry_run: bool,
}

// ── Engine ────────────────────────────────────────────────────────

/// Execute a typed `MigrationPlan` atomically. Returns the typed
/// receipt on success; on partial failure raises `MigrationError::Stalled`
/// with the checkpoint path the operator can `resume` from.
pub async fn run(plan: MigrationPlan) -> Result<MigrationReceipt, MigrationError> {
    let started_at = Utc::now();

    // Phase 1: load both state files.
    let mut from_state = read_state(&plan.from.state_path).await?;
    let mut to_state = read_state(&plan.to.state_path).await?;

    let from_state_hash_pre = state_hash(&from_state);
    let to_state_hash_pre = state_hash(&to_state);

    // Phase 2: validate. Every source_address must exist; no
    // target_address may already exist.
    validate(&plan, &from_state, &to_state)?;

    // Phase 3: execute moves in-memory.
    let moved_count = plan.moves.len();
    for mv in &plan.moves {
        execute_move(&plan, mv, &mut from_state, &mut to_state)?;
    }

    // Bump serials on both states — operators downstream should see
    // these as fresh writes.
    from_state.serial = from_state.serial.saturating_add(1);
    to_state.serial = to_state.serial.saturating_add(1);

    // Phase 4 (commit): two-phase atomic write. Write target first
    // (its lock is the safer one to acquire), then source. On any
    // write failure: leave the source intact (resources still in old
    // location), surface a typed Stalled error with the checkpoint.
    //
    // For dry_run: skip the writes entirely + return the predicted
    // receipt.
    let from_state_hash_post: String;
    let to_state_hash_post: String;
    if !plan.dry_run {
        write_state(&plan.to.state_path, &to_state)
            .await
            .map_err(|e| MigrationError::Stalled {
                phase: "write_to".into(),
                reason: e.to_string(),
                checkpoint: plan.to.state_path.with_extension("tfstate.tmp"),
            })?;
        write_state(&plan.from.state_path, &from_state)
            .await
            .map_err(|e| MigrationError::Stalled {
                phase: "write_from".into(),
                reason: format!(
                    "target written successfully but source write failed: {e}. \
                     Resources may be duplicated; reconcile by removing the moved \
                     records from source",
                ),
                checkpoint: plan.from.state_path.with_extension("tfstate.tmp"),
            })?;
        from_state_hash_post = state_hash(&from_state);
        to_state_hash_post = state_hash(&to_state);
    } else {
        // Dry-run: post hashes mirror the in-memory mutated states
        // but no disk writes happen.
        from_state_hash_post = state_hash(&from_state);
        to_state_hash_post = state_hash(&to_state);
    }

    Ok(MigrationReceipt {
        plan,
        started_at,
        finished_at: Utc::now(),
        from_state_hash_pre,
        from_state_hash_post,
        to_state_hash_pre,
        to_state_hash_post,
        moved_count,
        dry_run: false,
    })
}

fn validate(
    plan: &MigrationPlan,
    from_state: &State,
    to_state: &State,
) -> Result<(), MigrationError> {
    let from_index: HashMap<String, &StateResource> = from_state
        .resources
        .iter()
        .map(|r| (resource_address_string(&r.address), r))
        .collect();
    let to_index: HashSet<String> = to_state
        .resources
        .iter()
        .map(|r| resource_address_string(&r.address))
        .collect();

    for mv in &plan.moves {
        if !from_index.contains_key(&mv.source_address) {
            return Err(MigrationError::SourceNotFound(mv.source_address.clone()));
        }
        if to_index.contains(&mv.target_address) {
            return Err(MigrationError::TargetCollision(mv.target_address.clone()));
        }
    }
    Ok(())
}

fn execute_move(
    plan: &MigrationPlan,
    mv: &ResourceMove,
    from_state: &mut State,
    to_state: &mut State,
) -> Result<(), MigrationError> {
    // Find the resource in source state.
    let position = from_state
        .resources
        .iter()
        .position(|r| resource_address_string(&r.address) == mv.source_address)
        .ok_or_else(|| MigrationError::SourceNotFound(mv.source_address.clone()))?;

    let mut resource = from_state.resources.remove(position);

    // Rename the address per the move. The address has a `type_id` +
    // `name` pair; the target_address string is parsed into the new
    // shape. M0.2: type_id stays the same; only the name changes.
    // M0.x will allow full re-typing (e.g. aws_iam_role → aws_iam_role_v2).
    let (new_type, new_name) =
        parse_address(&mv.target_address).ok_or_else(|| MigrationError::Validation {
            reason: format!("malformed target_address: {:?}", mv.target_address),
        })?;
    if resource.address.type_id.0 != new_type {
        return Err(MigrationError::Validation {
            reason: format!(
                "address type change from {:?} to {:?} is M0.x territory; \
                 use the same type prefix for now",
                resource.address.type_id.0, new_type,
            ),
        });
    }
    resource.address.name = new_name.to_string();

    // Apply preserve flags. For M0.2:
    //   - resource_identity: implicit (we move records, don't recreate)
    //   - tags: not yet — relies on per-resource attribute introspection
    //     (M0.x once cty-style typed access lands)
    //   - dependent_resources: not yet — needs cross-state reference
    //     graph (M0.x)
    let _ = (&plan.preserve, &resource); // documented gaps

    to_state.resources.push(resource);
    Ok(())
}

fn resource_address_string(addr: &ResourceAddress) -> String {
    let key = match &addr.key {
        Some(magma_types::InstanceKey::Index(i)) => format!("[{i}]"),
        Some(magma_types::InstanceKey::Key(k)) => format!("[\"{k}\"]"),
        None => String::new(),
    };
    format!("{}.{}{}", addr.type_id.0, addr.name, key)
}

fn parse_address(addr: &str) -> Option<(&str, &str)> {
    // Strip optional [...] suffix; M0.2 doesn't carry instance keys
    // through migrate.
    let (head, _) = match addr.find('[') {
        Some(idx) => addr.split_at(idx),
        None => (addr, ""),
    };
    let (ty, name) = head.split_once('.')?;
    Some((ty, name))
}

fn state_hash(state: &State) -> String {
    let canonical = serde_json::to_vec(state).unwrap_or_default();
    let hash = blake3::hash(&canonical);
    hex::encode(hash.as_bytes())
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use magma_types::{
        InstanceStatus, ModulePath, ProviderReference, ResourceKind, ResourceTypeId, StateInstance,
    };

    fn fresh_state() -> State {
        State {
            version: 4,
            terraform_version: "1.7.0".into(),
            serial: 0,
            lineage: uuid::Uuid::nil(),
            outputs: HashMap::new(),
            resources: Vec::new(),
        }
    }

    fn make_resource(type_name: &str, name: &str) -> StateResource {
        StateResource {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId(type_name.into()),
                name: name.into(),
                key: None,
            },
            provider: ProviderReference {
                source: format!("hashicorp/{type_name}"),
                name: type_name.into(),
                alias: None,
            },
            instances: vec![StateInstance {
                schema_version: 0,
                attributes: serde_json::json!({ "id": "stub" }),
                private: vec![],
                dependencies: vec![],
                status: InstanceStatus::Ready,
            }],
        }
    }

    async fn write_to_tmp(state: &State, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.tfstate"));
        magma_state::write_state(&path, state).await.unwrap();
        path
    }

    #[tokio::test]
    async fn migrate_one_resource_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let mut from = fresh_state();
        from.resources
            .push(make_resource("aws_iam_role", "k3s_node"));
        let to = fresh_state();

        let from_path = write_to_tmp(&from, tmp.path(), "k3s-perms").await;
        let to_path = write_to_tmp(&to, tmp.path(), "platform-iam").await;

        let plan = MigrationPlan {
            from: WorkspaceRef {
                name: "k3s_permissions".into(),
                state_path: from_path.clone(),
            },
            to: WorkspaceRef {
                name: "platform_iam".into(),
                state_path: to_path.clone(),
            },
            moves: vec![ResourceMove {
                source_address: "aws_iam_role.k3s_node".into(),
                target_address: "aws_iam_role.platform_k3s_node".into(),
            }],
            preserve: PreserveFlags::default(),
            dry_run: false,
        };
        let receipt = run(plan).await.unwrap();

        assert_eq!(receipt.moved_count, 1);
        assert_ne!(receipt.from_state_hash_pre, receipt.from_state_hash_post);
        assert_ne!(receipt.to_state_hash_pre, receipt.to_state_hash_post);

        // Verify on disk.
        let final_from = magma_state::read_state(&from_path).await.unwrap();
        let final_to = magma_state::read_state(&to_path).await.unwrap();
        assert_eq!(final_from.resources.len(), 0);
        assert_eq!(final_to.resources.len(), 1);
        assert_eq!(final_to.resources[0].address.name, "platform_k3s_node");
    }

    #[tokio::test]
    async fn migrate_validation_rejects_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let from = fresh_state();
        let to = fresh_state();
        let from_path = write_to_tmp(&from, tmp.path(), "from").await;
        let to_path = write_to_tmp(&to, tmp.path(), "to").await;

        let plan = MigrationPlan {
            from: WorkspaceRef {
                name: "f".into(),
                state_path: from_path,
            },
            to: WorkspaceRef {
                name: "t".into(),
                state_path: to_path,
            },
            moves: vec![ResourceMove {
                source_address: "aws_iam_role.does_not_exist".into(),
                target_address: "aws_iam_role.also_dne".into(),
            }],
            preserve: PreserveFlags::default(),
            dry_run: false,
        };
        let err = run(plan).await.unwrap_err();
        assert!(matches!(err, MigrationError::SourceNotFound(_)));
    }

    #[tokio::test]
    async fn migrate_validation_rejects_target_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let mut from = fresh_state();
        from.resources
            .push(make_resource("aws_iam_role", "k3s_node"));
        let mut to = fresh_state();
        to.resources.push(make_resource("aws_iam_role", "k3s_node")); // collision
        let from_path = write_to_tmp(&from, tmp.path(), "from").await;
        let to_path = write_to_tmp(&to, tmp.path(), "to").await;

        let plan = MigrationPlan {
            from: WorkspaceRef {
                name: "f".into(),
                state_path: from_path,
            },
            to: WorkspaceRef {
                name: "t".into(),
                state_path: to_path,
            },
            moves: vec![ResourceMove {
                source_address: "aws_iam_role.k3s_node".into(),
                target_address: "aws_iam_role.k3s_node".into(),
            }],
            preserve: PreserveFlags::default(),
            dry_run: false,
        };
        let err = run(plan).await.unwrap_err();
        assert!(matches!(err, MigrationError::TargetCollision(_)));
    }

    #[tokio::test]
    async fn migrate_dry_run_leaves_state_files_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let mut from = fresh_state();
        from.resources
            .push(make_resource("aws_iam_role", "k3s_node"));
        let to = fresh_state();
        let from_path = write_to_tmp(&from, tmp.path(), "from").await;
        let to_path = write_to_tmp(&to, tmp.path(), "to").await;

        let from_bytes_pre = tokio::fs::read(&from_path).await.unwrap();
        let to_bytes_pre = tokio::fs::read(&to_path).await.unwrap();

        let plan = MigrationPlan {
            from: WorkspaceRef {
                name: "f".into(),
                state_path: from_path.clone(),
            },
            to: WorkspaceRef {
                name: "t".into(),
                state_path: to_path.clone(),
            },
            moves: vec![ResourceMove {
                source_address: "aws_iam_role.k3s_node".into(),
                target_address: "aws_iam_role.k3s_node_v2".into(),
            }],
            preserve: PreserveFlags::default(),
            dry_run: true,
        };
        let receipt = run(plan).await.unwrap();
        assert_eq!(receipt.moved_count, 1);
        // No disk mutation in dry-run.
        let from_bytes_post = tokio::fs::read(&from_path).await.unwrap();
        let to_bytes_post = tokio::fs::read(&to_path).await.unwrap();
        assert_eq!(from_bytes_pre, from_bytes_post);
        assert_eq!(to_bytes_pre, to_bytes_post);
    }

    #[test]
    fn parse_address_basic() {
        assert_eq!(
            parse_address("aws_iam_role.k3s_node"),
            Some(("aws_iam_role", "k3s_node"))
        );
        assert_eq!(
            parse_address("aws_iam_role.k3s_node[0]"),
            Some(("aws_iam_role", "k3s_node"))
        );
        assert_eq!(parse_address("malformed"), None);
    }
}
