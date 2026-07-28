//! The provider-native **import-id catalog** — the one place magma knows how
//! to name an already-existing resource so it can be adopted instead of
//! re-created.
//!
//! ## Why this is a catalog and not a `match`
//!
//! An import id is a *function of the resource's own configuration*: GitHub's
//! importer keys a label on `<repo-name>:<label-name>`, a branch protection on
//! `<repo-name>:<pattern>`, a repo-scoped singleton on `<repo-name>`. Nothing
//! about that is discoverable at runtime, so it is authored — and the moment it
//! is authored in two places it drifts. It already had: `pangea-operator`'s
//! `controller/import.rs::bundled_natural_ids` (proactive, pre-plan) and
//! magma's `engine::natural_import_id` (reactive, mid-apply) each carried their
//! own copy of the same table, and they disagreed on the load-bearing detail
//! (see [`IdPart::ParentName`]). This module is that table, once, typed, and
//! `pub` precisely so the operator can delete its copy and call [`derive`].
//!
//! ## The bug this shape removes
//!
//! A component of a composite id is very often a **reference to a parent**
//! (`${github_repository.cse_lint.node_id}`), and the importer wants the
//! parent's **name** regardless of which attribute the reference happens to
//! project. Treating such a component as a plain attribute — which is what a
//! bare `after.get("repository_id")` does — yields either the raw `${…}`
//! literal (parent unresolved) or a GraphQL node id like `R_kgDOTdnhyQ`
//! (parent resolved). Both are handed to an importer that will do
//! `getRepositoryID(<that string>)` and fail, so a branch protection that
//! already exists on GitHub can never be adopted and is re-planned as a create
//! forever. [`IdPart::ParentName`] is the type that makes that mistake
//! unstateable: a parent component is *declared* as one and is always resolved
//! to a name.
//!
//! ## Honesty about the answer
//!
//! [`derive`] never guesses silently. Every returned id carries a
//! [`Confidence`], and a catalog rule whose parts cannot be completed returns
//! `None` rather than falling through to a plausible-looking wrong id — a wrong
//! import id is not a failed adoption, it is an adoption of *something else*.

use std::collections::HashMap;

use magma_types::ResourceChange;
use serde_json::Value;

/// One component of a composite import id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdPart {
    /// The resource's own attribute, taken as a literal value.
    Attr(&'static str),
    /// The resource's attribute holds a **reference to a parent resource**, and
    /// the provider's importer keys on that parent's `name` — whatever
    /// attribute the reference itself projects.
    ///
    /// `github_branch_protection.repository_id` is authored as
    /// `${github_repository.<n>.node_id}` yet imports by `<repo-name>:<pattern>`;
    /// `github_issue_label.repository` is authored as
    /// `${github_repository.<n>.name}` and imports by `<repo-name>:<label>`.
    /// Both are the same kind of component, and this variant is what says so.
    ParentName(&'static str),
}

/// How an import id was arrived at. Carried so a log line (and a future
/// adoption gate) can tell a derived id from a guessed one — never rounded up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Every component came from the catalog rule and resolved cleanly.
    Catalog,
    /// A catalog component fell back to the parent's *resource* name because
    /// the parent is not in state yet. Sound only under the org-posture
    /// convention `resource-name == repo-name`, which underscore-sanitized
    /// resource names (`tag_forge` vs `tag-forge`) break.
    CatalogWithGuessedParent,
    /// No catalog rule; the type keys import on its own `name` attribute.
    NameAttribute,
    /// No catalog rule and no `name` attribute — the resource's *address* name
    /// is the last resort. A guess, and labelled as one.
    AddressName,
}

impl Confidence {
    /// Is this id derived from real data, as opposed to a naming convention?
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Catalog | Self::NameAttribute)
    }
}

/// A provider-native import id plus how much we trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportId {
    pub id: String,
    pub confidence: Confidence,
}

/// One catalog row: a resource type and the components of its import id.
#[derive(Debug, Clone, Copy)]
pub struct NaturalIdRule {
    pub resource_type: &'static str,
    pub parts: &'static [IdPart],
    pub sep: char,
}

/// **The** table. A new adoptable composite-keyed type is a row here, in one
/// repo, consumed by both the reactive (magma) and proactive (operator)
/// adoption paths.
pub const CATALOG: &[NaturalIdRule] = &[
    NaturalIdRule {
        resource_type: "github_branch_protection",
        parts: &[IdPart::ParentName("repository_id"), IdPart::Attr("pattern")],
        sep: ':',
    },
    NaturalIdRule {
        resource_type: "github_actions_secret",
        parts: &[
            IdPart::ParentName("repository"),
            IdPart::Attr("secret_name"),
        ],
        sep: ':',
    },
    NaturalIdRule {
        resource_type: "github_actions_variable",
        parts: &[
            IdPart::ParentName("repository"),
            IdPart::Attr("variable_name"),
        ],
        sep: ':',
    },
    NaturalIdRule {
        resource_type: "github_repository_environment",
        parts: &[IdPart::ParentName("repository"), IdPart::Attr("environment")],
        sep: ':',
    },
    NaturalIdRule {
        resource_type: "github_issue_label",
        parts: &[IdPart::ParentName("repository"), IdPart::Attr("name")],
        sep: ':',
    },
    // Repo-scoped singletons: the import id IS the parent repo's name.
    NaturalIdRule {
        resource_type: "github_repository_topics",
        parts: &[IdPart::ParentName("repository")],
        sep: ':',
    },
    NaturalIdRule {
        resource_type: "github_repository_collaborators",
        parts: &[IdPart::ParentName("repository")],
        sep: ':',
    },
    NaturalIdRule {
        resource_type: "github_actions_repository_permissions",
        parts: &[IdPart::ParentName("repository")],
        sep: ':',
    },
];

/// The catalog row for a resource type, if any.
#[must_use]
pub fn rule_for(resource_type: &str) -> Option<&'static NaturalIdRule> {
    CATALOG.iter().find(|r| r.resource_type == resource_type)
}

/// Split `${type.name.attr}` into `(type, name)`. Returns `None` for anything
/// that is not exactly one whole reference (an interpolated string, a literal,
/// a `data.*` source).
fn ref_parent(s: &str) -> Option<(&str, &str)> {
    let inner = s.trim().strip_prefix("${")?.strip_suffix('}')?;
    if inner.contains("${") {
        return None;
    }
    let mut segs = inner.split('.');
    let ty = segs.next()?;
    let name = segs.next()?;
    if ty.is_empty() || ty == "data" {
        return None;
    }
    let name = name.split('[').next().unwrap_or(name);
    (!name.is_empty()).then_some((ty, name))
}

/// Look up `state_map[type][name].name` — the parent's REAL name, as the
/// provider knows it.
fn parent_name_from_state(
    state_map: &HashMap<String, Value>,
    ty: &str,
    name: &str,
) -> Option<String> {
    state_map
        .get(ty)?
        .get(name)?
        .get("name")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}

fn attr_str<'a>(v: Option<&'a Value>, k: &str) -> Option<&'a str> {
    v.and_then(|a| a.get(k)).and_then(Value::as_str)
}

/// Derive a resource's provider-native import id.
///
/// * `change` — the **raw**, un-substituted change. Reference structure must
///   still be intact: it is the only thing that says *which* parent a
///   [`IdPart::ParentName`] component points at.
/// * `resolved_after` — the same `after` object post reference-substitution, if
///   available. Preferred for [`IdPart::Attr`] components (a `pattern` may
///   itself be interpolated).
/// * `state_map` — the apply engine's `type → {name → attributes}` resolution
///   map, used to turn a parent reference into the parent's real name.
///
/// Returns `None` when a catalog rule exists but a component is absent — a
/// deliberate refusal, because the alternative (fall through to the address
/// name) produces a *syntactically valid id for a different resource*.
#[must_use]
pub fn derive(
    change: &ResourceChange,
    resolved_after: Option<&Value>,
    state_map: &HashMap<String, Value>,
) -> Option<ImportId> {
    let raw = change.after.as_ref();
    if let Some(rule) = rule_for(change.address.type_id.0.as_str()) {
        let mut id = String::new();
        let mut confidence = Confidence::Catalog;
        for (i, part) in rule.parts.iter().enumerate() {
            let component = match *part {
                IdPart::Attr(k) => attr_str(resolved_after, k)
                    .or_else(|| attr_str(raw, k))
                    .map(std::string::ToString::to_string)?,
                IdPart::ParentName(k) => {
                    // The raw value carries the reference; the resolved one
                    // carries whatever the reference projected (a node id, a
                    // name, or the syntactic fallback). Only the raw value can
                    // tell us the parent's identity.
                    let rawv = attr_str(raw, k);
                    match rawv.and_then(ref_parent) {
                        Some((ty, name)) => match parent_name_from_state(state_map, ty, name) {
                            Some(real) => real,
                            None => {
                                // Parent not in state (or its name is null):
                                // fall back to the resource name under the
                                // org-posture convention, and SAY it is a guess.
                                confidence = Confidence::CatalogWithGuessedParent;
                                name.to_string()
                            }
                        },
                        // Not a reference: a literal repo name in config.
                        None => attr_str(resolved_after, k)
                            .or(rawv)
                            .map(std::string::ToString::to_string)?,
                    }
                }
            };
            if i > 0 {
                id.push(rule.sep);
            }
            id.push_str(&component);
        }
        return Some(ImportId { id, confidence });
    }

    // No catalog row: name-keyed provider (github_repository's id IS its name).
    if let Some(n) = attr_str(resolved_after, "name").or_else(|| attr_str(raw, "name")) {
        return Some(ImportId {
            id: n.to_string(),
            confidence: Confidence::NameAttribute,
        });
    }
    Some(ImportId {
        id: change.address.name.clone(),
        confidence: Confidence::AddressName,
    })
}

/// The attributes whose PLANNED value the imported resource must agree with.
///
/// A successful `ImportResourceState` answers *"something exists under this
/// id"* — never *"this is the resource you planned"*. For a catalog type those
/// are the rule's own [`IdPart::Attr`] components (a label's `name`, a branch
/// protection's `pattern`); [`IdPart::ParentName`] components are deliberately
/// excluded because the imported object projects the parent however the
/// provider likes (a node id, a full name) and disagreeing there is expected,
/// not evidence of a wrong resource. For a name-keyed type it is `name`.
#[must_use]
pub fn identity_attrs(resource_type: &str) -> Vec<&'static str> {
    match rule_for(resource_type) {
        Some(rule) => rule
            .parts
            .iter()
            .filter_map(|p| match *p {
                IdPart::Attr(k) => Some(k),
                IdPart::ParentName(_) => None,
            })
            .collect(),
        None => vec!["name"],
    }
}

/// An imported resource that is not the one that was planned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMismatch {
    pub attr: &'static str,
    pub planned: String,
    pub imported: String,
}

/// Confirm an adopted object is the one the change planned.
///
/// Compares only where BOTH sides carry a string value — an absent or null
/// attribute on either side is silence, not disagreement, and this function
/// never invents a mismatch out of silence (that would refuse legitimate
/// adoptions of providers whose import stub is sparse). What it does catch is
/// the case the whole adoption path is otherwise blind to: the provider found
/// a real resource under the derived id and it belongs to something else.
///
/// # Errors
/// Returns the first attribute whose planned and imported values disagree.
pub fn verify_identity(
    change: &ResourceChange,
    resolved_after: Option<&Value>,
    imported: &Value,
) -> Result<(), IdentityMismatch> {
    let raw = change.after.as_ref();
    for attr in identity_attrs(change.address.type_id.0.as_str()) {
        let Some(planned) = attr_str(resolved_after, attr).or_else(|| attr_str(raw, attr)) else {
            continue;
        };
        let Some(actual) = imported.get(attr).and_then(Value::as_str) else {
            continue;
        };
        if planned != actual {
            return Err(IdentityMismatch {
                attr,
                planned: planned.to_string(),
                imported: actual.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magma_types::{
        Action, ModulePath, ResourceAddress, ResourceKind, ResourceTypeId,
    };

    fn mk(ty: &str, name: &str, after: Value) -> ResourceChange {
        ResourceChange {
            address: ResourceAddress {
                module: ModulePath::root(),
                kind: ResourceKind::Managed,
                type_id: ResourceTypeId(ty.into()),
                name: name.into(),
                key: None,
            },
            action: Action::Create,
            before: None,
            after: Some(after),
            reasons: vec![],
        }
    }

    fn state_with_repo(resource_name: &str, real_name: &str) -> HashMap<String, Value> {
        let mut sm = HashMap::new();
        sm.insert(
            "github_repository".to_string(),
            serde_json::json!({ resource_name: { "name": real_name, "node_id": "R_kgDOabc" } }),
        );
        sm
    }

    // ── CATALOG REFLECTION ────────────────────────────────────────────────

    #[test]
    fn catalog_rows_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for r in CATALOG {
            assert!(
                seen.insert(r.resource_type),
                "duplicate catalog row for {}",
                r.resource_type
            );
            assert!(
                !r.parts.is_empty(),
                "{} has an empty id template",
                r.resource_type
            );
        }
    }

    /// The forcing function: one row here per row in [`CATALOG`]. A new
    /// adoptable type that lands without an exercised expectation fails the
    /// build rather than shipping an unproven import id.
    #[test]
    fn every_catalog_row_is_exercised() {
        struct Row {
            ty: &'static str,
            after: fn() -> Value,
            expect: &'static str,
        }
        let matrix: &[Row] = &[
            Row {
                ty: "github_branch_protection",
                after: || {
                    serde_json::json!({
                        "repository_id": "${github_repository.tag_forge.node_id}",
                        "pattern": "main"
                    })
                },
                expect: "tag-forge:main",
            },
            Row {
                ty: "github_actions_secret",
                after: || {
                    serde_json::json!({
                        "repository": "${github_repository.tag_forge.name}",
                        "secret_name": "TOKEN"
                    })
                },
                expect: "tag-forge:TOKEN",
            },
            Row {
                ty: "github_actions_variable",
                after: || {
                    serde_json::json!({
                        "repository": "${github_repository.tag_forge.name}",
                        "variable_name": "LEVEL"
                    })
                },
                expect: "tag-forge:LEVEL",
            },
            Row {
                ty: "github_repository_environment",
                after: || {
                    serde_json::json!({
                        "repository": "${github_repository.tag_forge.name}",
                        "environment": "prod"
                    })
                },
                expect: "tag-forge:prod",
            },
            Row {
                ty: "github_issue_label",
                after: || {
                    serde_json::json!({
                        "repository": "${github_repository.tag_forge.name}",
                        "name": "bug"
                    })
                },
                expect: "tag-forge:bug",
            },
            Row {
                ty: "github_repository_topics",
                after: || {
                    serde_json::json!({
                        "repository": "${github_repository.tag_forge.name}",
                        "topics": ["rust"]
                    })
                },
                expect: "tag-forge",
            },
            Row {
                ty: "github_repository_collaborators",
                after: || {
                    serde_json::json!({ "repository": "${github_repository.tag_forge.name}" })
                },
                expect: "tag-forge",
            },
            Row {
                ty: "github_actions_repository_permissions",
                after: || {
                    serde_json::json!({
                        "repository": "${github_repository.tag_forge.name}",
                        "allowed_actions": "all"
                    })
                },
                expect: "tag-forge",
            },
        ];
        assert_eq!(
            matrix.len(),
            CATALOG.len(),
            "every CATALOG row needs an exercised expectation"
        );
        let sm = state_with_repo("tag_forge", "tag-forge");
        let mut failures = Vec::new();
        for row in matrix {
            assert!(
                rule_for(row.ty).is_some(),
                "matrix row {} is not in CATALOG",
                row.ty
            );
            let after = (row.after)();
            let got = derive(&mk(row.ty, "x", after.clone()), Some(&after), &sm);
            match got {
                Some(ImportId { id, confidence }) if id == row.expect => {
                    assert_eq!(confidence, Confidence::Catalog, "{}", row.ty);
                }
                other => failures.push((row.ty, row.expect, other)),
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    // ── the defect this module exists for ─────────────────────────────────

    /// A branch protection's `repository_id` is a `${…node_id}` reference. The
    /// importer keys on the repository NAME. Before `ParentName`, the id was
    /// the node id (parent in state) or the raw `${…}` literal (parent absent)
    /// — both un-importable, which is why five branch protections that already
    /// exist on GitHub re-planned as creates every cycle.
    #[test]
    fn branch_protection_imports_by_repo_name_never_by_node_id() {
        let after = serde_json::json!({
            "repository_id": "${github_repository.cse_lint.node_id}",
            "pattern": "main"
        });
        // Post-substitution the field holds the node id — the value that used
        // to become the import id.
        let resolved = serde_json::json!({ "repository_id": "R_kgDOTdnhyQ", "pattern": "main" });
        let sm = state_with_repo("cse_lint", "cse-lint");
        let got = derive(
            &mk("github_branch_protection", "cse_lint_main", after),
            Some(&resolved),
            &sm,
        )
        .expect("derivable");
        assert_eq!(got.id, "cse-lint:main");
        assert!(!got.id.contains("R_kgDO"), "node id leaked into import id");
        assert!(!got.id.contains("${"), "raw reference leaked into import id");
    }

    /// Underscore-sanitized resource names are NOT repo names. Resolving the
    /// parent through state gets the real one; the syntactic fallback cannot.
    #[test]
    fn hyphenated_repo_name_comes_from_state_not_from_the_resource_name() {
        let after = serde_json::json!({
            "repository": "${github_repository.caixa_tlisp_handoff.name}",
            "name": "bug"
        });
        let sm = state_with_repo("caixa_tlisp_handoff", "caixa-tlisp-handoff");
        let got = derive(&mk("github_issue_label", "l", after), None, &sm).expect("derivable");
        assert_eq!(got.id, "caixa-tlisp-handoff:bug");
        assert_eq!(got.confidence, Confidence::Catalog);
    }

    /// Parent absent from state: still derive something (the convention), but
    /// never claim it is exact.
    #[test]
    fn an_absent_parent_downgrades_confidence_instead_of_pretending() {
        let after = serde_json::json!({
            "repository": "${github_repository.tag_forge.name}",
            "name": "bug"
        });
        let got = derive(
            &mk("github_issue_label", "l", after),
            None,
            &HashMap::new(),
        )
        .expect("derivable");
        assert_eq!(got.id, "tag_forge:bug");
        assert_eq!(got.confidence, Confidence::CatalogWithGuessedParent);
        assert!(!got.confidence.is_exact());
    }

    /// A literal (non-reference) parent value passes straight through.
    #[test]
    fn a_literal_parent_value_is_used_verbatim() {
        let after = serde_json::json!({ "repository": "breathe", "name": "bug" });
        let got = derive(&mk("github_issue_label", "l", after.clone()), Some(&after), &HashMap::new())
            .expect("derivable");
        assert_eq!(got.id, "breathe:bug");
        assert_eq!(got.confidence, Confidence::Catalog);
    }

    /// A catalog rule with a missing component REFUSES rather than falling
    /// through to the address name — a wrong import id adopts the wrong
    /// resource, which is worse than not adopting.
    #[test]
    fn an_incomplete_catalog_rule_refuses_instead_of_guessing_an_address_name() {
        let after = serde_json::json!({ "repository_id": "${github_repository.x.node_id}" });
        assert_eq!(
            derive(
                &mk("github_branch_protection", "x_main", after),
                None,
                &state_with_repo("x", "x")
            ),
            None
        );
    }

    #[test]
    fn name_keyed_types_are_unchanged() {
        let after = serde_json::json!({ "name": "breathe" });
        let got = derive(&mk("github_repository", "breathe", after.clone()), Some(&after), &HashMap::new())
            .expect("derivable");
        assert_eq!(got.id, "breathe");
        assert_eq!(got.confidence, Confidence::NameAttribute);

        let got = derive(
            &mk("some_other_type", "thing", serde_json::json!({ "x": 1 })),
            None,
            &HashMap::new(),
        )
        .expect("derivable");
        assert_eq!(got.id, "thing");
        assert_eq!(got.confidence, Confidence::AddressName);
    }

    // ── The confidence gate + the identity gate ───────────────────────────

    /// `is_exact` is the ONE thing standing between a convention-guessed id and
    /// `ImportResourceState`. It was computed and then only logged, which made
    /// it dead code; `engine::resolve_import_id` now refuses on it. Pin the
    /// partition so a future arm cannot be added on the trusted side silently.
    #[test]
    fn only_fully_resolved_confidences_are_exact() {
        assert!(Confidence::Catalog.is_exact());
        assert!(Confidence::NameAttribute.is_exact());
        assert!(
            !Confidence::CatalogWithGuessedParent.is_exact(),
            "a parent guessed from the resource-name convention is exactly the \
             case that produced `tag_forge:bug` for a repo really named \
             `tag-forge` — it must not reach the importer"
        );
        assert!(!Confidence::AddressName.is_exact());
    }

    /// The guessed-parent arm is REACHABLE, not theoretical: an empty
    /// resolution map (a state-less caller, or a parent not yet applied) sends
    /// every reference-keyed catalog type through it.
    #[test]
    fn an_absent_parent_downgrades_confidence_rather_than_silently_guessing() {
        let after = serde_json::json!({
            "repository": "${github_repository.tag_forge.name}",
            "name": "bug",
        });
        let got = derive(
            &mk("github_issue_label", "tag_forge_label_bug", after),
            None,
            &HashMap::new(),
        )
        .expect("derivable");
        assert_eq!(got.id, "tag_forge:bug");
        assert_eq!(
            got.confidence,
            Confidence::CatalogWithGuessedParent,
            "the real repo is `tag-forge`; this id names a different one"
        );
    }

    /// Only the rule's own `Attr` components are identity — a `ParentName`
    /// component is projected however the provider likes and disagreeing there
    /// is expected, not evidence of a wrong resource.
    #[test]
    fn identity_attrs_exclude_parent_components() {
        assert_eq!(identity_attrs("github_issue_label"), vec!["name"]);
        assert_eq!(identity_attrs("github_branch_protection"), vec!["pattern"]);
        assert!(identity_attrs("github_repository_topics").is_empty());
        assert_eq!(identity_attrs("github_repository"), vec!["name"]);
    }

    #[test]
    fn a_mismatched_identity_attribute_is_a_refusal() {
        let after = serde_json::json!({
            "repository": "${github_repository.banken.name}",
            "name": "bug",
        });
        let change = mk("github_issue_label", "banken_label_bug", after.clone());

        let imported = serde_json::json!({ "name": "bug", "repository": "banken" });
        assert_eq!(verify_identity(&change, Some(&after), &imported), Ok(()));

        let stranger = serde_json::json!({ "name": "enhancement", "repository": "banken" });
        assert_eq!(
            verify_identity(&change, Some(&after), &stranger),
            Err(IdentityMismatch {
                attr: "name",
                planned: "bug".into(),
                imported: "enhancement".into(),
            })
        );
    }

    /// Silence is not disagreement. A sparse import stub must not be read as a
    /// wrong resource — that would refuse legitimate adoptions of every
    /// provider whose importer returns only `id`.
    #[test]
    fn an_absent_attribute_on_either_side_is_not_a_mismatch() {
        let after = serde_json::json!({ "name": "breathe" });
        let change = mk("github_repository", "breathe", after.clone());
        assert_eq!(
            verify_identity(&change, Some(&after), &serde_json::json!({ "id": "breathe" })),
            Ok(())
        );
        assert_eq!(
            verify_identity(
                &change,
                Some(&after),
                &serde_json::json!({ "name": serde_json::Value::Null })
            ),
            Ok(())
        );
    }
}
