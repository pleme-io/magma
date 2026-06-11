//! Verify magma-types registers ResourceKind + Action into the
//! fleet-wide DispatcherCatalog. magma is the IaC executor (the
//! Rust-native OpenTofu replacement); seventh consumer class
//! adopting gen-platform's typed-dispatcher catamorphism.
//!
//! NOTE on the kind tags: magma-types uses `rename_all =
//! "snake_case"` for the wire format. The TypedDispatcher derive
//! always emits kebab-case for the reflection — this is the
//! canonical catalog form (matches the rest of the catalog).
//! Consumers needing to dispatch against serde-serialized magma
//! values handle that via magma's existing serde plumbing; the
//! catalog reflection is for inventory + discovery.

use gen_platform::{TypedDispatcherTrait, catalog};
use magma_types::{Action, ResourceKind};

#[test]
fn resource_kind_registers() {
    let entry = catalog::by_label("magma.resource-kind").expect("ResourceKind must register");
    assert_eq!((entry.variant_count)(), 5);
}

#[test]
fn action_registers() {
    let entry = catalog::by_label("magma.action").expect("Action must register");
    assert_eq!((entry.variant_count)(), 9);
}

#[test]
fn resource_kind_variants() {
    let kinds = ResourceKind::variant_kinds();
    assert_eq!(
        kinds,
        vec!["managed", "data", "output", "local", "variable"]
    );
}

#[test]
fn action_variants_kebab() {
    let kinds = Action::variant_kinds();
    assert_eq!(
        kinds,
        vec![
            "no-op",
            "create",
            "read",
            "update",
            "replace",
            "delete",
            "forget",
            "create-then-delete",
            "delete-then-create"
        ]
    );
}

#[test]
fn action_discriminant_snake_case() {
    // discriminant() is configured to emit snake_case matching the
    // serde wire format, even though variant_kinds() (TypedDispatcher)
    // emits the canonical kebab form.
    assert_eq!(Action::NoOp.discriminant(), "no_op");
    assert_eq!(
        Action::CreateThenDelete.discriminant(),
        "create_then_delete"
    );
    assert_eq!(
        Action::DeleteThenCreate.discriminant(),
        "delete_then_create"
    );
    assert_eq!(Action::Create.discriminant(), "create");
}

#[test]
fn action_round_trip_through_serde_wire_format() {
    use std::str::FromStr;
    for variant in [
        Action::NoOp,
        Action::Create,
        Action::Read,
        Action::Update,
        Action::Replace,
        Action::Delete,
        Action::Forget,
        Action::CreateThenDelete,
        Action::DeleteThenCreate,
    ] {
        let kind = variant.discriminant(); // snake_case
        let parsed = Action::from_str(kind)
            .unwrap_or_else(|_| panic!("Action::from_str must accept {kind}"));
        assert_eq!(parsed.discriminant(), variant.discriminant());

        // Also matches serde wire format — round-trip JSON.
        let json = serde_json::to_string(&variant).unwrap();
        let back: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(back.discriminant(), variant.discriminant());
    }
}

#[test]
fn resource_kind_round_trip() {
    use std::str::FromStr;
    for variant in [
        ResourceKind::Managed,
        ResourceKind::Data,
        ResourceKind::Output,
        ResourceKind::Local,
        ResourceKind::Variable,
    ] {
        let kind = variant.discriminant();
        let parsed = ResourceKind::from_str(kind)
            .unwrap_or_else(|_| panic!("ResourceKind::from_str must accept {kind}"));
        assert_eq!(parsed.discriminant(), variant.discriminant());
    }
}

#[test]
fn action_predicates() {
    let create = Action::Create;
    assert!(create.is_create());
    assert!(!create.is_delete());
    assert!(!create.is_no_op());

    let no_op = Action::NoOp;
    assert!(no_op.is_no_op());
    assert!(!no_op.is_create());
}

#[test]
fn action_display_delegates_to_discriminant() {
    assert_eq!(Action::Create.to_string(), "create");
    assert_eq!(Action::CreateThenDelete.to_string(), "create_then_delete");
}
