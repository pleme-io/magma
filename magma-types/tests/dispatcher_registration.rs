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

use gen_platform::{catalog, TypedDispatcherTrait};
use magma_types::{Action, ResourceKind};

#[test]
fn resource_kind_registers() {
    let entry =
        catalog::by_label("magma.resource-kind").expect("ResourceKind must register");
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
    assert_eq!(kinds, vec!["managed", "data", "output", "local", "variable"]);
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
