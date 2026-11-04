#[path = "../proto_root.rs"]
mod proto_root;

use proto_root::{PROTOS, proto_root as resolve};
use std::fs;
use std::path::{Path, PathBuf};

const MEMBER: &str = "magma-protocol";

fn fixture(name: &str, protos_under: &str, protos: &[&str]) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&root);
    let dir = root.join(protos_under);
    fs::create_dir_all(&dir).unwrap();
    for proto in protos {
        fs::write(dir.join(proto), "").unwrap();
    }
    root
}

#[test]
fn cargo_shape_resolves_under_the_member_directory() {
    let member_dir = fixture("cargo-shape", "proto", &PROTOS);
    assert_eq!(
        resolve(&member_dir, MEMBER).unwrap(),
        member_dir.join("proto")
    );
}

#[test]
fn build_rust_crate_shape_resolves_from_the_workspace_root() {
    let root = fixture("build-rust-crate-shape", "magma-protocol/proto", &PROTOS);
    assert_eq!(
        resolve(&root, MEMBER).unwrap(),
        root.join("magma-protocol/proto")
    );
}

#[test]
fn absent_protos_are_a_refusal_naming_where_it_looked() {
    let root = fixture("absent", "unrelated", &[]);
    let refusal = resolve(&root, MEMBER).unwrap_err();
    assert!(refusal.contains("tfplugin5.proto"), "{refusal}");
    assert!(
        refusal.contains(&root.join("proto").display().to_string()),
        "{refusal}"
    );
    assert!(
        refusal.contains(&root.join("magma-protocol/proto").display().to_string()),
        "{refusal}"
    );
}

#[test]
fn one_proto_of_two_is_a_refusal() {
    let root = fixture("one-of-two", "proto", &PROTOS[..1]);
    assert!(resolve(&root, MEMBER).is_err());
}

#[test]
fn the_vendored_protos_resolve_in_both_shapes() {
    let member_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = member_dir.parent().unwrap();
    let member = member_dir.file_name().unwrap().to_str().unwrap();
    assert_eq!(member, env!("CARGO_PKG_NAME"));
    let expected = member_dir.join("proto");
    assert_eq!(resolve(member_dir, member).unwrap(), expected);
    assert_eq!(resolve(workspace_root, member).unwrap(), expected);
}
