//! Build script for magma-protocol.
//!
//! Compiles the vendored tfplugin5.proto + tfplugin6.proto via tonic-build.

mod proto_root;

use std::path::Path;

/// First `protoc` found on `PATH`, if any.
///
/// Deliberately hand-rolled rather than pulling in `which`: this is a build
/// dependency, and the search is four lines.
fn protoc_on_path() -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("protoc"))
        .find(|candidate| candidate.is_file())
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let member = std::env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME");
    let root = proto_root::proto_root(Path::new(&manifest_dir), &member)
        .unwrap_or_else(|refusal| panic!("magma-protocol: {refusal}"));
    println!("cargo:rerun-if-changed={}", root.display());

    // ── PROTOC RESOLUTION: PATH FIRST, VENDORED ONLY AS A FALLBACK ────────
    // A `protoc` on PATH wins. Under Nix that is `pkgs.protobuf`, supplied as a
    // nativeBuildInput, and it is the only form that works there:
    // protoc-bin-vendored locates its bundled binary through a path baked in at
    // ITS OWN compile time, which does not survive past its own ephemeral build
    // sandbox. Called from a DIFFERENT crate's build script — a separate
    // derivation — it always reports the binary as missing.
    //
    // And it reports that by PANICKING inside `protoc_bin_path()`, not by
    // returning `Err`, so the `if let Ok(...)` below cannot contain it:
    //
    //   thread 'main' panicked at src/lib.rs:20:5:
    //   internal: protoc not found /build/protoc-bin-vendored-linux-x86_64-3.2.0/bin/protoc
    //
    // Trying PATH first means that call is never reached in a Nix build, while
    // a developer machine with no protoc installed keeps the vendored path and
    // the pure-Rust, no-apt/brew property this crate was written for.
    //
    // Same defect and same remedy as pleme-io/vigy's `vigy-rpc`, which is
    // already registered in gen's crate-quirk registry for exactly this.
    if std::env::var("PROTOC").is_err() {
        if let Some(path) = protoc_on_path() {
            // SAFETY: as below — single-threaded Cargo build script.
            unsafe {
                std::env::set_var("PROTOC", path);
            }
        } else if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            // SAFETY: this is a Cargo build script — single-threaded
            // and the only writer to env vars; no other thread can read
            // PROTOC concurrently. tonic-build reads it on the next
            // line.
            unsafe {
                std::env::set_var("PROTOC", path);
            }
        }
    }

    // Compile the proto files to Rust gRPC client + server stubs. The
    // client side lives in `magma-plugin`; the server side is consumed
    // by `magma-test/src/bin/mock_provider.rs` (and is the integration
    // surface a future WASI provider would also use).
    let proto_paths = proto_root::PROTOS.map(|proto| root.join(proto));
    if let Err(e) = tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_paths, &[&root])
    {
        panic!("magma-protocol: tonic-build failed: {e}");
    }
}
