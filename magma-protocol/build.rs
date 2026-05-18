//! Build script for magma-protocol.
//!
//! Compiles tfplugin5.proto + tfplugin6.proto via tonic-build when the
//! files are vendored in `proto/`. Until vendored from OpenTofu's
//! `internal/tfplugin{5,6}/`, this is a no-op and `lib.rs` exposes
//! placeholder modules so dependent crates can compile.

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=proto/");

    let proto_files = ["proto/tfplugin5.proto", "proto/tfplugin6.proto"];
    let present: Vec<&&str> = proto_files
        .iter()
        .filter(|p| Path::new(p).exists())
        .collect();

    if present.is_empty() {
        // No proto files yet — emit nothing. Will be populated in M0
        // when tfplugin5/6 are vendored from OpenTofu's internal/.
        println!(
            "cargo:warning=magma-protocol: proto files not yet vendored; \
             gRPC bindings unavailable. Vendor tfplugin5.proto + \
             tfplugin6.proto from github.com/opentofu/opentofu/internal/ \
             then rebuild."
        );
        return;
    }

    // Point PROTOC at the bundled protoc binary from protoc-bin-vendored —
    // pure-Rust build chain, no system protoc / brew / apt required.
    if std::env::var("PROTOC").is_err() {
        if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            // SAFETY: this is a Cargo build script — single-threaded
            // and the only writer to env vars; no other thread can read
            // PROTOC concurrently. tonic-build reads it on the next
            // line.
            unsafe { std::env::set_var("PROTOC", path); }
        }
    }

    // Compile the proto files to Rust gRPC client + server stubs. The
    // client side lives in `magma-plugin`; the server side is consumed
    // by `magma-test/src/bin/mock_provider.rs` (and is the integration
    // surface a future WASI provider would also use).
    let proto_paths: Vec<&str> = present.iter().map(|&&p| p).collect();
    if let Err(e) = tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&proto_paths, &["proto/"])
    {
        panic!("magma-protocol: tonic-build failed: {e}");
    }
}
