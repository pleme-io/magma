//! Integration test: spawn the mock provider binary, complete the
//! go-plugin handshake via magma-plugin's `Plugin::spawn`, assert the
//! parsed handshake line matches what the mock provider printed.
//!
//! This is the end-to-end proof for `theory/MAGMA.md` §IV.1 — the
//! load-bearing technical question (can magma actually handshake with
//! a go-plugin provider?) — using a controllable mock binary so the
//! test runs offline + deterministically.

use std::path::PathBuf;
use std::time::Duration;

use magma_plugin::{Plugin, PluginSpec};
use magma_protocol::PluginProtocol;

fn mock_provider_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mock_provider"))
}

#[tokio::test]
async fn handshake_against_mock_provider() {
    let binary = mock_provider_binary();
    assert!(
        binary.exists(),
        "mock_provider binary not built at {}",
        binary.display(),
    );

    let spec = PluginSpec {
        binary: binary.clone(),
        kill_grace: Duration::from_secs(1),
        secure: false,
        ..PluginSpec::default()
    };

    let plugin = Plugin::spawn(spec).await.expect("spawn handshake");
    let hs = plugin.handshake();

    assert_eq!(hs.core_protocol, 1, "core protocol must be 1");
    assert!(
        matches!(hs.app_protocol, PluginProtocol::V5 | PluginProtocol::V6),
        "app protocol must be 5 or 6, got {:?}",
        hs.app_protocol,
    );
    assert_eq!(hs.network, "tcp");
    assert!(hs.address.starts_with("127.0.0.1:"));
    assert_eq!(hs.proto_type, "grpc");
    assert!(
        hs.cert_pem_base64.is_some(),
        "mock provider always emits a cert field",
    );

    // Drop plugin → child should be killed within kill_grace.
    drop(plugin);
}

#[tokio::test]
async fn missing_binary_errs() {
    let spec = PluginSpec {
        binary: PathBuf::from("/nonexistent/path/zzz/no-such-provider"),
        ..PluginSpec::default()
    };
    match Plugin::spawn(spec).await {
        Err(magma_plugin::PluginError::BinaryNotFound(_)) => {}
        Err(e) => panic!("expected BinaryNotFound, got: {e:?}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}
