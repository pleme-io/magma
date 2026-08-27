//! The end-to-end claim, as an executable fact: with `random` registered
//! natively, the engine brings it up **with no provider binary anywhere on
//! disk** — no `.terraform/providers`, no `MAGMA_PROVIDER_DIR`, no
//! subprocess, no Go.
//!
//! This test lives HERE and not in `magma-apply` because it is the only
//! place that legitimately knows about both sides. `magma-apply` must not
//! depend on any particular provider, and `magma-provider-random` must not
//! depend on the engine — so the composition is exercised from a test that
//! dev-depends on both, which is also exactly how a real consumer
//! (pangea-operator, magma-cli) wires it.

use std::sync::Arc;

use magma_apply::engine::{ApplyContext, RoutingProviderFactory, dial_configured_provider};
use magma_provider_random::RandomProvider;
use magma_types::ProviderInstance;

fn instance(name: &str) -> ProviderInstance {
    ProviderInstance::default_instance(name).expect("valid provider name")
}

/// ★ THE ANTI-VACUITY HALF. The workspace must genuinely have no provider
/// binary, or the test below proves nothing.
#[tokio::test]
async fn an_unregistered_provider_still_needs_a_binary() {
    let td = tempfile::tempdir().expect("tempdir");
    let ctx = ApplyContext::new(td.path().to_path_buf()).with_provider_factory(Arc::new(
        RoutingProviderFactory::new().with_native("random", || Box::new(RandomProvider::new())),
    ));

    // `aws` is NOT registered natively, so it falls through to the
    // subprocess path — which has nothing to spawn in an empty workspace.
    let msg = match dial_configured_provider(&ctx, &instance("aws")).await {
        Ok(_) => panic!("aws is not served natively and has no binary here"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("locate provider"),
        "expected the subprocess path's locate failure, got: {msg}"
    );
}

/// The same empty workspace, the registered provider: it comes up.
#[tokio::test]
async fn random_is_served_in_process_with_no_binary_on_disk() {
    let td = tempfile::tempdir().expect("tempdir");
    let routing =
        RoutingProviderFactory::new().with_native("random", || Box::new(RandomProvider::new()));
    assert!(routing.serves_natively("random"));
    assert!(!routing.serves_natively("aws"));

    let ctx = ApplyContext::new(td.path().to_path_buf()).with_provider_factory(Arc::new(routing));

    let lp = dial_configured_provider(&ctx, &instance("random"))
        .await
        .expect("a native provider needs no binary");

    // It is genuinely the native one: the schema is ours, and the
    // transport reports no crash because there is no process to crash.
    assert!(
        lp.schema().resource("random_password").is_some(),
        "the engine must have received magma-provider-random's schema"
    );
    assert!(lp.transport().crash_summary().is_none());
    assert!(lp.transport().close_reason().is_none());
}

/// The live fleet config, driven through the ENGINE's dial path rather
/// than by calling the provider directly — so the schema round-trip and
/// the Configure step are exercised, not just the generation logic.
#[tokio::test]
async fn the_live_shaar_config_works_through_the_engine_seam() {
    let td = tempfile::tempdir().expect("tempdir");
    let ctx = ApplyContext::new(td.path().to_path_buf()).with_provider_factory(Arc::new(
        RoutingProviderFactory::new().with_native("random", || Box::new(RandomProvider::new())),
    ));
    let mut lp = dial_configured_provider(&ctx, &instance("random"))
        .await
        .expect("dials");

    let ty = lp
        .schema()
        .resource("random_password")
        .cloned()
        .expect("random_password is served");
    let cfg = magma_cty::DynamicValue::from_json(
        &serde_json::json!({ "length": 48, "special": false }),
        &ty,
    )
    .expect("encodes");
    let null = magma_cty::DynamicValue::marshal(&magma_cty::CtyValue::Null, &ty).expect("null");

    let plan = lp
        .provider_mut()
        .plan_resource_change("random_password", &null, &cfg, &cfg)
        .await
        .expect("plans");
    let state = lp
        .provider_mut()
        .apply_resource_change("random_password", &null, &plan.state, &cfg)
        .await
        .expect("applies");

    let v = state.to_value(&ty).expect("decodes");
    let magma_cty::CtyValue::Object(m) = v else {
        panic!("state must be an object")
    };
    let Some(magma_cty::CtyValue::String(pw)) = m.get("result") else {
        panic!("a password must have been generated")
    };
    assert_eq!(pw.chars().count(), 48);
    assert!(pw.chars().all(char::is_alphanumeric), "special=false");
}
