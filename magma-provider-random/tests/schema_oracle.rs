//! ★ THE ORACLE for the native `random` provider's SCHEMA.
//!
//! `magma-provider-random`'s central compatibility claim is that its schema
//! declares upstream's full attribute set, so state written by
//! terraform-provider-random still decodes and a provider swap is a no-op
//! rather than a state migration.
//!
//! That claim was written from upstream's documentation. This test checks
//! it against the actual Go binary: spawn it, ask it for its real schema
//! over tfplugin, and diff attribute-by-attribute.
//!
//! ── WHY A SCHEMA ORACLE AND NOT A VALUE ORACLE ───────────────────────
//! `random`'s outputs are random by design, so it can never be a
//! byte-differential (the value law is idempotence — see the unit tests).
//! But the SCHEMA is fully deterministic and is the half that silently
//! corrupts: a missing attribute does not fail loudly, it fails when some
//! resource created by the Go provider is next decoded, months later.
//!
//! ── HOW TO RUN IT ────────────────────────────────────────────────────
//! Gated on an env var so CI stays green without a Go binary — the same
//! shape `magma-provider-registry`'s mirror probe uses.
//!
//! ```text
//! P=$(nix build --no-link --print-out-paths 'nixpkgs#terraform-providers.hashicorp_random')
//! MAGMA_RANDOM_GO_BINARY=$(find "$P" -type f | head -1) \
//!   cargo test -p magma-provider-random --test schema_oracle -- --nocapture
//! ```

use std::collections::BTreeSet;

use magma_cty::CtyType;
use magma_plugin::{Plugin, PluginSpec, provider::ProviderConn};
use magma_provider_api::Provider;
use magma_provider_random::RandomProvider;

fn attrs(t: &CtyType) -> BTreeSet<String> {
    match t {
        CtyType::Object(m) => m.keys().cloned().collect(),
        _ => BTreeSet::new(),
    }
}

#[tokio::test]
async fn the_native_schema_matches_the_real_go_provider() {
    let Ok(binary) = std::env::var("MAGMA_RANDOM_GO_BINARY") else {
        eprintln!("MAGMA_RANDOM_GO_BINARY unset — skipping the Go schema oracle");
        return;
    };

    let mut plugin = Plugin::spawn(PluginSpec {
        binary: binary.into(),
        ..Default::default()
    })
    .await
    .expect("the Go provider must spawn");
    let protocol = plugin.handshake().app_protocol;
    let channel = plugin.dial().await.expect("dial").clone();
    let mut go = ProviderConn::new(channel, protocol);
    let go_schema = ProviderConn::get_schema(&mut go)
        .await
        .expect("the Go provider must answer GetProviderSchema");

    let ours = RandomProvider::new()
        .get_schema()
        .await
        .expect("native schema");

    // Types upstream serves that we do not. Reported, never asserted away:
    // the point is to know the gap, and `unsupported()` already makes each
    // one a loud refusal rather than a silent no-op.
    let go_types: BTreeSet<&String> = go_schema.resources.keys().collect();
    let our_types: BTreeSet<&String> = ours.resources.keys().collect();
    let missing: Vec<&&String> = go_types.difference(&our_types).collect();
    eprintln!(
        "upstream serves {} types; we serve {}",
        go_types.len(),
        our_types.len()
    );
    eprintln!("NOT implemented natively (refused loudly at runtime): {missing:?}");

    // Anything we claim to serve must not be invented.
    let extra: Vec<&&String> = our_types.difference(&go_types).collect();
    assert!(
        extra.is_empty(),
        "we declare resource types upstream does not have: {extra:?}"
    );

    // ★ THE ACTUAL CLAIM: for every type we serve, our attribute set must
    // match upstream's EXACTLY. A missing attribute breaks decoding of
    // state the Go provider wrote; an extra one breaks encoding against
    // upstream's type if the provider is ever swapped back.
    let mut problems: Vec<String> = Vec::new();
    for t in &our_types {
        let (Some(go_ty), Some(our_ty)) = (go_schema.resources.get(*t), ours.resources.get(*t))
        else {
            continue;
        };
        let (g, o) = (attrs(go_ty), attrs(our_ty));
        let missing: Vec<&String> = g.difference(&o).collect();
        let extra: Vec<&String> = o.difference(&g).collect();
        if !missing.is_empty() || !extra.is_empty() {
            problems.push(format!(
                "{t}: missing-from-ours={missing:?} not-in-upstream={extra:?}"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "native schema diverges from the real Go provider — state written by \
         terraform-provider-random would not decode:\n  {}",
        problems.join("\n  ")
    );

    // Schema VERSIONS decide whether the engine demands an
    // UpgradeResourceState. Declaring the wrong one is silent until a
    // resource created under the other version is next read.
    let mut version_problems: Vec<String> = Vec::new();
    for t in &our_types {
        let g = go_schema.resource_version(t);
        let o = ours.resource_version(t);
        if g != o {
            version_problems.push(format!("{t}: upstream={g} ours={o}"));
        }
    }
    assert!(
        version_problems.is_empty(),
        "schema version mismatch — the engine's upgrade decision would be \
         wrong:\n  {}",
        version_problems.join("\n  ")
    );

    eprintln!("SCHEMA ORACLE GREEN for {} shared types", our_types.len());
}
