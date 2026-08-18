//! Dump a REAL provider's schema in `terraform providers schema -json` shape,
//! without terraform or tofu.
//!
//! This is the input format `lava-forge` consumes. Producing it natively is the
//! missing link in the lava pipeline: lava-forge's own README names
//! `terraform providers schema -json` as its upstream, while the fleet bans
//! shelling out to tofu — so today a vendor's `schema.json` has no
//! doctrine-clean way to be produced. magma already speaks the plugin protocol,
//! so it can.

use std::path::PathBuf;
use std::time::Duration;

use magma_plugin::{Plugin, PluginSpec};
use magma_protocol::tfplugin5;
use magma_protocol::tfplugin5::provider_client::ProviderClient;
use serde_json::{Map, Value, json};

/// Convert one protocol `Block` into the tofu-JSON block shape.
fn block_to_json(b: &tfplugin5::schema::Block, version: i64) -> Value {
    let mut attributes = Map::new();
    for a in &b.attributes {
        // `Attribute.type` is JSON-encoded cty: `"string"`, `["list","string"]`,
        // `["object",{...}]`. Pass it through verbatim rather than re-deriving
        // it — lava-forge's `AttributeType` is untagged and accepts both arms.
        let ty: Value = serde_json::from_slice(&a.r#type).unwrap_or_else(|_| json!("string"));
        let mut m = Map::new();
        m.insert("type".into(), ty);
        m.insert("description".into(), json!(a.description));
        if a.required {
            m.insert("required".into(), json!(true));
        }
        if a.optional {
            m.insert("optional".into(), json!(true));
        }
        if a.computed {
            m.insert("computed".into(), json!(true));
        }
        if a.sensitive {
            m.insert("sensitive".into(), json!(true));
        }
        attributes.insert(a.name.clone(), Value::Object(m));
    }

    let mut block_types = Map::new();
    for nb in &b.block_types {
        // NestingMode is lowercase in the JSON surface lava-forge parses.
        let nesting = match nb.nesting {
            1 => "single",
            2 => "list",
            3 => "set",
            4 => "map",
            5 => "group",
            _ => "single",
        };
        let inner = nb
            .block
            .as_ref()
            .map_or_else(|| json!({}), |ib| block_to_json(ib, 0));
        let mut m = Map::new();
        m.insert("nesting".into(), json!(nesting));
        m.insert("block".into(), inner);
        if nb.min_items > 0 {
            m.insert("min_items".into(), json!(nb.min_items));
        }
        if nb.max_items > 0 {
            m.insert("max_items".into(), json!(nb.max_items));
        }
        block_types.insert(nb.type_name.clone(), Value::Object(m));
    }

    json!({
        "version": version,
        "description": b.description,
        "attributes": attributes,
        "block_types": block_types,
    })
}

fn schema_to_json(s: &tfplugin5::Schema) -> Value {
    s.block
        .as_ref()
        .map_or_else(|| json!({"version": s.version}), |b| {
            block_to_json(b, s.version)
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dump_provider_schema() {
    // Skip-with-print when unconfigured: this drives a real provider binary,
    // which a plain `cargo test` has no reason to have on hand.
    let (Ok(bin), Ok(source), Ok(out)) = (
        std::env::var("PROBE_PROVIDER"),
        std::env::var("PROBE_SOURCE"),
        std::env::var("PROBE_OUT"),
    ) else {
        eprintln!(
            "skipping: set PROBE_PROVIDER=<provider binary> \
             PROBE_SOURCE=<registry.terraform.io/ns/name> PROBE_OUT=<schema.json>"
        );
        return;
    };
    let binary = PathBuf::from(bin);

    let spec = PluginSpec {
        binary,
        kill_grace: Duration::from_secs(2),
        ..PluginSpec::default()
    };
    let mut plugin = Plugin::spawn(spec).await.expect("spawn provider");
    let protocol = plugin.handshake().app_protocol;
    let channel = plugin.dial().await.expect("dial gRPC").clone();

    assert!(
        matches!(protocol, magma_protocol::PluginProtocol::V5),
        "this probe drives the v5 client; provider negotiated {protocol:?}"
    );

    let mut client = ProviderClient::new(channel);
    let resp = client
        .get_schema(tfplugin5::get_provider_schema::Request {})
        .await
        .expect("GetSchema")
        .into_inner();

    assert!(
        resp.diagnostics.is_empty(),
        "provider returned diagnostics: {:?}",
        resp.diagnostics
    );

    let mut resources = Map::new();
    let mut names: Vec<&String> = resp.resource_schemas.keys().collect();
    names.sort(); // deterministic output — the file is committed
    for n in names {
        resources.insert(n.clone(), schema_to_json(&resp.resource_schemas[n]));
    }
    let mut data_sources = Map::new();
    let mut dnames: Vec<&String> = resp.data_source_schemas.keys().collect();
    dnames.sort();
    for n in dnames {
        data_sources.insert(n.clone(), schema_to_json(&resp.data_source_schemas[n]));
    }

    let doc = json!({
        "format_version": "1.0",
        "provider_schemas": {
            source: {
                "provider": resp.provider.as_ref().map_or_else(|| json!({}), schema_to_json),
                "resource_schemas": resources,
                "data_source_schemas": data_sources,
            }
        }
    });

    let text = serde_json::to_string_pretty(&doc).unwrap();
    std::fs::write(&out, format!("{text}\n")).expect("write schema.json");
    eprintln!(
        "WROTE {out} ({} bytes) resources={} data_sources={}",
        text.len(),
        resp.resource_schemas.len(),
        resp.data_source_schemas.len()
    );
}
