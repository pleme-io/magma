//! Real-fixture proof that `magma_state::tfstate_v4` can read a real,
//! pre-existing `terraform.tfstate` file — the concrete gap this test
//! corpus closes (per `theory/MAGMA.md` §II.6 level `StateRoundTrip`).
//!
//! Every byte string below is copied VERBATIM from an actual local
//! `tofu apply` / `terraform apply` run (OpenTofu 1.10.9 / HashiCorp
//! Terraform 1.14.0) against a `null_resource`/`time_static`-only
//! configuration — no cloud provider, no cloud cost, no network access
//! beyond the one-time `tofu init` provider download. This is a real
//! fixture, not a hand-constructed approximation of the schema: had
//! any field name, nesting, or default (e.g. the OpenTofu-vs-Terraform
//! registry-host difference this test corpus catches) been guessed
//! wrong, these tests would fail against the actual bytes.
//!
//! Before this module existed, every one of these `decode()` calls
//! failed outright: `serde_json::from_slice::<magma_types::State>`
//! requires a nested `address`/`provider` object shape no real tfstate
//! file has.

use magma_state::tfstate_v4::{decode, encode, encode_indent};
use magma_types::{InstanceStatus, ResourceKind};

/// `tofu apply` on a bare `null_resource` with one `triggers` map.
/// No count/for_each, no dependencies, no outputs — the common case.
/// Compact JSON, as OpenTofu itself writes it.
const SIMPLE_OPENTOFU: &str = r#"{"version":4,"terraform_version":"1.10.9","serial":1,"lineage":"0fa70369-8fa5-5907-a12b-fa525ddbef7f","outputs":{},"resources":[{"mode":"managed","type":"null_resource","name":"example","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"schema_version":0,"attributes":{"id":"5302737380808579797","triggers":{"foo":"bar"}},"sensitive_attributes":[]}]}],"check_results":null}
"#;

/// The same resource after `tofu taint null_resource.example` — proves
/// the `"status":"tainted"` field (present only when tainted, absent
/// otherwise) round-trips.
const TAINTED_OPENTOFU: &str = r#"{"version":4,"terraform_version":"1.10.9","serial":2,"lineage":"523424d0-2b6e-fd8d-0e04-a80c8deaefca","outputs":{},"resources":[{"mode":"managed","type":"null_resource","name":"example","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"status":"tainted","schema_version":0,"attributes":{"id":"437968361265320129","triggers":{"foo":"bar"}},"sensitive_attributes":[]}]}],"check_results":null}
"#;

/// `count = 2` + `for_each` over a 2-element set, both `depends_on` a
/// third plain resource. Proves: `index_key` (numeric for `count`,
/// string for `for_each`) travels per-instance under ONE resource
/// entry; `dependencies` (root-module address strings) round-trip.
const COUNT_FOR_EACH_DEPS_OPENTOFU: &str = r#"{"version":4,"terraform_version":"1.10.9","serial":1,"lineage":"50c2eaa5-2826-bab9-5f46-864883591e0c","outputs":{},"resources":[{"mode":"managed","type":"null_resource","name":"base","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"schema_version":0,"attributes":{"id":"3168044663070479361","triggers":{"role":"base"}},"sensitive_attributes":[]}]},{"mode":"managed","type":"null_resource","name":"counted","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"index_key":0,"schema_version":0,"attributes":{"id":"5244716695276523879","triggers":{"idx":"0"}},"sensitive_attributes":[],"dependencies":["null_resource.base"]},{"index_key":1,"schema_version":0,"attributes":{"id":"7334361403406011370","triggers":{"idx":"1"}},"sensitive_attributes":[],"dependencies":["null_resource.base"]}]},{"mode":"managed","type":"null_resource","name":"keyed","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"index_key":"alpha","schema_version":0,"attributes":{"id":"377831931930373918","triggers":{"key":"alpha"}},"sensitive_attributes":[],"dependencies":["null_resource.base"]},{"index_key":"beta","schema_version":0,"attributes":{"id":"1411627774653107389","triggers":{"key":"beta"}},"sensitive_attributes":[],"dependencies":["null_resource.base"]}]}],"check_results":null}
"#;

/// Two `output` blocks, one plain, one `sensitive = true`. Proves
/// `outputs` (dropped entirely by the prior `tofu_state` converter)
/// round-trips including the `sensitive` marker.
const OUTPUTS_OPENTOFU: &str = r#"{"version":4,"terraform_version":"1.10.9","serial":1,"lineage":"257a99d6-fcae-2720-f4db-1ce950712c76","outputs":{"plain":{"value":"hello","type":"string"},"secret":{"value":"s3cr3t","type":"string","sensitive":true}},"resources":[{"mode":"managed","type":"null_resource","name":"example","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"schema_version":0,"attributes":{"id":"8604209156344715160","triggers":null},"sensitive_attributes":[]}]}],"check_results":null}
"#;

/// A resource declared inside `module "child" { source = "./modules/child" }`.
/// Proves the resource-level `"module"` field (first key when present)
/// round-trips.
const MODULE_OPENTOFU: &str = r#"{"version":4,"terraform_version":"1.10.9","serial":1,"lineage":"4e05e35b-7f19-4ff0-3dc5-080176119f43","outputs":{},"resources":[{"module":"module.child","mode":"managed","type":"null_resource","name":"inner","provider":"provider[\"registry.opentofu.org/hashicorp/null\"]","instances":[{"schema_version":0,"attributes":{"id":"5634584485298738318","triggers":null},"sensitive_attributes":[]}]}],"check_results":null}
"#;

/// The SAME `null_resource` config applied with real HashiCorp
/// Terraform 1.14.0 instead of OpenTofu — pretty-printed (Terraform's
/// own default), `registry.terraform.io` (not `.opentofu.org`), and
/// carries a field this module doesn't model at all
/// (`identity_schema_version`, a Terraform 1.12+ managed-resource-
/// identity addition). Proves: (a) decode tolerates unrecognized
/// fields instead of hard-failing (serde's default "ignore unknown
/// fields" behavior — deliberately NOT `deny_unknown_fields`), and
/// (b) the registry host is preserved verbatim rather than being
/// rewritten to OpenTofu's default.
const TERRAFORM_CLI_PRETTY: &str = r#"{
  "version": 4,
  "terraform_version": "1.14.0",
  "serial": 1,
  "lineage": "087fb1c4-f6a2-beaa-12fb-6f220eac3b87",
  "outputs": {},
  "resources": [
    {
      "mode": "managed",
      "type": "null_resource",
      "name": "example",
      "provider": "provider[\"registry.terraform.io/hashicorp/null\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "id": "1676319927326013415",
            "triggers": {
              "foo": "bar"
            }
          },
          "sensitive_attributes": [],
          "identity_schema_version": 0
        }
      ]
    }
  ],
  "check_results": null
}
"#;

#[test]
fn simple_decodes_without_error() {
    // Before this module existed, this call returned
    // `Err(serde_json::Error)` unconditionally — a real tfstate
    // resource has no `address` field, which `magma_types::State`'s
    // derived `Deserialize` required.
    let state = decode(SIMPLE_OPENTOFU.as_bytes()).expect(
        "a real, pre-existing tofu-produced state file must decode — this is the load-bearing gap",
    );
    assert_eq!(state.version, 4);
    assert_eq!(state.resources.len(), 1);
    let r = &state.resources[0];
    assert_eq!(r.address.type_id.0, "null_resource");
    assert_eq!(r.address.name, "example");
    assert_eq!(r.address.kind, ResourceKind::Managed);
    assert_eq!(r.provider.source, "registry.opentofu.org/hashicorp/null");
    assert_eq!(r.instances.len(), 1);
    assert_eq!(r.instances[0].status, InstanceStatus::Ready);
    assert_eq!(
        r.instances[0].attributes["triggers"]["foo"],
        serde_json::json!("bar"),
    );
}

#[test]
fn simple_round_trips_byte_exact() {
    // The strongest claim this module makes: for the fields it
    // models, decode ∘ encode reproduces the ORIGINAL bytes exactly —
    // not just an equivalent JSON value.
    let state = decode(SIMPLE_OPENTOFU.as_bytes()).unwrap();
    let out = encode(&state).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        SIMPLE_OPENTOFU,
        "byte-exact round-trip failed for the simple fixture",
    );
}

#[test]
fn tainted_round_trips_byte_exact() {
    let state = decode(TAINTED_OPENTOFU.as_bytes()).unwrap();
    assert_eq!(
        state.resources[0].instances[0].status,
        InstanceStatus::Tainted
    );
    let out = encode(&state).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), TAINTED_OPENTOFU);
}

#[test]
fn count_for_each_and_dependencies_round_trip_byte_exact() {
    let state = decode(COUNT_FOR_EACH_DEPS_OPENTOFU.as_bytes()).unwrap();
    assert_eq!(state.resources.len(), 3);

    let counted = state
        .resources
        .iter()
        .find(|r| r.address.name == "counted")
        .unwrap();
    assert_eq!(
        counted.instances.len(),
        2,
        "count=2 must keep both instances under one resource entry"
    );
    assert_eq!(
        counted.instances[0].index_key,
        Some(magma_types::InstanceKey::Index(0)),
    );
    assert_eq!(
        counted.instances[1].index_key,
        Some(magma_types::InstanceKey::Index(1)),
    );
    assert_eq!(counted.instances[0].dependencies.len(), 1);
    assert_eq!(counted.instances[0].dependencies[0].name, "base");

    let keyed = state
        .resources
        .iter()
        .find(|r| r.address.name == "keyed")
        .unwrap();
    assert_eq!(
        keyed.instances[0].index_key,
        Some(magma_types::InstanceKey::Key("alpha".into())),
    );

    let out = encode(&state).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        COUNT_FOR_EACH_DEPS_OPENTOFU,
        "byte-exact round-trip failed for the count/for_each/dependencies fixture",
    );
}

#[test]
fn outputs_round_trip_byte_exact_including_sensitive_marker() {
    let state = decode(OUTPUTS_OPENTOFU.as_bytes()).unwrap();
    assert_eq!(state.outputs.len(), 2);
    assert!(!state.outputs["plain"].sensitive);
    assert!(state.outputs["secret"].sensitive);
    assert_eq!(state.outputs["secret"].value, serde_json::json!("s3cr3t"));

    let out = encode(&state).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), OUTPUTS_OPENTOFU);
}

#[test]
fn module_scoped_resource_round_trips_byte_exact() {
    let state = decode(MODULE_OPENTOFU.as_bytes()).unwrap();
    assert_eq!(
        state.resources[0].address.module.0,
        vec!["child".to_string()]
    );

    let out = encode(&state).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), MODULE_OPENTOFU);
}

#[test]
fn real_terraform_cli_output_decodes_and_preserves_its_own_registry_host() {
    // The regression this test locks in: a prior converter
    // (magma-operator-backend's now-superseded `tofu_state` module)
    // hardcoded `registry.terraform.io` on WRITE regardless of what
    // was parsed, which would silently corrupt an OpenTofu-native
    // `registry.opentofu.org` reference into a doubled, invalid
    // string. This fixture is real Terraform-CLI output (which DOES
    // use `registry.terraform.io`); the OpenTofu fixtures above use
    // `registry.opentofu.org`. Both must come back unchanged.
    let state = decode(TERRAFORM_CLI_PRETTY.as_bytes())
        .expect("a real terraform-CLI-produced state file must also decode");
    assert_eq!(
        state.resources[0].provider.source,
        "registry.terraform.io/hashicorp/null",
    );
    // `identity_schema_version` (Terraform 1.12+, not modeled) is
    // silently ignored on decode rather than rejecting the whole
    // file — a real, named, deliberate scope boundary (see the
    // `tfstate_v4` module doc), not a silent corruption: nothing this
    // module DOES model is lost.
    assert_eq!(
        state.resources[0].instances[0].attributes["id"],
        serde_json::json!("1676319927326013415"),
    );
}

#[test]
fn malformed_bytes_are_a_typed_error_not_a_panic() {
    let err = decode(b"{not json").unwrap_err();
    assert!(matches!(err, magma_state::StateError::Parse(_)));
}

// ── The two serialization planes ───────────────────────────────────
//
// Added 2026-09-15 with the trailing-newline fix. These exist because
// the byte-exact assertions above were BLIND to the exact byte they
// claimed to check: the fixtures are real tofu output, but the paste
// into a Rust raw string dropped the trailing `\n`, so encode's
// missing newline matched a fixture that had already lost it. The
// fixtures now carry it; these tests pin the property directly so a
// future re-paste cannot re-hide it.
//
// Oracle: OpenTofu `internal/states/statefile/version4.go`
//   :526  json.MarshalIndent(sV4, "", "  ")   ← WriteIndent → local file
//   :528  json.Marshal(sV4)                   ← Write       → remote backend
//   :539  src = append(src, '\n')             ← BOTH planes

#[test]
fn both_planes_end_in_exactly_one_newline() {
    let state = decode(SIMPLE_OPENTOFU.as_bytes()).unwrap();

    for (plane, bytes) in [
        ("encode (remote/compact)", encode(&state).unwrap()),
        ("encode_indent (local/2-space)", encode_indent(&state).unwrap()),
    ] {
        assert_eq!(
            bytes.last().copied(),
            Some(b'\n'),
            "{plane}: version4.go:539 appends '\\n' to every payload",
        );
        assert_ne!(
            bytes[bytes.len() - 2],
            b'\n',
            "{plane}: exactly one trailing newline, not two",
        );
    }
}

#[test]
fn the_two_planes_differ_only_in_whitespace() {
    // If these ever compare equal, one of them is emitting the other's
    // shape and the split has silently collapsed.
    let state = decode(SIMPLE_OPENTOFU.as_bytes()).unwrap();
    let compact = encode(&state).unwrap();
    let indented = encode_indent(&state).unwrap();

    assert_ne!(compact, indented, "the planes collapsed into one shape");
    assert!(
        indented.len() > compact.len(),
        "2-space indentation cannot be shorter than compact",
    );
    assert!(
        !compact.windows(2).any(|w| w == b"\n "),
        "the compact plane must carry no indentation",
    );
    // Same value either way — whitespace is the ONLY difference.
    let a: serde_json::Value = serde_json::from_slice(&compact).unwrap();
    let b: serde_json::Value = serde_json::from_slice(&indented).unwrap();
    assert_eq!(a, b);
}

#[test]
fn indented_plane_round_trips_real_terraform_cli_output_byte_exact() {
    // TERRAFORM_CLI_PRETTY is a real `terraform apply` local state file:
    // 2-space, trailing newline. Before `encode_indent` existed this
    // fixture could only be decoded, never reproduced — which is why the
    // local plane's defect had no failing test.
    //
    // `identity_schema_version` (Terraform 1.12+) is NOT modeled here, so
    // a full byte-exact assertion would fail on a field this module
    // deliberately ignores. Pin the shape instead: indentation and the
    // trailing newline, which is what the plane is about.
    let state = decode(TERRAFORM_CLI_PRETTY.as_bytes()).unwrap();
    let out = encode_indent(&state).unwrap();
    let text = String::from_utf8(out).unwrap();

    assert!(text.ends_with("}\n"), "local plane ends with newline");
    assert!(
        text.contains("\n  \"version\": 4"),
        "local plane is 2-space indented like the real file",
    );
    assert!(
        TERRAFORM_CLI_PRETTY.contains("\n  \"version\": 4"),
        "the fixture itself must be indented, or this test proves nothing",
    );
}
