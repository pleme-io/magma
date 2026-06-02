//! magma-cty — HashiCorp `cty` type system + msgpack `DynamicValue`
//! codec, the foundation of magma's provider-RPC apply.
//!
//! Every tfplugin5/6 RPC (`GetProviderSchema`, `ConfigureProvider`,
//! `PlanResourceChange`, `ApplyResourceChange`) carries resource
//! attributes as a `DynamicValue` — schema-typed, msgpack-encoded `cty`
//! values. magma cannot call a provider without this layer; it is the
//! prerequisite for `magma-apply` to stop being a structural no-op and
//! actually create resources. See `theory/MAGMA.md` §IV + magma#2.
//!
//! ## Surface
//!
//! - [`CtyType`] — the type system (+ go-cty JSON type wire form).
//! - [`CtyValue`] — null / unknown / concrete values.
//! - [`DynamicValue`] — the tfplugin wire type (the `bytes msgpack` field).
//! - [`marshal`] / [`unmarshal`] — type-driven msgpack codec.
//! - [`from_json`] / [`to_json`] — `serde_json::Value` bridge.
//!
//! The codec is byte-compatible with `go-cty/cty/msgpack`; see
//! [`msgpack`] for the table.

pub mod json;
pub mod msgpack;
pub mod types;
pub mod value;

pub use json::{from_json, to_json};
pub use msgpack::{marshal, unmarshal};
pub use types::CtyType;
pub use value::CtyValue;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CtyError {
    #[error("cty type error: {0}")]
    Type(String),
    #[error("msgpack encode: {0}")]
    Encode(String),
    #[error("msgpack decode: {0}")]
    Decode(String),
}

/// The tfplugin `DynamicValue` wire message — magma only uses the
/// `msgpack` representation (the `json` alternative is for debugging).
///
/// ```
/// use magma_cty::{CtyType, CtyValue, DynamicValue};
/// let ty = CtyType::String;
/// let dv = DynamicValue::marshal(&CtyValue::string("hello"), &ty).unwrap();
/// assert_eq!(dv.to_value(&ty).unwrap(), CtyValue::string("hello"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicValue {
    pub msgpack: Vec<u8>,
}

impl DynamicValue {
    /// Marshal a typed value into a `DynamicValue`.
    pub fn marshal(value: &CtyValue, ty: &CtyType) -> Result<Self, CtyError> {
        Ok(Self {
            msgpack: msgpack::marshal(value, ty)?,
        })
    }

    /// Marshal directly from JSON attributes + a schema type — the path
    /// the apply engine uses (rendered attributes → wire value).
    pub fn from_json(v: &serde_json::Value, ty: &CtyType) -> Result<Self, CtyError> {
        Self::marshal(&json::from_json(v, ty)?, ty)
    }

    /// Decode back into a typed `CtyValue` under `ty`.
    pub fn to_value(&self, ty: &CtyType) -> Result<CtyValue, CtyError> {
        msgpack::unmarshal(&self.msgpack, ty)
    }

    /// Decode and fold into magma's JSON state representation.
    pub fn to_json(&self, ty: &CtyType) -> Result<serde_json::Value, CtyError> {
        Ok(json::to_json(&self.to_value(ty)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn roundtrip(value: CtyValue, ty: CtyType) {
        let bytes = marshal(&value, &ty).expect("marshal");
        let back = unmarshal(&bytes, &ty).expect("unmarshal");
        assert_eq!(back, value, "round-trip under {ty:?}");
    }

    #[test]
    fn scalars_roundtrip() {
        roundtrip(CtyValue::string("hello"), CtyType::String);
        roundtrip(CtyValue::Bool(true), CtyType::Bool);
        roundtrip(CtyValue::Bool(false), CtyType::Bool);
        roundtrip(CtyValue::int(42), CtyType::Number);
        roundtrip(CtyValue::int(-7), CtyType::Number);
        roundtrip(
            CtyValue::Number(serde_json::Number::from_f64(3.5).unwrap()),
            CtyType::Number,
        );
    }

    #[test]
    fn null_encodes_as_msgpack_nil() {
        let bytes = marshal(&CtyValue::Null, &CtyType::String).unwrap();
        assert_eq!(bytes, vec![0xc0], "null must be msgpack nil (0xc0)");
        assert_eq!(unmarshal(&bytes, &CtyType::String).unwrap(), CtyValue::Null);
    }

    #[test]
    fn unknown_encodes_as_ext_type_zero() {
        let bytes = marshal(&CtyValue::Unknown, &CtyType::Number).unwrap();
        // fixext1 (0xd4), ext type 0x00, payload 0x00 — the go-cty
        // unknown-value extension.
        assert_eq!(bytes, vec![0xd4, 0x00, 0x00], "unknown must be ext type 0");
        assert_eq!(
            unmarshal(&bytes, &CtyType::Number).unwrap(),
            CtyValue::Unknown
        );
    }

    #[test]
    fn list_and_set_roundtrip() {
        let v = CtyValue::List(vec![CtyValue::string("a"), CtyValue::string("b")]);
        roundtrip(v, CtyType::list(CtyType::String));
        let s = CtyValue::Set(vec![CtyValue::int(1), CtyValue::int(2)]);
        roundtrip(s, CtyType::set(CtyType::Number));
    }

    #[test]
    fn map_roundtrip() {
        let mut m = BTreeMap::new();
        m.insert("x".into(), CtyValue::string("1"));
        m.insert("y".into(), CtyValue::string("2"));
        roundtrip(CtyValue::Map(m), CtyType::map(CtyType::String));
    }

    #[test]
    fn object_roundtrip_with_null_optional() {
        // github_repository-shaped: name (string), private (bool),
        // description (optional → null), topics (list(string)).
        let ty = CtyType::object([
            ("name".into(), CtyType::String),
            ("private".into(), CtyType::Bool),
            ("description".into(), CtyType::String),
            ("topics".into(), CtyType::list(CtyType::String)),
        ]);
        let mut o = BTreeMap::new();
        o.insert("name".into(), CtyValue::string("galho"));
        o.insert("private".into(), CtyValue::Bool(false));
        o.insert("description".into(), CtyValue::Null);
        o.insert(
            "topics".into(),
            CtyValue::List(vec![CtyValue::string("rust"), CtyValue::string("iac")]),
        );
        roundtrip(CtyValue::Object(o), ty);
    }

    #[test]
    fn object_fills_absent_attr_with_null() {
        let ty = CtyType::object([
            ("name".into(), CtyType::String),
            ("description".into(), CtyType::String),
        ]);
        // Value omits `description` entirely.
        let mut o = BTreeMap::new();
        o.insert("name".into(), CtyValue::string("galho"));
        let bytes = marshal(&CtyValue::Object(o), &ty).unwrap();
        let back = unmarshal(&bytes, &ty).unwrap();
        if let CtyValue::Object(m) = back {
            assert_eq!(
                m.get("description"),
                Some(&CtyValue::Null),
                "absent attr → null"
            );
        } else {
            panic!("expected object");
        }
    }

    #[test]
    fn nested_object_in_list_roundtrip() {
        // list(object({ key=string, value=string })) — github labels.
        let elem = CtyType::object([
            ("key".into(), CtyType::String),
            ("value".into(), CtyType::String),
        ]);
        let mk = |k: &str, v: &str| {
            CtyValue::object([
                ("key".into(), CtyValue::string(k)),
                ("value".into(), CtyValue::string(v)),
            ])
        };
        roundtrip(
            CtyValue::List(vec![mk("a", "1"), mk("b", "2")]),
            CtyType::list(elem),
        );
    }

    #[test]
    fn dynamic_pseudo_type_roundtrip() {
        roundtrip(CtyValue::string("dyn"), CtyType::DynamicPseudoType);
        roundtrip(CtyValue::int(9), CtyType::DynamicPseudoType);
        roundtrip(
            CtyValue::List(vec![CtyValue::string("a")]),
            CtyType::DynamicPseudoType,
        );
    }

    #[test]
    fn type_json_roundtrips() {
        let ty = CtyType::object([
            ("a".into(), CtyType::String),
            ("b".into(), CtyType::list(CtyType::Number)),
            ("c".into(), CtyType::map(CtyType::Bool)),
        ]);
        let j = ty.to_json();
        assert_eq!(CtyType::from_json(&j).unwrap(), ty);
    }

    #[test]
    fn json_bridge_drives_apply_shape() {
        // The apply path: rendered JSON attributes + schema type → wire.
        let ty = CtyType::object([
            ("name".into(), CtyType::String),
            ("private".into(), CtyType::Bool),
            ("topics".into(), CtyType::list(CtyType::String)),
        ]);
        let attrs = serde_json::json!({
            "name": "galho",
            "private": false,
            "topics": ["rust", "iac", "gitops"]
        });
        let dv = DynamicValue::from_json(&attrs, &ty).expect("from_json");
        // Decode back to JSON — must equal the input (modulo attr order).
        let out = dv.to_json(&ty).expect("to_json");
        assert_eq!(out, attrs);
    }

    #[test]
    fn dynamic_value_wire_roundtrip() {
        let ty = CtyType::list(CtyType::String);
        let v = CtyValue::List(vec![CtyValue::string("x")]);
        let dv = DynamicValue::marshal(&v, &ty).unwrap();
        assert_eq!(dv.to_value(&ty).unwrap(), v);
    }

    #[test]
    fn type_mismatch_is_an_error() {
        // bool value under string type → typed encode error, not panic.
        let err = marshal(&CtyValue::Bool(true), &CtyType::String).unwrap_err();
        assert!(matches!(err, CtyError::Encode(_)));
    }
}
