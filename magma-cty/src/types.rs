//! The cty type system — the type half of HashiCorp's `go-cty`.
//!
//! Every value crossing the tfplugin wire is a `cty.Value`, and every
//! `cty.Value` has a `cty.Type` that drives its msgpack encoding. This
//! module models the type; [`crate::value::CtyValue`] models the value;
//! [`crate::msgpack`] does the type-driven codec.
//!
//! Types also have a canonical **JSON** wire form (go-cty's
//! `cty/json` type serialization), which is how provider schemas and
//! the `DynamicPseudoType` wrapper carry types on the wire:
//!
//! ```text
//! "string" | "number" | "bool"
//! ["list", <elem-type>]   ["set", <elem-type>]   ["map", <elem-type>]
//! ["object", { "<attr>": <type>, … }]            (+ optional ["object", attrs, [optional…]])
//! ["tuple", [ <type>, … ]]
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A `cty.Type`. Mirrors `go-cty`'s type kinds.
///
/// `Object` attribute order is normalized via `BTreeMap` so encoding is
/// deterministic — a property the substrate relies on for attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtyType {
    String,
    Number,
    Bool,
    List(Box<CtyType>),
    Set(Box<CtyType>),
    Map(Box<CtyType>),
    Object(BTreeMap<String, CtyType>),
    Tuple(Vec<CtyType>),
    /// `cty.DynamicPseudoType` — the wire-level "any" that forces the
    /// value to be self-describing (encoded as a `[type, value]` pair).
    DynamicPseudoType,
}

impl CtyType {
    pub fn list(elem: CtyType) -> Self {
        CtyType::List(Box::new(elem))
    }
    pub fn set(elem: CtyType) -> Self {
        CtyType::Set(Box::new(elem))
    }
    pub fn map(elem: CtyType) -> Self {
        CtyType::Map(Box::new(elem))
    }
    pub fn object(attrs: impl IntoIterator<Item = (String, CtyType)>) -> Self {
        CtyType::Object(attrs.into_iter().collect())
    }

    /// Encode to go-cty's canonical JSON type representation — the form
    /// used inside `DynamicPseudoType` wrappers and provider schemas.
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value as J;
        match self {
            CtyType::String => J::String("string".into()),
            CtyType::Number => J::String("number".into()),
            CtyType::Bool => J::String("bool".into()),
            CtyType::DynamicPseudoType => J::String("dynamic".into()),
            CtyType::List(e) => J::Array(vec![J::String("list".into()), e.to_json()]),
            CtyType::Set(e) => J::Array(vec![J::String("set".into()), e.to_json()]),
            CtyType::Map(e) => J::Array(vec![J::String("map".into()), e.to_json()]),
            CtyType::Object(attrs) => {
                let obj: serde_json::Map<String, J> = attrs
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_json()))
                    .collect();
                J::Array(vec![J::String("object".into()), J::Object(obj)])
            }
            CtyType::Tuple(elems) => {
                let arr: Vec<J> = elems.iter().map(CtyType::to_json).collect();
                J::Array(vec![J::String("tuple".into()), J::Array(arr)])
            }
        }
    }

    /// Parse go-cty's canonical JSON type representation.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, crate::CtyError> {
        use serde_json::Value as J;
        match v {
            J::String(s) => match s.as_str() {
                "string" => Ok(CtyType::String),
                "number" => Ok(CtyType::Number),
                "bool" => Ok(CtyType::Bool),
                "dynamic" => Ok(CtyType::DynamicPseudoType),
                other => Err(crate::CtyError::Type(format!(
                    "unknown primitive type {other:?}"
                ))),
            },
            J::Array(items) if !items.is_empty() => {
                let kind = items[0].as_str().ok_or_else(|| {
                    crate::CtyError::Type("type kind tag must be a string".into())
                })?;
                match kind {
                    "list" => Ok(CtyType::list(Self::nth_type(items, 1)?)),
                    "set" => Ok(CtyType::set(Self::nth_type(items, 1)?)),
                    "map" => Ok(CtyType::map(Self::nth_type(items, 1)?)),
                    "object" => {
                        let obj = items.get(1).and_then(J::as_object).ok_or_else(|| {
                            crate::CtyError::Type("object type needs an attr map".into())
                        })?;
                        let mut attrs = BTreeMap::new();
                        for (k, ty) in obj {
                            attrs.insert(k.clone(), Self::from_json(ty)?);
                        }
                        Ok(CtyType::Object(attrs))
                    }
                    "tuple" => {
                        let arr = items.get(1).and_then(J::as_array).ok_or_else(|| {
                            crate::CtyError::Type("tuple type needs a type list".into())
                        })?;
                        let elems = arr.iter().map(Self::from_json).collect::<Result<_, _>>()?;
                        Ok(CtyType::Tuple(elems))
                    }
                    other => Err(crate::CtyError::Type(format!(
                        "unknown type kind {other:?}"
                    ))),
                }
            }
            _ => Err(crate::CtyError::Type(format!("not a cty type: {v}"))),
        }
    }

    fn nth_type(items: &[serde_json::Value], n: usize) -> Result<CtyType, crate::CtyError> {
        let v = items
            .get(n)
            .ok_or_else(|| crate::CtyError::Type("collection type missing element type".into()))?;
        CtyType::from_json(v)
    }
}
