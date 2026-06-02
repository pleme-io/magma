//! The value half of `go-cty` — a `cty.Value`.
//!
//! A value is `Null`, `Unknown`, or concrete. Encoding is **type-driven**
//! (see [`crate::msgpack`]): the same `CtyValue` may encode differently
//! under different [`CtyType`](crate::CtyType)s, exactly as in go-cty,
//! so the value here is deliberately type-free.
//!
//! `Number` is held as a [`serde_json::Number`] so int/float distinction
//! and JSON round-tripping are exact; the msgpack codec picks the
//! tightest msgpack scalar (int / uint / float) for it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CtyValue {
    /// A null of whatever type the encoder is told to use.
    Null,
    /// An as-yet-unknown value (provider will compute it). Encoded as
    /// go-cty's unknown-value msgpack extension.
    Unknown,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    List(Vec<CtyValue>),
    Set(Vec<CtyValue>),
    Map(BTreeMap<String, CtyValue>),
    Object(BTreeMap<String, CtyValue>),
    Tuple(Vec<CtyValue>),
}

impl CtyValue {
    pub fn string(s: impl Into<String>) -> Self {
        CtyValue::String(s.into())
    }
    pub fn bool(b: bool) -> Self {
        CtyValue::Bool(b)
    }
    pub fn int(n: i64) -> Self {
        CtyValue::Number(serde_json::Number::from(n))
    }
    pub fn object(attrs: impl IntoIterator<Item = (String, CtyValue)>) -> Self {
        CtyValue::Object(attrs.into_iter().collect())
    }

    pub fn is_null(&self) -> bool {
        matches!(self, CtyValue::Null)
    }
    pub fn is_unknown(&self) -> bool {
        matches!(self, CtyValue::Unknown)
    }

    /// Recursively true if this value or any nested value is `Unknown`.
    /// Provider `ApplyResourceChange` requires a fully-known config; the
    /// apply engine asserts `!has_unknown()` before marshaling.
    pub fn has_unknown(&self) -> bool {
        match self {
            CtyValue::Unknown => true,
            CtyValue::List(xs) | CtyValue::Set(xs) | CtyValue::Tuple(xs) => {
                xs.iter().any(CtyValue::has_unknown)
            }
            CtyValue::Map(m) | CtyValue::Object(m) => m.values().any(CtyValue::has_unknown),
            _ => false,
        }
    }
}
