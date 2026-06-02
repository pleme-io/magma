//! `serde_json::Value` ↔ [`CtyValue`] conversion.
//!
//! magma carries rendered resource attributes as `serde_json::Value`;
//! the tfplugin wire needs them as type-driven `cty` values. JSON is
//! untyped, so [`from_json`] takes the [`CtyType`] (from the provider
//! schema) to drive the conversion; [`to_json`] is type-free (used to
//! fold a provider's returned `cty` state back into magma's JSON state).

use std::collections::BTreeMap;

use serde_json::Value as J;

use crate::{CtyError, CtyType, CtyValue};

/// Convert a JSON value into a `CtyValue` under `ty`. A JSON `null`
/// becomes `CtyValue::Null` regardless of type (a null of that type).
pub fn from_json(v: &J, ty: &CtyType) -> Result<CtyValue, CtyError> {
    if v.is_null() {
        return Ok(CtyValue::Null);
    }
    match ty {
        CtyType::String => match v {
            J::String(s) => Ok(CtyValue::String(s.clone())),
            _ => Err(CtyError::Type(format!(
                "expected JSON string for cty string, got {v}"
            ))),
        },
        CtyType::Bool => match v {
            J::Bool(b) => Ok(CtyValue::Bool(*b)),
            _ => Err(CtyError::Type(format!(
                "expected JSON bool for cty bool, got {v}"
            ))),
        },
        CtyType::Number => match v {
            J::Number(n) => Ok(CtyValue::Number(n.clone())),
            _ => Err(CtyError::Type(format!(
                "expected JSON number for cty number, got {v}"
            ))),
        },
        CtyType::List(elem) => Ok(CtyValue::List(json_seq(v, elem)?)),
        CtyType::Set(elem) => Ok(CtyValue::Set(json_seq(v, elem)?)),
        CtyType::Tuple(types) => {
            let arr = v
                .as_array()
                .ok_or_else(|| CtyError::Type(format!("expected JSON array for tuple, got {v}")))?;
            if arr.len() != types.len() {
                return Err(CtyError::Type(format!(
                    "tuple arity mismatch: JSON has {}, type has {}",
                    arr.len(),
                    types.len()
                )));
            }
            Ok(CtyValue::Tuple(
                arr.iter()
                    .zip(types)
                    .map(|(x, t)| from_json(x, t))
                    .collect::<Result<_, _>>()?,
            ))
        }
        CtyType::Map(elem) => {
            let obj = v
                .as_object()
                .ok_or_else(|| CtyError::Type(format!("expected JSON object for map, got {v}")))?;
            let mut m = BTreeMap::new();
            for (k, val) in obj {
                m.insert(k.clone(), from_json(val, elem)?);
            }
            Ok(CtyValue::Map(m))
        }
        CtyType::Object(attrs) => {
            let obj = v.as_object().ok_or_else(|| {
                CtyError::Type(format!("expected JSON object for object, got {v}"))
            })?;
            let mut out = BTreeMap::new();
            for (attr, aty) in attrs {
                match obj.get(attr) {
                    Some(val) => {
                        out.insert(attr.clone(), from_json(val, aty)?);
                    }
                    // Absent attr ⇒ null of its type (optional attrs).
                    None => {
                        out.insert(attr.clone(), CtyValue::Null);
                    }
                }
            }
            Ok(CtyValue::Object(out))
        }
        CtyType::DynamicPseudoType => Ok(from_json_dynamic(v)),
    }
}

fn json_seq(v: &J, elem: &CtyType) -> Result<Vec<CtyValue>, CtyError> {
    let arr = v
        .as_array()
        .ok_or_else(|| CtyError::Type(format!("expected JSON array, got {v}")))?;
    arr.iter().map(|x| from_json(x, elem)).collect()
}

/// Structurally infer a `CtyValue` from untyped JSON (for
/// `DynamicPseudoType`): object → cty object, array → cty tuple, etc.
fn from_json_dynamic(v: &J) -> CtyValue {
    match v {
        J::Null => CtyValue::Null,
        J::Bool(b) => CtyValue::Bool(*b),
        J::Number(n) => CtyValue::Number(n.clone()),
        J::String(s) => CtyValue::String(s.clone()),
        J::Array(xs) => CtyValue::Tuple(xs.iter().map(from_json_dynamic).collect()),
        J::Object(o) => CtyValue::Object(
            o.iter()
                .map(|(k, val)| (k.clone(), from_json_dynamic(val)))
                .collect(),
        ),
    }
}

/// Convert a `CtyValue` back into JSON. `Unknown` becomes `null` (JSON
/// has no unknown); apply-time values are always fully known so this is
/// lossless in practice.
pub fn to_json(v: &CtyValue) -> J {
    match v {
        CtyValue::Null | CtyValue::Unknown => J::Null,
        CtyValue::Bool(b) => J::Bool(*b),
        CtyValue::Number(n) => J::Number(n.clone()),
        CtyValue::String(s) => J::String(s.clone()),
        CtyValue::List(xs) | CtyValue::Set(xs) | CtyValue::Tuple(xs) => {
            J::Array(xs.iter().map(to_json).collect())
        }
        CtyValue::Map(m) | CtyValue::Object(m) => {
            J::Object(m.iter().map(|(k, val)| (k.clone(), to_json(val))).collect())
        }
    }
}
