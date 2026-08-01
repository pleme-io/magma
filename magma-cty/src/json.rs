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
    if let Some(arr) = v.as_array() {
        return arr.iter().map(|x| from_json(x, elem)).collect();
    }
    // (A `null` list never reaches here — `from_json` returns `CtyValue::Null`
    //  for any null before dispatching to the List/Set arm.)
    // terraform leniency for `max_items = 1` nested blocks: a list/set-of-
    // object block may be written as a SINGLE OBJECT (e.g. github_repository's
    // `pages = { build_type = "workflow" }`) rather than a one-element array.
    // The block's cty type is still list(object)/set(object), so coerce the
    // lone object into a single-element sequence — exactly what HCL→cty does.
    // Only when the element is an object type, so genuine list(string)/etc.
    // mismatches still error.
    if v.is_object() && matches!(elem, CtyType::Object(_)) {
        return Ok(vec![from_json(v, elem)?]);
    }
    Err(CtyError::Type(format!("expected JSON array, got {v}")))
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

#[cfg(test)]
mod block_coercion_tests {
    use super::*;
    use crate::types::CtyType;
    use std::collections::BTreeMap;
    use serde_json::json;

    fn obj_elem() -> CtyType {
        let mut a = BTreeMap::new();
        a.insert("build_type".to_string(), CtyType::String);
        CtyType::Object(a)
    }

    #[test]
    fn max_items_one_block_written_as_object_coerces_to_single_element_list() {
        // github_repository's `pages = { build_type = "workflow" }`: a single
        // object for a list(object) block must become a 1-element list.
        let ty = CtyType::List(Box::new(obj_elem()));
        let v = json!({ "build_type": "workflow" });
        let out = from_json(&v, &ty).expect("object coerces to single-element list");
        match out {
            CtyValue::List(xs) => assert_eq!(xs.len(), 1, "exactly one element"),
            other => panic!("expected list, got {other:?}"),
        }
    }

    #[test]
    fn null_list_is_cty_null() {
        // A null list attribute resolves to cty null (handled at the top of
        // from_json), which the provider accepts as an absent block.
        let ty = CtyType::List(Box::new(obj_elem()));
        let out = from_json(&serde_json::Value::Null, &ty).expect("null → cty null");
        assert!(matches!(out, CtyValue::Null));
    }

    #[test]
    fn array_still_works_and_non_object_elem_still_errors() {
        // Normal array path unchanged.
        let ty = CtyType::List(Box::new(obj_elem()));
        let arr = json!([{ "build_type": "legacy" }, { "build_type": "workflow" }]);
        assert!(matches!(from_json(&arr, &ty), Ok(CtyValue::List(xs)) if xs.len() == 2));
        // A genuine list(string) given an object must STILL error (no over-coercion).
        let sty = CtyType::List(Box::new(CtyType::String));
        assert!(from_json(&json!({ "x": "y" }), &sty).is_err());
    }

    /// An attribute present in the JSON but ABSENT from the schema is DROPPED,
    /// never forwarded.
    ///
    /// This is the invariant magma's compliance escape hatches depend on.
    /// `allow_public_ingress` / `allow_public_database` / `allow_unencrypted_cache`
    /// are written into the committed Terraform JSON of a real resource (that
    /// visibility is the point — the exception is auditable in git), but no
    /// provider schema declares them. If `from_json` forwarded unknown keys,
    /// setting one would encode an attribute the AWS provider has never heard
    /// of and turn a clean compliance stop into a FAILED APPLY.
    ///
    /// The Object arm iterates the SCHEMA's attributes and looks each up in the
    /// JSON, so extra JSON keys are structurally unreachable. This test pins
    /// that, because the escape-hatch design is silently broken without it and
    /// the breakage would only ever show up mid-apply against real cloud
    /// resources.
    #[test]
    fn an_attribute_absent_from_the_schema_is_dropped_not_forwarded() {
        let ty = CtyType::Object(
            [
                ("type".to_string(), CtyType::String),
                ("from_port".to_string(), CtyType::Number),
            ]
            .into_iter()
            .collect(),
        );
        let v = from_json(
            &json!({
                "type": "ingress",
                "from_port": 51822,
                // Not in the schema — a magma-only compliance annotation.
                "allow_public_ingress": true
            }),
            &ty,
        )
        .expect("extra keys must not make encoding fail");

        let CtyValue::Object(m) = v else {
            panic!("expected an object");
        };
        assert!(
            !m.contains_key("allow_public_ingress"),
            "an unknown attribute must never reach the provider payload"
        );
        assert_eq!(m.len(), 2, "exactly the schema's attributes, no more");
        assert_eq!(m.get("type"), Some(&CtyValue::String("ingress".into())));
    }
}
