//! Type-driven msgpack codec — the wire format tfplugin5/6 carry in
//! `DynamicValue.msgpack`. Byte-compatible with HashiCorp's
//! `go-cty/cty/msgpack`:
//!
//! | cty | msgpack |
//! |---|---|
//! | null (any type)    | `nil` |
//! | unknown (any type) | ext type `0`, payload `[0]` (fixext1) |
//! | bool               | bool |
//! | number             | int / uint (integral) else float64 |
//! | string             | str |
//! | list / set / tuple | array |
//! | map / object       | map (string keys) |
//! | dynamic            | 2-array `[bin(type-json), bin(value-msgpack)]` |
//!
//! Encoding is **type-driven**: the [`CtyType`] decides the shape, so a
//! `CtyValue` round-trips iff decoded under the same type — exactly the
//! go-cty contract a provider relies on.

use rmpv::Value as R;

use crate::{CtyError, CtyType, CtyValue};

/// go-cty's unknown-value extension code.
const UNKNOWN_EXT: i8 = 0;

/// Marshal a value to msgpack bytes under `ty` (the `DynamicValue.msgpack`
/// payload).
pub fn marshal(value: &CtyValue, ty: &CtyType) -> Result<Vec<u8>, CtyError> {
    let rv = to_rmpv(value, ty)?;
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &rv).map_err(|e| CtyError::Encode(e.to_string()))?;
    Ok(buf)
}

/// Unmarshal msgpack bytes into a value under `ty`.
pub fn unmarshal(bytes: &[u8], ty: &CtyType) -> Result<CtyValue, CtyError> {
    let mut cursor = bytes;
    let rv = rmpv::decode::read_value(&mut cursor).map_err(|e| CtyError::Decode(e.to_string()))?;
    from_rmpv(&rv, ty)
}

fn to_rmpv(value: &CtyValue, ty: &CtyType) -> Result<R, CtyError> {
    // null + unknown are type-independent markers.
    if value.is_null() {
        return Ok(R::Nil);
    }
    if value.is_unknown() {
        return Ok(R::Ext(UNKNOWN_EXT, vec![0]));
    }

    match ty {
        CtyType::String => match value {
            CtyValue::String(s) => Ok(R::String(s.clone().into())),
            _ => Err(mismatch("string", value)),
        },
        CtyType::Bool => match value {
            CtyValue::Bool(b) => Ok(R::Boolean(*b)),
            _ => Err(mismatch("bool", value)),
        },
        CtyType::Number => match value {
            CtyValue::Number(n) => Ok(number_to_rmpv(n)),
            _ => Err(mismatch("number", value)),
        },
        CtyType::List(elem) | CtyType::Set(elem) => match value {
            CtyValue::List(xs) | CtyValue::Set(xs) => Ok(R::Array(
                xs.iter()
                    .map(|x| to_rmpv(x, elem))
                    .collect::<Result<_, _>>()?,
            )),
            _ => Err(mismatch("list/set", value)),
        },
        CtyType::Tuple(types) => match value {
            CtyValue::Tuple(xs) => {
                if xs.len() != types.len() {
                    return Err(CtyError::Encode(format!(
                        "tuple arity mismatch: value has {}, type has {}",
                        xs.len(),
                        types.len()
                    )));
                }
                Ok(R::Array(
                    xs.iter()
                        .zip(types)
                        .map(|(x, t)| to_rmpv(x, t))
                        .collect::<Result<_, _>>()?,
                ))
            }
            _ => Err(mismatch("tuple", value)),
        },
        CtyType::Map(elem) => match value {
            CtyValue::Map(m) => Ok(R::Map(
                m.iter()
                    .map(|(k, v)| {
                        Ok::<_, CtyError>((R::String(k.clone().into()), to_rmpv(v, elem)?))
                    })
                    .collect::<Result<_, _>>()?,
            )),
            _ => Err(mismatch("map", value)),
        },
        CtyType::Object(attrs) => match value {
            CtyValue::Object(o) => {
                // Encode in the type's attribute order; a missing attr
                // encodes as null (go-cty fills absent optionals with null).
                let mut pairs = Vec::with_capacity(attrs.len());
                for (attr, aty) in attrs {
                    let av = o.get(attr).cloned().unwrap_or(CtyValue::Null);
                    pairs.push((R::String(attr.clone().into()), to_rmpv(&av, aty)?));
                }
                Ok(R::Map(pairs))
            }
            _ => Err(mismatch("object", value)),
        },
        CtyType::DynamicPseudoType => {
            // Self-describing wrapper: [bin(type-json), bin(value-msgpack)].
            let concrete = infer_type(value)?;
            let type_json = serde_json::to_vec(&concrete.to_json())
                .map_err(|e| CtyError::Encode(format!("dynamic type json: {e}")))?;
            let val_bytes = marshal(value, &concrete)?;
            Ok(R::Array(vec![R::Binary(type_json), R::Binary(val_bytes)]))
        }
    }
}

fn from_rmpv(rv: &R, ty: &CtyType) -> Result<CtyValue, CtyError> {
    match rv {
        R::Nil => return Ok(CtyValue::Null),
        R::Ext(code, _) if *code == UNKNOWN_EXT => return Ok(CtyValue::Unknown),
        _ => {}
    }

    match ty {
        CtyType::String => rv
            .as_str()
            .map(|s| CtyValue::String(s.to_string()))
            .ok_or_else(|| decode_mismatch("string", rv)),
        CtyType::Bool => rv
            .as_bool()
            .map(CtyValue::Bool)
            .ok_or_else(|| decode_mismatch("bool", rv)),
        CtyType::Number => rmpv_to_number(rv),
        CtyType::List(elem) => Ok(CtyValue::List(decode_seq(rv, elem)?)),
        CtyType::Set(elem) => Ok(CtyValue::Set(decode_seq(rv, elem)?)),
        CtyType::Tuple(types) => {
            let arr = rv.as_array().ok_or_else(|| decode_mismatch("tuple", rv))?;
            if arr.len() != types.len() {
                return Err(CtyError::Decode(format!(
                    "tuple arity mismatch: msgpack has {}, type has {}",
                    arr.len(),
                    types.len()
                )));
            }
            Ok(CtyValue::Tuple(
                arr.iter()
                    .zip(types)
                    .map(|(v, t)| from_rmpv(v, t))
                    .collect::<Result<_, _>>()?,
            ))
        }
        CtyType::Map(elem) => Ok(CtyValue::Map(decode_map(rv, elem)?)),
        CtyType::Object(attrs) => {
            let pairs = rv.as_map().ok_or_else(|| decode_mismatch("object", rv))?;
            let mut out = std::collections::BTreeMap::new();
            for (k, v) in pairs {
                let key = k
                    .as_str()
                    .ok_or_else(|| CtyError::Decode("object key not a string".into()))?;
                if let Some(aty) = attrs.get(key) {
                    out.insert(key.to_string(), from_rmpv(v, aty)?);
                }
                // Unknown attrs (provider sent extra) are dropped — the
                // type is authoritative, matching go-cty's behavior.
            }
            Ok(CtyValue::Object(out))
        }
        CtyType::DynamicPseudoType => {
            let arr = rv
                .as_array()
                .ok_or_else(|| decode_mismatch("dynamic", rv))?;
            if arr.len() != 2 {
                return Err(CtyError::Decode("dynamic wrapper must be a 2-array".into()));
            }
            let type_bytes = arr[0]
                .as_slice()
                .ok_or_else(|| CtyError::Decode("dynamic type not bin".into()))?;
            let type_json: serde_json::Value = serde_json::from_slice(type_bytes)
                .map_err(|e| CtyError::Decode(format!("dynamic type json: {e}")))?;
            let concrete = CtyType::from_json(&type_json)?;
            let val_bytes = arr[1]
                .as_slice()
                .ok_or_else(|| CtyError::Decode("dynamic value not bin".into()))?;
            unmarshal(val_bytes, &concrete)
        }
    }
}

fn decode_seq(rv: &R, elem: &CtyType) -> Result<Vec<CtyValue>, CtyError> {
    let arr = rv
        .as_array()
        .ok_or_else(|| decode_mismatch("list/set", rv))?;
    arr.iter().map(|v| from_rmpv(v, elem)).collect()
}

fn decode_map(
    rv: &R,
    elem: &CtyType,
) -> Result<std::collections::BTreeMap<String, CtyValue>, CtyError> {
    let pairs = rv.as_map().ok_or_else(|| decode_mismatch("map", rv))?;
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in pairs {
        let key = k
            .as_str()
            .ok_or_else(|| CtyError::Decode("map key not a string".into()))?;
        out.insert(key.to_string(), from_rmpv(v, elem)?);
    }
    Ok(out)
}

fn number_to_rmpv(n: &serde_json::Number) -> R {
    if let Some(i) = n.as_i64() {
        R::Integer(i.into())
    } else if let Some(u) = n.as_u64() {
        R::Integer(u.into())
    } else if let Some(f) = n.as_f64() {
        R::F64(f)
    } else {
        R::Nil
    }
}

fn rmpv_to_number(rv: &R) -> Result<CtyValue, CtyError> {
    match rv {
        R::Integer(i) => {
            if let Some(i) = i.as_i64() {
                Ok(CtyValue::Number(serde_json::Number::from(i)))
            } else if let Some(u) = i.as_u64() {
                Ok(CtyValue::Number(serde_json::Number::from(u)))
            } else {
                Err(CtyError::Decode("integer out of range".into()))
            }
        }
        R::F64(f) => serde_json::Number::from_f64(*f)
            .map(CtyValue::Number)
            .ok_or_else(|| CtyError::Decode("non-finite float".into())),
        R::F32(f) => serde_json::Number::from_f64(*f as f64)
            .map(CtyValue::Number)
            .ok_or_else(|| CtyError::Decode("non-finite float".into())),
        _ => Err(decode_mismatch("number", rv)),
    }
}

/// Infer a concrete `CtyType` from a value, for the `DynamicPseudoType`
/// wrapper. Collections infer from their first element (empty ⇒ a
/// dynamic element type, which round-trips). Null/unknown can't reach
/// here (handled before).
fn infer_type(value: &CtyValue) -> Result<CtyType, CtyError> {
    Ok(match value {
        CtyValue::Bool(_) => CtyType::Bool,
        CtyValue::Number(_) => CtyType::Number,
        CtyValue::String(_) => CtyType::String,
        CtyValue::List(xs) | CtyValue::Set(xs) => {
            let e = xs
                .first()
                .map(infer_type)
                .transpose()?
                .unwrap_or(CtyType::DynamicPseudoType);
            CtyType::list(e)
        }
        CtyValue::Tuple(xs) => CtyType::Tuple(xs.iter().map(infer_type).collect::<Result<_, _>>()?),
        CtyValue::Map(m) => {
            let e = m
                .values()
                .next()
                .map(infer_type)
                .transpose()?
                .unwrap_or(CtyType::DynamicPseudoType);
            CtyType::map(e)
        }
        CtyValue::Object(o) => CtyType::Object(
            o.iter()
                .map(|(k, v)| Ok::<_, CtyError>((k.clone(), infer_type(v)?)))
                .collect::<Result<_, _>>()?,
        ),
        CtyValue::Null | CtyValue::Unknown => CtyType::DynamicPseudoType,
    })
}

fn mismatch(expected: &str, value: &CtyValue) -> CtyError {
    CtyError::Encode(format!(
        "value {value:?} does not match cty type {expected}"
    ))
}

fn decode_mismatch(expected: &str, rv: &R) -> CtyError {
    CtyError::Decode(format!("msgpack {rv:?} does not decode as cty {expected}"))
}
