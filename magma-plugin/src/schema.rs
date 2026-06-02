//! Provider schema → cty implied type (terraform's `Block.ImpliedType`).
//!
//! A tfplugin6 resource `Schema` describes a resource as a `Block` of
//! typed attributes + nested blocks. To marshal a resource's attributes
//! onto the wire as a [`DynamicValue`](magma_cty::DynamicValue), magma
//! needs the resource's **implied cty type** — the object type the
//! `Block` describes. This module derives it, composing
//! [`magma_cty::CtyType`] with the attributes' go-cty JSON type
//! encodings (which [`CtyType::from_json`] already parses).
//!
//! This is the bridge between `GetProviderSchema` and the apply codec:
//! `schema → CtyType`, then `magma_cty` encodes the rendered attributes
//! against that type for `ApplyResourceChange`.

use std::collections::BTreeMap;

use magma_cty::CtyType;
use magma_protocol::tfplugin6::schema::{self, Attribute, Block, NestedBlock, Object};

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("attribute {0:?} has neither a type nor a nested_type")]
    AttributeNoType(String),
    #[error("cty type decode for {0:?}: {1}")]
    Cty(String, magma_cty::CtyError),
    #[error("invalid nesting mode {0} for {1:?}")]
    BadNesting(i32, String),
    #[error("nested block {0:?} has no inner block")]
    EmptyNestedBlock(String),
}

/// The implied cty object type of a resource / provider / data-source
/// `Block` — attributes plus nested blocks, in a single object type.
pub fn block_implied_type(block: &Block) -> Result<CtyType, SchemaError> {
    let mut attrs: BTreeMap<String, CtyType> = BTreeMap::new();
    for attr in &block.attributes {
        attrs.insert(attr.name.clone(), attribute_type(attr)?);
    }
    for nb in &block.block_types {
        attrs.insert(nb.type_name.clone(), nested_block_type(nb)?);
    }
    Ok(CtyType::Object(attrs))
}

/// An attribute's cty type: a `nested_type` object (wrapped by its
/// nesting) takes precedence over the scalar go-cty-JSON `type` bytes.
fn attribute_type(attr: &Attribute) -> Result<CtyType, SchemaError> {
    if let Some(obj) = &attr.nested_type {
        return object_implied_type(obj, &attr.name);
    }
    if attr.r#type.is_empty() {
        return Err(SchemaError::AttributeNoType(attr.name.clone()));
    }
    let json: serde_json::Value = serde_json::from_slice(&attr.r#type).map_err(|e| {
        SchemaError::Cty(attr.name.clone(), magma_cty::CtyError::Type(e.to_string()))
    })?;
    CtyType::from_json(&json).map_err(|e| SchemaError::Cty(attr.name.clone(), e))
}

/// A `nested_type` `Object` → cty type, wrapped per its nesting mode.
fn object_implied_type(obj: &Object, label: &str) -> Result<CtyType, SchemaError> {
    let mut attrs = BTreeMap::new();
    for attr in &obj.attributes {
        attrs.insert(attr.name.clone(), attribute_type(attr)?);
    }
    let inner = CtyType::Object(attrs);
    let nesting = schema::object::NestingMode::try_from(obj.nesting)
        .map_err(|_| SchemaError::BadNesting(obj.nesting, label.to_string()))?;
    Ok(match nesting {
        schema::object::NestingMode::Single | schema::object::NestingMode::Invalid => inner,
        schema::object::NestingMode::List => CtyType::list(inner),
        schema::object::NestingMode::Set => CtyType::set(inner),
        schema::object::NestingMode::Map => CtyType::map(inner),
    })
}

/// A `NestedBlock` → cty type, wrapped per its nesting mode. `Single` /
/// `Group` imply a bare object; `List` / `Set` / `Map` wrap it.
fn nested_block_type(nb: &NestedBlock) -> Result<CtyType, SchemaError> {
    let block = nb
        .block
        .as_ref()
        .ok_or_else(|| SchemaError::EmptyNestedBlock(nb.type_name.clone()))?;
    let inner = block_implied_type(block)?;
    let nesting = schema::nested_block::NestingMode::try_from(nb.nesting)
        .map_err(|_| SchemaError::BadNesting(nb.nesting, nb.type_name.clone()))?;
    Ok(match nesting {
        schema::nested_block::NestingMode::Single
        | schema::nested_block::NestingMode::Group
        | schema::nested_block::NestingMode::Invalid => inner,
        schema::nested_block::NestingMode::List => CtyType::list(inner),
        schema::nested_block::NestingMode::Set => CtyType::set(inner),
        schema::nested_block::NestingMode::Map => CtyType::map(inner),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a go-cty JSON type into the `Attribute.type` bytes form.
    fn ty_bytes(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    fn attr(name: &str, ty: serde_json::Value) -> Attribute {
        Attribute {
            name: name.into(),
            r#type: ty_bytes(ty),
            ..Default::default()
        }
    }

    fn block(attributes: Vec<Attribute>, block_types: Vec<NestedBlock>) -> Block {
        Block {
            attributes,
            block_types,
            ..Default::default()
        }
    }

    #[test]
    fn simple_scalar_attributes() {
        let b = block(
            vec![
                attr("name", serde_json::json!("string")),
                attr("private", serde_json::json!("bool")),
                attr("retries", serde_json::json!("number")),
            ],
            vec![],
        );
        let ty = block_implied_type(&b).unwrap();
        let expected = CtyType::object([
            ("name".into(), CtyType::String),
            ("private".into(), CtyType::Bool),
            ("retries".into(), CtyType::Number),
        ]);
        assert_eq!(ty, expected);
    }

    #[test]
    fn collection_attribute_types() {
        let b = block(
            vec![
                attr("topics", serde_json::json!(["list", "string"])),
                attr("labels", serde_json::json!(["map", "string"])),
            ],
            vec![],
        );
        let ty = block_implied_type(&b).unwrap();
        let expected = CtyType::object([
            ("topics".into(), CtyType::list(CtyType::String)),
            ("labels".into(), CtyType::map(CtyType::String)),
        ]);
        assert_eq!(ty, expected);
    }

    #[test]
    fn nested_block_list_becomes_list_of_object() {
        // github_repository's `pages { source { branch=string } }`-shape.
        let inner = block(vec![attr("branch", serde_json::json!("string"))], vec![]);
        let nb = NestedBlock {
            type_name: "pages".into(),
            block: Some(inner),
            nesting: schema::nested_block::NestingMode::List as i32,
            ..Default::default()
        };
        let b = block(vec![attr("name", serde_json::json!("string"))], vec![nb]);
        let ty = block_implied_type(&b).unwrap();
        let expected = CtyType::object([
            ("name".into(), CtyType::String),
            (
                "pages".into(),
                CtyType::list(CtyType::object([("branch".into(), CtyType::String)])),
            ),
        ]);
        assert_eq!(ty, expected);
    }

    #[test]
    fn nested_block_single_is_bare_object() {
        let inner = block(vec![attr("id".into(), serde_json::json!("string"))], vec![]);
        let nb = NestedBlock {
            type_name: "template".into(),
            block: Some(inner),
            nesting: schema::nested_block::NestingMode::Single as i32,
            ..Default::default()
        };
        let b = block(vec![], vec![nb]);
        let ty = block_implied_type(&b).unwrap();
        let expected = CtyType::object([(
            "template".into(),
            CtyType::object([("id".into(), CtyType::String)]),
        )]);
        assert_eq!(ty, expected);
    }

    #[test]
    fn nested_type_object_map() {
        // Attribute with a nested_type Object, MAP nesting.
        let obj = Object {
            attributes: vec![attr("v", serde_json::json!("string"))],
            nesting: schema::object::NestingMode::Map as i32,
            ..Default::default()
        };
        let a = Attribute {
            name: "entries".into(),
            nested_type: Some(obj),
            ..Default::default()
        };
        let b = block(vec![a], vec![]);
        let ty = block_implied_type(&b).unwrap();
        let expected = CtyType::object([(
            "entries".into(),
            CtyType::map(CtyType::object([("v".into(), CtyType::String)])),
        )]);
        assert_eq!(ty, expected);
    }

    #[test]
    fn attribute_without_type_is_an_error() {
        let a = Attribute {
            name: "broken".into(),
            ..Default::default()
        };
        let b = block(vec![a], vec![]);
        assert!(matches!(
            block_implied_type(&b),
            Err(SchemaError::AttributeNoType(_))
        ));
    }
}
