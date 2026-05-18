//! tatara-lite — minimal s-expression reader for the M0.7 `deforch`
//! surface. Recognizes a tightly-typed subset of tatara-lisp:
//!
//! ```scheme
//! (deforch :name "seph"
//!   :workspaces (
//!     (:name "vpc"     :dir "workspaces/seph-vpc")
//!     (:name "cluster" :dir "workspaces/seph-cluster")
//!   )
//!   :edges (
//!     (:from "vpc" :from-output "vpc_id"
//!      :to   "cluster" :to-input  "vpc_id")
//!   )
//!   :optimization (:strategy "parallel_by_tier"
//!                  :max-concurrency 4
//!                  :retries (:max 2 :backoff-ms 500)))
//! ```
//!
//! Emits the canonical FlowFile JSON shape that `magma flow run`
//! already consumes — same artifact as JSON, alternate authoring
//! surface. The full tatara-lisp crate's `defcaixa`-style derivation
//! (Pillar 12) lands when the magma-config bridge wires up tatara
//! domains; this module is the proof-by-construction interim that
//! every form maps mechanically onto the same FlowFile.
//!
//! Hyphens in keyword names convert to underscores (`:from-output` →
//! `from_output`) so the JSON serde shape lines up with FlowFile's
//! snake_case fields.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

#[derive(Debug, Clone)]
enum Sexpr {
    Atom(String),
    Str(String),
    Keyword(String),
    Int(i64),
    List(Vec<Sexpr>),
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ParseError {}

/// Parse a `(deforch …)` form and return the equivalent FlowFile-shaped
/// JSON Value.
pub fn parse_deforch(src: &str) -> Result<Value, ParseError> {
    let mut p = Parser::new(src);
    let form = p.read_sexpr()?;
    match &form {
        Sexpr::List(items) => {
            let Some(Sexpr::Atom(head)) = items.first() else {
                return Err(ParseError("top form is not a list with head atom".into()));
            };
            if head != "deforch" {
                return Err(ParseError(format!("expected (deforch …), got ({head} …)")));
            }
            let kwargs = collect_kwargs(&items[1..])?;
            deforch_to_flow_file(&kwargs)
        }
        _ => Err(ParseError("top form must be a list".into())),
    }
}

fn deforch_to_flow_file(kwargs: &BTreeMap<String, Sexpr>) -> Result<Value, ParseError> {
    let workspaces = kwargs
        .get("workspaces")
        .ok_or_else(|| ParseError(":workspaces required".into()))?;
    let workspaces_json = parse_workspace_list(workspaces)?;

    let edges_json = match kwargs.get("edges") {
        Some(edges) => parse_edge_list(edges)?,
        None => Value::Array(vec![]),
    };

    let mut out = Map::new();
    out.insert("workspaces".into(), workspaces_json);
    out.insert("edges".into(), edges_json);

    if let Some(opt) = kwargs.get("optimization") {
        out.insert("optimization".into(), sexpr_kwargs_to_json(opt)?);
    }

    Ok(Value::Object(out))
}

fn parse_workspace_list(s: &Sexpr) -> Result<Value, ParseError> {
    let items = expect_list(s, "workspaces")?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let inner_kwargs = match item {
            Sexpr::List(_) => {
                let inner = expect_list(item, "workspace entry")?;
                collect_kwargs(inner)?
            }
            _ => return Err(ParseError("workspace entry must be a list".into())),
        };
        let mut entry = Map::new();
        for k in ["name", "dir"] {
            let v = inner_kwargs
                .get(k)
                .ok_or_else(|| ParseError(format!("workspace entry missing :{k}")))?;
            entry.insert(k.into(), sexpr_to_json(v)?);
        }
        out.push(Value::Object(entry));
    }
    Ok(Value::Array(out))
}

fn parse_edge_list(s: &Sexpr) -> Result<Value, ParseError> {
    let items = expect_list(s, "edges")?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let inner = expect_list(item, "edge entry")?;
        let inner_kwargs = collect_kwargs(inner)?;
        let mut entry = Map::new();
        for k in ["from", "from_output", "to", "to_input"] {
            let v = inner_kwargs
                .get(k)
                .ok_or_else(|| ParseError(format!("edge entry missing :{}", k.replace('_', "-"))))?;
            entry.insert(k.into(), sexpr_to_json(v)?);
        }
        out.push(Value::Object(entry));
    }
    Ok(Value::Array(out))
}

fn sexpr_kwargs_to_json(s: &Sexpr) -> Result<Value, ParseError> {
    let items = expect_list(s, "kwargs form")?;
    let kw = collect_kwargs(items)?;
    let mut out = Map::new();
    for (k, v) in kw {
        // Recursive: keyword-list values become nested objects.
        let json = match &v {
            Sexpr::List(inner) if inner.first().map(|x| matches!(x, Sexpr::Keyword(_))).unwrap_or(false) => {
                sexpr_kwargs_to_json(&v)?
            }
            _ => sexpr_to_json(&v)?,
        };
        out.insert(k, json);
    }
    Ok(Value::Object(out))
}

fn sexpr_to_json(s: &Sexpr) -> Result<Value, ParseError> {
    Ok(match s {
        Sexpr::Str(v)     => Value::String(v.clone()),
        Sexpr::Int(v)     => Value::Number((*v).into()),
        Sexpr::Atom(v)    => match v.as_str() {
            "true"  => Value::Bool(true),
            "false" => Value::Bool(false),
            "nil" | "null" => Value::Null,
            _ => Value::String(v.clone()),
        },
        Sexpr::Keyword(v) => Value::String(v.clone()),
        Sexpr::List(_)    => return Err(ParseError(
            "nested non-kwarg list not supported here; expected a scalar value".into())),
    })
}

fn expect_list<'a>(s: &'a Sexpr, ctx: &str) -> Result<&'a [Sexpr], ParseError> {
    if let Sexpr::List(items) = s {
        Ok(items)
    } else {
        Err(ParseError(format!("{ctx}: expected list")))
    }
}

/// Walk `items` as a sequence of `:key value` pairs. Returns a map
/// keyed by the keyword name (hyphens replaced with underscores so
/// the JSON matches FlowFile's snake_case fields).
fn collect_kwargs(items: &[Sexpr]) -> Result<BTreeMap<String, Sexpr>, ParseError> {
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < items.len() {
        let Sexpr::Keyword(k) = &items[i] else {
            return Err(ParseError(format!(
                "expected :keyword, got {:?}", items[i])));
        };
        let key = k.replace('-', "_");
        let value = items
            .get(i + 1)
            .ok_or_else(|| ParseError(format!("dangling keyword :{k}")))?;
        out.insert(key, value.clone());
        i += 2;
    }
    Ok(out)
}

// ── Reader ────────────────────────────────────────────────────────

struct Parser<'a> {
    bytes: &'a [u8],
    pos:   usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self { bytes: src.as_bytes(), pos: 0 }
    }

    fn read_sexpr(&mut self) -> Result<Sexpr, ParseError> {
        self.skip_ws();
        if self.pos >= self.bytes.len() {
            return Err(ParseError("unexpected EOF".into()));
        }
        let c = self.bytes[self.pos];
        if c == b'(' {
            self.pos += 1;
            let mut items = Vec::new();
            loop {
                self.skip_ws();
                if self.pos >= self.bytes.len() {
                    return Err(ParseError("unterminated list".into()));
                }
                if self.bytes[self.pos] == b')' {
                    self.pos += 1;
                    break;
                }
                items.push(self.read_sexpr()?);
            }
            Ok(Sexpr::List(items))
        } else if c == b'"' {
            self.read_string()
        } else if c == b':' {
            self.pos += 1;
            let name = self.read_atom_chars();
            Ok(Sexpr::Keyword(name))
        } else if c.is_ascii_digit() || c == b'-' {
            let s = self.read_atom_chars();
            if let Ok(n) = s.parse::<i64>() {
                Ok(Sexpr::Int(n))
            } else {
                Ok(Sexpr::Atom(s))
            }
        } else {
            Ok(Sexpr::Atom(self.read_atom_chars()))
        }
    }

    fn read_string(&mut self) -> Result<Sexpr, ParseError> {
        self.pos += 1; // skip opening quote
        let mut buf = String::new();
        while self.pos < self.bytes.len() {
            let c = self.bytes[self.pos];
            if c == b'"' {
                self.pos += 1;
                return Ok(Sexpr::Str(buf));
            }
            if c == b'\\' && self.pos + 1 < self.bytes.len() {
                let nxt = self.bytes[self.pos + 1];
                buf.push(match nxt {
                    b'n' => '\n',
                    b't' => '\t',
                    b'\\' => '\\',
                    b'"' => '"',
                    _ => nxt as char,
                });
                self.pos += 2;
                continue;
            }
            buf.push(c as char);
            self.pos += 1;
        }
        Err(ParseError("unterminated string".into()))
    }

    fn read_atom_chars(&mut self) -> String {
        let mut buf = String::new();
        while self.pos < self.bytes.len() {
            let c = self.bytes[self.pos];
            if c.is_ascii_whitespace() || c == b'(' || c == b')' || c == b'"' {
                break;
            }
            buf.push(c as char);
            self.pos += 1;
        }
        buf
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            let c = self.bytes[self.pos];
            if c.is_ascii_whitespace() {
                self.pos += 1;
                continue;
            }
            if c == b';' {
                while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\n' {
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_deforch() {
        let src = r#"
            (deforch :name "seph"
              :workspaces (
                (:name "vpc"     :dir "workspaces/seph-vpc")
                (:name "cluster" :dir "workspaces/seph-cluster")
              )
              :edges (
                (:from "vpc" :from-output "vpc_id"
                 :to   "cluster" :to-input "vpc_id")
              ))
        "#;
        let v = parse_deforch(src).unwrap();
        let workspaces = v["workspaces"].as_array().unwrap();
        assert_eq!(workspaces.len(), 2);
        assert_eq!(workspaces[0]["name"], "vpc");
        assert_eq!(workspaces[1]["dir"], "workspaces/seph-cluster");
        let edges = v["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["from"], "vpc");
        assert_eq!(edges[0]["from_output"], "vpc_id");
        assert_eq!(edges[0]["to_input"], "vpc_id");
    }

    #[test]
    fn parse_with_optimization() {
        let src = r#"
            (deforch :name "x"
              :workspaces ((:name "a" :dir "/a"))
              :edges ()
              :optimization (:strategy "parallel_by_tier"
                             :max-concurrency 8
                             :retries (:max 2 :backoff-ms 500)))
        "#;
        let v = parse_deforch(src).unwrap();
        let opt = &v["optimization"];
        assert_eq!(opt["strategy"], "parallel_by_tier");
        assert_eq!(opt["max_concurrency"], 8);
        assert_eq!(opt["retries"]["backoff_ms"], 500);
    }

    #[test]
    fn rejects_non_deforch_top_form() {
        let err = parse_deforch("(other :a 1)").unwrap_err();
        assert!(err.to_string().contains("deforch"));
    }

    #[test]
    fn rejects_missing_workspaces() {
        let err = parse_deforch("(deforch :name \"x\")").unwrap_err();
        assert!(err.to_string().contains("workspaces"));
    }

    #[test]
    fn comments_are_skipped() {
        let src = r#"
            ; comment
            (deforch :name "x"
              :workspaces ()
              :edges ())
        "#;
        let v = parse_deforch(src).unwrap();
        assert!(v["workspaces"].as_array().unwrap().is_empty());
    }
}
