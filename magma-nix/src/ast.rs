//! Typed Nix expression AST (M8.0 destination).
//!
//! Mirrors `theory/NIX-AST.md`'s canonical NixValue shape. Every
//! emitter that produces Nix syntax (`flake.nix`, home-manager
//! modules, gemset.nix, NixOS configurations) builds this typed
//! tree + renders through one canonical pretty-printer. Refuses
//! string-concatenation of Nix syntax (the antipattern this
//! crate eliminates).

use serde::{Deserialize, Serialize};

/// One Nix expression node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expr {
    /// Literal int / float.
    Int(i64),
    Float(f64),
    /// String literal (interior interpolations modeled as
    /// `InterpolatedString`).
    String(String),
    /// String with embedded `${...}` interpolation.
    InterpolatedString {
        parts: Vec<StringPart>,
    },
    /// Boolean literal.
    Bool(bool),
    /// `null`.
    Null,
    /// Path literal (`./foo`, `/abs`, `<nixpkgs>`).
    Path(String),
    /// Identifier (`pkgs`, `lib`, `stdenv`).
    Ident(String),
    /// Function lambda: `arg: body` or `{a, b ? default}: body`.
    Lambda {
        params: Vec<LambdaParam>,
        body: Box<Expr>,
    },
    /// Function application: `f x`.
    Apply {
        func: Box<Expr>,
        arg: Box<Expr>,
    },
    /// `let bindings; in body`.
    Let {
        bindings: Vec<Binding>,
        body: Box<Expr>,
    },
    /// `with set; body`.
    With {
        scope: Box<Expr>,
        body: Box<Expr>,
    },
    /// `if c then a else b`.
    If {
        condition: Box<Expr>,
        then_branch: Box<Expr>,
        else_branch: Box<Expr>,
    },
    /// Attribute set `{ a = ...; b = ...; }`.
    AttrSet {
        recursive: bool,
        bindings: Vec<Binding>,
    },
    /// List `[ a b c ]`.
    List(Vec<Expr>),
    /// Selection `set.attr`.
    Select {
        set: Box<Expr>,
        path: Vec<String>,
        or_default: Option<Box<Expr>>,
    },
    /// Binary op `a + b`.
    BinOp {
        op: BinaryOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// `inherit a b c;` inside an attribute set.
    Inherit {
        from: Option<Box<Expr>>,
        names: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StringPart {
    Lit(String),
    Interp(Expr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaParam {
    pub name: String,
    pub default: Option<Expr>,
    /// True for the `...` ellipsis in `{a, b, ...}: body`.
    #[serde(default)]
    pub ellipsis: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub name: String,
    pub value: Expr,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Impl,
    Concat,
    Update,
    HasAttr,
}
