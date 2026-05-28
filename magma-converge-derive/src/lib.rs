//! Proc-macros for `magma-converge` primitives.
//!
//! Ships `#[derive(Discriminant)]` — PATTERN-EXTRACTION Pattern 6.
//!
//! Eleven-plus enums in `magma-converge` + `shigoto-types` ship a
//! hand-rolled `.kind()` / `.name()` / `.state()` / `.mode()` method
//! that returns the variant name as a stable lowercase / kebab-case
//! identifier. Each is a ~6-line `match self { ... }` block. This
//! derive collapses each to one attribute + one derive.
//!
//! # Usage
//!
//! ```ignore
//! use magma_converge_derive::Discriminant;
//!
//! #[derive(Discriminant)]
//! #[discriminant(method = "kind", case = "kebab")]
//! pub enum BlobStoreError {
//!     NotFound { path: String },
//!     PermissionDenied { path: String, detail: String },
//!     Transient { op: &'static str, path: String, detail: String },
//!     Permanent { op: &'static str, path: String, detail: String },
//! }
//!
//! // Auto-generated:
//! //   impl BlobStoreError {
//! //       pub const fn kind(&self) -> &'static str {
//! //           match self {
//! //               Self::NotFound { .. }          => "not-found",
//! //               Self::PermissionDenied { .. }  => "permission-denied",
//! //               Self::Transient { .. }         => "transient",
//! //               Self::Permanent { .. }         => "permanent",
//! //           }
//! //       }
//! //   }
//! ```
//!
//! # Attribute reference
//!
//! - `method = "kind"` — method name (default `"discriminant"`)
//! - `case = "kebab"` / `"snake"` / `"lower"` / `"title"` —
//!   variant-name case transformation (default `"kebab"`)
//!
//! # Per-variant override
//!
//! Attach `#[discriminant(name = "explicit-name")]` to a variant to
//! override the auto-derived name (rare; useful when the wire format
//! pre-dates the rule).

#![allow(missing_docs)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Data, DataEnum, DeriveInput, Fields, Meta, Variant};

#[derive(Clone, Copy)]
enum Case {
    Kebab,
    Snake,
    Lower,
    Title,
}

impl Case {
    fn apply(self, s: &str) -> String {
        match self {
            Case::Kebab => to_kebab(s),
            Case::Snake => to_snake(s),
            Case::Lower => s.to_ascii_lowercase(),
            Case::Title => s.to_string(),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "kebab" | "kebab-case" => Some(Case::Kebab),
            "snake" | "snake_case" => Some(Case::Snake),
            "lower" | "lowercase" => Some(Case::Lower),
            "title" | "Title" | "TitleCase" => Some(Case::Title),
            _ => None,
        }
    }
}

fn to_kebab(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

struct EnumConfig {
    method: syn::Ident,
    case: Case,
}

fn parse_enum_attr(input: &DeriveInput) -> EnumConfig {
    let mut method = "discriminant".to_string();
    let mut case = Case::Kebab;

    for attr in &input.attrs {
        if !attr.path().is_ident("discriminant") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("method") {
                let value = meta.value()?;
                let s: syn::LitStr = value.parse()?;
                method = s.value();
            } else if meta.path.is_ident("case") {
                let value = meta.value()?;
                let s: syn::LitStr = value.parse()?;
                if let Some(c) = Case::parse(&s.value()) {
                    case = c;
                }
            }
            Ok(())
        });
    }

    EnumConfig {
        method: syn::Ident::new(&method, proc_macro2::Span::call_site()),
        case,
    }
}

fn variant_explicit_name(v: &Variant) -> Option<String> {
    for attr in &v.attrs {
        if !attr.path().is_ident("discriminant") {
            continue;
        }
        if let Meta::List(_) = &attr.meta {
            let mut explicit = None;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    let value = meta.value()?;
                    let s: syn::LitStr = value.parse()?;
                    explicit = Some(s.value());
                }
                Ok(())
            });
            if explicit.is_some() {
                return explicit;
            }
        }
    }
    None
}

fn variant_pattern(v: &Variant) -> TokenStream2 {
    let name = &v.ident;
    match &v.fields {
        Fields::Unit => quote! { Self::#name },
        Fields::Unnamed(_) => quote! { Self::#name(..) },
        Fields::Named(_) => quote! { Self::#name { .. } },
    }
}

#[proc_macro_derive(Discriminant, attributes(discriminant))]
pub fn derive_discriminant(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = input.ident.clone();

    let de = match &input.data {
        Data::Enum(de) => de.clone(),
        _ => {
            return syn::Error::new_spanned(
                &enum_name,
                "#[derive(Discriminant)] is only valid on enums",
            )
            .to_compile_error()
            .into();
        }
    };

    let cfg = parse_enum_attr(&input);
    let method = &cfg.method;

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let arms = build_arms(&de, cfg.case);

    let expanded = quote! {
        impl #impl_generics #enum_name #ty_generics #where_clause {
            /// Stable variant discriminant — auto-generated by
            /// `#[derive(Discriminant)]`. The string IS the wire
            /// identifier for metrics labels / audit-log tags /
            /// rate-limit keys; renaming an existing variant is a
            /// breaking change.
            pub const fn #method(&self) -> &'static str {
                match self {
                    #(#arms),*
                }
            }
        }
    };

    expanded.into()
}

fn build_arms(de: &DataEnum, case: Case) -> Vec<TokenStream2> {
    de.variants
        .iter()
        .map(|v| {
            let pattern = variant_pattern(v);
            let name_str = variant_explicit_name(v)
                .unwrap_or_else(|| case.apply(&v.ident.to_string()));
            quote! { #pattern => #name_str }
        })
        .collect()
}
