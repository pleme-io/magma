//! Read the real Pangea Gemfile.lock + emit gemset.nix to stdout.
//! For manual verification: `cargo run --example emit_pangea_gemset | nix-instantiate --parse -`.

use magma_rubygems::{lockfile::parse, nix::emit_gemset};

fn main() {
    let fixture = include_str!("../tests/fixtures/pangea_architectures.Gemfile.lock");
    let lock = parse(fixture).expect("parse failed");
    let gemset = emit_gemset(&lock).expect("emit failed");
    print!("{gemset}");
}
