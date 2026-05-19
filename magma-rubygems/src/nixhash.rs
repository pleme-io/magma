//! Nix-base32 hash encoding — the alphabet `nix-hash` emits.
//!
//! Nix stores cryptographic hashes (sha256, sha1, md5) in a
//! custom base32 alphabet (`0123456789abcdfghijklmnpqrsvwxyz` —
//! lowercase + digits, omitting `e`, `o`, `t`, `u` to avoid
//! confusable look-alikes). Output is little-endian, 52 chars
//! for sha256 / 32 chars for sha1 / 26 chars for md5.
//!
//! This module ships the encoder so M3 fetcher (or any other
//! magma primitive that needs to interop with Nix store paths)
//! can produce the exact `sha256-<base32>` format nix-build
//! expects.
//!
//! Reference: <https://github.com/NixOS/nix/blob/master/src/libutil/hash.cc>

/// Nix's custom base32 alphabet, omitting `e`, `o`, `t`, `u`.
const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Encode arbitrary bytes as nix-base32 (little-endian, no padding).
/// Output length is `ceil(bytes.len() * 8 / 5)`:
/// * sha256 (32 bytes) -> 52 chars
/// * sha1   (20 bytes) -> 32 chars
/// * md5    (16 bytes) -> 26 chars
pub fn encode(input: &[u8]) -> String {
    let len = (input.len() * 8 + 4) / 5;
    let mut out = String::with_capacity(len);
    // Emit chars from MSB; same order Nix's nix-hash uses.
    for n in (0..len).rev() {
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;
        let c = (u16::from(input[i]) >> j as u32)
            | input
                .get(i + 1)
                .map(|x| (u16::from(*x) << (8 - j as u32)))
                .unwrap_or(0);
        out.push(ALPHABET[(c & 0x1f) as usize] as char);
    }
    out
}

/// Compute the sha256 of `input` + encode as `sha256-<base32>`
/// (the SRI-ish format Nix accepts in `fetchurl` directives).
pub fn sha256_nix(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    encode(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference output computed by `nix-hash --type sha256 --to-base32`
    /// for the empty string's sha256.
    #[test]
    fn empty_sha256_encodes_to_known_nix_base32() {
        let got = sha256_nix(b"");
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // nix-base32(that 32-byte sha256) = 0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73
        assert_eq!(got, "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73");
        assert_eq!(got.len(), 52);
    }

    #[test]
    fn output_length_is_52_for_sha256() {
        let got = sha256_nix(b"hello world");
        assert_eq!(got.len(), 52);
        assert!(got.chars().all(|c| ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn encoding_is_deterministic() {
        let a = sha256_nix(b"pangea-core-0.3.0.gem");
        let b = sha256_nix(b"pangea-core-0.3.0.gem");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_distinct_outputs() {
        assert_ne!(sha256_nix(b"a"), sha256_nix(b"b"));
    }
}
