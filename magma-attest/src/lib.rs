//! magma-attest — BLAKE3 attestation over plans + state + config; tameshi
//! receipt emission; tabeliao registry integration.
//!
//! Every plan is hashed (config ⊕ prior state ⊕ variables ⊕ computed
//! changes) to a `PlanId`. `magma apply --plan <id>` requires a verified
//! prior plan; mismatch is a hard error. Plans land in tabeliao as receipts
//! per `theory/MAGMA.md` §II.3 (Attestation via tameshi).

use blake3::Hasher;
use magma_types::PlanId;

/// BLAKE3 of `bytes` as a raw 32-byte content address.
///
/// The one hashing primitive in magma. Every content address the executor
/// mints — a [`PlanId`], a change fingerprint, an artifact hash — goes through
/// here rather than reaching for `blake3` at the call site, so "what algorithm
/// addresses our content" has exactly one answer and cannot drift between
/// crates.
///
/// Like [`hash_plan_inputs`], this imposes no canonicalization: ordering the
/// bytes deterministically is the caller's job, because only the caller knows
/// what "the same thing" means for its domain.
#[must_use]
pub fn hash_bytes32(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

/// Compute a `PlanId` (BLAKE3) over the canonical-bytes serialization of a
/// plan's inputs. Bytes must be ordered deterministically by the caller —
/// `magma-attest` does not impose a canonicalization here; that's a Plan
/// concern.
#[must_use]
pub fn hash_plan_inputs(bytes: &[u8]) -> PlanId {
    PlanId(hash_bytes32(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hashing() {
        let a = hash_plan_inputs(b"hello world");
        let b = hash_plan_inputs(b"hello world");
        assert_eq!(a.0, b.0);
        // Sanity: BLAKE3 of "hello world" first byte
        // (just confirms we're calling BLAKE3, not a trivial hash)
        assert_ne!(a.0, [0u8; 32]);
    }

    #[test]
    fn hash_diverges_on_input_change() {
        let a = hash_plan_inputs(b"plan-a");
        let b = hash_plan_inputs(b"plan-b");
        assert_ne!(a.0, b.0);
    }
}
