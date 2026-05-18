//! magma-test — compatibility test harness.
//!
//! Tier 1 / 2 / 3 providers × 5 test levels (smoke / schema / plan-diff /
//! state-roundtrip / real-cloud-apply) per `theory/MAGMA.md` §II.6. The
//! non-negotiable release gate: any Tier 1 regression blocks release.
//!
//! Skeleton: real fixtures + the `magma_test!` macro + the InSpec
//! integration land in M0 as the corpus comes online.

/// Test level — what a particular test case proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Provider binary spawns, handshake completes, schema reads. No cloud cost.
    Smoke,
    /// Loaded provider schema is byte-equal to tofu's. No cloud cost.
    SchemaDiff,
    /// `magma plan` output is byte-equal to `tofu show -json` on identical inputs. No cloud cost.
    PlanDiff,
    /// state files round-trip byte-equal in both directions. No cloud cost.
    StateRoundTrip,
    /// `magma apply` produces resources functionally indistinguishable from `tofu apply`. Cloud cost.
    Apply,
}

/// Test corpus tier — see `theory/MAGMA.md` §II.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// pleme-io's own usage. M0 gate, every level.
    One,
    /// Most-downloaded public providers. M2 gate, levels 1-4.
    Two,
    /// Protocol-edge-case providers. Ongoing, targeted.
    Three,
}
