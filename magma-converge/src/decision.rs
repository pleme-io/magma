//! `Decision` (+ its generic `PoolDecisionDemo` reference impl + law
//! tests) was RE-HOMED to lightweight `shigoto-types::decision`
//! (2026-06-02, theory/CONVERGENCE-ADOPTION.md) — it is a pure, general
//! pure-decision-function primitive with no IaC coupling, and keeping it
//! in magma-converge forced lightweight controllers (tatara/pangea/lava)
//! to take magma's whole executor closure to adopt it. Re-exported here
//! for back-compat; the canonical definition + tests now live next to the
//! sibling convergence primitives in shigoto-types.

pub use shigoto_types::decision::{
    ClockNow, Decision, PoolDecisionDemo, PoolDecisionDemoImpl, PoolPolicyDemo, PoolStateDemo,
};
