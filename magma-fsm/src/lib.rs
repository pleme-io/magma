//! magma-fsm — typed reconcile lifecycle state machine.
//!
//! Every reconcile is a state machine. Today most operators model
//! it implicitly (a tangle of bool flags + timestamps). This crate
//! makes it explicit + typed:
//!
//! ```text
//! Idle ──→ Planning ──→ Approving ──→ Applying ──→ Verifying ──→ Stable
//!                                            │           │
//!                                            ↓           ↓
//!                                          Failed ───→ Retrying ──→ Stable
//!                                            ↓
//!                                         Refused (terminal)
//! ```
//!
//! Each `Transition` carries timestamps + the typed plan_id + a
//! reason. The whole `LifecycleState` is serializable so the
//! operator's reconcile state survives pod restarts.
//!
//! Per `theory/CONVERGENCE-SUBSTRATE.md` §IV.5.

#![deny(unsafe_code)]

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use magma_converge::PlanId;

// ── Phase enum ────────────────────────────────────────────────────

/// Canonical reconcile phases. Every operator reconcile transitions
/// through some subset of these in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Nothing's happening; waiting for a trigger.
    Idle,
    /// `compute_plan` is in flight.
    Planning,
    /// Plan computed; awaiting approval (typed RequireApproval policy).
    Approving,
    /// `apply` is in flight.
    Applying,
    /// Apply succeeded; verifying post-conditions (read_state, drift check).
    Verifying,
    /// Steady state — desired == observed, no pending changes.
    Stable,
    /// Reconcile failed; eligible for retry.
    Failed,
    /// Operator is retrying after a transient failure.
    Retrying,
    /// Policy refused the plan; terminal until human intervention.
    Refused,
}

impl Phase {
    /// True for phases an operator should consider "done" for this
    /// reconcile cycle (next trigger restarts the loop).
    pub fn is_terminal(self) -> bool {
        matches!(self, Phase::Stable | Phase::Refused)
    }

    /// True iff a phase represents in-progress work (so a watchdog
    /// can decide whether to escalate).
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Phase::Planning | Phase::Applying | Phase::Verifying | Phase::Retrying,
        )
    }

    /// Soft-deadline budget per phase. Stuck transitions exceeding
    /// this trigger an escalation event (see
    /// `LifecycleState::is_stuck`).
    pub fn soft_deadline(self) -> Duration {
        match self {
            Phase::Planning  => Duration::seconds(120),
            Phase::Approving => Duration::seconds(86_400), // 24h — humans are slow
            Phase::Applying  => Duration::seconds(900),    // 15m default per apply
            Phase::Verifying => Duration::seconds(60),
            Phase::Retrying  => Duration::seconds(300),
            // No deadline for terminal / idle phases.
            Phase::Idle | Phase::Stable | Phase::Failed | Phase::Refused => Duration::zero(),
        }
    }
}

// ── Transition errors ─────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("disallowed transition: {from:?} → {to:?}")]
    Disallowed { from: Phase, to: Phase },
}

/// Allowed transitions. Implementing as an explicit table makes
/// "what's reachable from where" auditable.
fn is_transition_allowed(from: Phase, to: Phase) -> bool {
    use Phase::*;
    match (from, to) {
        // From Idle — always allowed to begin a reconcile cycle.
        (Idle, Planning) => true,
        // Planning paths.
        (Planning, Approving) => true,
        (Planning, Applying)  => true,  // when auto_approve = true
        (Planning, Failed)    => true,
        (Planning, Refused)   => true,  // policy denied
        (Planning, Stable)    => true,  // empty plan = already stable
        // Approving paths.
        (Approving, Applying) => true,
        (Approving, Refused)  => true,
        (Approving, Failed)   => true,  // timeout / external rejection
        // Applying paths.
        (Applying, Verifying) => true,
        (Applying, Failed)    => true,
        // Verifying paths.
        (Verifying, Stable) => true,
        (Verifying, Failed) => true,
        // Failed paths.
        (Failed, Retrying) => true,
        (Failed, Idle)     => true,  // operator chose to abandon retry
        // Retrying paths.
        (Retrying, Planning) => true, // re-plan after the cause is gone
        (Retrying, Failed)   => true, // retry budget exhausted
        // Stable can re-enter Planning (next reconcile cycle).
        (Stable, Planning) => true,
        // Refused is terminal — only operator override (back to Idle).
        (Refused, Idle) => true,
        // Idle from any non-Refused state is allowed for graceful reset.
        (_, Idle) => true,
        _ => false,
    }
}

// ── Transition record ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub from:       Phase,
    pub to:         Phase,
    pub at:         DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id:    Option<PlanId>,
    pub reason:     String,
}

// ── LifecycleState ────────────────────────────────────────────────

/// Serializable lifecycle state for a single reconcile. The
/// operator persists this in CR status (as a sub-resource); on pod
/// restart, the controller rehydrates it via serde + resumes from
/// `current`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleState {
    pub current:    Phase,
    /// Timestamp of the last transition into `current`.
    pub entered_at: DateTime<Utc>,
    /// Full transition history, newest last.
    pub history:    Vec<Transition>,
}

impl Default for LifecycleState {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleState {
    pub fn new() -> Self {
        Self {
            current:    Phase::Idle,
            entered_at: Utc::now(),
            history:    vec![],
        }
    }

    /// Number of transitions recorded.
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// True iff no transitions have occurred (still Idle).
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// Attempt a transition. Returns Ok on success (history +
    /// current updated) or Err with the disallowed pair.
    pub fn transition(
        &mut self,
        to:      Phase,
        plan_id: Option<PlanId>,
        reason:  impl Into<String>,
    ) -> Result<(), TransitionError> {
        if !is_transition_allowed(self.current, to) {
            return Err(TransitionError::Disallowed { from: self.current, to });
        }
        let now = Utc::now();
        self.history.push(Transition {
            from:    self.current,
            to,
            at:      now,
            plan_id,
            reason:  reason.into(),
        });
        self.current    = to;
        self.entered_at = now;
        Ok(())
    }

    /// True iff the current phase has exceeded its soft deadline.
    pub fn is_stuck(&self) -> bool {
        let deadline = self.current.soft_deadline();
        if deadline.is_zero() {
            return false;
        }
        let elapsed = Utc::now() - self.entered_at;
        elapsed > deadline
    }

    /// Compute elapsed time in the current phase. Useful for
    /// observability without forcing the caller to compute it.
    pub fn time_in_phase(&self) -> Duration {
        Utc::now() - self.entered_at
    }

    /// Round-trip through serde — the persistence shape.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// Restore from serialized state. Used after operator restart.
    pub fn from_json(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_is_idle() {
        let s = LifecycleState::new();
        assert_eq!(s.current, Phase::Idle);
        assert!(s.is_empty());
    }

    #[test]
    fn happy_path_idle_to_stable() {
        let mut s = LifecycleState::new();
        s.transition(Phase::Planning, None, "trigger").unwrap();
        s.transition(Phase::Applying, None, "auto_approve").unwrap();
        s.transition(Phase::Verifying, None, "applied").unwrap();
        s.transition(Phase::Stable, None, "verified").unwrap();
        assert_eq!(s.current, Phase::Stable);
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn approval_path_routes_through_approving() {
        let mut s = LifecycleState::new();
        s.transition(Phase::Planning, None, "trigger").unwrap();
        s.transition(Phase::Approving, None, "policy: critical").unwrap();
        s.transition(Phase::Applying, None, "approved").unwrap();
        s.transition(Phase::Verifying, None, "applied").unwrap();
        s.transition(Phase::Stable, None, "verified").unwrap();
        assert_eq!(s.current, Phase::Stable);
    }

    #[test]
    fn failure_into_retry_cycle() {
        let mut s = LifecycleState::new();
        s.transition(Phase::Planning, None, "x").unwrap();
        s.transition(Phase::Applying, None, "x").unwrap();
        s.transition(Phase::Failed,   None, "API 503").unwrap();
        s.transition(Phase::Retrying, None, "backoff").unwrap();
        s.transition(Phase::Planning, None, "retry: replan").unwrap();
        assert_eq!(s.current, Phase::Planning);
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn disallowed_transition_errors_typed() {
        let mut s = LifecycleState::new();
        // Idle → Verifying is not allowed.
        let err = s.transition(Phase::Verifying, None, "bogus").unwrap_err();
        assert_eq!(err, TransitionError::Disallowed {
            from: Phase::Idle,
            to:   Phase::Verifying,
        });
        // State unchanged after failed transition.
        assert_eq!(s.current, Phase::Idle);
    }

    #[test]
    fn refused_terminal_only_reset_through_idle() {
        let mut s = LifecycleState::new();
        s.transition(Phase::Planning, None, "x").unwrap();
        s.transition(Phase::Refused, None, "policy: refuse").unwrap();
        // Refused → Planning is disallowed (only Idle resets it).
        assert!(s.transition(Phase::Planning, None, "x").is_err());
        // Refused → Idle resets cleanly.
        s.transition(Phase::Idle, None, "operator override").unwrap();
        assert_eq!(s.current, Phase::Idle);
    }

    #[test]
    fn time_in_phase_grows_monotonically() {
        let s = LifecycleState::new();
        let t1 = s.time_in_phase();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t2 = s.time_in_phase();
        assert!(t2 > t1);
    }

    #[test]
    fn is_stuck_false_for_terminal_phases() {
        let s = LifecycleState {
            current:    Phase::Stable,
            entered_at: Utc::now() - Duration::days(7),
            history:    vec![],
        };
        // Stable has zero deadline → never stuck.
        assert!(!s.is_stuck());
    }

    #[test]
    fn is_stuck_true_when_active_phase_exceeds_deadline() {
        let s = LifecycleState {
            current:    Phase::Applying,
            // Stuck for 1h — Applying soft deadline is 15m.
            entered_at: Utc::now() - Duration::hours(1),
            history:    vec![],
        };
        assert!(s.is_stuck());
    }

    #[test]
    fn is_stuck_false_within_deadline() {
        let s = LifecycleState {
            current:    Phase::Applying,
            entered_at: Utc::now() - Duration::seconds(30),
            history:    vec![],
        };
        assert!(!s.is_stuck());
    }

    #[test]
    fn round_trip_through_json_preserves_full_state() {
        let mut s = LifecycleState::new();
        s.transition(Phase::Planning, Some(PlanId("abc".into())), "trigger").unwrap();
        s.transition(Phase::Applying, Some(PlanId("def".into())), "auto").unwrap();
        let json = s.to_json();
        let restored = LifecycleState::from_json(json).unwrap();
        assert_eq!(restored.current, s.current);
        assert_eq!(restored.len(), s.len());
        assert_eq!(
            restored.history[0].plan_id.as_ref().unwrap().0,
            "abc",
        );
    }

    #[test]
    fn phase_classification_helpers() {
        assert!(Phase::Stable.is_terminal());
        assert!(Phase::Refused.is_terminal());
        assert!(!Phase::Planning.is_terminal());

        assert!(Phase::Planning.is_active());
        assert!(Phase::Applying.is_active());
        assert!(Phase::Verifying.is_active());
        assert!(Phase::Retrying.is_active());
        assert!(!Phase::Idle.is_active());
        assert!(!Phase::Stable.is_active());
        assert!(!Phase::Failed.is_active());
    }

    #[test]
    fn idle_reset_always_allowed_from_non_refused() {
        for from in [Phase::Planning, Phase::Approving, Phase::Applying,
                     Phase::Verifying, Phase::Failed, Phase::Retrying, Phase::Stable] {
            let mut s = LifecycleState {
                current:    from,
                entered_at: Utc::now(),
                history:    vec![],
            };
            s.transition(Phase::Idle, None, "reset").unwrap();
            assert_eq!(s.current, Phase::Idle);
        }
    }

    #[test]
    fn approving_to_failed_handles_external_rejection_timeout() {
        let mut s = LifecycleState::new();
        s.transition(Phase::Planning,  None, "x").unwrap();
        s.transition(Phase::Approving, None, "policy").unwrap();
        s.transition(Phase::Failed,    None, "approval timed out").unwrap();
        assert_eq!(s.current, Phase::Failed);
    }
}
