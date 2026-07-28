//! Observation — the typed trust record for a plan's `before` side.
//!
//! # The bug this type exists to make unrepresentable
//!
//! `magma-apply`'s plan-time refresh calls `ReadResource` against every
//! state instance and NEVER drops state on uncertainty: a provider that
//! cannot be spawned, a missing schema, a decode error, an RPC failure —
//! every one of those keeps the instance unchanged and counts it
//! `kept_on_error`. That is the right behavior (refresh must never delete
//! state because a read failed), and it has exactly one consequence
//! downstream:
//!
//! > A refresh in which **every** `ReadResource` failed leaves state
//! > byte-identical, so the plan computed from it is all-`NoOp` — which is
//! > **bit-indistinguishable** from a refresh in which reality genuinely
//! > matched desired state.
//!
//! Under a provider outage or an expired credential, magma would report
//! "everything is fine" when it in fact learned *nothing*. Publishing that
//! as "reality" is publishing a lie.
//!
//! [`Observation`] is the fix: the refresh's own trustworthiness travels
//! with the artifact it qualifies, and the two cases are **different
//! values** of a type a consumer must match on — not two readings of the
//! same value that happen to differ in a counter nobody looked at.
//!
//! # Tier honesty (per the fleet UNREPRESENTABILITY doctrine)
//!
//! State the tier; never round up.
//!
//! * **Downstream of `magma-types` — truly unrepresentable.** [`Observation`]'s
//!   fields are private and there is no constructor that takes a
//!   [`Coverage`]. No crate outside `magma-types` can build an
//!   `Observation` whose coverage contradicts its counts; the attempt is a
//!   compile error (no such field, no such constructor), not a runtime
//!   check that returns `Err`.
//! * **At the serde boundary — parse-time-rejected.** [`Observation`]
//!   deserializes through a wire shape that RE-DERIVES the coverage and
//!   returns [`ObservationError::CoverageContradictsCounts`] when a forged
//!   or corrupted record disagrees. A lying record never becomes a live
//!   `Observation` value.
//! * **Inside `magma-types` — only-mitigated.** [`Observation::of`] is the
//!   single classifier and the invariant is pinned by tests. Rust cannot
//!   express "this is the only function permitted to set the field" beyond
//!   module privacy, so the honest floor here is a one-place discipline,
//!   not a proof.
//!
//! # The vacuous-guard corner
//!
//! A refresh over an EMPTY state probes nothing and therefore "never
//! failed" — the textbook vacuous guard. It gets its own
//! [`Coverage::Vacuous`] verdict rather than being folded into
//! [`Coverage::Complete`], and every [`DriftVerdict`] carries an `in_sync`
//! count so the *subject set* travels with the claim: `InSync { in_sync: 0 }`
//! is a verdict about nothing, and says so.

use serde::{Deserialize, Serialize};

/// Raw per-instance accounting of one plan-time refresh pass.
///
/// Mirrors `magma_apply::engine::RefreshReport` field-for-field. That type
/// stays where the refresh lives; this one is the border shape that travels
/// on persisted artifacts, so `magma-types` never has to depend on the
/// apply engine.
///
/// # Invariant
///
/// Every state instance the refresh considered lands in exactly one of
/// `refreshed` / `dropped_instances` / `kept_on_error`, so
/// [`probed`](Self::probed) is the size of the subject set. `dropped_resources`
/// counts whole resources whose every instance went away (it is a roll-up of
/// `dropped_instances`, never an independent subject), and
/// `suppressed_mass_drop` counts whole-resource drops the mass-drop safety
/// guard REFUSED — non-zero means a systemic read malfunction was detected.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshCounts {
    /// Instances whose attributes were updated from a real provider answer.
    pub refreshed: usize,
    /// Instances the provider reported gone (dropped from state).
    pub dropped_instances: usize,
    /// Resources dropped entirely (all their instances were gone).
    pub dropped_resources: usize,
    /// Instances kept unchanged because the read could not be performed
    /// (provider spawn failure, missing schema, encode/decode error, RPC
    /// error). **This is the count that makes a plan a lie when nobody
    /// looks at it.**
    pub kept_on_error: usize,
    /// Whole-resource drops the mass-drop safety guard suppressed and
    /// restored. Non-zero ⇒ a systemic read malfunction was detected, so
    /// the pass can never be [`Coverage::Complete`].
    pub suppressed_mass_drop: usize,
}

impl RefreshCounts {
    /// Size of the subject set: how many state instances the refresh
    /// actually considered.
    #[must_use]
    pub const fn probed(&self) -> usize {
        self.refreshed + self.dropped_instances + self.kept_on_error
    }

    /// How many of the probed instances produced a REAL provider answer
    /// ("here it is, refreshed" or "confirmed gone"). Everything else is
    /// an absence of knowledge wearing the shape of unchanged state.
    #[must_use]
    pub const fn answered(&self) -> usize {
        self.refreshed + self.dropped_instances
    }
}

/// How much of a refreshed artifact is real, observed fact.
///
/// Deliberately five-way rather than a boolean: "no drift" and "learned
/// nothing" are the two ends this type exists to keep apart, and the three
/// cases in between are each a different honest answer.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
)]
#[discriminant(method = "kind", case = "snake", also_display)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// No refresh was attempted. The `before` side is REMEMBERED state —
    /// what magma was told last time, never what the provider says now.
    /// This is the honest default, and the honest answer for
    /// `--refresh=false`.
    Unrefreshed,
    /// A refresh ran but had nothing to probe (empty state). A "complete"
    /// claim over an empty subject set proves nothing, so it gets its own
    /// verdict instead of being rounded up.
    Vacuous,
    /// Every probed instance produced a real provider answer. The `before`
    /// side is observed fact.
    Complete,
    /// Some instances answered, some could not be read. The observed half
    /// is fact; the unread half is remembered state, and NOTHING in the
    /// aggregate counts says which resource is which.
    Partial,
    /// At least one instance was probed and **zero** answered. The refresh
    /// learned nothing at all; an all-`NoOp` plan built on this coverage is
    /// not evidence of anything.
    Blind,
}

impl Coverage {
    /// True iff a "reality matches desired state" claim can rest on this
    /// coverage. [`Coverage::Partial`] is deliberately excluded: aggregate
    /// counts cannot say WHICH resources went unread, so a partial pass can
    /// confirm drift it found but can never confirm the absence of drift.
    #[must_use]
    pub const fn supports_in_sync_claim(self) -> bool {
        matches!(self, Self::Complete | Self::Vacuous)
    }
}

/// A trust record that cannot contradict itself.
///
/// Construct via [`Observation::unrefreshed`] (nothing was asked) or
/// [`Observation::of`] (a refresh ran; the coverage is DERIVED from its
/// counts). There is no constructor that accepts a [`Coverage`], so
/// `Complete`-with-failures has no code path outside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ObservationWire", into = "ObservationWire")]
pub struct Observation {
    coverage: Coverage,
    counts: RefreshCounts,
}

impl Default for Observation {
    /// The honest default for any artifact that never ran a refresh.
    fn default() -> Self {
        Self::unrefreshed()
    }
}

impl Observation {
    /// No refresh was attempted — the artifact's `before` side is
    /// remembered state.
    #[must_use]
    pub const fn unrefreshed() -> Self {
        Self {
            coverage: Coverage::Unrefreshed,
            counts: RefreshCounts {
                refreshed: 0,
                dropped_instances: 0,
                dropped_resources: 0,
                kept_on_error: 0,
                suppressed_mass_drop: 0,
            },
        }
    }

    /// Classify a completed refresh pass. **The single classifier** — the
    /// one place in the codebase where a [`Coverage`] is chosen.
    #[must_use]
    pub const fn of(counts: RefreshCounts) -> Self {
        Self {
            coverage: Self::derive_coverage(&counts),
            counts,
        }
    }

    /// The coverage ladder, derived from counts alone.
    ///
    /// Order matters and each rung is deliberate:
    ///
    /// 1. nothing probed ⇒ `Vacuous` (an empty subject set, not a pass),
    /// 2. nothing answered ⇒ `Blind` (probed and learned nothing),
    /// 3. a suppressed mass-drop ⇒ `Partial` at best — the guard fired
    ///    because reads looked systemically wrong, so the answers that DID
    ///    arrive cannot carry a completeness claim,
    /// 4. no read failures ⇒ `Complete`,
    /// 5. otherwise ⇒ `Partial`.
    const fn derive_coverage(counts: &RefreshCounts) -> Coverage {
        if counts.probed() == 0 {
            Coverage::Vacuous
        } else if counts.answered() == 0 {
            Coverage::Blind
        } else if counts.suppressed_mass_drop > 0 {
            Coverage::Partial
        } else if counts.kept_on_error == 0 {
            Coverage::Complete
        } else {
            Coverage::Partial
        }
    }

    /// How much of this observation is real.
    #[must_use]
    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }

    /// The underlying accounting, for operators and receipts.
    #[must_use]
    pub const fn counts(&self) -> &RefreshCounts {
        &self.counts
    }

    /// True iff no refresh was attempted at all.
    #[must_use]
    pub const fn is_unrefreshed(&self) -> bool {
        matches!(self.coverage, Coverage::Unrefreshed)
    }

    /// True iff a refresh ran, probed at least one instance, and learned
    /// nothing — the failure this whole module exists to surface.
    #[must_use]
    pub const fn is_blind(&self) -> bool {
        matches!(self.coverage, Coverage::Blind)
    }

    /// The honest answer to "does reality match desired state?", given a
    /// plan's change counts.
    ///
    /// `changes` is the number of non-`NoOp` resource changes; `in_sync` is
    /// the number of `NoOp` ones (resources whose desired state matched the
    /// state we hold). Total over every coverage — there is no input for
    /// which this returns "in sync" without an observation that supports
    /// the claim.
    #[must_use]
    pub const fn verdict(&self, changes: usize, in_sync: usize) -> DriftVerdict {
        if !self.coverage.supports_in_sync_claim() {
            // Partial coverage CAN confirm drift it actually found — a
            // resource that read back different is different regardless of
            // how many siblings failed to read. It can never confirm the
            // ABSENCE of drift.
            if changes > 0 && matches!(self.coverage, Coverage::Partial) {
                return DriftVerdict::Drifted {
                    changes,
                    in_sync,
                    coverage: self.coverage,
                };
            }
            return DriftVerdict::Unobserved {
                coverage: self.coverage,
                changes,
                in_sync,
            };
        }
        if changes == 0 {
            DriftVerdict::InSync { in_sync }
        } else {
            DriftVerdict::Drifted {
                changes,
                in_sync,
                coverage: self.coverage,
            }
        }
    }
}

/// What an artifact is entitled to claim about reality.
///
/// The point of the sum: a consumer asking "is there drift?" gets a value
/// it must match on, and the `Unobserved` arm has no "no" in it. There is
/// no way to read a blind refresh as a clean bill of health without
/// deleting an arm the compiler requires.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    gen_platform::Discriminant,
    gen_platform::IsVariant,
)]
#[discriminant(method = "kind", case = "snake")]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum DriftVerdict {
    /// Reality was observed and matches: `in_sync` resources confirmed
    /// correct, zero changes needed.
    ///
    /// `in_sync` IS the subject-set witness — `InSync { in_sync: 0 }` is a
    /// verdict about an empty world and must never be read as a proof that
    /// anything was checked.
    InSync { in_sync: usize },
    /// Reality was observed and differs: `changes` resources need work.
    /// `coverage` says whether the rest of the world was fully read.
    Drifted {
        changes: usize,
        in_sync: usize,
        coverage: Coverage,
    },
    /// **No claim about reality is available.** The refresh was blind,
    /// never ran, or read too little to support the absence of drift. The
    /// counts are reported so an operator can see the shape of the plan —
    /// they are NOT evidence.
    Unobserved {
        coverage: Coverage,
        changes: usize,
        in_sync: usize,
    },
}

impl DriftVerdict {
    /// True iff this verdict asserts that reality was checked and matched.
    /// The one predicate a caller should gate a "nothing to do" decision on.
    #[must_use]
    pub const fn is_confirmed_in_sync(&self) -> bool {
        matches!(self, Self::InSync { .. })
    }
}

// ── serde border: a lying record is rejected, never normalized ──────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct ObservationWire {
    coverage: Coverage,
    #[serde(default)]
    counts: RefreshCounts,
}

/// Failure modes of the observation parse boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObservationError {
    /// A serialized observation declared a coverage its own counts do not
    /// support — a forged or corrupted trust record. Rejected rather than
    /// silently corrected: silently correcting would hide that someone (or
    /// something) shipped a record claiming more knowledge than it had.
    #[error(
        "observation declares coverage `{declared}` but its refresh counts derive `{derived}` \
         (probed {probed}, answered {answered}, kept_on_error {kept_on_error})"
    )]
    CoverageContradictsCounts {
        declared: Coverage,
        derived: Coverage,
        probed: usize,
        answered: usize,
        kept_on_error: usize,
    },
}

impl TryFrom<ObservationWire> for Observation {
    type Error = ObservationError;

    fn try_from(wire: ObservationWire) -> Result<Self, Self::Error> {
        // `Unrefreshed` is the one coverage that is a statement about the
        // ABSENCE of a pass rather than a classification of one, so it is
        // accepted on its own terms (its counts are all zero by
        // construction; zeroed counts would otherwise derive `Vacuous`).
        if matches!(wire.coverage, Coverage::Unrefreshed) && wire.counts.probed() == 0 {
            return Ok(Self::unrefreshed());
        }
        let derived = Self::derive_coverage(&wire.counts);
        if derived == wire.coverage {
            Ok(Self {
                coverage: derived,
                counts: wire.counts,
            })
        } else {
            Err(ObservationError::CoverageContradictsCounts {
                declared: wire.coverage,
                derived,
                probed: wire.counts.probed(),
                answered: wire.counts.answered(),
                kept_on_error: wire.counts.kept_on_error,
            })
        }
    }
}

impl From<Observation> for ObservationWire {
    fn from(o: Observation) -> Self {
        Self {
            coverage: o.coverage,
            counts: o.counts,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(refreshed: usize, dropped: usize, kept_on_error: usize) -> RefreshCounts {
        RefreshCounts {
            refreshed,
            dropped_instances: dropped,
            dropped_resources: 0,
            kept_on_error,
            suppressed_mass_drop: 0,
        }
    }

    #[test]
    fn every_read_failing_is_blind_never_complete() {
        let o = Observation::of(counts(0, 0, 7));
        assert_eq!(o.coverage(), Coverage::Blind);
        assert!(o.is_blind());
    }

    #[test]
    fn every_read_succeeding_is_complete() {
        let o = Observation::of(counts(7, 0, 0));
        assert_eq!(o.coverage(), Coverage::Complete);
    }

    #[test]
    fn confirmed_gone_counts_as_a_real_answer() {
        // "The provider says it is gone" is knowledge, not a failure.
        let o = Observation::of(counts(0, 3, 0));
        assert_eq!(o.coverage(), Coverage::Complete);
    }

    #[test]
    fn a_single_read_failure_downgrades_to_partial() {
        let o = Observation::of(counts(6, 0, 1));
        assert_eq!(o.coverage(), Coverage::Partial);
    }

    #[test]
    fn an_empty_probe_set_is_vacuous_not_complete() {
        let o = Observation::of(counts(0, 0, 0));
        assert_eq!(
            o.coverage(),
            Coverage::Vacuous,
            "a refresh that probed nothing must never claim completeness",
        );
    }

    #[test]
    fn a_suppressed_mass_drop_can_never_be_complete() {
        // Reads "succeeded" but the guard says they were systemically
        // wrong. Zero kept_on_error must NOT round up to Complete.
        let o = Observation::of(RefreshCounts {
            refreshed: 4,
            dropped_instances: 0,
            dropped_resources: 0,
            kept_on_error: 0,
            suppressed_mass_drop: 5,
        });
        assert_eq!(o.coverage(), Coverage::Partial);
    }

    #[test]
    fn probed_partitions_the_subject_set() {
        let c = counts(2, 3, 4);
        assert_eq!(c.probed(), 9);
        assert_eq!(c.answered(), 5);
    }

    // ── The verdict ladder ──────────────────────────────────────

    #[test]
    fn a_blind_refresh_can_never_yield_an_in_sync_verdict() {
        let blind = Observation::of(counts(0, 0, 12));
        // Twelve resources, all NoOp, zero changes — the exact shape of a
        // clean reconcile. The verdict refuses to say so.
        let v = blind.verdict(0, 12);
        assert!(!v.is_confirmed_in_sync());
        assert!(matches!(
            v,
            DriftVerdict::Unobserved {
                coverage: Coverage::Blind,
                ..
            }
        ));
    }

    #[test]
    fn a_clean_refresh_over_the_same_shape_does_yield_in_sync() {
        let clean = Observation::of(counts(12, 0, 0));
        let v = clean.verdict(0, 12);
        assert!(v.is_confirmed_in_sync());
        assert_eq!(v, DriftVerdict::InSync { in_sync: 12 });
    }

    #[test]
    fn unrefreshed_never_claims_in_sync() {
        let v = Observation::unrefreshed().verdict(0, 12);
        assert!(matches!(
            v,
            DriftVerdict::Unobserved {
                coverage: Coverage::Unrefreshed,
                ..
            }
        ));
    }

    #[test]
    fn partial_confirms_found_drift_but_never_its_absence() {
        let partial = Observation::of(counts(6, 0, 1));
        assert!(matches!(
            partial.verdict(2, 4),
            DriftVerdict::Drifted { changes: 2, .. }
        ));
        assert!(
            matches!(partial.verdict(0, 6), DriftVerdict::Unobserved { .. }),
            "aggregate counts cannot say WHICH resource went unread, so a \
             partial pass can never confirm the absence of drift",
        );
    }

    #[test]
    fn in_sync_carries_its_subject_set_witness() {
        // A vacuous pass is in-sync about NOTHING, and the count says so.
        let v = Observation::of(counts(0, 0, 0)).verdict(0, 0);
        assert_eq!(v, DriftVerdict::InSync { in_sync: 0 });
    }

    // ── The parse boundary ──────────────────────────────────────

    #[test]
    fn observation_round_trips_through_serde() {
        for o in [
            Observation::unrefreshed(),
            Observation::of(counts(0, 0, 3)),
            Observation::of(counts(3, 0, 0)),
            Observation::of(counts(3, 1, 2)),
            Observation::of(counts(0, 0, 0)),
        ] {
            let json = serde_json::to_string(&o).unwrap();
            let back: Observation = serde_json::from_str(&json).unwrap();
            assert_eq!(o, back);
        }
    }

    #[test]
    fn a_forged_complete_record_is_rejected_at_the_parse_boundary() {
        // Someone (or a corrupted store) claims a clean observation while
        // the counts say every read failed. Rejected, not normalized.
        let forged = serde_json::json!({
            "coverage": "complete",
            "counts": {
                "refreshed": 0,
                "dropped_instances": 0,
                "dropped_resources": 0,
                "kept_on_error": 9,
                "suppressed_mass_drop": 0
            }
        });
        let err = serde_json::from_value::<Observation>(forged).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("complete") && msg.contains("blind"),
            "the rejection must name both the claim and the truth: {msg}",
        );
    }

    #[test]
    fn a_forged_unrefreshed_record_with_probes_is_rejected() {
        let forged = serde_json::json!({
            "coverage": "unrefreshed",
            "counts": {
                "refreshed": 4,
                "dropped_instances": 0,
                "dropped_resources": 0,
                "kept_on_error": 0,
                "suppressed_mass_drop": 0
            }
        });
        assert!(serde_json::from_value::<Observation>(forged).is_err());
    }

    #[test]
    fn the_default_observation_is_the_honest_one() {
        assert!(Observation::default().is_unrefreshed());
        assert!(!Observation::default().verdict(0, 5).is_confirmed_in_sync());
    }
}
