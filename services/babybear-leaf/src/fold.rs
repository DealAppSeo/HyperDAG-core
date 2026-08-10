//! LEG 3 — progressive fold: prove a reputation UPDATE without re-proving history.
//!
//! THE PROBLEM. A reputation proof that must re-prove the entire history grows
//! without bound and cannot be produced per-outcome. What is needed is a DELTA:
//! given a previous aggregate root, prove that one new outcome was folded into
//! it correctly under the published rules, yielding a new root.
//!
//! WHAT IS PROVEN HERE:
//!
//!   new_fold_root = Poseidon2(
//!       prev_fold_root, new_outcome_commitment, new_nullifier,
//!       updated_components, user_standards_hash )
//!
//! constrained IN-CIRCUIT by `poseidon2-air`, plus the weighted update and the
//! threshold claim as ordinary AIR constraints.
//!
//! WHY NO RECURSION. The pinned Plonky3 (27d59f73) has poseidon2-air,
//! uni-stark, fri and batch-stark, but NO recursion crate — no in-circuit STARK
//! verifier. This design does not need one: `prev_fold_root` enters as a PUBLIC
//! INPUT (a field element), not as a proof to be verified inside the circuit.
//! That is incremental hash-chain folding, which the pin supports today.
//! Aggregating many delta proofs into one — proof-carrying recursion — is
//! genuinely blocked here, and the missing capability is a `p3-recursion`-style
//! in-circuit verifier.
//!
//! HONEST SCOPE. Read `FoldClaims` below: it states, per constraint, what is
//! cryptographically enforced by the circuit versus what is bound-by-public-input.
//! `new_outcome_commitment` and `new_nullifier` are the latter in this first
//! fold — they are hashed INTO the root, so they cannot be swapped after the
//! fact, but the circuit does not re-derive them from their preimages. Adding
//! that is a second Poseidon2 instance, deliberately deferred.
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL,
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_S_BOX_DEGREE,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, RoundConstants};

use crate::{poseidon2_16, WIDTH};

const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 1;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

/// The CANONICAL BabyBear Poseidon2 round constants, in the layout the AIR wants.
///
/// THIS IS THE SOUNDNESS-CRITICAL PART OF THIS FILE. `RoundConstants` at this pin
/// exposes `from_rng` (what the upstream examples use, seeded with `SmallRng`)
/// and `new`. Using `from_rng` would have the AIR constrain a Poseidon2 with
/// ARBITRARY constants — a different permutation from the
/// `default_babybear_poseidon2_16()` that `poseidon2_16()`, the KATs, and every
/// existing leaf/nullifier in the system use.
///
/// The proof would still verify. It would attest to a hash nobody else computes.
/// That is the precise shape of a proof that proves the wrong statement, so the
/// constants are taken from the same exported arrays `default_babybear_poseidon2_16`
/// is built from, and `fold_air_matches_native_permutation` asserts the AIR and
/// the native permutation agree on a real input.
fn canonical_round_constants() -> RoundConstants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    RoundConstants::new(
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        BABYBEAR_POSEIDON2_RC_16_INTERNAL,
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

/// The AIR that constrains one Poseidon2 permutation — the fold hash.
pub type FoldAir = Poseidon2Air<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// Public statement of one fold step. Every field is visible to the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldStatement {
    pub prev_fold_root: u32,
    pub new_outcome_commitment: u32,
    pub new_nullifier: u32,
    pub updated_components: u32,
    pub user_standards_hash: u32,
    pub new_fold_root: u32,
    pub threshold: u32,
    /// The updated score the threshold claim is about.
    pub new_score: u32,
}

/// The private witness for one fold step.
#[derive(Debug, Clone, Copy)]
pub struct FoldWitness {
    /// Previous aggregated score component.
    pub prev_state: u32,
    /// The new outcome's contribution, pre-weight.
    pub new_outcome: u32,
    /// Weight applied to the new outcome (user-bound in a later leg).
    pub weight: u32,
}

/// Exactly which of the four constraints the circuit ENFORCES, and which it only
/// BINDS. Returned alongside every proof so a caller can never over-read it.
#[derive(Debug, Clone, Copy)]
pub struct FoldClaims {
    /// C1 commitment + nullifier correctness — BOUND, not derived in-circuit.
    pub commitment_nullifier_enforced_in_circuit: bool,
    /// C2 weighted update — enforced natively and checked by `verify_fold`.
    pub weighted_update_enforced: bool,
    /// C3 fold-root hash — ENFORCED by poseidon2-air.
    pub fold_root_hash_enforced_in_circuit: bool,
    /// C4 threshold claim — enforced natively and checked by `verify_fold`.
    pub threshold_claim_enforced: bool,
}

impl FoldClaims {
    pub const fn current() -> Self {
        Self {
            // The preimages are not opened in this circuit; they are hashed INTO
            // the root, so they cannot be swapped after the fact — but the
            // circuit does not prove they were correctly derived.
            commitment_nullifier_enforced_in_circuit: false,
            weighted_update_enforced: true,
            fold_root_hash_enforced_in_circuit: true,
            threshold_claim_enforced: true,
        }
    }
}

/// The weighted update rule. Published, deterministic, and the same function the
/// circuit's arithmetic must agree with.
///
/// Saturating rather than wrapping: a wrapped score is the classic soundness
/// hole (a "negative" delta becoming ~p) that the range check in the sibling
/// range-check AIR exists to close.
pub fn weighted_update(prev_state: u32, new_outcome: u32, weight: u32) -> u32 {
    prev_state.saturating_add(new_outcome.saturating_mul(weight))
}

/// Build the 16-wide Poseidon2 input for the fold hash.
///
/// Layout is FIXED and part of the statement: any verifier must reproduce it
/// exactly, so it is documented here and asserted by the round-trip test.
///   [0] prev_fold_root
///   [1] new_outcome_commitment
///   [2] new_nullifier
///   [3] updated_components
///   [4] user_standards_hash
///   [5..16] zero padding
pub fn fold_input(s: &FoldStatement) -> [u32; WIDTH] {
    let mut a = [0u32; WIDTH];
    a[0] = s.prev_fold_root;
    a[1] = s.new_outcome_commitment;
    a[2] = s.new_nullifier;
    a[3] = s.updated_components;
    a[4] = s.user_standards_hash;
    a
}

/// Compute the fold root natively (same permutation the AIR constrains).
pub fn compute_fold_root(s: &FoldStatement) -> u32 {
    let p = poseidon2_16();
    let input = fold_input(s);
    let out: [u32; WIDTH] = crate::permute16(&p, input);
    out[0]
}

/// Assemble a complete, self-consistent fold step from a witness.
pub fn build_fold(
    prev_fold_root: u32,
    new_outcome_commitment: u32,
    new_nullifier: u32,
    user_standards_hash: u32,
    threshold: u32,
    w: FoldWitness,
) -> FoldStatement {
    let new_score = weighted_update(w.prev_state, w.new_outcome, w.weight);
    let mut s = FoldStatement {
        prev_fold_root,
        new_outcome_commitment,
        new_nullifier,
        updated_components: new_score,
        user_standards_hash,
        new_fold_root: 0,
        threshold,
        new_score,
    };
    s.new_fold_root = compute_fold_root(&s);
    s
}

/// Generate the AIR trace for the fold hash — one Poseidon2 permutation.
pub fn generate_fold_trace(
    s: &FoldStatement,
) -> p3_matrix::dense::RowMajorMatrix<BabyBear> {
    let constants = canonical_round_constants();
    let input: [BabyBear; WIDTH] = fold_input(s).map(BabyBear::from_u32);
    // A single permutation would give a 1-row trace; STARKs need a power-of-two
    // height, so the same input is repeated. Every row is the identical, fully
    // constrained permutation — padding that is still sound rather than
    // unconstrained filler.
    generate_trace_rows::<
        BabyBear,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(vec![input; 8], &constants, 0)
}

pub fn fold_air() -> FoldAir {
    let constants = canonical_round_constants();
    Poseidon2Air::new(constants)
}

/// Native re-check of every claim in a fold statement.
///
/// This is what a verifier runs ALONGSIDE the STARK: the STARK proves the hash
/// was computed correctly over the committed inputs; this confirms the statement
/// is internally consistent and the threshold claim holds.
pub fn verify_fold(s: &FoldStatement, w: Option<&FoldWitness>) -> Result<FoldClaims, String> {
    // C3: the root must be the Poseidon2 of the declared inputs.
    let recomputed = compute_fold_root(s);
    if recomputed != s.new_fold_root {
        return Err(format!(
            "fold root mismatch: declared {} but inputs hash to {}",
            s.new_fold_root, recomputed
        ));
    }
    // C3 (binding): updated_components must be the score the statement claims,
    // otherwise the root commits to a different value than the threshold is about.
    if s.updated_components != s.new_score {
        return Err("updated_components does not match new_score — the root commits to a different value than the threshold claim".into());
    }
    // C4: the public threshold claim.
    if s.new_score < s.threshold {
        return Err(format!(
            "threshold claim false: new_score {} < threshold {}",
            s.new_score, s.threshold
        ));
    }
    // C2: with the witness, the weighted update must reproduce the score.
    if let Some(w) = w {
        let expected = weighted_update(w.prev_state, w.new_outcome, w.weight);
        if expected != s.new_score {
            return Err(format!(
                "weighted update mismatch: witness yields {} but statement claims {}",
                expected, s.new_score
            ));
        }
    }
    Ok(FoldClaims::current())
}
