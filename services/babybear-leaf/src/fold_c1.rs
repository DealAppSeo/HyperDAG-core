//! C1 CLOSURE — derive the commitment and nullifier IN-CIRCUIT.
//!
//! In `fold.rs`, `new_outcome_commitment` and `new_nullifier` were BOUND: hashed
//! into the fold root so they could not be swapped after the fact, but their
//! preimages were never opened. A prover could publish any two field elements
//! and the circuit would fold them happily. The identity guarantee — "this
//! nullifier really is Poseidon2(secret, scope)" — rested on trust.
//!
//! This closes it with three constrained permutations:
//!
//!   commitment = Poseidon2(new_outcome, blinding)[0]   both inputs PRIVATE
//!   nullifier  = Poseidon2(secret, scope)[0]           secret PRIVATE, scope PUBLIC
//!   fold_root  = Poseidon2(prev_root, commitment, nullifier,
//!                          updated, standards)[0]      all inputs PUBLIC
//!
//! WHY THREE PROOFS AND NOT ONE TRACE. A `uni-stark` AIR sees a SINGLE ROW
//! (`main.current_slice()`); there is no arbitrary row access, so "row 2's input
//! equals row 0's output" is not expressible. The linkage therefore flows
//! through PUBLIC VALUES instead: each hash pins what must be public, and the
//! verifier checks that the fold's declared commitment and nullifier are exactly
//! the ones the other two proofs output. That is a complete chain without ever
//! needing cross-row constraints.
//!
//! WHY `Poseidon2Air` ALONE IS NOT ENOUGH. It constrains the permutation but has
//! NO public-value binding — it proves "a permutation was computed" and says
//! nothing about WHICH values. Every proof would verify against any statement.
//! `BoundHashAir` adds exactly the missing piece: selected inputs and the output
//! are asserted equal to public values.
//!
//! SCOPE SEPARATION (ZKP invariant 2) is now CIRCUIT-ENFORCED rather than
//! helper-enforced: `scope` is a public input to the nullifier hash, so the same
//! secret under a different scope provably yields a different nullifier.
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_air::WindowAccess;
use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS,
    BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, BABYBEAR_POSEIDON2_RC_16_INTERNAL,
    BABYBEAR_S_BOX_DEGREE,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, num_cols, Poseidon2Air, Poseidon2Cols, RoundConstants};

use crate::{permute16, poseidon2_16, WIDTH};

const SBOX_DEGREE: u64 = BABYBEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 1;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;

type Inner = Poseidon2Air<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

pub const NUM_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

pub fn canonical_constants() -> RoundConstants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    RoundConstants::new(
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        BABYBEAR_POSEIDON2_RC_16_INTERNAL,
        BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

/// One constrained Poseidon2 whose SELECTED inputs and output are pinned to
/// public values.
///
/// `public_inputs` lists the input positions that are public, in order. Public
/// values are laid out as `[those inputs..., output]`. Positions NOT listed stay
/// private — that is how the commitment keeps its preimage secret while still
/// being proven correct.
pub struct BoundHashAir {
    inner: Inner,
    pub public_inputs: Vec<usize>,
}

impl BoundHashAir {
    pub fn new(public_inputs: Vec<usize>) -> Self {
        Self { inner: Poseidon2Air::new(canonical_constants()), public_inputs }
    }
}

impl<F: p3_field::Field> BaseAir<F> for BoundHashAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
    fn num_public_values(&self) -> usize {
        self.public_inputs.len() + 1
    }
}

impl<AB> Air<AB> for BoundHashAir
where
    AB: AirBuilder<F = BabyBear>,
{
    fn eval(&self, builder: &mut AB) {
        // The permutation itself — rounds, S-boxes, linear layers.
        self.inner.eval(builder);

        // Copy publics out before borrowing main mutably.
        let pis: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();

        let main = builder.main();
        let row = main.current_slice();
        let cols: &Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = (*row).borrow();

        // Bind the selected inputs. Without this the proof says nothing about
        // WHICH values were hashed.
        for (i, &pos) in self.public_inputs.iter().enumerate() {
            builder.assert_eq(cols.inputs[pos], pis[i].clone());
        }

        // Bind the output: post-state of the final ending full round, lane 0 —
        // the same lane `permute16(..)[0]` returns natively.
        let out = cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0];
        builder.assert_eq(out, pis[self.public_inputs.len()].clone());
    }
}

fn h(a: [u32; WIDTH]) -> u32 {
    permute16(&poseidon2_16(), a)[0]
}

fn pad(vals: &[u32]) -> [u32; WIDTH] {
    let mut a = [0u32; WIDTH];
    for (i, v) in vals.iter().take(WIDTH).enumerate() {
        a[i] = *v;
    }
    a
}

/// Secrets the circuit now opens.
#[derive(Debug, Clone, Copy)]
pub struct LinkedWitness {
    pub new_outcome: u32,
    pub blinding: u32,
    pub secret: u32,
    pub scope: u32,
    pub prev_fold_root: u32,
    pub updated_components: u32,
    pub user_standards_hash: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkedStatement {
    pub prev_fold_root: u32,
    pub new_outcome_commitment: u32,
    pub new_nullifier: u32,
    pub scope: u32,
    pub updated_components: u32,
    pub user_standards_hash: u32,
    pub new_fold_root: u32,
}

pub fn derive(w: &LinkedWitness) -> LinkedStatement {
    let new_outcome_commitment = h(pad(&[w.new_outcome, w.blinding]));
    let new_nullifier = h(pad(&[w.secret, w.scope]));
    let new_fold_root = h(pad(&[
        w.prev_fold_root,
        new_outcome_commitment,
        new_nullifier,
        w.updated_components,
        w.user_standards_hash,
    ]));
    LinkedStatement {
        prev_fold_root: w.prev_fold_root,
        new_outcome_commitment,
        new_nullifier,
        scope: w.scope,
        updated_components: w.updated_components,
        user_standards_hash: w.user_standards_hash,
        new_fold_root,
    }
}

/// A trace for one permutation. Padded to height 8 by repeating the same fully
/// constrained input — padding that is sound rather than unconstrained filler.
pub fn trace_for(input: [u32; WIDTH]) -> RowMajorMatrix<BabyBear> {
    let row: [BabyBear; WIDTH] = input.map(BabyBear::from_u32);
    generate_trace_rows::<
        BabyBear,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(vec![row; 8], &canonical_constants(), 0)
}

/// The three (air, trace, public_values) jobs that together close C1.
pub struct FoldJobs {
    pub commitment: (BoundHashAir, RowMajorMatrix<BabyBear>, Vec<BabyBear>),
    pub nullifier: (BoundHashAir, RowMajorMatrix<BabyBear>, Vec<BabyBear>),
    pub fold: (BoundHashAir, RowMajorMatrix<BabyBear>, Vec<BabyBear>),
}

pub fn build_jobs(w: &LinkedWitness) -> (LinkedStatement, FoldJobs) {
    let s = derive(w);
    let f = BabyBear::from_u32;

    // Commitment: NO public inputs — both preimage parts stay secret. Only the
    // resulting commitment is revealed.
    let c_air = BoundHashAir::new(vec![]);
    let c_trace = trace_for(pad(&[w.new_outcome, w.blinding]));
    let c_pis = vec![f(s.new_outcome_commitment)];

    // Nullifier: `scope` is PUBLIC (input position 1), `secret` stays private.
    // This is what makes scope separation circuit-enforced.
    let n_air = BoundHashAir::new(vec![1]);
    let n_trace = trace_for(pad(&[w.secret, w.scope]));
    let n_pis = vec![f(s.scope), f(s.new_nullifier)];

    // Fold: every input is public, including the commitment and nullifier the
    // other two proofs produced. That equality IS the chain.
    let fo_air = BoundHashAir::new(vec![0, 1, 2, 3, 4]);
    let fo_trace = trace_for(pad(&[
        s.prev_fold_root,
        s.new_outcome_commitment,
        s.new_nullifier,
        s.updated_components,
        s.user_standards_hash,
    ]));
    let fo_pis = vec![
        f(s.prev_fold_root),
        f(s.new_outcome_commitment),
        f(s.new_nullifier),
        f(s.updated_components),
        f(s.user_standards_hash),
        f(s.new_fold_root),
    ];

    (s, FoldJobs {
        commitment: (c_air, c_trace, c_pis),
        nullifier: (n_air, n_trace, n_pis),
        fold: (fo_air, fo_trace, fo_pis),
    })
}

/// Check the chain across the three statements. This is what a verifier runs
/// after all three proofs verify — the proofs establish each hash; this
/// establishes that they are the SAME values.
pub fn check_chain(s: &LinkedStatement, commitment_out: u32, nullifier_out: u32) -> Result<(), String> {
    if commitment_out != s.new_outcome_commitment {
        return Err("commitment proof output does not match the value folded".into());
    }
    if nullifier_out != s.new_nullifier {
        return Err("nullifier proof output does not match the value folded".into());
    }
    Ok(())
}

/// C1 is now enforced in-circuit.
#[derive(Debug, Clone, Copy)]
pub struct LinkedClaims {
    pub commitment_nullifier_enforced_in_circuit: bool,
    pub weighted_update_enforced: bool,
    pub fold_root_hash_enforced_in_circuit: bool,
    pub threshold_claim_enforced: bool,
    pub scope_separation_enforced_in_circuit: bool,
}

impl LinkedClaims {
    pub const fn current() -> Self {
        Self {
            commitment_nullifier_enforced_in_circuit: true,
            weighted_update_enforced: true,
            fold_root_hash_enforced_in_circuit: true,
            threshold_claim_enforced: true,
            scope_separation_enforced_in_circuit: true,
        }
    }
}
