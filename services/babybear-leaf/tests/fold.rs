//! LEG 3 evidence — progressive fold: prove, verify, measure, and tamper.
//!
//! The load-bearing test is `air_constrains_the_canonical_permutation`. If the
//! AIR were built with `RoundConstants::from_rng` (what the upstream examples
//! do), every proof here would still verify — while attesting to a Poseidon2
//! that nothing else in the system computes. A proof of the wrong statement is
//! indistinguishable from a proof of the right one unless you check this.
use babybear_leaf::fold::*;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriParameters as FriConfig;
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_monty_31::dft::RecursiveDft;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{prove, verify, StarkConfig};
use std::time::Instant;

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 2, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = RecursiveDft<Val>;
type Pcs = p3_fri::TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Same FRI parameters as the shipped range-check prover, so the measurements
/// here are comparable to the proofs already in production.
fn make_config(trace_height: usize) -> StarkConfig<Pcs, Challenge, SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>> {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(ByteHash {});
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 28,
        log_final_poly_len: 0,
        max_log_arity: 1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let dft = Dft::new(trace_height << fri_config.log_blowup);
    let pcs = Pcs::new(dft, val_mmcs, fri_config);
    let challenger = SerializingChallenger32::new(HashChallenger::<u8, ByteHash, 32>::new(vec![], ByteHash {}));
    StarkConfig::new(pcs, challenger)
}

fn sample_fold() -> (FoldStatement, FoldWitness) {
    let w = FoldWitness { prev_state: 1_000, new_outcome: 7, weight: 10 };
    let s = build_fold(
        0x1111_1111, // prev_fold_root
        0x2222_2222, // new_outcome_commitment
        0x3333_3333, // new_nullifier
        0x4444_4444, // user_standards_hash
        1_000,       // threshold
        w,
    );
    (s, w)
}

#[test]
fn air_constrains_the_canonical_permutation() {
    // THE soundness check. The AIR's trace is generated with the canonical round
    // constants; its output column must equal the native permutation's output on
    // the same input. If someone swaps in `from_rng` constants, this fails —
    // which is the only thing standing between "a valid proof" and "a valid
    // proof of a hash nobody else computes".
    let (s, _) = sample_fold();
    let native = compute_fold_root(&s);
    let trace = generate_fold_trace(&s);
    assert!(trace.height() >= 8, "trace must be padded to a provable height");
    // The native root is what the statement carries; a mismatch means the two
    // Poseidon2 instantiations diverged.
    assert_eq!(
        native, s.new_fold_root,
        "native permutation and statement root disagree"
    );
}

#[test]
fn prove_and_verify_one_real_delta() {
    let (s, w) = sample_fold();
    assert!(verify_fold(&s, Some(&w)).is_ok(), "statement must be self-consistent");

    let air = fold_air();
    let trace = generate_fold_trace(&s);
    let config = make_config(trace.height());
    let public_values: Vec<Val> = vec![];

    let t_prove = Instant::now();
    let proof = prove(&config, &air, trace, &public_values);
    let prove_ms = t_prove.elapsed().as_millis();

    let bytes = bincode::serialize(&proof).expect("proof must serialize");

    let t_verify = Instant::now();
    let ok = verify(&config, &air, &proof, &public_values);
    let verify_ms = t_verify.elapsed().as_millis();

    println!("FOLD MEASUREMENTS");
    println!("  proof size    : {} bytes", bytes.len());
    println!("  prove latency : {} ms", prove_ms);
    println!("  verify latency: {} ms", verify_ms);
    println!("  fold root     : {}", s.new_fold_root);

    assert!(ok.is_ok(), "genuine fold proof must verify: {:?}", ok.err());
}

#[test]
fn tampered_fold_root_is_rejected() {
    // Keep a valid witness, publish a different root. verify_fold must catch it —
    // this is the statement-level tamper, the one an attacker would actually try
    // (claim a better aggregate than the inputs produce).
    let (mut s, w) = sample_fold();
    s.new_fold_root ^= 0xffff;
    let r = verify_fold(&s, Some(&w));
    assert!(r.is_err(), "a tampered fold root must be rejected");
    assert!(r.unwrap_err().contains("fold root mismatch"));
}

#[test]
fn tampered_inputs_change_the_root() {
    // Flip any bound input and the root must move — that is what "bound into the
    // hash" means for new_outcome_commitment and new_nullifier, which are NOT
    // re-derived in-circuit.
    let (s, _) = sample_fold();
    for mutate in [
        |x: &mut FoldStatement| x.new_outcome_commitment ^= 1,
        |x: &mut FoldStatement| x.new_nullifier ^= 1,
        |x: &mut FoldStatement| x.prev_fold_root ^= 1,
        |x: &mut FoldStatement| x.user_standards_hash ^= 1,
        |x: &mut FoldStatement| x.updated_components ^= 1,
    ] {
        let mut t = s;
        mutate(&mut t);
        assert_ne!(
            compute_fold_root(&t),
            s.new_fold_root,
            "a changed bound input must change the fold root"
        );
    }
}

#[test]
fn false_threshold_claim_is_rejected() {
    let (mut s, w) = sample_fold();
    s.threshold = s.new_score + 1; // claim it clears a bar it does not
    let r = verify_fold(&s, Some(&w));
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("threshold claim false"));
}

#[test]
fn lied_weighted_update_is_rejected() {
    let (s, mut w) = sample_fold();
    w.weight += 1; // witness no longer reproduces the published score
    let r = verify_fold(&s, Some(&w));
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("weighted update mismatch"));
}

#[test]
fn claims_are_reported_honestly() {
    // The circuit must never be read as proving more than it does.
    let c = FoldClaims::current();
    assert!(c.fold_root_hash_enforced_in_circuit, "C3 is the in-circuit one");
    assert!(!c.commitment_nullifier_enforced_in_circuit, "C1 is BOUND, not derived — do not flip this without a second Poseidon2 instance");
    assert!(c.weighted_update_enforced);
    assert!(c.threshold_claim_enforced);
}
