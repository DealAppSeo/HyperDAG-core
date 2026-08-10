//! C1 EVIDENCE — the commitment and nullifier are now DERIVED in-circuit.
//!
//! The decisive test is `forged_commitment_is_rejected_by_the_verifier`. In
//! `fold.rs` a prover could publish ANY field element as the commitment and the
//! fold accepted it — the value was merely hashed into the root. Here a
//! commitment that is not Poseidon2 of a preimage the prover holds produces a
//! proof that FAILS VERIFICATION. That is the difference between BOUND and
//! ENFORCED.
//!
//! Note where the rejection happens: in release builds `prove` does not evaluate
//! constraints, so a forgery still produces proof BYTES. It is `verify` that
//! rejects — which is exactly where a relying party checks, and why these tests
//! assert on the verifier rather than on a prover panic.
use babybear_leaf::fold_c1::*;
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
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
type Config = StarkConfig<Pcs, Challenge, SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>>;

fn make_config(trace_height: usize) -> Config {
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

fn sample() -> LinkedWitness {
    LinkedWitness {
        new_outcome: 7,
        blinding: 0xDEAD_BEEF,
        secret: 12_345,
        scope: 1, // 1 = ownership
        prev_fold_root: 0x1111_1111,
        updated_components: 1_070,
        user_standards_hash: 0x4444_4444,
    }
}

#[test]
fn all_three_hashes_prove_and_verify_with_measurements() {
    let w = sample();
    let (s, jobs) = build_jobs(&w);

    let mut total_bytes = 0usize;
    let mut total_prove = 0u128;
    let mut total_verify = 0u128;

    for (name, (air, trace, pis)) in [
        ("commitment", jobs.commitment),
        ("nullifier", jobs.nullifier),
        ("fold", jobs.fold),
    ] {
        let config = make_config(trace.height());
        let t0 = Instant::now();
        let proof = prove(&config, &air, trace, &pis);
        let prove_ms = t0.elapsed().as_millis();
        let bytes = bincode::serialize(&proof).expect("serialize");
        let t1 = Instant::now();
        let r = verify(&config, &air, &proof, &pis);
        let verify_ms = t1.elapsed().as_millis();
        assert!(r.is_ok(), "{name} proof must verify: {:?}", r.err());
        println!("  {name:<11} {:>7} bytes   prove {prove_ms:>3} ms   verify {verify_ms:>3} ms", bytes.len());
        total_bytes += bytes.len();
        total_prove += prove_ms;
        total_verify += verify_ms;
    }

    println!("C1 TOTALS");
    println!("  proof size    : {total_bytes} bytes (3 proofs)");
    println!("  prove latency : {total_prove} ms");
    println!("  verify latency: {total_verify} ms");
    println!("  fold root     : {}", s.new_fold_root);
    println!("  commitment    : {}", s.new_outcome_commitment);
    println!("  nullifier     : {}", s.new_nullifier);

    assert!(check_chain(&s, s.new_outcome_commitment, s.new_nullifier).is_ok());
}

#[test]
fn forged_commitment_is_rejected_by_the_verifier() {
    // THE C1 TEST. Claim a commitment that is not the hash of any preimage the
    // prover holds. Under fold.rs this was accepted — the value was merely
    // hashed into the root.
    let w = sample();
    let (s, jobs) = build_jobs(&w);
    let (air, trace, _) = jobs.commitment;
    let forged = vec![BabyBear::from_u32(s.new_outcome_commitment ^ 0xFFFF)];
    let config = make_config(trace.height());
    // In release builds `prove` does not evaluate constraints — verification
    // does. So the forgery must be caught at verify, which is exactly where a
    // real relying party would catch it.
    let proof = prove(&config, &air, trace, &forged);
    let r = verify(&config, &air, &proof, &forged);
    assert!(r.is_err(), "a commitment that is not the hash of the witness MUST be rejected");
}

#[test]
fn forged_nullifier_scope_is_rejected_by_the_verifier() {
    // Scope separation, circuit-enforced: claim the nullifier was computed under
    // a different scope than the witness actually used.
    let w = sample();
    let (s, jobs) = build_jobs(&w);
    let (air, trace, _) = jobs.nullifier;
    let lied_scope = vec![BabyBear::from_u32(999), BabyBear::from_u32(s.new_nullifier)];
    let config = make_config(trace.height());
    let proof = prove(&config, &air, trace, &lied_scope);
    let r = verify(&config, &air, &proof, &lied_scope);
    assert!(r.is_err(), "claiming a different scope than the witness used MUST be rejected");
}

#[test]
fn fold_over_unrelated_commitment_is_rejected_by_the_verifier() {
    // Try to fold a commitment the other proof never produced.
    let w = sample();
    let (s, jobs) = build_jobs(&w);
    let (air, trace, _) = jobs.fold;
    let pis = vec![
        BabyBear::from_u32(s.prev_fold_root),
        BabyBear::from_u32(s.new_outcome_commitment ^ 1), // not what was hashed
        BabyBear::from_u32(s.new_nullifier),
        BabyBear::from_u32(s.updated_components),
        BabyBear::from_u32(s.user_standards_hash),
        BabyBear::from_u32(s.new_fold_root),
    ];
    let config = make_config(trace.height());
    let proof = prove(&config, &air, trace, &pis);
    let r = verify(&config, &air, &proof, &pis);
    assert!(r.is_err(), "folding a commitment the witness never hashed MUST be rejected");
}

#[test]
fn scope_separation_holds_end_to_end() {
    // Same secret, two scopes, two different nullifiers — now a property of the
    // proven statement, not just of a native helper.
    let mut a = sample();
    let mut b = sample();
    a.scope = 1;
    b.scope = 2;
    assert_ne!(derive(&a).new_nullifier, derive(&b).new_nullifier);
    // And therefore two different fold roots.
    assert_ne!(derive(&a).new_fold_root, derive(&b).new_fold_root);
}

#[test]
fn chain_rejects_a_substituted_value() {
    let w = sample();
    let s = derive(&w);
    assert!(check_chain(&s, s.new_outcome_commitment ^ 1, s.new_nullifier).is_err());
    assert!(check_chain(&s, s.new_outcome_commitment, s.new_nullifier ^ 1).is_err());
}

#[test]
fn c1_is_now_reported_as_enforced() {
    let c = LinkedClaims::current();
    assert!(c.commitment_nullifier_enforced_in_circuit, "C1 closed 2026-08-06");
    assert!(c.scope_separation_enforced_in_circuit);
    assert!(c.fold_root_hash_enforced_in_circuit);
    assert!(c.weighted_update_enforced);
    assert!(c.threshold_claim_enforced);
}
