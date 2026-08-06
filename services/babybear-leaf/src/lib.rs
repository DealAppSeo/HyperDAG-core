//! BabyBear identity leaf (B3) — WITNESS-LEVEL computation over the CANONICAL
//! Poseidon2-16 permutation (`p3_baby_bear::default_babybear_poseidon2_16()` — NO
//! hand-rolled constants). Ports the BN254/circom `reputation_proof.circom` leaf to
//! BabyBear per ZK_BABYBEAR_LEAF_PORT_SPEC. Scoped nullifier per Inv-2.

use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

pub const WIDTH: usize = 16;

/// The canonical width-16 Poseidon2-BabyBear permutation (pinned-rev fixed constants).
pub fn poseidon2_16() -> impl Permutation<[BabyBear; WIDTH]> {
    default_babybear_poseidon2_16()
}

/// Apply the permutation to a 16-wide u32 state; return the 16-wide u32 output.
pub fn permute16(p: &impl Permutation<[BabyBear; WIDTH]>, x: [u32; WIDTH]) -> [u32; WIDTH] {
    let mut s = BabyBear::new_array(x);
    p.permute_mut(&mut s);
    let mut out = [0u32; WIDTH];
    for (i, e) in s.iter().enumerate() {
        out[i] = e.as_canonical_u32();
    }
    out
}

/// Single-field digest: `permute([inputs.., 0-pad])[0]`. ONE hash primitive for the
/// leaf, all from the canonical permutation.
pub fn hash(p: &impl Permutation<[BabyBear; WIDTH]>, inputs: &[u32]) -> u32 {
    let mut a = [0u32; WIDTH];
    for (i, x) in inputs.iter().take(WIDTH).enumerate() {
        a[i] = *x;
    }
    permute16(p, a)[0]
}

/// Identity commitment `C1 = hash(secret, nullifier, trapdoor)` (Semaphore-style),
/// porting circom `identityCommitment = Poseidon(3)(secret, nullifier, trapdoor)`.
pub fn commitment(
    p: &impl Permutation<[BabyBear; WIDTH]>,
    secret: u32,
    nullifier: u32,
    trapdoor: u32,
) -> u32 {
    hash(p, &[secret, nullifier, trapdoor])
}

/// Merkle 2-to-1 compression for membership, porting circom `Poseidon(2)` pair hash.
pub fn merkle_compress(p: &impl Permutation<[BabyBear; WIDTH]>, left: u32, right: u32) -> u32 {
    hash(p, &[left, right])
}

/// SCOPED nullifier (Inv-2): `N(secret, scope) = permute([secret, scope, 0..])[0]`.
pub fn nullifier(p: &impl Permutation<[BabyBear; WIDTH]>, secret: u32, scope: u32) -> u32 {
    hash(p, &[secret, scope])
}

/// Recompute the Merkle root from a leaf + path (porting the circom 20-level loop with
/// `Mux1` ordering). `index_bits[i]`: 0 => accumulator on the left, 1 => on the right.
pub fn merkle_root(
    p: &impl Permutation<[BabyBear; WIDTH]>,
    leaf: u32,
    siblings: &[u32],
    index_bits: &[u8],
) -> u32 {
    assert_eq!(
        siblings.len(),
        index_bits.len(),
        "siblings/index_bits length mismatch"
    );
    let mut acc = leaf;
    for (sib, bit) in siblings.iter().zip(index_bits.iter()) {
        acc = if *bit == 0 {
            merkle_compress(p, acc, *sib)
        } else {
            merkle_compress(p, *sib, acc)
        };
    }
    acc
}

fn agent_id_to_16_bytes(agent_id: &str) -> [u8; 16] {
    let cleaned: String = agent_id.chars().filter(|c| *c != '-').collect();
    if cleaned.len() == 32 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(&cleaned) {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            return arr;
        }
    }
    let digest = Sha256::digest(agent_id.as_bytes());
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&digest[..16]);
    arr
}

/// B-2 — aggregation-ready Poseidon2/BabyBear LEAF (Invariant 1). A single BabyBear field element
/// committing the postcard statement {agent_id, threshold, repid_score}, computed with the canonical
/// `default_babybear_poseidon2_16()` permutation.
#[wasm_bindgen]
pub fn poseidon2_postcard_leaf(agent_id: &str, threshold: u64, repid_score: u64) -> String {
    let bytes = agent_id_to_16_bytes(agent_id);
    let mut inputs: Vec<u32> = Vec::with_capacity(10);
    for i in 0..8 {
        inputs.push(((bytes[2 * i] as u32) << 8) | (bytes[2 * i + 1] as u32));
    }
    inputs.push((threshold % (1u64 << 31)) as u32);
    inputs.push((repid_score % (1u64 << 31)) as u32);
    let p = poseidon2_16();
    let leaf = hash(&p, &inputs);
    format!("0x{:08x}", leaf)
}
pub mod fold;
pub mod fold_c1;
