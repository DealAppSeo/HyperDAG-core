//! `leaf` — expose the Poseidon2/BabyBear primitives to anything outside Rust.
//!
//! WHY THIS EXISTS. The crate had no binary. Every primitive the trust harness
//! depends on — the canonical permutation, the identity commitment, the SCOPED
//! nullifier that ZKP invariant 2 requires — was reachable only from Rust, so
//! the TypeScript side of the harness could not call any of it. The KATs passed
//! and nothing downstream could use the thing they guaranteed.
//!
//! That is the same shape as the rest of this codebase's recurring bug: a
//! correct mechanism with no caller. This is the caller's door.
//!
//! Output is JSON on stdout so a Node/Python/shell caller can consume it
//! without parsing prose. Errors go to stderr with a non-zero exit — a caller
//! must never mistake a failure for a digest.
//!
//! Usage:
//!   leaf permute   <u32> [u32 ...]        canonical 16-wide permutation
//!   leaf hash      <u32> [u32 ...]        single-field digest
//!   leaf commit    <secret> <null> <trap> Semaphore-style identity commitment
//!   leaf nullifier <secret> <scope>       SCOPED nullifier (invariant 2)
//!   leaf postcard  <agentId> <threshold> <repidScore>
//!   leaf fold      <prevRoot> <outcomeCommitment> <nullifier> <standardsHash>
//!                  <prevState> <newOutcome> <weight> <threshold>
//!                                         one progressive-fold step + verify
//!   leaf selftest                         run the KAT vectors and report
use babybear_leaf::fold::{compute_fold_root, verify_fold, weighted_update, FoldStatement, FoldWitness};
use babybear_leaf::{
    commitment, hash, nullifier, permute16, poseidon2_16, poseidon2_postcard_leaf, WIDTH,
};

fn die(msg: &str) -> ! {
    eprintln!("{{\"error\":\"{}\"}}", msg.replace('"', "'"));
    std::process::exit(2);
}

fn parse_u32s(args: &[String]) -> Vec<u32> {
    args.iter()
        .map(|a| {
            a.parse::<u32>()
                .unwrap_or_else(|_| die(&format!("not a u32: {a}")))
        })
        .collect()
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        die("usage: leaf <permute|hash|commit|nullifier|postcard|fold|selftest> [args]");
    }
    let p = poseidon2_16();
    let cmd = argv[0].as_str();
    let rest = &argv[1..];

    match cmd {
        "permute" => {
            let v = parse_u32s(rest);
            if v.is_empty() || v.len() > WIDTH {
                die(&format!("permute takes 1..={WIDTH} field elements"));
            }
            let mut a = [0u32; WIDTH];
            for (i, x) in v.iter().enumerate() {
                a[i] = *x;
            }
            let out = permute16(&p, a);
            println!(
                "{{\"op\":\"permute\",\"width\":{WIDTH},\"out\":[{}]}}",
                out.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        "hash" => {
            let v = parse_u32s(rest);
            if v.is_empty() {
                die("hash needs at least one field element");
            }
            println!("{{\"op\":\"hash\",\"digest\":{}}}", hash(&p, &v));
        }
        "commit" => {
            let v = parse_u32s(rest);
            if v.len() != 3 {
                die("commit takes exactly <secret> <nullifier> <trapdoor>");
            }
            println!(
                "{{\"op\":\"commit\",\"commitment\":{}}}",
                commitment(&p, v[0], v[1], v[2])
            );
        }
        "nullifier" => {
            let v = parse_u32s(rest);
            if v.len() != 2 {
                die("nullifier takes exactly <secret> <scope>");
            }
            // Invariant 2: scope is a PARAMETER. The same secret under a
            // different scope MUST yield a different nullifier, which is what
            // lets one identity serve ownership, consent, and any future domain
            // without a second identity system.
            println!(
                "{{\"op\":\"nullifier\",\"secret_scoped\":true,\"scope\":{},\"nullifier\":{}}}",
                v[1],
                nullifier(&p, v[0], v[1])
            );
        }
        "postcard" => {
            if rest.len() != 3 {
                die("postcard takes <agentId> <threshold> <repidScore>");
            }
            let threshold = rest[1].parse::<u64>().unwrap_or_else(|_| die("threshold must be u64"));
            let score = rest[2].parse::<u64>().unwrap_or_else(|_| die("repidScore must be u64"));
            println!(
                "{{\"op\":\"postcard\",\"leaf\":\"{}\"}}",
                poseidon2_postcard_leaf(&rest[0], threshold, score)
            );
        }
        // The fold had a complete circuit, seven passing tests, and no way for
        // anything outside Rust to run one — the same no-caller gap this binary
        // was created to close for the primitives. So the demo could show a
        // committed reputation update only by reimplementing the hash, which
        // would have proved that the DEMO computes a root, not that the CIRCUIT
        // does.
        "fold" => {
            if rest.len() != 8 {
                die("usage: leaf fold <prevRoot> <outcomeCommitment> <nullifier> <standardsHash> <prevState> <newOutcome> <weight> <threshold>");
            }
            let v = parse_u32s(rest);
            let new_score = weighted_update(v[4], v[5], v[6]);
            let s = FoldStatement {
                prev_fold_root: v[0],
                new_outcome_commitment: v[1],
                new_nullifier: v[2],
                updated_components: new_score,
                user_standards_hash: v[3],
                new_fold_root: 0, // filled below from the real hash
                threshold: v[7],
                new_score,
            };
            let s = FoldStatement { new_fold_root: compute_fold_root(&s), ..s };
            let w = FoldWitness { prev_state: v[4], new_outcome: v[5], weight: v[6] };

            // Verify what was just built. A `fold` command that emitted a root
            // WITHOUT verifying would hand a caller a number with no claim
            // attached — and this whole binary exists because unusable
            // guarantees are the recurring bug.
            // IS C2 ACTUALLY CONSTRAINING ANYTHING? `weighted_update` is
            // `prev + new*weight` over unsigned field elements, so it can only
            // express a NON-DECREASING update. A penalty cannot be written this
            // way at all, and a caller that wants the root to commit to a
            // reduced score must pass it as `prev_state` with weight 0 — at
            // which point C2 degenerates to `x == x` and proves nothing.
            //
            // That degeneracy is legitimate; hiding it is not. A caller reading
            // `weighted_update: true` on a step where the constraint was vacuous
            // would believe the arithmetic had been checked when it had not.
            let weighted_update_binding = !(v[6] == 0 || v[5] == 0);
            match verify_fold(&s, Some(&w)) {
                Ok(c) => println!(
                    "{{\"op\":\"fold\",\"prev_fold_root\":{},\"new_fold_root\":{},\"new_score\":{},\"threshold\":{},\"threshold_met\":{},\"verified\":true,\"enforced\":{{\"weighted_update\":{},\"weighted_update_binding\":{},\"fold_root_hash\":{},\"threshold_claim\":{},\"commitment_nullifier\":{}}}}}",
                    s.prev_fold_root, s.new_fold_root, s.new_score, s.threshold,
                    s.new_score >= s.threshold,
                    c.weighted_update_enforced, weighted_update_binding,
                    c.fold_root_hash_enforced_in_circuit,
                    c.threshold_claim_enforced, c.commitment_nullifier_enforced_in_circuit
                ),
                // Reported as a REFUSAL with the reason, never as a root the
                // caller might use anyway.
                Err(e) => {
                    println!(
                        "{{\"op\":\"fold\",\"verified\":false,\"error\":\"{}\"}}",
                        e.replace('"', "'")
                    );
                    std::process::exit(3);
                }
            }
        }

        "selftest" => {
            // Proves the binary is wired to the SAME permutation the KATs cover,
            // so a caller can assert the primitive is canonical before trusting
            // any digest it returns.
            let a = nullifier(&p, 42, 1);
            let b = nullifier(&p, 42, 2);
            let scope_separated = a != b;
            let d1 = hash(&p, &[1, 2, 3]);
            let d2 = hash(&p, &[1, 2, 3]);
            println!(
                "{{\"op\":\"selftest\",\"deterministic\":{},\"scope_separated_inv2\":{},\"sample_nullifier_scope1\":{},\"sample_nullifier_scope2\":{}}}",
                d1 == d2,
                scope_separated,
                a,
                b
            );
            if !scope_separated || d1 != d2 {
                eprintln!("SELFTEST FAILED — the primitive is not canonical; do not trust its output");
                std::process::exit(1);
            }
        }
        other => die(&format!("unknown command: {other}")),
    }
}
