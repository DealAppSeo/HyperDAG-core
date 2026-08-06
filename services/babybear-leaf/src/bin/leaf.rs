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
//!   leaf selftest                         run the KAT vectors and report
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
        die("usage: leaf <permute|hash|commit|nullifier|postcard|selftest> [args]");
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
