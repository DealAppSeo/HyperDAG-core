# HyperDAG-core

**This repository is the prover.** `services/zkp-postcard` is the HTTP service that
[DealAppSeo/repid-engine](https://github.com/DealAppSeo/repid-engine) calls to produce its
Plonky3 STARK proofs: a range proof that one agent's RepID score is above a threshold.
It is deployed as one Railway service, `zkp-postcard`, at
`https://zkp-postcard-production.up.railway.app`.

Protocol documentation (what RepID is, the tiers, the contracts, current figures) is not kept
here. It lives in [DealAppSeo/hyperdag-protocol](https://github.com/DealAppSeo/hyperdag-protocol).

## What it proves

One statement per request: **`repid_score > threshold`, for one `agent_id`**
(`services/zkp-postcard/src/circuit.rs`).

- **Public values.** 18 BabyBear field elements: the agent id as 16 bytes (a UUID's raw bytes;
  any other id is bound as the first 16 bytes of its SHA-256), then `threshold`, then
  `repid_score`. All three are public. The proof binds the claim to that agent and that score.
  It does not hide the score, and the HTTP response returns it as `repid_score_actual`.
- **Constraints.** One trace row of 32 bit-columns holding `gap = repid_score - threshold - 1`.
  The high 16 columns must be zero, the low 16 must be boolean, and on the first row they must
  recombine to `repid_score - threshold - 1` computed from the public values. When the score is
  not above the threshold, the gap wraps to a large field element that does not fit in 16 bits,
  so no valid proof exists. This assumes `repid_score - threshold < 65536`.
- **Proof system.** Plonky3 `uni-stark` over BabyBear with a degree-4 extension field, Keccak-256
  Merkle commitments, and FRI with the parameters set in `prove_range_check`. This README makes
  no claim about soundness level.
- The service verifies each proof itself before returning it, serializes it with `bincode`, and
  returns it base64-encoded in `proof_bytes`.
- **Two more values in each response. The circuit checks neither of them.**
  `commitment` is `0x` followed by the SHA-256 of `hyperdag_v1:{agent_id}:{repid_score}:{threshold}`.
  For real proofs only, `poseidon2_leaf` is one BabyBear element hashing the same statement with
  the Poseidon2 permutation from `services/babybear-leaf` (`leaf_scheme: "poseidon2_babybear"`).

`cargo test` in `services/zkp-postcard` runs the circuit tests: a round trip, a proof rejected
under another agent's id, a proof rejected under an inflated score, the boundary
`repid_score = threshold + 1`, and forged wrapped gaps.

## HTTP endpoints

These are the routes in `services/zkp-postcard/src/main.rs`. There is no authentication, and CORS
allows any origin (`CorsLayer::permissive()`).

| Method | Path | What it does |
|---|---|---|
| `GET` | `/health` | Fixed JSON (`status`, `service`, `version`, `proof_types`, `protocol`). It does not contact Supabase. |
| `POST` | `/zkp/repid-proof` | Produces a proof. The request and response are described below. |
| `POST` | `/prove/trade_auth` | **The same handler as `/zkp/repid-proof`.** It produces the RepID range proof described above, not a trade-authorization proof. This repository has no trade-authorization circuit. |
| `GET` | `/zkp/verify/{commitment}` | **This route does not work in the current build** (see the note below). |

### `POST /zkp/repid-proof`

The request body is JSON:

- `agent_id` is required. Without it the service returns `400 {"error":"missing_agent_id"}`.
- `tier` and `threshold` are optional. If `threshold` is missing, `tier_to_threshold` in `main.rs`
  derives it from the tier. That is the request's `tier` if given, otherwise the agent's stored
  tier. In that case an unknown tier returns `400 {"error":"invalid_tier"}`.
- `repid_score` is accepted and **ignored**. The service always reads the score itself (see
  *Calls* below) and echoes the value you sent back as `repid_score_supplied`.
- `requester_pubkey` and `timestamp` are accepted and not used.
- If the agent is unknown, the service returns `404 {"error":"agent_not_found"}`. If the Supabase
  read fails, it returns `500 {"error":"internal_error"}`.

Check `proof_type` in the response before reading any other field:

| `proof_type` | Meaning |
|---|---|
| `plonky3_range_check` | A real STARK proof in `proof_bytes`, with `poseidon2_leaf` set. |
| `sha256_commitment_poc` | **No proof.** `proof_bytes` holds a placeholder string. The service returns this type when the score is not above the threshold, or when proving failed. |

`verified` is the result of comparing `repid_score > threshold`. It does not mean `proof_bytes`
was verified. It is `true` on the `sha256_commitment_poc` path when proving failed, so a `true`
value does not mean a proof exists. `erc8004_token_id` is a copy of `agent_id`.

### `GET /zkp/verify/{commitment}`: this route does not work in the current build

The path uses axum 0.8's `{param}` syntax. The crate depends on `axum = "0.7"` (`Cargo.lock`
pins 0.7.9), and in that version braces are literal characters. VERIFIED on 2026-10-07 by
running a binary built from this repository with `--locked`: a request for a commitment the same
process had just returned got 404. A request for the literal path `/zkp/verify/{commitment}`
got 500. Not checked against the live service.

If the route worked, it would still only look up an in-memory map of the proofs this process
has made since it last started, and return the stored comparison result. It does not
re-verify proof bytes.

## Where this sits

**Calls:**

- **Supabase (PostgREST): one read per proof request.**
  `GET {SUPABASE_URL}/rest/v1/repid_agents?id=eq.<agent_id>&select=current_repid,tier`.
  The base URL comes from `SUPABASE_URL`. The key comes from `SUPABASE_SECRET_KEY`, or
  `SUPABASE_SERVICE_KEY`, or `SUPABASE_SERVICE_ROLE_KEY`, in that order of preference.
- The service makes no other calls at runtime. It does not call repid-engine, does not write to
  Supabase or to any other store, does not send anything on-chain, and keeps proof records in
  process memory only.

**Called by:**

- [DealAppSeo/repid-engine](https://github.com/DealAppSeo/repid-engine): its API's scoring pipeline
  and its proof-drain worker call `POST /zkp/repid-proof` at
  `https://zkp-postcard-production.up.railway.app`. That URL is the engine's default when its
  `ZKP_SERVICE_URL` is unset.
- This README names no caller of `/prove/trade_auth`, `/zkp/verify/{commitment}` or `/health`.
  NOT CHECKED: the engine's trade-authorization bridge would send its request to
  `/prove/trade_auth` here if the engine's `PLONKY3_PROVER_URL` or `ZKP_SERVICE_URL` pointed at
  this service. Nobody has checked whether either variable is set.

**The whole map:** [How the pieces fit](https://github.com/DealAppSeo/hyperdag-protocol/blob/main/BUILDERS.md#how-the-pieces-fit),
in DealAppSeo/hyperdag-protocol.

`scripts/check-readme-edges.mjs` checks these edges against the code. See [Checks](#checks).

## Build and deploy

- **Image.** `services/zkp-postcard/Dockerfile` has two stages. The first runs
  `cargo build --release` in `rustlang/rust:nightly-slim`. The second copies only the
  `zkp-postcard` binary into `debian:bookworm-slim`. `PORT` defaults to `8080`.
- **Deploy.** One Railway service, `zkp-postcard`, built from this repository's `main` branch
  with root directory `services/zkp-postcard` and the Dockerfile
  (`services/zkp-postcard/railway.toml`). Its public domain is
  `zkp-postcard-production.up.railway.app`.
- **Dependencies.** `services/zkp-postcard/Cargo.toml` pins every Plonky3 crate to one git
  revision. It pulls `babybear-leaf` from this repository over git at a pinned `rev`, not as a
  path dependency, because the Docker build context stops at `services/zkp-postcard`. A change
  to `services/babybear-leaf` therefore reaches the prover only when that `rev` is bumped.

## Run it locally

The binary panics at startup unless `SUPABASE_URL` and one of the three key variables are set.
Every proof request reads the agent's score from that URL, so the service has no offline mode.
For local work, any HTTP server that answers the one query above with
`[{"current_repid": <n>, "tier": "<TIER>"}]` is enough.

```bash
cd services/zkp-postcard
export SUPABASE_URL="https://<your-project>.supabase.co"
export SUPABASE_SECRET_KEY="<server-side key>"     # never commit a key
cargo run --release                                  # listens on 0.0.0.0:$PORT, default 8080
curl -s localhost:8080/health
cargo test                                           # circuit tests; needs no environment
```

PowerShell:

```powershell
cd services\zkp-postcard
$env:SUPABASE_URL = "https://<your-project>.supabase.co"
$env:SUPABASE_SECRET_KEY = "<server-side key>"
cargo run --release
```

The Dockerfile uses a nightly toolchain. On 2026-10-07, `cargo build --locked` and
`cargo test --locked` also succeeded on stable Rust 1.97, and the circuit tests passed.

## Other folders

- `services/babybear-leaf/` is a Rust crate with the Poseidon2/BabyBear hash that the prover uses
  for `poseidon2_leaf`. It also contains known-answer test vectors, a `leaf` command-line binary,
  wasm-bindgen exports, and fold circuits (`fold.rs`, `fold_c1.rs`) that the prover does not call.
- `migrations/` holds one SQL migration. It adds a `domain` column to `zkp_circuits` and
  leaf-lineage columns to `repid_zkp_proofs`. Its header marks it DRAFT, and this repository does
  not record whether it was applied.
- `METHODOLOGY.md` and `docs/` are earlier write-ups about the wider protocol: HAL methodology, a
  benchmark note, and custodian accountability. They do not describe this prover. Current
  protocol documentation is in DealAppSeo/hyperdag-protocol.
- `create_issues.js` and `create_issues.ps1` are scripts that open GitHub issues with the `gh` CLI.

## Checks

```bash
node scripts/check-readme-edges.mjs
```

This script checks the edges named above against the code, with no dependencies. It checks:

- Every route this README lists matches the router in `main.rs`, in both directions.
- The *Calls* list matches the outbound requests in `services/zkp-postcard/src/`.
- Every environment variable the code reads is named here.
- The only deployment domain named here is the one the engine calls.
- The map link is present.
- The `/zkp/verify` note still matches the pinned axum version.

If `REPID_ENGINE_DIR` points at a checkout of DealAppSeo/repid-engine, the script also checks the
*Called by* edge against the engine's source.

Exit codes: `0` VERIFIED, `1` FAILED, `2` NOT CHECKED. `2` means nothing failed but at least one
check could not run. `.github/workflows/readme-edges.yml` runs the script on every pull request
with the engine checked out.

## License

Apache 2.0. See `LICENSE`.
