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
`repid_score = threshold + 1`, and forged wrapped gaps. It also runs HTTP tests against the real
router: `verified` is `false` whenever there is no proof, a protected route answers `401` without
the right token and `503` with no token configured, `/health` stays public, and the verify route
is gone.

## HTTP endpoints

These are the routes in `services/zkp-postcard/src/main.rs`. Every route except `/health` needs a
bearer token (see [Authentication](#authentication)). CORS allows any origin
(`CorsLayer::permissive()`).

| Method | Path | Auth | What it does |
|---|---|---|---|
| `GET` | `/health` | Public | Fixed JSON (`status`, `service`, `version`, `proof_types`, `protocol`, `auth_configured`). It does not contact Supabase. |
| `POST` | `/zkp/repid-proof` | Bearer token | Produces a proof. The request and response are described below. |
| `POST` | `/prove/trade_auth` | Bearer token | **The same handler as `/zkp/repid-proof`.** It produces the RepID range proof described above, not a trade-authorization proof. This repository has no trade-authorization circuit. |

### Authentication

Every route except `/health` requires the header `Authorization: Bearer <token>`, where the token
must equal the service's `PROVER_AUTH_TOKEN` environment variable. The service compares the two in
constant time and never logs or returns the token or the header.

- **`PROVER_AUTH_TOKEN` unset or empty: `503 {"error":"auth_not_configured"}`** on every route
  except `/health`. The service fails closed. It never serves a protected route without a token.
- **Token missing or wrong: `401 {"error":"unauthorized"}`** with `WWW-Authenticate: Bearer`.
- The check runs before the handler, so a refused request causes no Supabase read and no proving.
- `/health` stays public, because DealAppSeo/trinity-symphony-shared's pulse check calls it with no
  credentials. It reports `auth_configured: true|false`, never the token.

Before 2026-10-07 the service had no authentication, so anyone could read any agent's score and
tier through it.

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
- Without a valid token it returns `401`, and `503` if the service has no token configured
  (see [Authentication](#authentication)).

Check `proof_type` in the response before reading any other field:

| `proof_type` | Meaning |
|---|---|
| `plonky3_range_check` | A real STARK proof in `proof_bytes`, with `poseidon2_leaf` set. `verified` is `true`. |
| `sha256_commitment_poc` | **No proof.** `proof_bytes` holds a placeholder string. `verified` is `false`, and `reason` says why: `not_above_threshold` or `proving_failed`. |

`verified` is `true` only when the response carries a real proof, which the service verified
before returning it. On both no-proof paths it is `false`, and the HTTP status is still `200`.
`reason` is `null` on a real proof. Until 2026-10-07, `verified` was the comparison
`repid_score > threshold`, so it said `true` when proving failed and no proof existed.
`erc8004_token_id` is a copy of `agent_id`.

### No verify route

The verify route, `/zkp/verify/{commitment}`, was removed on 2026-10-07. It never routed: it used axum 0.8's
`{param}` syntax, and `Cargo.lock` pins axum 0.7.9, where braces are literal characters. It also
could not have checked anything. It read a stored `repid_score > threshold` flag from an
in-process map that held neither the proof bytes nor the score, and the map was emptied at every
restart. To verify a proof, run the independent verifier `@hyperdag/proof-verifier` on
`proof_bytes` and the statement `{agent_id, threshold, repid_score}`.

## Where this sits

**Calls:**

- **Supabase (PostgREST): one read per proof request.**
  `GET {SUPABASE_URL}/rest/v1/repid_agents?id=eq.<agent_id>&select=current_repid,tier`.
  The base URL comes from `SUPABASE_URL`. The key comes from `SUPABASE_SECRET_KEY`, or
  `SUPABASE_SERVICE_KEY`, or `SUPABASE_SERVICE_ROLE_KEY`, in that order of preference.
- The service makes no other calls at runtime. It does not call repid-engine, does not write to
  Supabase or to any other store, does not send anything on-chain, and keeps no proof records.

**Called by:**

- [DealAppSeo/repid-engine](https://github.com/DealAppSeo/repid-engine): its API's scoring pipeline
  and its proof-drain worker call `POST /zkp/repid-proof` at
  `https://zkp-postcard-production.up.railway.app`. That URL is the engine's default when its
  `ZKP_SERVICE_URL` is unset.
- Every one of those calls must now send the bearer token. As of 2026-10-07 the engine sends
  none, so this change must not reach production before the engine sends it (see
  [Build and deploy](#build-and-deploy)).
- DealAppSeo/trinity-symphony-shared's pulse check calls `/health` with no token.
- NOT CHECKED: the engine's trade-authorization bridge would send its request to
  `/prove/trade_auth` here if the engine's `PLONKY3_PROVER_URL` or `ZKP_SERVICE_URL` pointed at
  this service. Nobody has checked whether either variable is set. Its request body carries
  `timestamp` as an ISO string, and this service declares `timestamp` as an integer, so a local
  build answers that body with `422`.

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
- **Deploy order for authentication.** A deployed build with no `PROVER_AUTH_TOKEN` answers `503`
  to every proof request, and one with a token answers `401` to any caller that does not send it.
  Either way no proofs are made. So the engine must send the token first (a header the old build
  ignores is harmless), the same token value must be set on both services, and only then may this
  build be deployed. After deploying, `/health` should report `auth_configured: true`.

## Run it locally

The binary panics at startup unless `SUPABASE_URL` and one of the three key variables are set.
Every proof request reads the agent's score from that URL, so the service has no offline mode.
For local work, any HTTP server that answers the one query above with
`[{"current_repid": <n>, "tier": "<TIER>"}]` is enough. Without `PROVER_AUTH_TOKEN` the service
starts, and every route except `/health` answers `503`.

```bash
cd services/zkp-postcard
export SUPABASE_URL="https://<your-project>.supabase.co"
export SUPABASE_SECRET_KEY="<server-side key>"     # never commit a key
export PROVER_AUTH_TOKEN="<a long random value>"   # never commit it either
cargo run --release                                  # listens on 0.0.0.0:$PORT, default 8080
curl -s localhost:8080/health
curl -s -X POST localhost:8080/zkp/repid-proof \
  -H "Authorization: Bearer $PROVER_AUTH_TOKEN" -H 'Content-Type: application/json' \
  -d '{"agent_id":"<agent uuid>"}'
cargo test --locked                                  # circuit and HTTP tests; needs no environment
```

PowerShell:

```powershell
cd services\zkp-postcard
$env:SUPABASE_URL = "https://<your-project>.supabase.co"
$env:SUPABASE_SECRET_KEY = "<server-side key>"
$env:PROVER_AUTH_TOKEN = "<a long random value>"
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
- The *Auth* column matches `PUBLIC_PATHS` in `main.rs`, and the auth layer is applied after
  every route, so no route can be served without the token while this table says it needs one.
- The *Calls* list matches the outbound requests in `services/zkp-postcard/src/`.
- Every environment variable the code reads is named here.
- The only deployment domain named here is the one the engine calls.
- The map link is present.
- Any route using axum 0.8 `{param}` syntax is marked as not working while `Cargo.lock` pins
  axum below 0.8.

Code inside `#[cfg(test)]` modules is skipped: the tests' stand-in server and client are not
edges of the running service.

If `REPID_ENGINE_DIR` points at a checkout of DealAppSeo/repid-engine, the script also checks the
*Called by* edge against the engine's source.

Exit codes: `0` VERIFIED, `1` FAILED, `2` NOT CHECKED. `2` means nothing failed but at least one
check could not run. `.github/workflows/readme-edges.yml` runs the script on every pull request
with the engine checked out.

## License

Apache 2.0. See `LICENSE`.
