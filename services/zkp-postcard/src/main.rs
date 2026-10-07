//! ZKP Postcard Service — HyperDAG Trust Protocol v1
//!
//! Proves "RepID > threshold" using a Plonky3 STARK range-check on BabyBear field.
//! The circuit decomposes (repid - threshold - 1) into 32 bits and proves non-negativity.
//! The score is NOT a private input. The statement {agent_id, threshold, repid_score} is entirely
//! public: all three are circuit public values, and the response returns the score as
//! `repid_score_actual`. The proof binds "this agent's score > threshold"; it does not hide the score.

mod circuit;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tower_http::cors::CorsLayer;
use base64::Engine;

struct AppState {
    http_client: reqwest::Client,
    supabase_url: String,
    supabase_key: String,
    /// `PROVER_AUTH_TOKEN`, trimmed. `None` means auth is NOT configured, and then every route
    /// except `/health` answers 503. It never means "serve without auth".
    auth_token: Option<String>,
}

type SharedState = Arc<AppState>;

#[derive(Deserialize)]
struct ProofRequest {
    agent_id: Option<String>,
    requester_pubkey: Option<String>,
    tier: Option<String>,
    timestamp: Option<u64>,
    threshold: Option<u64>,
    repid_score: Option<u64>,
}

#[derive(Serialize)]
struct ProofResponse {
    proof_type: String,
    public_statement: String,
    commitment: String,
    verified: bool,
    agent_id: String,
    erc8004_token_id: String,
    tier: String,
    timestamp: String,
    protocol: String,
    proving_time_ms: u64,
    proof_size_bytes: usize,
    proof_bytes: String,
    // Phase 3 fields
    repid_score_actual: u64,
    repid_score_supplied: Option<u64>,
    score_source: String,
    // B-2: aggregation-ready Poseidon2/BabyBear leaf (Invariant 1) + its scheme tag. The engine
    // stores this as the new commitment lineage (scheme='poseidon2_babybear'); legacy sha256 rows
    // are left untouched. Empty for the sha256 fallback path.
    poseidon2_leaf: String,
    leaf_scheme: String,
    /// Why there is no proof: `not_above_threshold` or `proving_failed`. `null` on a real proof.
    reason: Option<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    proof_types: Vec<String>,
    protocol: String,
    /// Whether `PROVER_AUTH_TOKEN` is set. Never the token itself.
    auth_configured: bool,
}

async fn fetch_agent_repid(
    state: &SharedState,
    agent_id: &str,
) -> Result<(u64, String), StatusCode> {
    // Check if agent_id is a UUID or a legacy numeric ID
    // If it's 3747, 3748, etc., we might need to map it or it might be in the 'id' column as UUID-equivalent
    // The sample showed 'id' is UUID.
    
    let url = format!("{}/rest/v1/repid_agents?id=eq.{}&select=current_repid,tier", state.supabase_url, agent_id);
    
    let res = state.http_client
        .get(&url)
        .header("apikey", &state.supabase_key)
        .header("Authorization", format!("Bearer {}", state.supabase_key))
        .send()
        .await
        .map_err(|e| {
            eprintln!("[ZKP] Supabase request failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(StatusCode::NOT_FOUND);
    }

    let agents: Vec<serde_json::Value> = res.json().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let agent = agents.first().ok_or(StatusCode::NOT_FOUND)?;

    let score = agent["current_repid"].as_u64().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let tier = agent["tier"].as_str().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?.to_string();

    Ok((score, tier))
}

fn score_to_tier(score: u64) -> &'static str {
    match score {
        0..=499 => "PROBATIONARY",
        500..=999 => "EARNING",
        1000..=4999 => "ESTABLISHED",
        5000..=7999 => "AUTONOMOUS",
        8000..=10000 => "VETERAN",
        _ => "PROBATIONARY",
    }
}

fn tier_to_threshold(tier: &str) -> Result<u64, &'static str> {
    match tier {
        "PROBATIONARY" => Ok(0),
        "EARNING" => Ok(499),
        "ESTABLISHED" => Ok(999),
        "AUTONOMOUS" => Ok(4999),
        "VETERAN" => Ok(7999),
        "CUSTODIED_DBT" | "EARNING_AUTONOMY" => Err("Obsolete tier nomenclature"),
        _ => Err("Unknown tier"),
    }
}

fn sha256_commitment(agent_id: &str, repid: u64, threshold: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("hyperdag_v1:{}:{}:{}", agent_id, repid, threshold));
    format!("0x{}", hex::encode(hasher.finalize()))
}

async fn health(State(state): State<SharedState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".into(),
        service: "zkp-postcard".into(),
        version: "0.2.0".into(),
        proof_types: vec![
            PROOF_TYPE_REAL.into(),
            PROOF_TYPE_NONE.into(),
        ],
        protocol: "HyperDAG Trust Protocol v1".into(),
        auth_configured: state.auth_token.is_some(),
    })
}

// ---------------------------------------------------------------------------------------------
// What a proof request produced. The ONLY place `verified` is decided.
// ---------------------------------------------------------------------------------------------

/// A real STARK proof is in `proof_bytes`.
const PROOF_TYPE_REAL: &str = "plonky3_range_check";
/// NO proof. `proof_bytes` holds a placeholder string, not a proof.
const PROOF_TYPE_NONE: &str = "sha256_commitment_poc";
const REASON_NOT_ABOVE_THRESHOLD: &str = "not_above_threshold";
const REASON_PROVING_FAILED: &str = "proving_failed";

struct ProofOutcome {
    proof_type: &'static str,
    proof_bytes: Vec<u8>,
    verified: bool,
    reason: Option<&'static str>,
}

/// F-10 (2026-10-07): `verified` is true ONLY when a real proof exists. `prove_range_check`
/// verifies every proof before returning it, so `Ok` means proved AND verified here.
///
/// `verified` used to be `repid > threshold`. When proving FAILED for an agent above the
/// threshold, the response therefore said `verified: true` next to a placeholder in
/// `proof_bytes`: a pass on a miss. The two no-proof paths keep their existing `proof_type` and
/// placeholder bytes, because callers already key on those, and now also say why.
fn proof_outcome(above: bool, prove: impl FnOnce() -> Result<Vec<u8>, String>) -> ProofOutcome {
    if !above {
        return ProofOutcome {
            proof_type: PROOF_TYPE_NONE,
            proof_bytes: b"not_above_threshold".to_vec(),
            verified: false,
            reason: Some(REASON_NOT_ABOVE_THRESHOLD),
        };
    }
    match prove() {
        Ok(bytes) => ProofOutcome {
            proof_type: PROOF_TYPE_REAL,
            proof_bytes: bytes,
            verified: true,
            reason: None,
        },
        Err(e) => {
            eprintln!("[ZKP] Plonky3 proof failed ({}); answering verified=false with no proof", e);
            ProofOutcome {
                proof_type: PROOF_TYPE_NONE,
                proof_bytes: b"sha256_fallback_placeholder".to_vec(),
                verified: false,
                reason: Some(REASON_PROVING_FAILED),
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Authentication (F-10, 2026-10-07)
// ---------------------------------------------------------------------------------------------

/// The only paths served without a token. `/health` stays public because
/// DealAppSeo/trinity-symphony-shared's pulse check calls it with no credentials.
const PUBLIC_PATHS: &[&str] = &["/health"];

/// `None` = not configured. Whitespace-only counts as unset, so an empty secret can never match.
fn auth_token_from(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The token from `Authorization: Bearer <token>` (scheme case-insensitive, per RFC 7235).
fn bearer_token(value: &[u8]) -> Option<&[u8]> {
    const SCHEME: &[u8] = b"bearer ";
    if value.len() < SCHEME.len() || !value[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let token = value[SCHEME.len()..].trim_ascii();
    if token.is_empty() { None } else { Some(token) }
}

/// Constant-time. Both sides are hashed to 32 bytes first, so the comparison never stops at the
/// first differing byte and does not leak the expected token's length.
fn token_matches(presented: &[u8], expected: &[u8]) -> bool {
    let a = Sha256::digest(presented);
    let b = Sha256::digest(expected);
    let diff = a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Until F-10 the prover had no authentication: anyone could POST an agent id and read back that
/// agent's score and tier, at our CPU cost. Now, on every path except `PUBLIC_PATHS`:
///   - `PROVER_AUTH_TOKEN` unset or empty -> 503. FAILS CLOSED; it never serves unauthenticated.
///   - bearer token missing or wrong      -> 401.
///   - bearer token matches               -> the route runs.
/// It runs before any handler, so a refused request costs no Supabase read and no proving.
/// Neither the token nor the Authorization header is ever logged or echoed.
async fn require_bearer(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    if PUBLIC_PATHS.contains(&req.uri().path()) {
        return next.run(req).await;
    }
    let Some(expected) = state.auth_token.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "auth_not_configured",
                "detail": "PROVER_AUTH_TOKEN is not set on this service, so every route except /health is refused"
            })),
        )
            .into_response();
    };
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| bearer_token(v.as_bytes()));
    match presented {
        Some(token) if token_matches(token, expected.as_bytes()) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response(),
    }
}

/// The whole service, built in one place so the tests exercise exactly what `main` serves.
///
/// The auth layer goes on AFTER every route: axum applies `.layer` only to routes added before
/// it (and to the fallback), so a route added above this line is protected by default. Do not add
/// a `.route` below it.
fn app(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/zkp/repid-proof", post(generate_proof))
        .route("/prove/trade_auth", post(generate_proof))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn generate_proof(
    State(state): State<SharedState>,
    Json(req): Json<ProofRequest>,
) -> Result<Json<ProofResponse>, (StatusCode, Json<serde_json::Value>)> {
    let agent_id = match req.agent_id.clone() {
        Some(id) => id,
        None => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "missing_agent_id" })))),
    };
    
    if req.repid_score.is_some() {
        println!("[ZKP] client_supplied_score={:?} ignored, using server-side lookup", req.repid_score);
    }

    // Server-side lookup
    let (repid, actual_tier) = fetch_agent_repid(&state, &agent_id).await.map_err(|status| {
        if status == StatusCode::NOT_FOUND {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": "agent_not_found",
                "agent_id": agent_id
            })))
        } else {
            (status, Json(serde_json::json!({ "error": "internal_error" })))
        }
    })?;

    let tier = req.tier.clone().unwrap_or(actual_tier);
    
    let threshold = match req.threshold {
        Some(t) => t,
        None => tier_to_threshold(&tier).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_tier" }))))?,
    };
    let above = repid > threshold;
    let statement = format!("RepID > {}", threshold);

    let start = Instant::now();

    // Try a Plonky3 STARK proof. Agent-bound: the statement is the public tuple
    // {agent_id, threshold, repid_score}. The closure runs only when `above`, so no underflow.
    let outcome = proof_outcome(above, || {
        let diff = (repid - threshold - 1) as u32;
        circuit::prove_range_check(diff, &agent_id, threshold, repid)
    });
    let commitment = sha256_commitment(&agent_id, repid, threshold);

    let proof_size = outcome.proof_bytes.len();
    let proof_bytes_str = base64::engine::general_purpose::STANDARD.encode(&outcome.proof_bytes);

    // B-2: compute the Poseidon2/BabyBear aggregation-ready leaf for real proofs only.
    let (poseidon2_leaf, leaf_scheme) = if outcome.proof_type == PROOF_TYPE_REAL {
        (circuit::poseidon2_postcard_leaf(&agent_id, threshold, repid), "poseidon2_babybear".to_string())
    } else {
        (String::new(), String::new())
    };

    let proving_time = start.elapsed().as_millis() as u64;

    Ok(Json(ProofResponse {
        proof_type: outcome.proof_type.to_string(),
        public_statement: statement,
        commitment,
        verified: outcome.verified,
        agent_id: agent_id.clone(),
        erc8004_token_id: agent_id,
        tier,
        timestamp: chrono::Utc::now().to_rfc3339(),
        protocol: "HyperDAG Trust Protocol v1".into(),
        proving_time_ms: proving_time,
        proof_size_bytes: proof_size,
        proof_bytes: proof_bytes_str,
        repid_score_actual: repid,
        repid_score_supplied: req.repid_score,
        score_source: "server_side_lookup".into(),
        poseidon2_leaf,
        leaf_scheme,
        reason: outcome.reason.map(str::to_string),
    }))
}

// `GET /zkp/verify/{commitment}` was REMOVED here (F-10, 2026-10-07). It never routed (axum 0.8
// `{param}` syntax under axum 0.7.9), and it could not have done a real check if it had: it read
// a stored `repid > threshold` flag out of an in-process map that held neither the proof bytes
// nor the score, so it could only repeat what this process had said, and only until a restart.
// The map also grew by one entry per request, forever. A real check needs the proof bytes and the
// statement, and the independent verifier (`@hyperdag/proof-verifier`) is where that happens.

#[tokio::main]
async fn main() {
    let http_client = reqwest::Client::new();
    
    let supabase_url = std::env::var("SUPABASE_URL")
        .expect("SUPABASE_URL must be set");
    // Accept the SAME three names repid-engine accepts (its src/config.ts), newest
    // canonical first.
    //
    // WHY THIS LIST GREW: on 2026-08-04 this service crash-looped on
    // "SUPABASE_SERVICE_KEY or SUPABASE_SERVICE_ROLE_KEY must be set: NotPresent"
    // while the TypeScript engine — talking to the same Supabase project — stayed
    // up. The credential had not been revoked; the Supabase key migration moved it
    // to `SUPABASE_SECRET_KEY`, a name config.ts already accepted and this binary
    // did not. One service surviving a rename while its sibling dies is not a
    // credential problem, it is a VOCABULARY problem — and it is the third time
    // this shape has cost real downtime here (a dead DATABASE_URL on one service
    // while 25 others were fine; a present-but-dead HUGGINGFACE_API_TOKEN).
    //
    // So the durable fix is to converge on one accepted set, not to re-set the old
    // variable. The legacy names stay: dropping them would merely invert which
    // deployment breaks.
    let supabase_key = std::env::var("SUPABASE_SECRET_KEY")
        .or_else(|_| std::env::var("SUPABASE_SERVICE_KEY"))
        .or_else(|_| std::env::var("SUPABASE_SERVICE_ROLE_KEY"))
        .expect(
            "one of SUPABASE_SECRET_KEY / SUPABASE_SERVICE_KEY / SUPABASE_SERVICE_ROLE_KEY \
             must be set (repid-engine accepts the same three — if the engine is up and this \
             is not, the key was RENAMED rather than revoked)",
        );

    // Fail closed, but stay up: with no token the service still answers /health (which reports
    // `auth_configured: false`) and refuses everything else with 503, rather than crash-looping.
    let auth_token = auth_token_from(std::env::var("PROVER_AUTH_TOKEN").ok());

    let state = Arc::new(AppState {
        http_client,
        supabase_url,
        supabase_key,
        auth_token,
    });

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("ZKP Postcard v0.2.0 listening on {}", addr);
    println!("Plonky3 STARK range-check (BabyBear field)");
    println!("HyperDAG Trust Protocol v1");
    if state.auth_token.is_some() {
        println!("Auth: bearer token required on every route except /health");
    } else {
        eprintln!("[ZKP] PROVER_AUTH_TOKEN is not set: every route except /health answers 503 until it is");
    }

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app(state)).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Tests. The HTTP tests run the real router from `app()` on a loopback port, against a stand-in
// for the one Supabase query, so they exercise the same layers and handler `main` serves.
// ---------------------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const AGENT: &str = "394b6ee4-62e7-4c66-8445-29107b097b4c";
    /// A test fixture, not a credential: it exists only inside these tests.
    const TOKEN: &str = "test-fixture-token-0123456789";

    fn client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        url
    }

    /// Answers the prover's one Supabase query with a fixed score and tier, and counts hits, so a
    /// test can show that a refused request never reached the handler.
    async fn fake_supabase(score: u64, tier: &'static str) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let router = Router::new().route(
            "/rest/v1/repid_agents",
            get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!([{ "current_repid": score, "tier": tier }]))
                }
            }),
        );
        (serve(router).await, hits)
    }

    async fn prover(auth_token: Option<&str>, supabase_url: String) -> String {
        serve(app(Arc::new(AppState {
            http_client: client(),
            supabase_url,
            supabase_key: "test-supabase-key".into(),
            auth_token: auth_token_from(auth_token.map(str::to_string)),
        })))
        .await
    }

    async fn prove(base: &str, authorization: Option<&str>) -> reqwest::Response {
        let mut req = client()
            .post(format!("{}/zkp/repid-proof", base))
            .json(&serde_json::json!({ "agent_id": AGENT }));
        if let Some(a) = authorization {
            req = req.header(header::AUTHORIZATION, a);
        }
        req.send().await.unwrap()
    }

    fn bearer() -> String {
        format!("Bearer {}", TOKEN)
    }

    // ----- fallback truth -------------------------------------------------------------------

    #[test]
    fn proving_failure_is_not_verified() {
        let o = proof_outcome(true, || Err("forced failure".into()));
        assert!(!o.verified, "a failed proof must never answer verified=true");
        assert_eq!(o.proof_type, PROOF_TYPE_NONE);
        assert_eq!(o.reason, Some(REASON_PROVING_FAILED));
    }

    #[test]
    fn not_above_threshold_is_not_verified_and_does_not_prove() {
        let o = proof_outcome(false, || panic!("must not attempt a proof below the threshold"));
        assert!(!o.verified);
        assert_eq!(o.proof_type, PROOF_TYPE_NONE);
        assert_eq!(o.reason, Some(REASON_NOT_ABOVE_THRESHOLD));
    }

    #[test]
    fn real_proof_is_verified() {
        let o = proof_outcome(true, || Ok(vec![1, 2, 3]));
        assert!(o.verified);
        assert_eq!(o.proof_type, PROOF_TYPE_REAL);
        assert_eq!(o.reason, None);
    }

    /// End to end through the real handler and circuit. A score >= 2^31 cannot be encoded as a
    /// public value, so `prove_range_check` returns Err and the fallback path runs. Before F-10
    /// this exact response said `verified: true`.
    #[tokio::test]
    async fn http_proving_failure_answers_verified_false() {
        let (sb, _) = fake_supabase(1u64 << 31, "ESTABLISHED").await;
        let base = prover(Some(TOKEN), sb).await;
        let res = prove(&base, Some(&bearer())).await;
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["proof_type"], PROOF_TYPE_NONE);
        assert_eq!(body["verified"], false, "fallback said verified: {}", body);
        assert_eq!(body["reason"], REASON_PROVING_FAILED);
        assert_eq!(body["poseidon2_leaf"], "");
    }

    /// Positive control: the right token reaches the handler, and a real proof still says true.
    #[tokio::test]
    async fn http_real_proof_answers_verified_true() {
        let (sb, hits) = fake_supabase(2280, "ESTABLISHED").await;
        let base = prover(Some(TOKEN), sb).await;
        let res = prove(&base, Some(&bearer())).await;
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["proof_type"], PROOF_TYPE_REAL);
        assert_eq!(body["verified"], true);
        assert!(body["reason"].is_null());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn http_below_threshold_answers_verified_false() {
        let (sb, _) = fake_supabase(500, "ESTABLISHED").await; // threshold 999
        let base = prover(Some(TOKEN), sb).await;
        let body: serde_json::Value = prove(&base, Some(&bearer())).await.json().await.unwrap();
        assert_eq!(body["proof_type"], PROOF_TYPE_NONE);
        assert_eq!(body["verified"], false);
        assert_eq!(body["reason"], REASON_NOT_ABOVE_THRESHOLD);
    }

    // ----- authentication -------------------------------------------------------------------

    #[tokio::test]
    async fn protected_routes_answer_401_without_a_token() {
        let (sb, hits) = fake_supabase(2280, "ESTABLISHED").await;
        let base = prover(Some(TOKEN), sb).await;
        for path in ["/zkp/repid-proof", "/prove/trade_auth"] {
            let res = client()
                .post(format!("{}{}", base, path))
                .json(&serde_json::json!({ "agent_id": AGENT }))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 401, "{} without a token", path);
            assert_eq!(res.headers()[header::WWW_AUTHENTICATE], "Bearer");
        }
        // An unknown path is refused too: the layer wraps the fallback, not just named routes.
        let res = client().get(format!("{}/anything-else", base)).send().await.unwrap();
        assert_eq!(res.status(), 401);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "a refused request must not reach Supabase");
    }

    #[tokio::test]
    async fn protected_routes_answer_401_with_a_wrong_token() {
        let (sb, hits) = fake_supabase(2280, "ESTABLISHED").await;
        let base = prover(Some(TOKEN), sb).await;
        let wrong = [
            "Bearer wrong-token".to_string(),
            format!("Bearer {}x", TOKEN),                  // the right token plus one byte
            format!("Bearer {}", &TOKEN[..TOKEN.len() - 1]), // the right token minus one byte
            format!("Basic {}", TOKEN),                    // right value, wrong scheme
            format!("{}", TOKEN),                          // no scheme
            "Bearer ".to_string(),                         // empty token
        ];
        for auth in &wrong {
            let res = prove(&base, Some(auth)).await;
            assert_eq!(res.status(), 401, "Authorization {:?} must be refused", auth);
            let text = res.text().await.unwrap();
            assert!(!text.contains(TOKEN), "a 401 must not echo the presented or expected token");
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn protected_routes_answer_503_when_auth_is_not_configured() {
        for configured in [None, Some(""), Some("   ")] {
            let (sb, hits) = fake_supabase(2280, "ESTABLISHED").await;
            let base = prover(configured, sb).await;
            for auth in [None, Some(bearer()), Some("Bearer ".to_string())] {
                let res = prove(&base, auth.as_deref()).await;
                assert_eq!(res.status(), 503, "PROVER_AUTH_TOKEN={:?}, Authorization {:?}", configured, auth);
                let body: serde_json::Value = res.json().await.unwrap();
                assert_eq!(body["error"], "auth_not_configured");
            }
            assert_eq!(hits.load(Ordering::SeqCst), 0, "unconfigured auth must never serve");
        }
    }

    #[tokio::test]
    async fn health_is_public_and_reports_auth_state_without_the_token() {
        for (configured, expect) in [(Some(TOKEN), true), (None, false)] {
            let (sb, hits) = fake_supabase(2280, "ESTABLISHED").await;
            let base = prover(configured, sb).await;
            let res = client().get(format!("{}/health", base)).send().await.unwrap();
            assert_eq!(res.status(), 200);
            let text = res.text().await.unwrap();
            assert!(!text.contains(TOKEN), "/health must never contain the token");
            let body: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(body["auth_configured"], expect);
            assert_eq!(hits.load(Ordering::SeqCst), 0, "/health does not contact Supabase");
        }
    }

    // ----- the verify route is gone ---------------------------------------------------------

    #[tokio::test]
    async fn verify_route_is_removed() {
        let (sb, _) = fake_supabase(2280, "ESTABLISHED").await;
        let base = prover(Some(TOKEN), sb).await;
        let commitment = sha256_commitment(AGENT, 2280, 999);
        for path in [format!("/zkp/verify/{}", commitment), "/zkp/verify/{commitment}".to_string()] {
            let res = client()
                .get(format!("{}{}", base, path))
                .header(header::AUTHORIZATION, bearer())
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), 404, "GET {} must not answer anything", path);
        }
    }

    // ----- the pieces -----------------------------------------------------------------------

    #[test]
    fn token_comparison() {
        assert!(token_matches(b"abc", b"abc"));
        assert!(!token_matches(b"abd", b"abc"));
        assert!(!token_matches(b"ab", b"abc"));
        assert!(!token_matches(b"abcd", b"abc"));
        assert!(!token_matches(b"", b"abc"));
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer_token(b"Bearer tok"), Some(&b"tok"[..]));
        assert_eq!(bearer_token(b"bearer tok"), Some(&b"tok"[..]));
        assert_eq!(bearer_token(b"BEARER  tok "), Some(&b"tok"[..]));
        assert_eq!(bearer_token(b"Basic tok"), None);
        assert_eq!(bearer_token(b"Bearertok"), None);
        assert_eq!(bearer_token(b"Bearer "), None);
        assert_eq!(bearer_token(b"Bearer"), None);
        assert_eq!(bearer_token(b""), None);
    }

    #[test]
    fn auth_token_parsing() {
        assert_eq!(auth_token_from(None), None);
        assert_eq!(auth_token_from(Some(String::new())), None);
        assert_eq!(auth_token_from(Some("  \n".into())), None);
        assert_eq!(auth_token_from(Some(" tok\n".into())), Some("tok".to_string()));
    }
}
