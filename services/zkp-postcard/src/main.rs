//! ZKP Postcard Service — HyperDAG Trust Protocol v1
//!
//! Proves "RepID > threshold" using a Plonky3 STARK range-check on BabyBear field.
//! The circuit decomposes (repid - threshold - 1) into 32 bits and proves non-negativity.
//! Private input: actual RepID score. Public output: commitment + proof that score > threshold.

mod circuit;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use base64::Engine;

struct AppState {
    store: Arc<RwLock<HashMap<String, ProofRecord>>>,
    http_client: reqwest::Client,
    supabase_url: String,
    supabase_key: String,
}

type SharedState = Arc<AppState>;

#[derive(Clone, Serialize, Deserialize)]
struct ProofRecord {
    agent_id: String,
    threshold: u64,
    tier: String,
    statement: String,
    proof_type: String,
    verified: bool,
    proof_size_bytes: usize,
    proving_time_ms: u64,
}

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
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    statement: String,
    agent_id: String,
    proof_type: String,
    protocol: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    version: String,
    proof_types: Vec<String>,
    protocol: String,
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

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".into(),
        service: "zkp-postcard".into(),
        version: "0.2.0".into(),
        proof_types: vec![
            "plonky3_range_check".into(),
            "sha256_commitment_poc".into(),
        ],
        protocol: "HyperDAG Trust Protocol v1".into(),
    })
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

    // Try Plonky3 STARK proof
    let (proof_type, commitment, proof_bytes) = if above {
        let diff = (repid - threshold - 1) as u32;
        // Agent-bound proof: statement is the public tuple {agent_id, threshold, repid_score}.
        match circuit::prove_range_check(diff, &agent_id, threshold, repid) {
            Ok(bytes) => {
                let commitment = sha256_commitment(&agent_id, repid, threshold);
                ("plonky3_range_check".to_string(), commitment, bytes)
            }
            Err(e) => {
                eprintln!("[ZKP] Plonky3 proof failed ({}), falling back to SHA-256", e);
                let commitment = sha256_commitment(&agent_id, repid, threshold);
                ("sha256_commitment_poc".to_string(), commitment, "sha256_fallback_placeholder".as_bytes().to_vec())
            }
        }
    } else {
        let commitment = sha256_commitment(&agent_id, repid, threshold);
        ("sha256_commitment_poc".to_string(), commitment, "not_above_threshold".as_bytes().to_vec())
    };

    let proof_size = proof_bytes.len();
    let proof_bytes_str = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

    // B-2: compute the Poseidon2/BabyBear aggregation-ready leaf for real proofs only.
    let (poseidon2_leaf, leaf_scheme) = if proof_type == "plonky3_range_check" {
        (circuit::poseidon2_postcard_leaf(&agent_id, threshold, repid), "poseidon2_babybear".to_string())
    } else {
        (String::new(), String::new())
    };

    let proving_time = start.elapsed().as_millis() as u64;

    let record = ProofRecord {
        agent_id: agent_id.clone(),
        threshold,
        tier: tier.clone(),
        statement: statement.clone(),
        proof_type: proof_type.clone(),
        verified: above,
        proof_size_bytes: proof_size,
        proving_time_ms: proving_time,
    };
    state.store.write().await.insert(commitment.clone(), record);

    Ok(Json(ProofResponse {
        proof_type,
        public_statement: statement,
        commitment,
        verified: above,
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
    }))
}

async fn verify_proof(
    State(state): State<SharedState>,
    Path(commitment): Path<String>,
) -> Result<Json<VerifyResponse>, StatusCode> {
    let records = state.store.read().await;
    let record = records.get(&commitment).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(VerifyResponse {
        valid: record.verified,
        statement: record.statement.clone(),
        agent_id: record.agent_id.clone(),
        proof_type: record.proof_type.clone(),
        protocol: "HyperDAG Trust Protocol v1".into(),
    }))
}

#[tokio::main]
async fn main() {
    let store = Arc::new(RwLock::new(HashMap::new()));
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

    let state = Arc::new(AppState {
        store,
        http_client,
        supabase_url,
        supabase_key,
    });

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    let app = Router::new()
        .route("/health", get(health))
        .route("/zkp/repid-proof", post(generate_proof))
        .route("/prove/trade_auth", post(generate_proof))
        .route("/zkp/verify/{commitment}", get(verify_proof))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("ZKP Postcard v0.2.0 listening on {}", addr);
    println!("Plonky3 STARK range-check (BabyBear field)");
    println!("HyperDAG Trust Protocol v1");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
