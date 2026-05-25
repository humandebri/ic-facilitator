// rust/facilitator/src/lib.rs: ICP HTTP gateway 上で JPYC x402 facilitator API を公開する。
mod eip712;
mod facilitator;
mod hexutil;
mod rpc;
mod state;
mod tx;
mod types;

use std::cell::RefCell;
use std::collections::BTreeMap;

use candid::CandidType;
use ic_cdk::{post_upgrade, pre_upgrade, query, update};
use ic_cdk_management_canister::{HttpRequestResult, TransformArgs};
use k256::ecdsa::SigningKey;
use serde::Serialize;

use crate::facilitator::{failed_settlement, supported, validate_request, verify_request};
use crate::hexutil::{address_hex, keccak256, parse_hex, NETWORK};
use crate::rpc::{refresh_settlement, send_settlement, snapshot, RpcConfig, SettlementOutcome};
use crate::state::SettlementRecord;
use crate::types::{
    json_response, text_response, FacilitatorRequest, HeaderField, HttpRequest, HttpResponse,
    SettleResponse,
};

const DEFAULT_RPC_SERVICES: &str = "https://polygon-bor-rpc.publicnode.com";
const DEFAULT_MAX_GAS: u128 = 500_000;
const DEFAULT_CONFIRMATION_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, CandidType, candid::Deserialize)]
struct StableState {
    env: BTreeMap<String, String>,
    settlements: BTreeMap<String, SettlementRecord>,
}

#[derive(Clone, Debug, CandidType, candid::Deserialize)]
struct OldStableState {
    env: BTreeMap<String, String>,
    settlements: BTreeMap<String, SettleResponse>,
}

thread_local! {
    static ENV: RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
    static SETTLEMENTS: RefCell<BTreeMap<String, SettlementRecord>> = RefCell::new(BTreeMap::new());
}

#[query]
fn http_request(request: HttpRequest) -> HttpResponse {
    route(request, false)
}

#[update]
async fn http_request_update(request: HttpRequest) -> HttpResponse {
    match (request.method.as_str(), path(&request.url).as_str()) {
        ("POST", "/verify") => verify_http(request).await,
        ("POST", "/settle") => settle_http(request).await,
        _ => route(request, true),
    }
}

#[update]
fn set_env(name: String, value: String) {
    let caller = ic_cdk::api::msg_caller();
    if !ic_cdk::api::is_controller(&caller) {
        ic_cdk::trap("caller is not a controller");
    }
    ENV.with(|env| {
        env.borrow_mut().insert(name, value);
    });
}

#[query]
fn env_names() -> Vec<String> {
    ENV.with(|env| env.borrow().keys().cloned().collect())
}

#[query]
fn transform_rpc(args: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: args.response.body,
    }
}

#[pre_upgrade]
fn pre_upgrade() {
    let env = ENV.with(|items| items.borrow().clone());
    let settlements = SETTLEMENTS.with(|items| items.borrow().clone());
    let state = StableState { env, settlements };
    ic_cdk::storage::stable_save((state,)).expect("stable_save");
}

#[post_upgrade]
fn post_upgrade() {
    if let Ok((state,)) = ic_cdk::storage::stable_restore::<(StableState,)>() {
        ENV.with(|items| *items.borrow_mut() = state.env);
        SETTLEMENTS.with(|items| *items.borrow_mut() = state.settlements);
    } else if let Ok((state,)) = ic_cdk::storage::stable_restore::<(OldStableState,)>() {
        ENV.with(|items| *items.borrow_mut() = state.env);
        let now = now_seconds();
        let ttl = DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS;
        let settlements = state
            .settlements
            .into_iter()
            .map(|(key, response)| {
                let status = if response.success {
                    "settled"
                } else {
                    "failed"
                }
                .to_string();
                (
                    key,
                    SettlementRecord {
                        status,
                        response,
                        created_at: now,
                        updated_at: now,
                        expires_at: now.saturating_add(ttl),
                    },
                )
            })
            .collect();
        SETTLEMENTS.with(|items| *items.borrow_mut() = settlements);
    }
}

fn route(request: HttpRequest, updated: bool) -> HttpResponse {
    match (request.method.as_str(), path(&request.url).as_str()) {
        ("GET", "/health") => json_response(200, &health()),
        ("GET", "/supported") => json_response(200, &supported(facilitator_address())),
        ("POST", "/verify") | ("POST", "/settle") if !updated => HttpResponse {
            status_code: 202,
            headers: vec![HeaderField(
                "content-type".to_string(),
                "text/plain".to_string(),
            )],
            body: b"upgrade required".to_vec(),
            upgrade: Some(true),
        },
        _ => text_response(404, "not found"),
    }
}

async fn verify_http(request: HttpRequest) -> HttpResponse {
    match parse_request(&request).and_then(|body| Ok((body, rpc_config()?))) {
        Ok((body, config)) => match snapshot(&config, &body).await {
            Ok(state) => json_response(200, &verify_request(&body, Some(&state))),
            Err(message) => json_response(200, &verify_error("rpc_error", &message)),
        },
        Err(message) => json_response(400, &verify_error("invalid_request", &message)),
    }
}

async fn settle_http(request: HttpRequest) -> HttpResponse {
    let body = match parse_request(&request) {
        Ok(body) => body,
        Err(message) => {
            return json_response(400, &settle_error("invalid_request", &message, None))
        }
    };
    let key = settlement_key(&body);
    purge_expired_settlements(now_seconds());
    if let Some(existing) = SETTLEMENTS.with(|items| items.borrow().get(&key).cloned()) {
        return cached_settlement_response(&key, existing).await;
    }
    let config = match rpc_config() {
        Ok(config) => config,
        Err(message) => return json_response(400, &settle_error("invalid_config", &message, None)),
    };
    let state = match snapshot(&config, &body).await {
        Ok(state) => state,
        Err(message) => return json_response(502, &settle_error("rpc_error", &message, None)),
    };
    let payer = match validate_request(&body, Some(&state)) {
        Ok(payer) => payer,
        Err(err) => {
            let response = failed_settlement(NETWORK, &err.reason, &err.message, err.payer);
            return json_response(402, &response);
        }
    };
    let private_key = match env("FACILITATOR_EVM_PRIVATE_KEY") {
        Ok(value) => value,
        Err(message) => {
            return json_response(400, &settle_error("invalid_config", &message, Some(payer)))
        }
    };
    let ttl = settlement_cache_ttl_seconds();
    insert_settlement(
        &key,
        SettlementRecord::checking(
            payer.clone(),
            body.payment_requirements.amount.clone(),
            now_seconds(),
            ttl,
        ),
    );
    match send_settlement(&config, &private_key, &body).await {
        Ok(SettlementOutcome::Settled(tx)) => {
            let record = SettlementRecord::settled(
                tx,
                payer,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            json_response(200, &record.response)
        }
        Ok(SettlementOutcome::Pending(tx)) => {
            let record = SettlementRecord::broadcast(
                tx,
                payer,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            json_response(202, &record.response)
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            let record = SettlementRecord::failed(tx, message, payer, now_seconds(), ttl);
            insert_settlement(&key, record.clone());
            json_response(502, &record.response)
        }
        Err(message) => {
            SETTLEMENTS.with(|items| items.borrow_mut().remove(&key));
            json_response(
                502,
                &settle_error("settlement_failed", &message, Some(payer)),
            )
        }
    }
}

async fn cached_settlement_response(key: &str, existing: SettlementRecord) -> HttpResponse {
    let Some(details) = existing.broadcast_settlement() else {
        return json_response(existing.status_code(), &existing.response);
    };
    let config = match rpc_config() {
        Ok(config) => config,
        Err(_) => return json_response(existing.status_code(), &existing.response),
    };
    let refreshed = match refresh_settlement(&config, &details.tx).await {
        Ok(outcome) => outcome,
        Err(message) => {
            return json_response(
                502,
                &settle_error("rpc_error", &message, Some(details.payer)),
            )
        }
    };
    let ttl = settlement_cache_ttl_seconds();
    match refreshed {
        SettlementOutcome::Settled(tx) => {
            let record =
                SettlementRecord::settled(tx, details.payer, details.amount, now_seconds(), ttl);
            insert_settlement(key, record.clone());
            json_response(200, &record.response)
        }
        SettlementOutcome::Pending(_) => json_response(existing.status_code(), &existing.response),
        SettlementOutcome::Failed { tx, message } => {
            let record = SettlementRecord::failed(tx, message, details.payer, now_seconds(), ttl);
            insert_settlement(key, record.clone());
            json_response(502, &record.response)
        }
    }
}

fn parse_request(request: &HttpRequest) -> Result<FacilitatorRequest, String> {
    serde_json::from_slice(&request.body).map_err(|err| format!("invalid JSON body: {err}"))
}

fn rpc_config() -> Result<RpcConfig, String> {
    let max_gas = env("FACILITATOR_MAX_GAS")
        .ok()
        .and_then(|value| value.parse::<u128>().ok())
        .unwrap_or(DEFAULT_MAX_GAS);
    Ok(RpcConfig {
        services: env("POLYGON_RPC_SERVICES").unwrap_or_else(|_| DEFAULT_RPC_SERVICES.to_string()),
        max_gas,
        confirmation_timeout_seconds: env("SETTLE_CONFIRMATION_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_CONFIRMATION_TIMEOUT_SECONDS),
    })
}

fn health() -> impl Serialize {
    serde_json::json!({
        "ok": true,
        "network": NETWORK,
        "facilitatorAddress": facilitator_address()
    })
}

fn verify_error(reason: &str, message: &str) -> crate::types::VerifyResponse {
    crate::types::VerifyResponse {
        is_valid: false,
        invalid_reason: Some(reason.to_string()),
        invalid_message: Some(message.to_string()),
        payer: None,
    }
}

fn settle_error(reason: &str, message: &str, payer: Option<String>) -> SettleResponse {
    failed_settlement(NETWORK, reason, message, payer)
}

fn env(name: &str) -> Result<String, String> {
    if let Some(value) = ENV.with(|env| env.borrow().get(name).cloned()) {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    let value = ic_cdk::api::env_var_value(name);
    if value.trim().is_empty() {
        return Err(format!("missing required env: {name}"));
    }
    Ok(value)
}

fn path(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

fn facilitator_address() -> String {
    env("FACILITATOR_EVM_PRIVATE_KEY")
        .ok()
        .and_then(|key| private_key_address(&key).ok())
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string())
}

pub fn private_key_address(private_key: &str) -> Result<String, String> {
    let bytes = parse_hex(private_key, Some(32))?;
    let key = SigningKey::from_slice(&bytes).map_err(|_| "invalid facilitator private key")?;
    let point = key.verifying_key().to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address_hex(&address))
}

pub fn now_seconds() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        ic_cdk::api::time() / 1_000_000_000
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        1_700_000_000
    }
}

fn settlement_key(body: &FacilitatorRequest) -> String {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    format!("0x{}", hex::encode(keccak256(&bytes)))
}

fn insert_settlement(key: &str, record: SettlementRecord) {
    SETTLEMENTS.with(|items| {
        items.borrow_mut().insert(key.to_string(), record);
    });
}

fn purge_expired_settlements(now: u64) {
    SETTLEMENTS.with(|items| {
        items
            .borrow_mut()
            .retain(|_, record| !record.is_expired(now));
    });
}

fn settlement_cache_ttl_seconds() -> u64 {
    env("SETTLEMENT_CACHE_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS)
}

ic_cdk::export_candid!();
