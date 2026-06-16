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
use k256::ecdsa::SigningKey;
use serde::Serialize;

use crate::facilitator::{failed_settlement, supported, validate_request};
use crate::hexutil::{
    address_hex, keccak256, parse_address, parse_hex, JPYC_EIP712_NAME, JPYC_POLYGON_ADDRESS,
    NETWORK,
};
use crate::rpc::{
    pending_nonce, refresh_settlement, send_settlement, ExpectedTransfer, RpcConfig,
    SettlementOutcome, SettlementSendError,
};
use crate::state::SettlementRecord;
use crate::types::{
    json_response, text_response, FacilitatorRequest, HeaderField, HttpRequest, HttpResponse,
    PaymentPayload, PaymentRequiredResponse, PaymentRequirements, ResourceInfo, SettleResponse,
};

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_GAS: u128 = 500_000;
const DEFAULT_MAX_SETTLEMENT_FEE_WEI: u128 = 30_000_000_000_000_000;
const DEFAULT_CONFIRMATION_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS: u64 = 86_400;
const GAS_TOO_EXPENSIVE_MESSAGE: &str = "estimated POL settlement fee exceeds configured cap";

#[derive(Clone, Debug, CandidType, candid::Deserialize)]
struct StableState {
    env: BTreeMap<String, String>,
    settlements: BTreeMap<String, SettlementRecord>,
    seller_credits: BTreeMap<String, SellerCredit>,
    credited_settlements: BTreeMap<String, String>,
    active_settlements: Option<BTreeMap<String, ActiveSettlement>>,
    nonces: Option<BTreeMap<String, NonceState>>,
}

thread_local! {
    static ENV: RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
    static SETTLEMENTS: RefCell<BTreeMap<String, SettlementRecord>> = RefCell::new(BTreeMap::new());
    static SELLER_CREDITS: RefCell<BTreeMap<String, SellerCredit>> = RefCell::new(BTreeMap::new());
    static CREDITED_SETTLEMENTS: RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
    static ACTIVE_SETTLEMENTS: RefCell<BTreeMap<String, ActiveSettlement>> = RefCell::new(BTreeMap::new());
    static NONCES: RefCell<BTreeMap<String, NonceState>> = RefCell::new(BTreeMap::new());
}

#[derive(Clone, Debug, CandidType, candid::Deserialize)]
struct SellerCredit {
    credit_atoms: u128,
    updated_at: u64,
}

#[derive(Clone, Debug, CandidType, candid::Deserialize)]
struct ActiveSettlement {
    key: String,
    nonce: Option<u128>,
    tx: Option<String>,
}

#[derive(Clone, Debug, Default, CandidType, candid::Deserialize)]
struct NonceState {
    next_nonce: Option<u128>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CostStep {
    name: &'static str,
    instructions: u64,
    rpc_calls: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CostReport {
    total_instructions: u64,
    rpc_calls: u64,
    steps: Vec<CostStep>,
}

#[derive(Clone, Debug)]
struct CostTrace {
    enabled: bool,
    start: u64,
    last: u64,
    rpc_calls: u64,
    steps: Vec<CostStep>,
}

#[query]
fn http_request(request: HttpRequest) -> HttpResponse {
    route(request, false)
}

#[update]
async fn http_request_update(request: HttpRequest) -> HttpResponse {
    match (request.method.as_str(), path(&request.url).as_str()) {
        ("GET", "/seller-credit") => seller_credit_http(request).await,
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
    let caller = ic_cdk::api::msg_caller();
    if !ic_cdk::api::is_controller(&caller) {
        ic_cdk::trap("caller is not a controller");
    }
    ENV.with(|env| env.borrow().keys().cloned().collect())
}

#[pre_upgrade]
fn pre_upgrade() {
    let env = ENV.with(|items| items.borrow().clone());
    let settlements = SETTLEMENTS.with(|items| items.borrow().clone());
    let seller_credits = SELLER_CREDITS.with(|items| items.borrow().clone());
    let credited_settlements = CREDITED_SETTLEMENTS.with(|items| items.borrow().clone());
    let active_settlements = ACTIVE_SETTLEMENTS.with(|items| items.borrow().clone());
    let nonces = NONCES.with(|items| items.borrow().clone());
    let state = StableState {
        env,
        settlements,
        seller_credits,
        credited_settlements,
        active_settlements: Some(active_settlements),
        nonces: Some(nonces),
    };
    ic_cdk::storage::stable_save((state,)).expect("stable_save");
}

#[post_upgrade]
fn post_upgrade() {
    let (state,) = ic_cdk::storage::stable_restore::<(StableState,)>().expect("stable_restore");
    ENV.with(|items| *items.borrow_mut() = state.env);
    SETTLEMENTS.with(|items| *items.borrow_mut() = state.settlements);
    SELLER_CREDITS.with(|items| *items.borrow_mut() = state.seller_credits);
    CREDITED_SETTLEMENTS.with(|items| *items.borrow_mut() = state.credited_settlements);
    ACTIVE_SETTLEMENTS
        .with(|items| *items.borrow_mut() = state.active_settlements.unwrap_or_default());
    NONCES.with(|items| *items.borrow_mut() = state.nonces.unwrap_or_default());
}

fn route(request: HttpRequest, updated: bool) -> HttpResponse {
    match (request.method.as_str(), path(&request.url).as_str()) {
        ("GET", "/health") => json_response(200, &health()),
        ("GET", "/supported") => match env("JPYC_EIP712_VERSION") {
            Ok(version) => json_response(200, &supported(facilitator_address(), &version)),
            Err(message) => json_response(
                500,
                &serde_json::json!({ "error": "invalid_config", "message": message }),
            ),
        },
        ("GET", "/seller-credit") if payment_signature_header(&request).is_some() && !updated => {
            HttpResponse {
                status_code: 202,
                headers: vec![HeaderField(
                    "content-type".to_string(),
                    "text/plain".to_string(),
                )],
                body: b"upgrade required".to_vec(),
                upgrade: Some(true),
            }
        }
        ("GET", "/seller-credit") => {
            seller_credit_required_response(&request).unwrap_or_else(|message| {
                json_response(400, &retryable_error("invalid_request", &message, false))
            })
        }
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
    let mut trace = CostTrace::for_request(&request);
    trace.step("verify.unsupported", 0);
    json_response_with_cost(
        501,
        &retryable_error("unsupported", "verify is disabled; use settle", false),
        &trace,
    )
}

async fn settle_http(request: HttpRequest) -> HttpResponse {
    let mut trace = CostTrace::for_request(&request);
    let body = match parse_request(&request) {
        Ok(body) => body,
        Err(message) => {
            trace.step("settle.parse", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, None),
                &trace,
            );
        }
    };
    trace.step("settle.parse", 0);
    let payer = match validate_request(&body) {
        Ok(payer) => payer,
        Err(err) => {
            trace.step("settle.local_validation", 0);
            let response = failed_settlement(NETWORK, &err.reason, &err.message, err.payer);
            return json_response_with_cost(402, &response, &trace);
        }
    };
    trace.step("settle.local_validation", 0);
    let key = match settlement_key(&body) {
        Ok(key) => key,
        Err(message) => {
            trace.step("settle.key", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, Some(payer)),
                &trace,
            );
        }
    };
    trace.step("settle.key", 0);
    purge_expired_settlements(now_seconds());
    if let Some(existing) = SETTLEMENTS.with(|items| items.borrow().get(&key).cloned()) {
        return cached_settlement_response(&key, existing, &body, &mut trace).await;
    }
    let private_key = match env("FACILITATOR_EVM_PRIVATE_KEY") {
        Ok(value) => value,
        Err(message) => {
            trace.step("settle.config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                &trace,
            );
        }
    };
    let from = match private_key_address(&private_key) {
        Ok(value) => value,
        Err(message) => {
            trace.step("settle.config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                &trace,
            );
        }
    };
    trace.step("settle.config", 0);
    if !acquire_active_settlement(&from, &key) {
        trace.step("settle.active_lock", 0);
        return json_response_with_cost(
            429,
            &settle_error(
                "settlement_queue_busy",
                "another settlement is active for this facilitator address",
                Some(payer),
            ),
            &trace,
        );
    }
    trace.step("settle.active_lock", 0);
    let ttl = match settlement_cache_ttl_seconds() {
        Ok(ttl) => ttl,
        Err(message) => {
            release_active_settlement(&from, &key);
            trace.step("settle.ttl", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                &trace,
            );
        }
    };
    trace.step("settle.ttl", 0);
    let settlement_fee = match seller_settlement_fee_amount() {
        Ok(value) => value,
        Err(message) => {
            release_active_settlement(&from, &key);
            trace.step("settle.seller_fee_config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                &trace,
            );
        }
    };
    trace.step("settle.seller_fee_config", 0);
    if let Err(message) = reserve_seller_credit(&body.payment_requirements.pay_to, settlement_fee) {
        release_active_settlement(&from, &key);
        trace.step("settle.reserve_seller_credit", 0);
        return json_response_with_cost(
            402,
            &settle_error("seller_insufficient_credit", &message, Some(payer)),
            &trace,
        );
    }
    trace.step("settle.reserve_seller_credit", 0);
    insert_settlement(
        &key,
        SettlementRecord::checking(
            payer.clone(),
            body.payment_requirements.pay_to.clone(),
            body.payment_requirements.amount.clone(),
            now_seconds(),
            ttl,
        ),
    );
    let config = match rpc_config() {
        Ok(config) => config,
        Err(message) => {
            remove_settlement(&key);
            refund_seller_credit(&body.payment_requirements.pay_to, settlement_fee);
            release_active_settlement(&from, &key);
            trace.step("settle.rpc_config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                &trace,
            );
        }
    };
    trace.step("settle.rpc_config", 0);
    let rpc_nonce = match pending_nonce(&config, &from).await {
        Ok(nonce) => nonce,
        Err(message) => {
            remove_settlement(&key);
            refund_seller_credit(&body.payment_requirements.pay_to, settlement_fee);
            release_active_settlement(&from, &key);
            trace.step("settle.pending_nonce", 1);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, Some(payer)),
                &trace,
            );
        }
    };
    trace.step("settle.pending_nonce", 1);
    let nonce = reserve_nonce(&from, rpc_nonce);
    match send_settlement(&config, &private_key, &body, nonce).await {
        Ok(SettlementOutcome::Settled(tx)) => {
            trace.step("settle.send_settlement", 4);
            let record = SettlementRecord::settled(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            release_active_settlement(&from, &key);
            json_response_with_cost(200, &record.response, &trace)
        }
        Ok(SettlementOutcome::Pending { nonce, tx }) => {
            trace.step("settle.send_settlement", 4);
            update_active_broadcast(&from, &key, nonce, &tx);
            let record = SettlementRecord::broadcast(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            json_response_with_cost(202, &record.response, &trace)
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            trace.step("settle.send_settlement", 4);
            let record = SettlementRecord::failed(
                tx,
                message,
                payer,
                body.payment_requirements.pay_to,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            release_active_settlement(&from, &key);
            json_response_with_cost(502, &record.response, &trace)
        }
        Err(SettlementSendError::GasTooExpensive) => {
            trace.step("settle.send_settlement", 2);
            rollback_reserved_nonce(&from, nonce);
            remove_settlement(&key);
            refund_seller_credit(&body.payment_requirements.pay_to, settlement_fee);
            release_active_settlement(&from, &key);
            json_response_with_cost(
                503,
                &settle_error("gas_too_expensive", GAS_TOO_EXPENSIVE_MESSAGE, Some(payer)),
                &trace,
            )
        }
        Err(SettlementSendError::Other(message)) => {
            trace.step("settle.send_settlement", 4);
            rollback_reserved_nonce(&from, nonce);
            remove_settlement(&key);
            refund_seller_credit(&body.payment_requirements.pay_to, settlement_fee);
            release_active_settlement(&from, &key);
            json_response_with_cost(
                502,
                &settle_error("settlement_failed", &message, Some(payer)),
                &trace,
            )
        }
    }
}

async fn cached_settlement_response(
    key: &str,
    existing: SettlementRecord,
    body: &FacilitatorRequest,
    trace: &mut CostTrace,
) -> HttpResponse {
    let Some(details) = existing.broadcast_settlement() else {
        trace.step("settle.cache_hit", 0);
        return json_response_with_cost(existing.status_code(), &existing.response, trace);
    };
    let config = match rpc_config() {
        Ok(config) => config,
        Err(_) => {
            trace.step("settle.cache_config", 0);
            return json_response_with_cost(existing.status_code(), &existing.response, trace);
        }
    };
    trace.step("settle.cache_config", 0);
    let expected = ExpectedTransfer {
        amount: details.amount.clone(),
        from: details.payer.clone(),
        to: details.pay_to.clone(),
    };
    let refreshed = match refresh_settlement(&config, &details.tx, &expected).await {
        Ok(outcome) => outcome,
        Err(message) => {
            trace.step("settle.refresh", 1);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, Some(details.payer)),
                trace,
            );
        }
    };
    trace.step("settle.refresh", 1);
    let ttl = settlement_cache_ttl_seconds();
    let ttl = match ttl {
        Ok(ttl) => ttl,
        Err(_) => {
            trace.step("settle.cache_ttl", 0);
            return json_response_with_cost(existing.status_code(), &existing.response, trace);
        }
    };
    trace.step("settle.cache_ttl", 0);
    match refreshed {
        SettlementOutcome::Settled(tx) => {
            let record = SettlementRecord::settled(
                tx,
                details.payer.clone(),
                details.pay_to.clone(),
                details.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record.clone());
            release_active_settlement_by_key(key);
            json_response_with_cost(200, &record.response, trace)
        }
        SettlementOutcome::Pending { .. } => {
            let record = maybe_replace_pending_settlement_record(
                key,
                existing,
                body,
                details,
                ttl,
                trace,
                SETTLE_REPLACEMENT_TRACE,
            )
            .await;
            json_response_with_cost(record.status_code(), &record.response, trace)
        }
        SettlementOutcome::Failed { tx, message } => {
            let record = SettlementRecord::failed(
                tx,
                message,
                details.payer.clone(),
                details.pay_to.clone(),
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record.clone());
            release_active_settlement_by_key(key);
            json_response_with_cost(502, &record.response, trace)
        }
    }
}

async fn seller_credit_http(request: HttpRequest) -> HttpResponse {
    let mut trace = CostTrace::for_request(&request);
    let seller = match seller_from_request(&request) {
        Ok(value) => value,
        Err(message) => {
            trace.step("seller_credit.parse_seller", 0);
            return json_response_with_cost(
                400,
                &retryable_error("invalid_request", &message, false),
                &trace,
            );
        }
    };
    trace.step("seller_credit.parse_seller", 0);
    let signature = match payment_signature_header(&request) {
        Some(value) => value,
        None => {
            trace.step("seller_credit.payment_header", 0);
            return seller_credit_required_response(&request).unwrap_or_else(|message| {
                json_response_with_cost(
                    400,
                    &retryable_error("invalid_request", &message, false),
                    &trace,
                )
            });
        }
    };
    trace.step("seller_credit.payment_header", 0);
    let payload = match payment_payload_from_header(&signature) {
        Ok(value) => value,
        Err(message) => {
            trace.step("seller_credit.decode_payment", 0);
            return json_response_with_cost(
                402,
                &settle_error("invalid_payment_header", &message, None),
                &trace,
            );
        }
    };
    trace.step("seller_credit.decode_payment", 0);
    if let Err(message) = validate_seller_credit_seller(&seller, &payload) {
        trace.step("seller_credit.seller_validation", 0);
        return json_response_with_cost(
            402,
            &settle_error("invalid_payment_seller", &message, None),
            &trace,
        );
    }
    trace.step("seller_credit.seller_validation", 0);
    let resource = match seller_credit_resource(&request) {
        Ok(value) => value,
        Err(message) => {
            trace.step("seller_credit.resource", 0);
            return json_response_with_cost(
                400,
                &retryable_error("invalid_request", &message, false),
                &trace,
            );
        }
    };
    trace.step("seller_credit.resource", 0);
    if payload.resource.as_ref().map(|item| item.url.as_str()) != Some(resource.url.as_str()) {
        trace.step("seller_credit.resource_validation", 0);
        return json_response_with_cost(
            402,
            &settle_error(
                "invalid_payment_resource",
                "payment resource URL mismatch",
                None,
            ),
            &trace,
        );
    }
    trace.step("seller_credit.resource_validation", 0);
    let requirements = match seller_credit_requirements(&resource) {
        Ok(value) => value,
        Err(message) => {
            trace.step("seller_credit.requirements", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, None),
                &trace,
            );
        }
    };
    trace.step("seller_credit.requirements", 0);
    let body = FacilitatorRequest {
        x402_version: payload.x402_version,
        payment_payload: payload,
        payment_requirements: requirements,
    };
    settle_seller_credit_payment(seller, body, &mut trace).await
}

async fn settle_seller_credit_payment(
    seller: String,
    body: FacilitatorRequest,
    trace: &mut CostTrace,
) -> HttpResponse {
    let payer = match validate_request(&body) {
        Ok(payer) => payer,
        Err(err) => {
            trace.step("seller_credit.local_validation", 0);
            let response = failed_settlement(NETWORK, &err.reason, &err.message, err.payer);
            return json_response_with_cost(402, &response, trace);
        }
    };
    trace.step("seller_credit.local_validation", 0);
    let key = match settlement_key(&body) {
        Ok(value) => value,
        Err(message) => {
            trace.step("seller_credit.key", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, Some(payer)),
                trace,
            );
        }
    };
    trace.step("seller_credit.key", 0);
    purge_expired_settlements(now_seconds());
    if let Some(existing) = SETTLEMENTS.with(|items| items.borrow().get(&key).cloned()) {
        return cached_seller_credit_response(&seller, &key, existing, &body, trace).await;
    }
    let private_key = match env("FACILITATOR_EVM_PRIVATE_KEY") {
        Ok(value) => value,
        Err(message) => {
            trace.step("seller_credit.config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                trace,
            );
        }
    };
    let from = match private_key_address(&private_key) {
        Ok(value) => value,
        Err(message) => {
            trace.step("seller_credit.config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                trace,
            );
        }
    };
    trace.step("seller_credit.config", 0);
    if !acquire_active_settlement(&from, &key) {
        trace.step("seller_credit.active_lock", 0);
        return json_response_with_cost(
            429,
            &settle_error(
                "settlement_queue_busy",
                "another settlement is active for this facilitator address",
                Some(payer),
            ),
            trace,
        );
    }
    trace.step("seller_credit.active_lock", 0);
    let ttl = match settlement_cache_ttl_seconds() {
        Ok(ttl) => ttl,
        Err(message) => {
            release_active_settlement(&from, &key);
            trace.step("seller_credit.ttl", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                trace,
            );
        }
    };
    trace.step("seller_credit.ttl", 0);
    insert_settlement(
        &key,
        SettlementRecord::checking(
            payer.clone(),
            body.payment_requirements.pay_to.clone(),
            body.payment_requirements.amount.clone(),
            now_seconds(),
            ttl,
        ),
    );
    let config = match rpc_config() {
        Ok(config) => config,
        Err(message) => {
            remove_settlement(&key);
            release_active_settlement(&from, &key);
            trace.step("seller_credit.rpc_config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(payer)),
                trace,
            );
        }
    };
    trace.step("seller_credit.rpc_config", 0);
    let rpc_nonce = match pending_nonce(&config, &from).await {
        Ok(nonce) => nonce,
        Err(message) => {
            remove_settlement(&key);
            release_active_settlement(&from, &key);
            trace.step("seller_credit.pending_nonce", 1);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, Some(payer)),
                trace,
            );
        }
    };
    trace.step("seller_credit.pending_nonce", 1);
    let nonce = reserve_nonce(&from, rpc_nonce);
    match send_settlement(&config, &private_key, &body, nonce).await {
        Ok(SettlementOutcome::Settled(tx)) => {
            trace.step("seller_credit.send_settlement", 4);
            let record = SettlementRecord::settled(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            release_active_settlement(&from, &key);
            if let Err(message) = credit_seller_from_record_once(&key, &seller, &record) {
                return json_response_with_cost(
                    500,
                    &settle_error("invalid_state", &message, record.response.payer.clone()),
                    trace,
                );
            }
            seller_credit_paid_response(200, &seller, &record, trace)
        }
        Ok(SettlementOutcome::Pending { nonce, tx }) => {
            trace.step("seller_credit.send_settlement", 4);
            update_active_broadcast(&from, &key, nonce, &tx);
            let record = SettlementRecord::broadcast(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            seller_credit_paid_response(202, &seller, &record, trace)
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            trace.step("seller_credit.send_settlement", 4);
            let record = SettlementRecord::failed(
                tx,
                message,
                payer,
                body.payment_requirements.pay_to,
                now_seconds(),
                ttl,
            );
            insert_settlement(&key, record.clone());
            release_active_settlement(&from, &key);
            seller_credit_paid_response(502, &seller, &record, trace)
        }
        Err(SettlementSendError::GasTooExpensive) => {
            trace.step("seller_credit.send_settlement", 2);
            rollback_reserved_nonce(&from, nonce);
            remove_settlement(&key);
            release_active_settlement(&from, &key);
            json_response_with_cost(
                503,
                &settle_error("gas_too_expensive", GAS_TOO_EXPENSIVE_MESSAGE, Some(payer)),
                trace,
            )
        }
        Err(SettlementSendError::Other(message)) => {
            trace.step("seller_credit.send_settlement", 4);
            rollback_reserved_nonce(&from, nonce);
            remove_settlement(&key);
            release_active_settlement(&from, &key);
            json_response_with_cost(
                502,
                &settle_error("settlement_failed", &message, Some(payer)),
                trace,
            )
        }
    }
}

async fn cached_seller_credit_response(
    seller: &str,
    key: &str,
    existing: SettlementRecord,
    body: &FacilitatorRequest,
    trace: &mut CostTrace,
) -> HttpResponse {
    let Some(details) = existing.broadcast_settlement() else {
        trace.step("seller_credit.cache_hit", 0);
        if existing.status == "settled" {
            if let Err(message) = credit_seller_from_record_once(key, seller, &existing) {
                return json_response_with_cost(
                    500,
                    &settle_error("invalid_state", &message, existing.response.payer.clone()),
                    trace,
                );
            }
        }
        return seller_credit_paid_response(existing.status_code(), seller, &existing, trace);
    };
    let config = match rpc_config() {
        Ok(config) => config,
        Err(_) => {
            trace.step("seller_credit.cache_config", 0);
            return seller_credit_paid_response(existing.status_code(), seller, &existing, trace);
        }
    };
    trace.step("seller_credit.cache_config", 0);
    let expected = ExpectedTransfer {
        amount: details.amount.clone(),
        from: details.payer.clone(),
        to: details.pay_to.clone(),
    };
    let refreshed = match refresh_settlement(&config, &details.tx, &expected).await {
        Ok(outcome) => outcome,
        Err(message) => {
            trace.step("seller_credit.refresh", 1);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, Some(details.payer)),
                trace,
            );
        }
    };
    trace.step("seller_credit.refresh", 1);
    let ttl = match settlement_cache_ttl_seconds() {
        Ok(ttl) => ttl,
        Err(_) => {
            trace.step("seller_credit.cache_ttl", 0);
            return seller_credit_paid_response(existing.status_code(), seller, &existing, trace);
        }
    };
    trace.step("seller_credit.cache_ttl", 0);
    match refreshed {
        SettlementOutcome::Settled(tx) => {
            let record = SettlementRecord::settled(
                tx,
                details.payer.clone(),
                details.pay_to.clone(),
                details.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record.clone());
            release_active_settlement_by_key(key);
            if let Err(message) = credit_seller_from_record_once(key, seller, &record) {
                return json_response_with_cost(
                    500,
                    &settle_error("invalid_state", &message, record.response.payer.clone()),
                    trace,
                );
            }
            seller_credit_paid_response(200, seller, &record, trace)
        }
        SettlementOutcome::Pending { .. } => {
            let record = maybe_replace_pending_settlement_record(
                key,
                existing,
                body,
                details,
                ttl,
                trace,
                SELLER_CREDIT_REPLACEMENT_TRACE,
            )
            .await;
            if record.status == "settled" {
                if let Err(message) = credit_seller_from_record_once(key, seller, &record) {
                    return json_response_with_cost(
                        500,
                        &settle_error("invalid_state", &message, record.response.payer.clone()),
                        trace,
                    );
                }
            }
            seller_credit_paid_response(record.status_code(), seller, &record, trace)
        }
        SettlementOutcome::Failed { tx, message } => {
            let record = SettlementRecord::failed(
                tx,
                message,
                details.payer.clone(),
                details.pay_to.clone(),
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record.clone());
            release_active_settlement_by_key(key);
            seller_credit_paid_response(502, seller, &record, trace)
        }
    }
}

fn parse_request(request: &HttpRequest) -> Result<FacilitatorRequest, String> {
    if request.body.len() > MAX_REQUEST_BODY_BYTES {
        return Err("request body exceeds 64KiB".to_string());
    }
    serde_json::from_slice(&request.body).map_err(|err| format!("invalid JSON body: {err}"))
}

fn rpc_config() -> Result<RpcConfig, String> {
    let max_gas = optional_positive_u128("FACILITATOR_MAX_GAS", DEFAULT_MAX_GAS)?;
    let max_settlement_fee_wei = optional_positive_u128(
        "FACILITATOR_MAX_SETTLEMENT_FEE_WEI",
        DEFAULT_MAX_SETTLEMENT_FEE_WEI,
    )?;
    Ok(RpcConfig {
        services: env("POLYGON_RPC_SERVICES")?,
        max_gas,
        max_settlement_fee_wei,
    })
}

fn health() -> impl Serialize {
    serde_json::json!({
        "ok": true,
        "network": NETWORK,
        "facilitatorAddress": facilitator_address()
    })
}

fn retryable_error(reason: &str, message: &str, retryable: bool) -> impl Serialize {
    serde_json::json!({
        "error": reason,
        "message": message,
        "retryable": retryable
    })
}

fn json_response_with_cost<T: Serialize>(
    status_code: u16,
    value: &T,
    trace: &CostTrace,
) -> HttpResponse {
    let Some(cost) = trace.report() else {
        return json_response(status_code, value);
    };
    let result = serde_json::to_value(value).expect("response JSON must serialize");
    json_response(
        status_code,
        &serde_json::json!({
            "result": result,
            "cost": cost
        }),
    )
}

impl CostTrace {
    fn for_request(request: &HttpRequest) -> Self {
        let enabled = debug_cost_enabled(request);
        let now = instruction_counter_now();
        Self {
            enabled,
            start: now,
            last: now,
            rpc_calls: 0,
            steps: Vec::new(),
        }
    }

    fn step(&mut self, name: &'static str, rpc_calls: u64) {
        if !self.enabled {
            return;
        }
        let now = instruction_counter_now();
        let instructions = now.saturating_sub(self.last);
        self.last = now;
        self.rpc_calls = self.rpc_calls.saturating_add(rpc_calls);
        self.steps.push(CostStep {
            name,
            instructions,
            rpc_calls,
        });
    }

    fn report(&self) -> Option<CostReport> {
        if !self.enabled {
            return None;
        }
        Some(CostReport {
            total_instructions: instruction_counter_now().saturating_sub(self.start),
            rpc_calls: self.rpc_calls,
            steps: self.steps.clone(),
        })
    }
}

fn debug_cost_enabled(request: &HttpRequest) -> bool {
    let query_enabled = query_param(&request.url, "debugCost").as_deref() == Some("1");
    let header_enabled = header_value(request, "x-debug-cost")
        .map(|value| value.trim() == "1")
        .unwrap_or(false);
    query_enabled || header_enabled
}

fn instruction_counter_now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        ic_cdk::api::call_context_instruction_counter()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

fn settle_error(reason: &str, message: &str, payer: Option<String>) -> SettleResponse {
    failed_settlement(NETWORK, reason, message, payer)
}

fn seller_credit_required_response(request: &HttpRequest) -> Result<HttpResponse, String> {
    let resource = seller_credit_resource(request)?;
    let requirements = seller_credit_requirements(&resource)?;
    let payment = PaymentRequiredResponse {
        x402_version: 2,
        error: "Payment required".to_string(),
        resource,
        accepts: vec![requirements],
    };
    let header = json_base64(&payment)?;
    let mut response = json_response(402, &payment);
    response
        .headers
        .push(HeaderField("payment-required".to_string(), header));
    Ok(response)
}

fn seller_credit_paid_response(
    status_code: u16,
    seller: &str,
    record: &SettlementRecord,
    trace: &CostTrace,
) -> HttpResponse {
    let mut response = json_response_with_cost(
        status_code,
        &serde_json::json!({
            "seller": seller,
            "creditAtoms": seller_credit_balance_for(seller),
            "settlement": record.response
        }),
        trace,
    );
    if let Ok(header) = json_base64(&record.response) {
        response
            .headers
            .push(HeaderField("payment-response".to_string(), header));
    }
    response
}

fn seller_credit_requirements(resource: &ResourceInfo) -> Result<PaymentRequirements, String> {
    if resource.url.trim().is_empty() {
        return Err("seller credit resource URL is empty".to_string());
    }
    Ok(PaymentRequirements {
        scheme: "exact".to_string(),
        network: NETWORK.to_string(),
        asset: JPYC_POLYGON_ADDRESS.to_string(),
        amount: seller_credit_topup_amount()?.to_string(),
        pay_to: normalize_evm_address("SELLER_CREDIT_PAY_TO", &env("SELLER_CREDIT_PAY_TO")?)?,
        max_timeout_seconds: optional_positive_u64("SELLER_CREDIT_MAX_TIMEOUT_SECONDS", 60)?,
        extra: serde_json::json!({
            "assetTransferMethod": "eip3009",
            "name": JPYC_EIP712_NAME,
            "version": env("JPYC_EIP712_VERSION")?
        }),
    })
}

fn seller_credit_resource(request: &HttpRequest) -> Result<ResourceInfo, String> {
    Ok(ResourceInfo {
        url: request_url(request)?,
        description: Some("Seller credit top-up".to_string()),
        mime_type: Some("application/json".to_string()),
    })
}

fn seller_from_request(request: &HttpRequest) -> Result<String, String> {
    let value = query_param(&request.url, "seller")
        .ok_or_else(|| "missing seller query parameter".to_string())?;
    normalize_evm_address("seller", &value)
}

fn validate_seller_credit_seller(seller: &str, payload: &PaymentPayload) -> Result<(), String> {
    let payer = normalize_evm_address("authorization.from", &payload.payload.authorization.from)?;
    if seller != payer {
        return Err("seller must match EIP-3009 authorization.from".to_string());
    }
    Ok(())
}

fn normalize_evm_address(label: &str, value: &str) -> Result<String, String> {
    parse_address(value, label).map(|address| address_hex(&address))
}

fn seller_credit_topup_amount() -> Result<u128, String> {
    required_positive_u128("SELLER_CREDIT_TOPUP_AMOUNT")
}

fn seller_settlement_fee_amount() -> Result<u128, String> {
    required_positive_u128("SELLER_SETTLEMENT_FEE_AMOUNT")
}

fn required_positive_u128(name: &str) -> Result<u128, String> {
    parse_positive_u128(name, &env(name)?)
}

fn parse_positive_u128(label: &str, value: &str) -> Result<u128, String> {
    value
        .parse::<u128>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}

fn reserve_seller_credit(seller: &str, amount: u128) -> Result<(), String> {
    let seller = normalize_evm_address("seller", seller)?;
    SELLER_CREDITS.with(|items| {
        let mut items = items.borrow_mut();
        let current = items
            .get(&seller)
            .map(|item| item.credit_atoms)
            .unwrap_or(0);
        if current < amount {
            return Err(format!(
                "seller credit is below required fee: required={amount}, current={current}"
            ));
        }
        items.insert(
            seller,
            SellerCredit {
                credit_atoms: current - amount,
                updated_at: now_seconds(),
            },
        );
        Ok(())
    })
}

fn refund_seller_credit(seller: &str, amount: u128) {
    if let Ok(seller) = normalize_evm_address("seller", seller) {
        add_seller_credit(&seller, amount);
    }
}

fn credit_seller_once(settlement_key: &str, seller: &str, amount: u128) {
    if amount == 0 {
        return;
    }
    let Ok(seller) = normalize_evm_address("seller", seller) else {
        return;
    };
    let should_credit = CREDITED_SETTLEMENTS.with(|items| {
        let mut items = items.borrow_mut();
        if items.contains_key(settlement_key) {
            false
        } else {
            items.insert(settlement_key.to_string(), seller.clone());
            true
        }
    });
    if should_credit {
        add_seller_credit(&seller, amount);
    }
}

fn credit_seller_from_record_once(
    settlement_key: &str,
    seller: &str,
    record: &SettlementRecord,
) -> Result<(), String> {
    let amount = settlement_credit_amount(record)?;
    credit_seller_once(settlement_key, seller, amount);
    Ok(())
}

fn settlement_credit_amount(record: &SettlementRecord) -> Result<u128, String> {
    let amount = record
        .response
        .amount
        .as_deref()
        .ok_or_else(|| "settlement amount is missing".to_string())?;
    parse_positive_u128("settlement amount", amount)
}

fn add_seller_credit(seller: &str, amount: u128) {
    SELLER_CREDITS.with(|items| {
        let mut items = items.borrow_mut();
        let current = items.get(seller).map(|item| item.credit_atoms).unwrap_or(0);
        items.insert(
            seller.to_string(),
            SellerCredit {
                credit_atoms: current.saturating_add(amount),
                updated_at: now_seconds(),
            },
        );
    });
}

#[query]
fn seller_credit(seller: String) -> u128 {
    normalize_evm_address("seller", &seller)
        .ok()
        .map(|seller| seller_credit_balance_for(&seller))
        .unwrap_or(0)
}

fn seller_credit_balance_for(seller: &str) -> u128 {
    SELLER_CREDITS.with(|items| {
        items
            .borrow()
            .get(seller)
            .map(|item| item.credit_atoms)
            .unwrap_or(0)
    })
}

fn payment_payload_from_header(value: &str) -> Result<PaymentPayload, String> {
    let bytes = base64_decode(value)?;
    serde_json::from_slice(&bytes).map_err(|err| format!("invalid payment-signature JSON: {err}"))
}

fn json_base64(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| base64_encode(&bytes))
        .map_err(|err| format!("failed to encode JSON header: {err}"))
}

fn payment_signature_header(request: &HttpRequest) -> Option<String> {
    header_value(request, "payment-signature")
}

fn header_value(request: &HttpRequest, name: &str) -> Option<String> {
    request
        .headers
        .iter()
        .find(|header| header.0.eq_ignore_ascii_case(name))
        .map(|header| header.1.clone())
}

fn request_url(request: &HttpRequest) -> Result<String, String> {
    if request.url.starts_with("https://") || request.url.starts_with("http://") {
        return Ok(request.url.clone());
    }
    let host = header_value(request, "host").ok_or_else(|| "missing host header".to_string())?;
    let proto = header_value(request, "x-forwarded-proto").unwrap_or_else(|| "https".to_string());
    Ok(format!("{proto}://{host}{}", request.url))
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if key == name {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn env(name: &str) -> Result<String, String> {
    if let Some(value) = ENV.with(|env| env.borrow().get(name).cloned()) {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    #[cfg(test)]
    {
        return Err(format!("missing required env: {name}"));
    }
    #[cfg(not(test))]
    {
        let value = ic_cdk::api::env_var_value(name);
        if value.trim().is_empty() {
            return Err(format!("missing required env: {name}"));
        }
        Ok(value)
    }
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

fn settlement_key(body: &FacilitatorRequest) -> Result<String, String> {
    let auth = &body.payment_payload.payload.authorization;
    let signature = parse_hex(&body.payment_payload.payload.signature, Some(65))?;
    let signature_hash = keccak256(&signature);
    let identity = [
        NETWORK.to_string(),
        body.payment_requirements.asset.to_ascii_lowercase(),
        auth.from.to_ascii_lowercase(),
        auth.nonce.to_ascii_lowercase(),
        auth.valid_before.clone(),
        auth.valid_after.clone(),
        body.payment_requirements.pay_to.to_ascii_lowercase(),
        body.payment_requirements.amount.clone(),
        format!("0x{}", hex::encode(signature_hash)),
    ]
    .join("|");
    Ok(format!("0x{}", hex::encode(keccak256(identity.as_bytes()))))
}

fn insert_settlement(key: &str, record: SettlementRecord) {
    SETTLEMENTS.with(|items| {
        items.borrow_mut().insert(key.to_string(), record);
    });
}

fn remove_settlement(key: &str) {
    SETTLEMENTS.with(|items| {
        items.borrow_mut().remove(key);
    });
}

fn purge_expired_settlements(now: u64) {
    let expired_keys = SETTLEMENTS.with(|items| {
        items
            .borrow()
            .iter()
            .filter(|(_, record)| record.is_expired(now))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>()
    });
    SETTLEMENTS.with(|items| {
        items
            .borrow_mut()
            .retain(|_, record| !record.is_expired(now));
    });
    for key in expired_keys {
        release_active_settlement_by_key(&key);
    }
}

fn settlement_cache_ttl_seconds() -> Result<u64, String> {
    optional_positive_u64(
        "SETTLEMENT_CACHE_TTL_SECONDS",
        DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS,
    )
}

fn settlement_confirmation_timeout_seconds() -> Result<u64, String> {
    optional_positive_u64(
        "SETTLE_CONFIRMATION_TIMEOUT_SECONDS",
        DEFAULT_CONFIRMATION_TIMEOUT_SECONDS,
    )
}

fn optional_positive_u64(name: &str, default: u64) -> Result<u64, String> {
    match env(name) {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("{name} must be a positive integer")),
        Err(_) => Ok(default),
    }
}

fn optional_positive_u128(name: &str, default: u128) -> Result<u128, String> {
    match env(name) {
        Ok(value) => value
            .parse::<u128>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("{name} must be a positive integer")),
        Err(_) => Ok(default),
    }
}

fn base64_decode(value: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for ch in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if ch == b'=' {
            break;
        }
        let Some(next) = base64_value(ch) else {
            return Err("invalid base64 payment-signature".to_string());
        };
        buffer = (buffer << 6) | u32::from(next);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn base64_value(ch: u8) -> Option<u8> {
    match ch {
        b'A'..=b'Z' => Some(ch - b'A'),
        b'a'..=b'z' => Some(ch - b'a' + 26),
        b'0'..=b'9' => Some(ch - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn acquire_active_settlement(from: &str, key: &str) -> bool {
    ACTIVE_SETTLEMENTS.with(|items| {
        let mut items = items.borrow_mut();
        match items.get(from) {
            Some(active) if active.key != key => false,
            Some(_) => true,
            None => {
                items.insert(
                    from.to_string(),
                    ActiveSettlement {
                        key: key.to_string(),
                        nonce: None,
                        tx: None,
                    },
                );
                true
            }
        }
    })
}

fn update_active_broadcast(from: &str, key: &str, nonce: u128, tx: &str) {
    ACTIVE_SETTLEMENTS.with(|items| {
        let mut items = items.borrow_mut();
        if let Some(active) = items.get_mut(from).filter(|active| active.key == key) {
            active.nonce = Some(nonce);
            active.tx = Some(tx.to_string());
        }
    });
}

fn active_nonce(from: &str, key: &str) -> Option<u128> {
    ACTIVE_SETTLEMENTS.with(|items| {
        items
            .borrow()
            .get(from)
            .filter(|active| active.key == key)
            .and_then(|active| active.nonce)
    })
}

fn release_active_settlement(from: &str, key: &str) {
    ACTIVE_SETTLEMENTS.with(|items| {
        let should_remove = items
            .borrow()
            .get(from)
            .map(|active| active.key == key)
            .unwrap_or(false);
        if should_remove {
            items.borrow_mut().remove(from);
        }
    });
}

fn release_active_settlement_by_key(key: &str) {
    ACTIVE_SETTLEMENTS.with(|items| {
        items.borrow_mut().retain(|_, active| active.key != key);
    });
}

fn reserve_nonce(from: &str, rpc_pending_nonce: u128) -> u128 {
    NONCES.with(|items| {
        let mut items = items.borrow_mut();
        let state = items.entry(from.to_string()).or_default();
        let nonce = state
            .next_nonce
            .map(|next| next.max(rpc_pending_nonce))
            .unwrap_or(rpc_pending_nonce);
        state.next_nonce = Some(nonce.saturating_add(1));
        nonce
    })
}

fn rollback_reserved_nonce(from: &str, nonce: u128) {
    NONCES.with(|items| {
        let mut items = items.borrow_mut();
        let Some(state) = items.get_mut(from) else {
            return;
        };
        if state.next_nonce == Some(nonce.saturating_add(1)) {
            state.next_nonce = Some(nonce);
        }
    });
}

#[derive(Clone, Copy)]
struct ReplacementTraceLabels {
    config: &'static str,
    nonce: &'static str,
    rpc_config: &'static str,
    retry_window: &'static str,
    send: &'static str,
}

const SETTLE_REPLACEMENT_TRACE: ReplacementTraceLabels = ReplacementTraceLabels {
    config: "settle.replace_config",
    nonce: "settle.replace_nonce",
    rpc_config: "settle.replace_rpc_config",
    retry_window: "settle.replace_retry_window",
    send: "settle.replace_send",
};

const SELLER_CREDIT_REPLACEMENT_TRACE: ReplacementTraceLabels = ReplacementTraceLabels {
    config: "seller_credit.replace_config",
    nonce: "seller_credit.replace_nonce",
    rpc_config: "seller_credit.replace_rpc_config",
    retry_window: "seller_credit.replace_retry_window",
    send: "seller_credit.replace_send",
};

async fn maybe_replace_pending_settlement_record(
    key: &str,
    existing: SettlementRecord,
    body: &FacilitatorRequest,
    details: crate::state::BroadcastSettlement,
    ttl: u64,
    trace: &mut CostTrace,
    labels: ReplacementTraceLabels,
) -> SettlementRecord {
    let private_key = match env("FACILITATOR_EVM_PRIVATE_KEY") {
        Ok(value) => value,
        Err(_) => {
            trace.step(labels.config, 0);
            return existing;
        }
    };
    let from = match private_key_address(&private_key) {
        Ok(value) => value,
        Err(_) => {
            trace.step(labels.config, 0);
            return existing;
        }
    };
    trace.step(labels.config, 0);
    let Some(nonce) = active_nonce(&from, key) else {
        trace.step(labels.nonce, 0);
        return existing;
    };
    trace.step(labels.nonce, 0);
    let config = match rpc_config() {
        Ok(config) => config,
        Err(_) => {
            trace.step(labels.rpc_config, 0);
            return existing;
        }
    };
    trace.step(labels.rpc_config, 0);
    let retry_after =
        settlement_confirmation_timeout_seconds().unwrap_or(DEFAULT_CONFIRMATION_TIMEOUT_SECONDS);
    if now_seconds().saturating_sub(existing.updated_at) < retry_after {
        trace.step(labels.retry_window, 0);
        return existing;
    }
    trace.step(labels.retry_window, 0);
    match send_settlement(&config, &private_key, body, nonce).await {
        Ok(SettlementOutcome::Settled(tx)) => {
            trace.step(labels.send, 4);
            let record = SettlementRecord::settled(
                tx,
                details.payer.clone(),
                details.pay_to.clone(),
                details.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record.clone());
            release_active_settlement(&from, key);
            record
        }
        Ok(SettlementOutcome::Pending { nonce, tx }) => {
            trace.step(labels.send, 4);
            update_active_broadcast(&from, key, nonce, &tx);
            let record = SettlementRecord::broadcast(
                tx,
                details.payer,
                details.pay_to,
                details.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record.clone());
            record
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            trace.step(labels.send, 4);
            let record = SettlementRecord::failed(
                tx,
                message,
                details.payer.clone(),
                details.pay_to.clone(),
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record.clone());
            release_active_settlement(&from, key);
            record
        }
        Err(SettlementSendError::GasTooExpensive) => {
            trace.step(labels.send, 2);
            existing
        }
        Err(SettlementSendError::Other(_)) => {
            trace.step(labels.send, 4);
            existing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll};

    const SELLER: &str = "0x1000000000000000000000000000000000000402";
    const CREDIT_PAY_TO: &str = "0x2000000000000000000000000000000000000402";

    fn set_test_env() {
        ENV.with(|items| {
            let mut items = items.borrow_mut();
            items.insert("JPYC_EIP712_VERSION".to_string(), "1".to_string());
            items.insert(
                "SELLER_CREDIT_PAY_TO".to_string(),
                CREDIT_PAY_TO.to_string(),
            );
            items.insert("SELLER_CREDIT_TOPUP_AMOUNT".to_string(), "1000".to_string());
            items.insert(
                "SELLER_SETTLEMENT_FEE_AMOUNT".to_string(),
                "100".to_string(),
            );
            items.insert(
                "SELLER_CREDIT_MAX_TIMEOUT_SECONDS".to_string(),
                "60".to_string(),
            );
        });
    }

    fn seller_credit_request() -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            url: format!("/seller-credit?seller={SELLER}"),
            headers: vec![HeaderField(
                "host".to_string(),
                "canister.example.test".to_string(),
            )],
            body: vec![],
            certificate_version: None,
        }
    }

    fn seller_credit_payload(from: &str) -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: PaymentRequirements {
                scheme: "exact".to_string(),
                network: NETWORK.to_string(),
                asset: JPYC_POLYGON_ADDRESS.to_string(),
                amount: "1000".to_string(),
                pay_to: CREDIT_PAY_TO.to_lowercase(),
                max_timeout_seconds: 60,
                extra: serde_json::json!({
                    "assetTransferMethod": "eip3009",
                    "name": JPYC_EIP712_NAME,
                    "version": "1"
                }),
            },
            payload: crate::types::Eip3009Payload {
                signature: format!("0x{}1b", "11".repeat(64)),
                authorization: crate::types::Eip3009Authorization {
                    from: from.to_string(),
                    to: CREDIT_PAY_TO.to_lowercase(),
                    value: "1000".to_string(),
                    valid_after: "0".to_string(),
                    valid_before: "9999999999".to_string(),
                    nonce: format!("0x{}", "22".repeat(32)),
                },
            },
            extensions: None,
        }
    }

    fn run_ready<T>(future: impl Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly awaited"),
        }
    }

    #[test]
    fn verify_is_unsupported_without_parsing_body() {
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: b"{".to_vec(),
            certificate_version: None,
        };
        let response = run_ready(verify_http(request));
        assert_eq!(response.status_code, 501);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["error"], "unsupported");
        assert_eq!(value["message"], "verify is disabled; use settle");
        assert_eq!(value["retryable"], false);
        assert!(value.get("cost").is_none());
    }

    #[test]
    fn verify_debug_cost_wraps_unsupported_response() {
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/verify?debugCost=1".to_string(),
            headers: vec![],
            body: b"{".to_vec(),
            certificate_version: None,
        };
        let response = run_ready(verify_http(request));
        assert_eq!(response.status_code, 501);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["error"], "unsupported");
        assert_eq!(value["result"]["message"], "verify is disabled; use settle");
        assert_eq!(value["result"]["retryable"], false);
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert_eq!(value["cost"]["steps"][0]["name"], "verify.unsupported");
        assert_eq!(value["cost"]["steps"][0]["rpcCalls"], 0);
    }

    #[test]
    fn cost_report_is_debug_only() {
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/verify?debugCost=1".to_string(),
            headers: vec![],
            body: vec![],
            certificate_version: None,
        };
        let mut trace = CostTrace::for_request(&request);
        trace.step("test.snapshot", 3);
        let response = json_response_with_cost(200, &serde_json::json!({ "ok": true }), &trace);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["ok"], true);
        assert_eq!(value["cost"]["rpcCalls"], 3);
        assert_eq!(value["cost"]["steps"][0]["name"], "test.snapshot");

        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: vec![],
            certificate_version: None,
        };
        let mut trace = CostTrace::for_request(&request);
        trace.step("test.snapshot", 3);
        let response = json_response_with_cost(200, &serde_json::json!({ "ok": true }), &trace);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["ok"], true);
        assert!(value.get("cost").is_none());
    }

    #[test]
    fn cost_debug_can_use_header() {
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/settle".to_string(),
            headers: vec![HeaderField("x-debug-cost".to_string(), "1".to_string())],
            body: vec![],
            certificate_version: None,
        };
        assert!(debug_cost_enabled(&request));
    }

    #[test]
    fn rpc_config_uses_default_settlement_fee_cap() {
        ENV.with(|items| {
            let mut items = items.borrow_mut();
            items.clear();
            items.insert(
                "POLYGON_RPC_SERVICES".to_string(),
                "https://polygon.example".to_string(),
            );
        });
        let config = rpc_config().unwrap();
        assert_eq!(
            config.max_settlement_fee_wei,
            DEFAULT_MAX_SETTLEMENT_FEE_WEI
        );
    }

    #[test]
    fn rpc_config_rejects_invalid_settlement_fee_cap() {
        for value in ["0", "not-a-number"] {
            ENV.with(|items| {
                let mut items = items.borrow_mut();
                items.clear();
                items.insert(
                    "POLYGON_RPC_SERVICES".to_string(),
                    "https://polygon.example".to_string(),
                );
                items.insert(
                    "FACILITATOR_MAX_SETTLEMENT_FEE_WEI".to_string(),
                    value.to_string(),
                );
            });
            match rpc_config() {
                Ok(_) => panic!("invalid settlement fee cap must fail"),
                Err(message) => assert_eq!(
                    message,
                    "FACILITATOR_MAX_SETTLEMENT_FEE_WEI must be a positive integer"
                ),
            }
        }
    }

    #[test]
    fn gas_too_expensive_response_uses_settle_response_shape() {
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/settle?debugCost=1".to_string(),
            headers: vec![],
            body: vec![],
            certificate_version: None,
        };
        let trace = CostTrace::for_request(&request);
        let response = json_response_with_cost(
            503,
            &settle_error("gas_too_expensive", GAS_TOO_EXPENSIVE_MESSAGE, None),
            &trace,
        );
        assert_eq!(response.status_code, 503);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["success"], false);
        assert_eq!(value["result"]["errorReason"], "gas_too_expensive");
        assert!(value["result"].get("retryable").is_none());
    }

    #[test]
    fn encodes_seller_credit_payment_required_header() {
        set_test_env();
        let response = seller_credit_required_response(&seller_credit_request()).unwrap();
        assert_eq!(response.status_code, 402);
        let header = response
            .headers
            .iter()
            .find(|item| item.0 == "payment-required")
            .map(|item| item.1.clone())
            .expect("payment-required header");
        let value: Value = serde_json::from_slice(&base64_decode(&header).unwrap()).unwrap();
        assert_eq!(value["x402Version"], 2);
        assert_eq!(
            value["resource"]["url"],
            format!("https://canister.example.test/seller-credit?seller={SELLER}")
        );
        assert_eq!(value["accepts"][0]["amount"], "1000");
        assert_eq!(value["accepts"][0]["payTo"], CREDIT_PAY_TO.to_lowercase());
    }

    #[test]
    fn seller_credit_seller_validation_accepts_matching_payer() {
        let seller = normalize_evm_address("seller", SELLER).unwrap();
        let payload = seller_credit_payload(SELLER);

        validate_seller_credit_seller(&seller, &payload).unwrap();
    }

    #[test]
    fn seller_credit_seller_validation_rejects_mismatched_payer() {
        let seller = normalize_evm_address("seller", SELLER).unwrap();
        let payload = seller_credit_payload("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993");

        assert_eq!(
            validate_seller_credit_seller(&seller, &payload).unwrap_err(),
            "seller must match EIP-3009 authorization.from"
        );
    }

    #[test]
    fn seller_credit_rejects_mismatched_payer_before_rpc() {
        set_test_env();
        let mut request = seller_credit_request();
        request.url = format!("/seller-credit?seller={SELLER}&debugCost=1");
        let payload = seller_credit_payload("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993");
        request.headers.push(HeaderField(
            "payment-signature".to_string(),
            json_base64(&payload).unwrap(),
        ));

        let response = run_ready(seller_credit_http(request));

        assert_eq!(response.status_code, 402);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["success"], false);
        assert_eq!(value["result"]["errorReason"], "invalid_payment_seller");
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert_eq!(
            value["cost"]["steps"][3]["name"],
            "seller_credit.seller_validation"
        );
        assert_eq!(value["cost"]["steps"][3]["rpcCalls"], 0);
    }

    #[test]
    fn reserves_refunds_and_credits_seller_once() {
        let seller = normalize_evm_address("seller", SELLER).unwrap();
        SELLER_CREDITS.with(|items| items.borrow_mut().clear());
        CREDITED_SETTLEMENTS.with(|items| items.borrow_mut().clear());
        add_seller_credit(&seller, 150);
        reserve_seller_credit(&seller, 100).unwrap();
        assert_eq!(seller_credit_balance_for(&seller), 50);
        refund_seller_credit(&seller, 25);
        assert_eq!(seller_credit_balance_for(&seller), 75);
        credit_seller_once("settlement-key", &seller, 1000);
        credit_seller_once("settlement-key", &seller, 1000);
        assert_eq!(seller_credit_balance_for(&seller), 1075);
    }

    #[test]
    fn credits_seller_from_settlement_record_amount_after_env_changes() {
        set_test_env();
        let seller = normalize_evm_address("seller", SELLER).unwrap();
        SELLER_CREDITS.with(|items| items.borrow_mut().clear());
        CREDITED_SETTLEMENTS.with(|items| items.borrow_mut().clear());
        ENV.with(|items| {
            items.borrow_mut().remove("SELLER_CREDIT_TOPUP_AMOUNT");
        });
        let record = SettlementRecord::settled(
            "0xtx".to_string(),
            seller.clone(),
            CREDIT_PAY_TO.to_lowercase(),
            "2500".to_string(),
            now_seconds(),
            60,
        );

        credit_seller_from_record_once("settlement-key-record", &seller, &record).unwrap();
        credit_seller_from_record_once("settlement-key-record", &seller, &record).unwrap();

        assert_eq!(seller_credit_balance_for(&seller), 2500);
    }

    #[test]
    fn settlement_credit_amount_rejects_missing_invalid_or_zero_amount() {
        let seller = normalize_evm_address("seller", SELLER).unwrap();
        let mut record = SettlementRecord::settled(
            "0xtx".to_string(),
            seller,
            CREDIT_PAY_TO.to_lowercase(),
            "2500".to_string(),
            now_seconds(),
            60,
        );

        record.response.amount = None;
        assert_eq!(
            settlement_credit_amount(&record).unwrap_err(),
            "settlement amount is missing"
        );

        record.response.amount = Some("0".to_string());
        assert_eq!(
            settlement_credit_amount(&record).unwrap_err(),
            "settlement amount must be a positive integer"
        );

        record.response.amount = Some("not-a-number".to_string());
        assert_eq!(
            settlement_credit_amount(&record).unwrap_err(),
            "settlement amount must be a positive integer"
        );
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use candid::{CandidType, Deserialize as CandidDeserialize};
    use serde_json::json;

    const PAYER: &str = "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993";
    const PAY_TO: &str = "0x1000000000000000000000000000000000000402";

    fn request_json() -> serde_json::Value {
        json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": requirements_json(),
                "resource": { "url": "https://example.test/report" },
                "payload": {
                    "signature": format!("0x{}1b", "11".repeat(64)),
                    "authorization": {
                        "from": PAYER,
                        "to": PAY_TO,
                        "value": "1000000000000000000",
                        "validAfter": "0",
                        "validBefore": "9999999999",
                        "nonce": format!("0x{}", "22".repeat(32))
                    }
                }
            },
            "paymentRequirements": requirements_json()
        })
    }

    fn requirements_json() -> serde_json::Value {
        json!({
            "scheme": "exact",
            "network": NETWORK,
            "asset": JPYC_POLYGON_ADDRESS,
            "amount": "1000000000000000000",
            "payTo": PAY_TO,
            "maxTimeoutSeconds": 60,
            "extra": {
                "assetTransferMethod": "eip3009",
                "name": JPYC_EIP712_NAME,
                "version": "1"
            }
        })
    }

    fn request() -> FacilitatorRequest {
        serde_json::from_value(request_json()).unwrap()
    }

    fn http_request(body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body,
            certificate_version: None,
        }
    }

    fn clear_active_state() {
        ACTIVE_SETTLEMENTS.with(|items| items.borrow_mut().clear());
        NONCES.with(|items| items.borrow_mut().clear());
    }

    fn clear_settlement_state() {
        clear_active_state();
        SETTLEMENTS.with(|items| items.borrow_mut().clear());
    }

    fn run_ready<T>(future: impl std::future::Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("test future unexpectedly awaited"),
        }
    }

    #[derive(CandidType, CandidDeserialize)]
    struct LegacyStableState {
        env: std::collections::BTreeMap<String, String>,
        settlements: std::collections::BTreeMap<String, SettlementRecord>,
        seller_credits: std::collections::BTreeMap<String, SellerCredit>,
        credited_settlements: std::collections::BTreeMap<String, String>,
    }

    #[test]
    fn stable_state_decodes_legacy_without_active_state() {
        let legacy = LegacyStableState {
            env: std::collections::BTreeMap::new(),
            settlements: std::collections::BTreeMap::new(),
            seller_credits: std::collections::BTreeMap::new(),
            credited_settlements: std::collections::BTreeMap::new(),
        };
        let bytes = candid::encode_one(legacy).unwrap();
        let decoded: StableState = candid::decode_one(&bytes).unwrap();

        assert!(decoded.active_settlements.is_none());
        assert!(decoded.nonces.is_none());
    }

    #[test]
    fn parse_rejects_oversized_body_before_json() {
        let request = http_request(vec![b'{'; MAX_REQUEST_BODY_BYTES + 1]);
        assert_eq!(
            parse_request(&request).unwrap_err(),
            "request body exceeds 64KiB"
        );
    }

    #[test]
    fn local_validation_rejects_before_rpc() {
        let mut body = request();
        body.payment_requirements.network = "eip155:1".to_string();
        let err = validate_request(&body).unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_network_mismatch");

        let mut body = request();
        body.payment_payload.payload.signature = "0x01".to_string();
        let err = validate_request(&body).unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_signature");
    }

    #[test]
    fn verify_rpc_errors_are_retryable_error_responses() {
        let value =
            serde_json::to_value(retryable_error("rpc_error", "eth_call failed", true)).unwrap();
        assert_eq!(value["error"], "rpc_error");
        assert_eq!(value["message"], "eth_call failed");
        assert_eq!(value["retryable"], true);
    }

    #[test]
    fn canonical_settlement_key_ignores_json_field_order() {
        let first = request();
        let second: FacilitatorRequest = serde_json::from_value(json!({
            "paymentRequirements": requirements_json(),
            "paymentPayload": request_json()["paymentPayload"].clone(),
            "x402Version": 2
        }))
        .unwrap();

        assert_eq!(
            settlement_key(&first).unwrap(),
            settlement_key(&second).unwrap()
        );

        let mut changed_nonce = first.clone();
        changed_nonce.payment_payload.payload.authorization.nonce =
            format!("0x{}", "33".repeat(32));
        assert_ne!(
            settlement_key(&first).unwrap(),
            settlement_key(&changed_nonce).unwrap()
        );

        let mut changed_amount = first.clone();
        changed_amount.payment_requirements.amount = "2000000000000000000".to_string();
        assert_ne!(
            settlement_key(&first).unwrap(),
            settlement_key(&changed_amount).unwrap()
        );

        let mut changed_signature = first.clone();
        changed_signature.payment_payload.payload.signature = format!("0x{}1c", "11".repeat(64));
        assert_ne!(
            settlement_key(&first).unwrap(),
            settlement_key(&changed_signature).unwrap()
        );
    }

    #[test]
    fn nonce_manager_uses_max_pending_and_stored_nonce() {
        clear_active_state();
        let from = "0x0000000000000000000000000000000000000402";
        assert_eq!(reserve_nonce(from, 7), 7);
        assert_eq!(reserve_nonce(from, 3), 8);
        assert_eq!(reserve_nonce(from, 20), 20);
        assert_eq!(reserve_nonce(from, 19), 21);
    }

    #[test]
    fn nonce_manager_rolls_back_only_latest_reservation() {
        clear_active_state();
        let from = "0x0000000000000000000000000000000000000402";
        let nonce = reserve_nonce(from, 7);
        rollback_reserved_nonce(from, nonce);
        assert_eq!(reserve_nonce(from, 7), 7);

        clear_active_state();
        let first = reserve_nonce(from, 7);
        assert_eq!(reserve_nonce(from, 3), 8);
        rollback_reserved_nonce(from, first);
        assert_eq!(reserve_nonce(from, 3), 9);
    }

    #[test]
    fn active_settlement_blocks_different_key_for_same_sender() {
        clear_active_state();
        let from = "0x0000000000000000000000000000000000000402";
        assert!(acquire_active_settlement(from, "key-a"));
        assert!(acquire_active_settlement(from, "key-a"));
        assert!(!acquire_active_settlement(from, "key-b"));
        update_active_broadcast(from, "key-a", 9, "0xabc");
        assert_eq!(active_nonce(from, "key-a"), Some(9));
        release_active_settlement(from, "key-a");
        assert!(acquire_active_settlement(from, "key-b"));
    }

    #[test]
    fn purge_expired_settlements_releases_matching_active_lock() {
        clear_settlement_state();
        let from = "0x0000000000000000000000000000000000000402";
        insert_settlement(
            "key-a",
            SettlementRecord::broadcast(
                "0xtx".to_string(),
                PAYER.to_lowercase(),
                PAY_TO.to_lowercase(),
                "100".to_string(),
                now_seconds().saturating_sub(20),
                10,
            ),
        );
        assert!(acquire_active_settlement(from, "key-a"));
        assert!(!acquire_active_settlement(from, "key-b"));

        purge_expired_settlements(now_seconds());

        assert!(SETTLEMENTS.with(|items| items.borrow().get("key-a").is_none()));
        assert!(acquire_active_settlement(from, "key-b"));
    }

    #[test]
    fn purge_expired_settlements_keeps_unexpired_active_lock() {
        clear_settlement_state();
        let from = "0x0000000000000000000000000000000000000402";
        insert_settlement(
            "key-a",
            SettlementRecord::broadcast(
                "0xtx".to_string(),
                PAYER.to_lowercase(),
                PAY_TO.to_lowercase(),
                "100".to_string(),
                now_seconds(),
                60,
            ),
        );
        assert!(acquire_active_settlement(from, "key-a"));

        purge_expired_settlements(now_seconds());

        assert!(SETTLEMENTS.with(|items| items.borrow().get("key-a").is_some()));
        assert!(!acquire_active_settlement(from, "key-b"));
    }

    #[test]
    fn seller_credit_pending_replacement_uses_seller_credit_trace_labels() {
        clear_settlement_state();
        ENV.with(|items| items.borrow_mut().clear());
        let existing = SettlementRecord::broadcast(
            "0xtx".to_string(),
            PAYER.to_lowercase(),
            PAY_TO.to_lowercase(),
            "100".to_string(),
            now_seconds().saturating_sub(120),
            60,
        );
        let details = existing.broadcast_settlement().unwrap();
        let trace_request = HttpRequest {
            method: "GET".to_string(),
            url: "/seller-credit?debugCost=1".to_string(),
            headers: vec![],
            body: vec![],
            certificate_version: None,
        };
        let mut trace = CostTrace::for_request(&trace_request);

        let record = run_ready(maybe_replace_pending_settlement_record(
            "key-a",
            existing.clone(),
            &request(),
            details,
            60,
            &mut trace,
            SELLER_CREDIT_REPLACEMENT_TRACE,
        ));

        assert_eq!(record.status, existing.status);
        assert_eq!(record.response.transaction, existing.response.transaction);
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0].name, "seller_credit.replace_config");
        assert_eq!(trace.steps[0].rpc_calls, 0);
    }
}

ic_cdk::export_candid!();
