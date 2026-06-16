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

use candid::{CandidType, Deserialize as CandidDeserialize};
use ic_cdk::{post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use k256::ecdsa::SigningKey;
use serde::Serialize;

use crate::eip712::recover_eip191_signer;
use crate::facilitator::{
    failed_settlement, supported, validate_request, validate_request_before_signature,
    validate_request_signature,
};
use crate::hexutil::{
    address_hex, keccak256, parse_address, parse_hex, same_address, JPYC_EIP712_NAME,
    JPYC_POLYGON_ADDRESS, NETWORK,
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
const DEFAULT_MIN_CONFIRMATIONS: u64 = 3;
const DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS: u64 = 86_400;
const GAS_TOO_EXPENSIVE_MESSAGE: &str = "estimated POL settlement fee exceeds configured cap";
const SELLER_AUTH_MESSAGE_PREFIX: &str = "IC_JPYC_X402_SELLER_AUTH_V1";

type Memory = VirtualMemory<DefaultMemoryImpl>;
const ENV_MEM_ID: MemoryId = MemoryId::new(0);
const SETTLEMENTS_MEM_ID: MemoryId = MemoryId::new(1);
const SELLER_CREDITS_MEM_ID: MemoryId = MemoryId::new(2);
const CREDITED_SETTLEMENTS_MEM_ID: MemoryId = MemoryId::new(3);
const ACTIVE_SETTLEMENTS_MEM_ID: MemoryId = MemoryId::new(4);
const NONCES_MEM_ID: MemoryId = MemoryId::new(5);

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct StableState {
    env: BTreeMap<String, String>,
    settlements: BTreeMap<String, SettlementRecord>,
    seller_credits: BTreeMap<String, SellerCredit>,
    credited_settlements: BTreeMap<String, String>,
    active_settlements: Option<BTreeMap<String, ActiveSettlement>>,
    nonces: Option<BTreeMap<String, NonceState>>,
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    static ENV: RefCell<StableBTreeMap<String, String, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(ENV_MEM_ID))));
    static SETTLEMENTS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(SETTLEMENTS_MEM_ID))));
    static SELLER_CREDITS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(SELLER_CREDITS_MEM_ID))));
    static CREDITED_SETTLEMENTS: RefCell<StableBTreeMap<String, String, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(CREDITED_SETTLEMENTS_MEM_ID))));
    static ACTIVE_SETTLEMENTS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(ACTIVE_SETTLEMENTS_MEM_ID))));
    static NONCES: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(NONCES_MEM_ID))));
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct SellerCredit {
    credit_atoms: u128,
    updated_at: u64,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct ActiveSettlement {
    key: String,
    nonce: Option<u128>,
    tx: Option<String>,
}

#[derive(Clone, Debug, Default, CandidType, CandidDeserialize)]
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
    set_env_value(&name, &value);
}

#[query]
fn env_names() -> Vec<String> {
    let caller = ic_cdk::api::msg_caller();
    if !ic_cdk::api::is_controller(&caller) {
        ic_cdk::trap("caller is not a controller");
    }
    ENV.with(|env| {
        env.borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    })
}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade() {
    if let Ok((state,)) = ic_cdk::storage::stable_restore::<(StableState,)>() {
        migrate_legacy_state(state);
    }
}

fn encode_stable<T: CandidType>(value: &T) -> Vec<u8> {
    candid::encode_one(value).expect("stable value must encode")
}

fn decode_stable<T: CandidType + for<'de> CandidDeserialize<'de>>(bytes: Vec<u8>) -> T {
    candid::decode_one(&bytes).expect("stable value must decode")
}

fn set_env_value(name: &str, value: &str) {
    ENV.with(|env| {
        env.borrow_mut().insert(name.to_string(), value.to_string());
    });
}

fn clear_env_values_runtime() {
    ENV.with(|env| {
        let keys = env
            .borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut env = env.borrow_mut();
        for key in keys {
            env.remove(&key);
        }
    });
}

#[cfg(test)]
fn remove_env_value(name: &str) {
    ENV.with(|env| {
        env.borrow_mut().remove(&name.to_string());
    });
}

#[cfg(test)]
fn clear_env_values() {
    clear_env_values_runtime();
}

fn get_settlement(key: &str) -> Option<SettlementRecord> {
    SETTLEMENTS.with(|items| {
        items
            .borrow()
            .get(&key.to_string())
            .map(decode_stable::<SettlementRecord>)
    })
}

fn put_seller_credit(seller: &str, credit: SellerCredit) {
    SELLER_CREDITS.with(|items| {
        items
            .borrow_mut()
            .insert(seller.to_string(), encode_stable(&credit));
    });
}

fn get_seller_credit(seller: &str) -> Option<SellerCredit> {
    SELLER_CREDITS.with(|items| {
        items
            .borrow()
            .get(&seller.to_string())
            .map(decode_stable::<SellerCredit>)
    })
}

fn put_active_settlement(from: &str, active: ActiveSettlement) {
    ACTIVE_SETTLEMENTS.with(|items| {
        items
            .borrow_mut()
            .insert(from.to_string(), encode_stable(&active));
    });
}

fn get_active_settlement(from: &str) -> Option<ActiveSettlement> {
    ACTIVE_SETTLEMENTS.with(|items| {
        items
            .borrow()
            .get(&from.to_string())
            .map(decode_stable::<ActiveSettlement>)
    })
}

fn put_nonce_state(from: &str, state: NonceState) {
    NONCES.with(|items| {
        items
            .borrow_mut()
            .insert(from.to_string(), encode_stable(&state));
    });
}

fn get_nonce_state(from: &str) -> NonceState {
    NONCES.with(|items| {
        items
            .borrow()
            .get(&from.to_string())
            .map(decode_stable::<NonceState>)
            .unwrap_or_default()
    })
}

fn clear_settlements() {
    SETTLEMENTS.with(|items| {
        let keys = items
            .borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut items = items.borrow_mut();
        for key in keys {
            items.remove(&key);
        }
    });
}

fn clear_seller_credits() {
    SELLER_CREDITS.with(|items| {
        let keys = items
            .borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut items = items.borrow_mut();
        for key in keys {
            items.remove(&key);
        }
    });
}

fn clear_credited_settlements() {
    CREDITED_SETTLEMENTS.with(|items| {
        let keys = items
            .borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut items = items.borrow_mut();
        for key in keys {
            items.remove(&key);
        }
    });
}

fn clear_active_settlements() {
    ACTIVE_SETTLEMENTS.with(|items| {
        let keys = items
            .borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut items = items.borrow_mut();
        for key in keys {
            items.remove(&key);
        }
    });
}

fn clear_nonces() {
    NONCES.with(|items| {
        let keys = items
            .borrow()
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut items = items.borrow_mut();
        for key in keys {
            items.remove(&key);
        }
    });
}

fn migrate_legacy_state(state: StableState) {
    clear_env_values_runtime();
    clear_settlements();
    clear_seller_credits();
    clear_credited_settlements();
    clear_active_settlements();
    clear_nonces();
    for (key, value) in state.env {
        set_env_value(&key, &value);
    }
    for (key, record) in state.settlements {
        insert_settlement(&key, record);
    }
    for (key, credit) in state.seller_credits {
        put_seller_credit(&key, credit);
    }
    for (key, seller) in state.credited_settlements {
        CREDITED_SETTLEMENTS.with(|items| {
            items.borrow_mut().insert(key, seller);
        });
    }
    for (key, active) in state.active_settlements.unwrap_or_default() {
        put_active_settlement(&key, active);
    }
    for (key, nonce) in state.nonces.unwrap_or_default() {
        put_nonce_state(&key, nonce);
    }
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
        ("POST", "/settle") if !updated => HttpResponse {
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
    let untrusted_payer = body.payment_payload.payload.authorization.from.clone();
    if let Err(err) = validate_request_before_signature(&body) {
        trace.step("settle.cheap_validation", 0);
        let response = failed_settlement(NETWORK, &err.reason, &err.message, err.payer);
        return json_response_with_cost(402, &response, &trace);
    }
    trace.step("settle.cheap_validation", 0);
    let eip712_version = match env("JPYC_EIP712_VERSION") {
        Ok(value) => value,
        Err(message) => {
            trace.step("settle.version_config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, Some(untrusted_payer)),
                &trace,
            );
        }
    };
    trace.step("settle.version_config", 0);
    if let Err(err) = validate_eip712_version(&body, &eip712_version) {
        trace.step("settle.version_validation", 0);
        return json_response_with_cost(
            402,
            &failed_settlement(NETWORK, &err.reason, &err.message, err.payer),
            &trace,
        );
    }
    trace.step("settle.version_validation", 0);
    if let Err(message) = validate_seller_authorization(&body) {
        trace.step("settle.seller_authorization", 0);
        return json_response_with_cost(
            402,
            &settle_error(
                "invalid_seller_authorization",
                &message,
                Some(untrusted_payer),
            ),
            &trace,
        );
    }
    trace.step("settle.seller_authorization", 0);
    let payer = match validate_request_signature(&body) {
        Ok(payer) => payer,
        Err(err) => {
            trace.step("settle.signature_validation", 0);
            let response = failed_settlement(NETWORK, &err.reason, &err.message, err.payer);
            return json_response_with_cost(402, &response, &trace);
        }
    };
    trace.step("settle.signature_validation", 0);
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
    if let Some(existing) = get_settlement(&key) {
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
    let active_scope = match active_settlement_scope(&from, &body.payment_requirements.pay_to) {
        Ok(value) => value,
        Err(message) => {
            trace.step("settle.active_scope", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, Some(payer)),
                &trace,
            );
        }
    };
    trace.step("settle.active_scope", 0);
    if !acquire_active_settlement(&active_scope, &key) {
        trace.step("settle.active_lock", 0);
        return json_response_with_cost(
            429,
            &settle_error(
                "settlement_queue_busy",
                "another settlement is active for this seller",
                Some(payer),
            ),
            &trace,
        );
    }
    trace.step("settle.active_lock", 0);
    let ttl = match settlement_cache_ttl_seconds() {
        Ok(ttl) => ttl,
        Err(message) => {
            release_active_settlement(&active_scope, &key);
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
            release_active_settlement(&active_scope, &key);
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
        release_active_settlement(&active_scope, &key);
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
            release_active_settlement(&active_scope, &key);
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
            release_active_settlement(&active_scope, &key);
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
            trace.step("settle.send_settlement", 5);
            let record = SettlementRecord::settled(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(&key, record);
            release_active_settlement(&active_scope, &key);
            json_response_with_cost(200, &record.response, &trace)
        }
        Ok(SettlementOutcome::Pending { nonce, tx }) => {
            trace.step("settle.send_settlement", 5);
            update_active_broadcast(&active_scope, &key, nonce, &tx);
            let record = SettlementRecord::broadcast(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(&key, record);
            json_response_with_cost(202, &record.response, &trace)
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            trace.step("settle.send_settlement", 5);
            let record = SettlementRecord::failed(
                tx,
                message,
                payer,
                body.payment_requirements.pay_to,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(&key, record);
            release_active_settlement(&active_scope, &key);
            json_response_with_cost(502, &record.response, &trace)
        }
        Err(SettlementSendError::GasTooExpensive) => {
            trace.step("settle.send_settlement", 2);
            rollback_reserved_nonce(&from, nonce);
            remove_settlement(&key);
            refund_seller_credit(&body.payment_requirements.pay_to, settlement_fee);
            release_active_settlement(&active_scope, &key);
            json_response_with_cost(
                503,
                &settle_error("gas_too_expensive", GAS_TOO_EXPENSIVE_MESSAGE, Some(payer)),
                &trace,
            )
        }
        Err(SettlementSendError::Other(message)) => {
            trace.step("settle.send_settlement", 5);
            rollback_reserved_nonce(&from, nonce);
            remove_settlement(&key);
            refund_seller_credit(&body.payment_requirements.pay_to, settlement_fee);
            release_active_settlement(&active_scope, &key);
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
            trace.step("settle.refresh", 2);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, Some(details.payer)),
                trace,
            );
        }
    };
    trace.step("settle.refresh", 2);
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
            let record = insert_settlement(key, record);
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
            let record = insert_settlement(key, record);
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
    if let Some(existing) = get_settlement(&key) {
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
            trace.step("seller_credit.send_settlement", 5);
            let record = SettlementRecord::settled(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(&key, record);
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
            trace.step("seller_credit.send_settlement", 5);
            update_active_broadcast(&from, &key, nonce, &tx);
            let record = SettlementRecord::broadcast(
                tx,
                payer,
                body.payment_requirements.pay_to,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(&key, record);
            seller_credit_paid_response(202, &seller, &record, trace)
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            trace.step("seller_credit.send_settlement", 5);
            let record = SettlementRecord::failed(
                tx,
                message,
                payer,
                body.payment_requirements.pay_to,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(&key, record);
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
            trace.step("seller_credit.send_settlement", 5);
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
            trace.step("seller_credit.refresh", 2);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, Some(details.payer)),
                trace,
            );
        }
    };
    trace.step("seller_credit.refresh", 2);
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
            let record = insert_settlement(key, record);
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
            let record = insert_settlement(key, record);
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
    let min_confirmations =
        optional_positive_u64("SETTLE_MIN_CONFIRMATIONS", DEFAULT_MIN_CONFIRMATIONS)?;
    Ok(RpcConfig {
        services: env("POLYGON_RPC_SERVICES")?,
        max_gas,
        max_settlement_fee_wei,
        min_confirmations,
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
    if env("FACILITATOR_DEBUG_COST").as_deref() != Ok("1") {
        return false;
    }
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

fn validate_eip712_version(
    request: &FacilitatorRequest,
    expected: &str,
) -> Result<(), crate::facilitator::VerifyFailure> {
    let requirement_version = request
        .payment_requirements
        .extra
        .get("version")
        .and_then(|value| value.as_str());
    let accepted_version = request
        .payment_payload
        .accepted
        .extra
        .get("version")
        .and_then(|value| value.as_str());
    if requirement_version != Some(expected) || accepted_version != Some(expected) {
        return Err(crate::facilitator::VerifyFailure {
            reason: "invalid_exact_evm_eip712_version".to_string(),
            message: "EIP-712 domain version does not match JPYC_EIP712_VERSION".to_string(),
            payer: Some(request.payment_payload.payload.authorization.from.clone()),
        });
    }
    Ok(())
}

struct SellerAuthorization {
    seller: String,
    payer: String,
    amount: String,
    asset: String,
    network: String,
    resource: String,
    valid_after: String,
    valid_before: String,
    authorization_nonce: String,
    expires_at: String,
    signature: String,
}

fn validate_seller_authorization(request: &FacilitatorRequest) -> Result<(), String> {
    let authorization = seller_authorization_from_request(request)?;
    let auth = &request.payment_payload.payload.authorization;
    let pay_to = normalize_evm_address(
        "paymentRequirements.payTo",
        &request.payment_requirements.pay_to,
    )?;
    if authorization.seller != pay_to {
        return Err("sellerAuthorization.seller must match paymentRequirements.payTo".to_string());
    }
    let payer = normalize_evm_address("authorization.from", &auth.from)?;
    if authorization.payer != payer {
        return Err("sellerAuthorization.payer must match authorization.from".to_string());
    }
    if authorization.amount != request.payment_requirements.amount
        || authorization.amount != auth.value
    {
        return Err("sellerAuthorization.amount must match settlement amount".to_string());
    }
    let asset = normalize_evm_address(
        "paymentRequirements.asset",
        &request.payment_requirements.asset,
    )?;
    if authorization.asset != asset {
        return Err("sellerAuthorization.asset must match paymentRequirements.asset".to_string());
    }
    if authorization.network != request.payment_requirements.network {
        return Err(
            "sellerAuthorization.network must match paymentRequirements.network".to_string(),
        );
    }
    let resource = request
        .payment_payload
        .resource
        .as_ref()
        .map(|item| item.url.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            "paymentPayload.resource.url is required for seller authorization".to_string()
        })?;
    if authorization.resource != resource {
        return Err(
            "sellerAuthorization.resource must match paymentPayload.resource.url".to_string(),
        );
    }
    if authorization.valid_after != auth.valid_after {
        return Err(
            "sellerAuthorization.validAfter must match authorization.validAfter".to_string(),
        );
    }
    if authorization.valid_before != auth.valid_before {
        return Err(
            "sellerAuthorization.validBefore must match authorization.validBefore".to_string(),
        );
    }
    if authorization.authorization_nonce != auth.nonce.to_ascii_lowercase() {
        return Err(
            "sellerAuthorization.authorizationNonce must match authorization.nonce".to_string(),
        );
    }
    let expires_at = authorization
        .expires_at
        .parse::<u64>()
        .map_err(|_| "sellerAuthorization.expiresAt must be an integer string".to_string())?;
    if expires_at < now_seconds().saturating_add(6) {
        return Err("sellerAuthorization.expiresAt is expired".to_string());
    }
    let message = seller_authorization_message(&authorization);
    let recovered = recover_eip191_signer(&message, &authorization.signature)?;
    if !same_address(&recovered, &authorization.seller) {
        return Err("sellerAuthorization.signature signer must match seller".to_string());
    }
    Ok(())
}

fn seller_authorization_from_request(
    request: &FacilitatorRequest,
) -> Result<SellerAuthorization, String> {
    let value = request
        .payment_requirements
        .extra
        .get("sellerAuthorization")
        .ok_or_else(|| "paymentRequirements.extra.sellerAuthorization is required".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "sellerAuthorization must be an object".to_string())?;
    if object.get("version").and_then(|value| value.as_u64()) != Some(1) {
        return Err("sellerAuthorization.version must be 1".to_string());
    }
    if object.get("scheme").and_then(|value| value.as_str()) != Some("eip191") {
        return Err("sellerAuthorization.scheme must be eip191".to_string());
    }
    Ok(SellerAuthorization {
        seller: normalize_evm_address(
            "sellerAuthorization.seller",
            required_object_string(object, "seller")?,
        )?,
        payer: normalize_evm_address(
            "sellerAuthorization.payer",
            required_object_string(object, "payer")?,
        )?,
        amount: required_object_string(object, "amount")?.to_string(),
        asset: normalize_evm_address(
            "sellerAuthorization.asset",
            required_object_string(object, "asset")?,
        )?,
        network: required_object_string(object, "network")?.to_string(),
        resource: required_object_string(object, "resource")?.to_string(),
        valid_after: required_object_string(object, "validAfter")?.to_string(),
        valid_before: required_object_string(object, "validBefore")?.to_string(),
        authorization_nonce: required_object_string(object, "authorizationNonce")?
            .to_ascii_lowercase(),
        expires_at: required_object_string(object, "expiresAt")?.to_string(),
        signature: required_object_string(object, "signature")?.to_string(),
    })
}

fn required_object_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<&'a str, String> {
    object
        .get(name)
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("sellerAuthorization.{name} is required"))
}

fn seller_authorization_message(authorization: &SellerAuthorization) -> String {
    [
        SELLER_AUTH_MESSAGE_PREFIX.to_string(),
        format!("seller={}", authorization.seller),
        format!("payer={}", authorization.payer),
        format!("amount={}", authorization.amount),
        format!("asset={}", authorization.asset),
        format!("network={}", authorization.network),
        format!("resource={}", authorization.resource),
        format!("validAfter={}", authorization.valid_after),
        format!("validBefore={}", authorization.valid_before),
        format!("authorizationNonce={}", authorization.authorization_nonce),
        format!("expiresAt={}", authorization.expires_at),
    ]
    .join("\n")
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
    let current = get_seller_credit(&seller)
        .map(|item| item.credit_atoms)
        .unwrap_or(0);
    if current < amount {
        return Err(format!(
            "seller credit is below required fee: required={amount}, current={current}"
        ));
    }
    put_seller_credit(
        &seller,
        SellerCredit {
            credit_atoms: current - amount,
            updated_at: now_seconds(),
        },
    );
    Ok(())
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
        if items.contains_key(&settlement_key.to_string()) {
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
    let current = get_seller_credit(seller)
        .map(|item| item.credit_atoms)
        .unwrap_or(0);
    put_seller_credit(
        seller,
        SellerCredit {
            credit_atoms: current.saturating_add(amount),
            updated_at: now_seconds(),
        },
    );
}

#[query]
fn seller_credit(seller: String) -> u128 {
    normalize_evm_address("seller", &seller)
        .ok()
        .map(|seller| seller_credit_balance_for(&seller))
        .unwrap_or(0)
}

#[query]
fn settlement(key: String) -> Option<SettlementRecord> {
    get_settlement(&key)
}

#[query]
fn settlement_count() -> u64 {
    SETTLEMENTS.with(|items| items.borrow().len())
}

#[query]
fn active_settlement_count() -> u64 {
    ACTIVE_SETTLEMENTS.with(|items| items.borrow().len())
}

fn seller_credit_balance_for(seller: &str) -> u128 {
    get_seller_credit(seller)
        .map(|item| item.credit_atoms)
        .unwrap_or(0)
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
    let origin = public_origin()?;
    Ok(format!("{origin}{}", request_path_and_query(&request.url)))
}

fn public_origin() -> Result<String, String> {
    let value = env("FACILITATOR_PUBLIC_ORIGIN")?;
    let origin = value.trim_end_matches('/');
    let host = origin
        .strip_prefix("https://")
        .ok_or_else(|| "FACILITATOR_PUBLIC_ORIGIN must be an https origin".to_string())?;
    if host.is_empty() || host.contains('/') || host.contains('?') || host.contains('#') {
        return Err("FACILITATOR_PUBLIC_ORIGIN must be an https origin".to_string());
    }
    Ok(origin.to_string())
}

fn request_path_and_query(url: &str) -> String {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return url.to_string();
    }
    let Some(after_scheme) = url.split_once("://").map(|(_, rest)| rest) else {
        return "/".to_string();
    };
    after_scheme
        .find('/')
        .map(|index| after_scheme[index..].to_string())
        .unwrap_or_else(|| "/".to_string())
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
    if let Some(value) = ENV.with(|env| env.borrow().get(&name.to_string())) {
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

fn insert_settlement(key: &str, mut record: SettlementRecord) -> SettlementRecord {
    attach_settlement_key(key, &mut record);
    SETTLEMENTS.with(|items| {
        items
            .borrow_mut()
            .insert(key.to_string(), encode_stable(&record));
    });
    record
}

fn attach_settlement_key(key: &str, record: &mut SettlementRecord) {
    let mut extra = record.response.extra.clone().unwrap_or_default();
    extra.insert("settlementKey".to_string(), key.to_string());
    record.response.extra = Some(extra);
}

fn remove_settlement(key: &str) {
    SETTLEMENTS.with(|items| {
        items.borrow_mut().remove(&key.to_string());
    });
}

fn purge_expired_settlements(now: u64) {
    let expired_keys = SETTLEMENTS.with(|items| {
        items
            .borrow()
            .iter()
            .filter(|entry| {
                let record = decode_stable::<SettlementRecord>(entry.value());
                record.is_expired(now) && !record.is_broadcast()
            })
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>()
    });
    SETTLEMENTS.with(|items| {
        let mut items = items.borrow_mut();
        for key in &expired_keys {
            items.remove(key);
        }
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
    match get_active_settlement(from) {
        Some(active) if active.key != key => false,
        Some(_) => true,
        None => {
            put_active_settlement(
                from,
                ActiveSettlement {
                    key: key.to_string(),
                    nonce: None,
                    tx: None,
                },
            );
            true
        }
    }
}

fn update_active_broadcast(from: &str, key: &str, nonce: u128, tx: &str) {
    if let Some(mut active) = get_active_settlement(from).filter(|active| active.key == key) {
        active.nonce = Some(nonce);
        active.tx = Some(tx.to_string());
        put_active_settlement(from, active);
    }
}

#[cfg(test)]
fn active_nonce(from: &str, key: &str) -> Option<u128> {
    get_active_settlement(from)
        .filter(|active| active.key == key)
        .and_then(|active| active.nonce)
}

fn active_nonce_by_key(key: &str) -> Option<u128> {
    ACTIVE_SETTLEMENTS.with(|items| {
        items.borrow().iter().find_map(|entry| {
            let active = decode_stable::<ActiveSettlement>(entry.value());
            (active.key == key).then_some(active.nonce).flatten()
        })
    })
}

fn update_active_broadcast_by_key(key: &str, nonce: u128, tx: &str) {
    let scope = ACTIVE_SETTLEMENTS.with(|items| {
        items.borrow().iter().find_map(|entry| {
            let active = decode_stable::<ActiveSettlement>(entry.value());
            (active.key == key).then(|| entry.key().clone())
        })
    });
    if let Some(scope) = scope {
        update_active_broadcast(&scope, key, nonce, tx);
    }
}

fn release_active_settlement(from: &str, key: &str) {
    if get_active_settlement(from)
        .map(|active| active.key == key)
        .unwrap_or(false)
    {
        ACTIVE_SETTLEMENTS.with(|items| {
            items.borrow_mut().remove(&from.to_string());
        });
    }
}

fn release_active_settlement_by_key(key: &str) {
    ACTIVE_SETTLEMENTS.with(|items| {
        let keys = items
            .borrow()
            .iter()
            .filter(|entry| decode_stable::<ActiveSettlement>(entry.value()).key == key)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        let mut items = items.borrow_mut();
        for from in keys {
            items.remove(&from);
        }
    });
}

fn reserve_nonce(from: &str, rpc_pending_nonce: u128) -> u128 {
    let mut state = get_nonce_state(from);
    let nonce = state
        .next_nonce
        .map(|next| next.max(rpc_pending_nonce))
        .unwrap_or(rpc_pending_nonce);
    state.next_nonce = Some(nonce.saturating_add(1));
    put_nonce_state(from, state);
    nonce
}

fn rollback_reserved_nonce(from: &str, nonce: u128) {
    let mut state = get_nonce_state(from);
    if state.next_nonce == Some(nonce.saturating_add(1)) {
        state.next_nonce = Some(nonce);
        put_nonce_state(from, state);
    }
}

fn active_settlement_scope(from: &str, seller: &str) -> Result<String, String> {
    let seller = normalize_evm_address("seller", seller)?;
    Ok(format!("{}|{}", from.to_ascii_lowercase(), seller))
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
    let _from = match private_key_address(&private_key) {
        Ok(value) => value,
        Err(_) => {
            trace.step(labels.config, 0);
            return existing;
        }
    };
    trace.step(labels.config, 0);
    let Some(nonce) = active_nonce_by_key(key) else {
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
            trace.step(labels.send, 5);
            let record = SettlementRecord::settled(
                tx,
                details.payer.clone(),
                details.pay_to.clone(),
                details.amount,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(key, record);
            release_active_settlement_by_key(key);
            record
        }
        Ok(SettlementOutcome::Pending { nonce, tx }) => {
            trace.step(labels.send, 5);
            update_active_broadcast_by_key(key, nonce, &tx);
            let record = SettlementRecord::broadcast(
                tx,
                details.payer,
                details.pay_to,
                details.amount,
                now_seconds(),
                ttl,
            );
            insert_settlement(key, record)
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            trace.step(labels.send, 5);
            let record = SettlementRecord::failed(
                tx,
                message,
                details.payer.clone(),
                details.pay_to.clone(),
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(key, record);
            release_active_settlement_by_key(key);
            record
        }
        Err(SettlementSendError::GasTooExpensive) => {
            trace.step(labels.send, 2);
            existing
        }
        Err(SettlementSendError::Other(_)) => {
            trace.step(labels.send, 5);
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
        clear_env_values();
        set_env_value("FACILITATOR_PUBLIC_ORIGIN", "https://canister.example.test");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("SELLER_CREDIT_PAY_TO", CREDIT_PAY_TO);
        set_env_value("SELLER_CREDIT_TOPUP_AMOUNT", "1000");
        set_env_value("SELLER_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value("SELLER_CREDIT_MAX_TIMEOUT_SECONDS", "60");
    }

    fn seller_credit_request() -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            url: format!("/seller-credit?seller={SELLER}"),
            headers: vec![],
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
    fn cost_report_is_debug_only() {
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/settle?debugCost=1".to_string(),
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

        remove_env_value("FACILITATOR_DEBUG_COST");
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/settle?debugCost=1".to_string(),
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
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        let request = HttpRequest {
            method: "POST".to_string(),
            url: "/settle".to_string(),
            headers: vec![HeaderField("x-debug-cost".to_string(), "1".to_string())],
            body: vec![],
            certificate_version: None,
        };
        assert!(debug_cost_enabled(&request));
        remove_env_value("FACILITATOR_DEBUG_COST");
        assert!(!debug_cost_enabled(&request));
    }

    #[test]
    fn rpc_config_uses_default_settlement_fee_cap() {
        clear_env_values();
        set_env_value("POLYGON_RPC_SERVICES", "https://polygon.example");
        let config = rpc_config().unwrap();
        assert_eq!(
            config.max_settlement_fee_wei,
            DEFAULT_MAX_SETTLEMENT_FEE_WEI
        );
        assert_eq!(config.min_confirmations, DEFAULT_MIN_CONFIRMATIONS);
    }

    #[test]
    fn rpc_config_rejects_invalid_settlement_fee_cap() {
        for value in ["0", "not-a-number"] {
            clear_env_values();
            set_env_value("POLYGON_RPC_SERVICES", "https://polygon.example");
            set_env_value("FACILITATOR_MAX_SETTLEMENT_FEE_WEI", value);
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
        set_env_value("FACILITATOR_DEBUG_COST", "1");
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
        set_env_value("FACILITATOR_DEBUG_COST", "1");
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
        clear_seller_credits();
        clear_credited_settlements();
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
        clear_seller_credits();
        clear_credited_settlements();
        remove_env_value("SELLER_CREDIT_TOPUP_AMOUNT");
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
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{RecoveryId, Signature, SigningKey};
    use serde_json::{json, Value};

    const PAYER: &str = "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993";
    const PAY_TO: &str = "0x1000000000000000000000000000000000000402";
    const PAYER_PRIVATE_KEY: &str =
        "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
    const SELLER_PRIVATE_KEY: &str =
        "0x1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_PRIVATE_KEY: &str =
        "0x2222222222222222222222222222222222222222222222222222222222222222";

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
                        "validBefore": "1700000050",
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

    fn request_for_settle_validation() -> FacilitatorRequest {
        let mut body = request();
        body.payment_payload.payload.authorization.valid_before =
            now_seconds().saturating_add(60).to_string();
        body
    }

    fn sign_message(private_key: &str, message: &str) -> String {
        let key = SigningKey::from_slice(&parse_hex(private_key, Some(32)).unwrap()).unwrap();
        let digest = crate::eip712::eip191_digest(message);
        let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash(&digest).unwrap();
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.push(u8::from(recovery) + 27);
        format!("0x{}", hex::encode(bytes))
    }

    fn sign_eip3009(body: &mut FacilitatorRequest) {
        let key = SigningKey::from_slice(&parse_hex(PAYER_PRIVATE_KEY, Some(32)).unwrap()).unwrap();
        let digest = crate::eip712::eip3009_digest(&body.payment_payload).unwrap();
        let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash(&digest).unwrap();
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.push(u8::from(recovery) + 27);
        body.payment_payload.payload.signature = format!("0x{}", hex::encode(bytes));
    }

    fn request_with_seller_auth() -> FacilitatorRequest {
        let seller = private_key_address(SELLER_PRIVATE_KEY).unwrap();
        let mut body = request_for_settle_validation();
        body.payment_requirements.pay_to = seller.clone();
        body.payment_payload.accepted.pay_to = seller.clone();
        body.payment_payload.payload.authorization.to = seller.clone();
        body.payment_payload.resource = Some(ResourceInfo {
            url: "https://example.test/report".to_string(),
            description: None,
            mime_type: None,
        });
        let mut authorization = serde_json::json!({
            "version": 1,
            "scheme": "eip191",
            "seller": seller,
            "payer": PAYER,
            "amount": body.payment_requirements.amount,
            "asset": body.payment_requirements.asset,
            "network": body.payment_requirements.network,
            "resource": "https://example.test/report",
            "validAfter": body.payment_payload.payload.authorization.valid_after,
            "validBefore": body.payment_payload.payload.authorization.valid_before,
            "authorizationNonce": body.payment_payload.payload.authorization.nonce,
            "expiresAt": "1700000120",
            "signature": "0x"
        });
        body.payment_requirements.extra["sellerAuthorization"] = authorization.clone();
        body.payment_payload.accepted.extra = body.payment_requirements.extra.clone();
        let parsed = seller_authorization_from_request(&body).unwrap();
        authorization["signature"] = json!(sign_message(
            SELLER_PRIVATE_KEY,
            &seller_authorization_message(&parsed),
        ));
        body.payment_requirements.extra["sellerAuthorization"] = authorization;
        body.payment_payload.accepted.extra = body.payment_requirements.extra.clone();
        body
    }

    fn settle_request(body: &FacilitatorRequest) -> HttpRequest {
        HttpRequest {
            method: "POST".to_string(),
            url: "/settle?debugCost=1".to_string(),
            headers: vec![],
            body: serde_json::to_vec(body).unwrap(),
            certificate_version: None,
        }
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
        clear_active_settlements();
        clear_nonces();
    }

    fn clear_settlement_state() {
        clear_active_state();
        clear_settlements();
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
        let err = validate_request_signature(&body).unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_signature");
    }

    #[test]
    fn eip712_version_must_match_config() {
        let mut body = request();
        body.payment_requirements.extra["version"] = json!("2");
        let err = validate_eip712_version(&body, "1").unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_eip712_version");

        let mut body = request();
        body.payment_payload.accepted.extra["version"] = json!("2");
        let err = validate_eip712_version(&body, "1").unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_eip712_version");

        let body = request_for_settle_validation();
        validate_eip712_version(&body, "1").unwrap();
    }

    #[test]
    fn seller_authorization_requires_pay_to_signature_and_matching_fields() {
        let body = request_for_settle_validation();
        assert_eq!(
            validate_seller_authorization(&body).unwrap_err(),
            "paymentRequirements.extra.sellerAuthorization is required"
        );

        let body = request_with_seller_auth();
        validate_seller_authorization(&body).unwrap();

        let mut amount_mismatch = body.clone();
        amount_mismatch.payment_requirements.extra["sellerAuthorization"]["amount"] =
            json!("2000000000000000000");
        assert_eq!(
            validate_seller_authorization(&amount_mismatch).unwrap_err(),
            "sellerAuthorization.amount must match settlement amount"
        );

        let mut resource_mismatch = body.clone();
        resource_mismatch
            .payment_payload
            .resource
            .as_mut()
            .unwrap()
            .url = "https://example.test/other".to_string();
        assert_eq!(
            validate_seller_authorization(&resource_mismatch).unwrap_err(),
            "sellerAuthorization.resource must match paymentPayload.resource.url"
        );

        let mut nonce_mismatch = body.clone();
        nonce_mismatch.payment_payload.payload.authorization.nonce =
            format!("0x{}", "33".repeat(32));
        assert_eq!(
            validate_seller_authorization(&nonce_mismatch).unwrap_err(),
            "sellerAuthorization.authorizationNonce must match authorization.nonce"
        );

        let mut expired = body.clone();
        expired.payment_requirements.extra["sellerAuthorization"]["expiresAt"] = json!("1");
        expired.payment_payload.accepted.extra = expired.payment_requirements.extra.clone();
        assert_eq!(
            validate_seller_authorization(&expired).unwrap_err(),
            "sellerAuthorization.expiresAt is expired"
        );

        let mut signer_mismatch = body.clone();
        let parsed = seller_authorization_from_request(&signer_mismatch).unwrap();
        signer_mismatch.payment_requirements.extra["sellerAuthorization"]["signature"] = json!(
            sign_message(OTHER_PRIVATE_KEY, &seller_authorization_message(&parsed))
        );
        signer_mismatch.payment_payload.accepted.extra =
            signer_mismatch.payment_requirements.extra.clone();
        assert_eq!(
            validate_seller_authorization(&signer_mismatch).unwrap_err(),
            "sellerAuthorization.signature signer must match seller"
        );
    }

    #[test]
    fn settle_rejects_missing_seller_authorization_before_credit_or_lock() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 500);
        let body = request_for_settle_validation();

        let response = run_ready(settle_http(settle_request(&body)));

        assert_eq!(response.status_code, 402);
        assert_eq!(seller_credit_balance_for(&seller), 500);
        assert_eq!(active_settlement_count(), 0);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            value["result"]["errorReason"],
            "invalid_seller_authorization"
        );
        assert_eq!(value["cost"]["rpcCalls"], 0);
        let steps = value["cost"]["steps"].as_array().unwrap();
        assert!(steps
            .iter()
            .any(|step| step["name"] == "settle.seller_authorization"));
        assert!(!steps
            .iter()
            .any(|step| step["name"] == "settle.reserve_seller_credit"));
    }

    #[test]
    fn settle_with_valid_seller_authorization_reaches_reserve_path() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        set_env_value("SELLER_SETTLEMENT_FEE_AMOUNT", "100");
        let mut body = request_with_seller_auth();
        sign_eip3009(&mut body);
        let seller = normalize_evm_address("seller", &body.payment_requirements.pay_to).unwrap();
        add_seller_credit(&seller, 500);

        let response = run_ready(settle_http(settle_request(&body)));

        assert_eq!(response.status_code, 400);
        assert_eq!(seller_credit_balance_for(&seller), 500);
        assert_eq!(active_settlement_count(), 0);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_config");
        let steps = value["cost"]["steps"].as_array().unwrap();
        assert!(steps
            .iter()
            .any(|step| step["name"] == "settle.reserve_seller_credit"));
        assert!(steps.iter().any(|step| step["name"] == "settle.rpc_config"));
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
    fn active_settlement_scope_blocks_same_seller_only() {
        clear_active_state();
        let from = "0x0000000000000000000000000000000000000402";
        let seller_a = "0x1000000000000000000000000000000000000402";
        let seller_b = "0x2000000000000000000000000000000000000402";
        let scope_a = active_settlement_scope(from, seller_a).unwrap();
        let scope_b = active_settlement_scope(from, seller_b).unwrap();

        assert!(acquire_active_settlement(&scope_a, "key-a"));
        assert!(!acquire_active_settlement(&scope_a, "key-b"));
        assert!(acquire_active_settlement(&scope_b, "key-b"));
    }

    #[test]
    fn purge_expired_settlements_keeps_expired_broadcast_active_lock() {
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

        assert!(get_settlement("key-a").is_some());
        assert!(!acquire_active_settlement(from, "key-b"));
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

        assert!(get_settlement("key-a").is_some());
        assert!(!acquire_active_settlement(from, "key-b"));
    }

    #[test]
    fn seller_credit_pending_replacement_uses_seller_credit_trace_labels() {
        clear_settlement_state();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
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
