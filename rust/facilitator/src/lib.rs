// rust/facilitator/src/lib.rs: ICP HTTP gateway 上で JPYC x402 facilitator API を公開する。
mod batch;
mod eip712;
mod facilitator;
mod hexutil;
mod rpc;
mod state;
mod tx;
mod types;

use std::cell::RefCell;
use std::collections::BTreeMap;

use candid::{CandidType, Deserialize as CandidDeserialize, Principal};
use ic_cdk::{post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use k256::ecdsa::SigningKey;
use serde::Serialize;

use crate::batch::{
    batch_payload, compute_batch_channel_id, is_pending_only_provisional_channel,
    requires_batch_eip712_version, validate_batch_channel, validate_batch_channel_transition,
    validate_batch_eip712_version, validate_batch_request, validate_batch_settle_request,
    validate_channel_id, validate_optional_batch_eip712_version, validate_withdraw_delay,
    voucher_channel_id, BatchChannel, BatchChannelUpdate, BatchChannelUpdateResult,
    BatchFacilitatorRequest, BATCH_SCHEME, CANONICAL_BATCH_SETTLEMENT_CONTRACT,
    DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS, MAX_BATCH_CHANNELS_LIST, MAX_BATCH_CHANNELS_STORED,
};
use crate::eip712::recover_eip191_signer;
use crate::facilitator::{
    failed_settlement, supported, validate_request, validate_request_before_signature,
    validate_request_signature,
};
use crate::hexutil::{
    address_hex, keccak256, parse_address, parse_hex, parse_u256_decimal, same_address,
    JPYC_EIP712_NAME, JPYC_POLYGON_ADDRESS, NETWORK,
};
use crate::rpc::{
    batch_channel_snapshot, batch_settled_amount, pending_nonce, refresh_contract_settlement,
    refresh_settlement, send_contract_transaction, send_settlement, BatchChannelSnapshot,
    ContractExpectation, ExpectedClaimState, ExpectedTransfer, RpcConfig, SettlementOutcome,
    SettlementSendError,
};
use crate::state::SettlementRecord;
use crate::tx::{
    encode_batch_claim_calldata, encode_batch_deposit_calldata, encode_batch_refund_calldata,
    encode_batch_settle_calldata, recover_batch_claim_authorizer, recover_batch_refund_authorizer,
};
use crate::types::{
    json_response, text_response, FacilitatorRequest, HeaderField, HttpRequest, HttpResponse,
    PaymentPayload, PaymentRequiredResponse, PaymentRequirements, ResourceInfo,
    SettleChannelStateExtra, SettleResponse, SettleResponseExtra, SettleVoucherStateExtra,
    SupportedKind, VerifyResponse,
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
const BATCH_CHANNELS_MEM_ID: MemoryId = MemoryId::new(6);
const BATCH_DELETED_CHANNELS_MEM_ID: MemoryId = MemoryId::new(7);

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct StableState {
    env: BTreeMap<String, String>,
    settlements: BTreeMap<String, SettlementRecord>,
    seller_credits: BTreeMap<String, SellerCredit>,
    credited_settlements: BTreeMap<String, String>,
    active_settlements: Option<BTreeMap<String, ActiveSettlement>>,
    nonces: Option<BTreeMap<String, NonceState>>,
    batch_channels: Option<BTreeMap<String, BatchChannel>>,
    batch_deleted_channels: Option<BTreeMap<String, BatchDeletedChannel>>,
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
    static BATCH_CHANNELS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(BATCH_CHANNELS_MEM_ID))));
    static BATCH_DELETED_CHANNELS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(BATCH_DELETED_CHANNELS_MEM_ID))));
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

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct BatchDeletedChannel {
    channel: BatchChannel,
    deleted_at: u64,
    deleted_by: String,
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
        ("POST", "/verify") => verify_http(request).await,
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

fn require_batch_channel_storage_writer() -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    authorize_batch_channel_storage_writer(caller, ic_cdk::api::is_controller(&caller))
}

fn authorize_batch_channel_storage_writer(
    caller: Principal,
    is_controller: bool,
) -> Result<(), String> {
    if caller == Principal::anonymous() {
        return Err(
            "anonymous caller is not authorized to update batch channel storage".to_string(),
        );
    }
    if is_controller {
        return Ok(());
    }
    if batch_channel_storage_writer_principal()?.is_some_and(|writer| writer == caller) {
        return Ok(());
    }
    Err("caller is not authorized to update batch channel storage".to_string())
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
    if !stable_structures_empty() {
        return;
    }
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

fn stable_structures_empty() -> bool {
    ENV.with(|items| items.borrow().is_empty())
        && SETTLEMENTS.with(|items| items.borrow().is_empty())
        && SELLER_CREDITS.with(|items| items.borrow().is_empty())
        && CREDITED_SETTLEMENTS.with(|items| items.borrow().is_empty())
        && ACTIVE_SETTLEMENTS.with(|items| items.borrow().is_empty())
        && NONCES.with(|items| items.borrow().is_empty())
        && BATCH_CHANNELS.with(|items| items.borrow().is_empty())
        && BATCH_DELETED_CHANNELS.with(|items| items.borrow().is_empty())
}

fn set_env_value(name: &str, value: &str) {
    ENV.with(|env| {
        if value.trim().is_empty() {
            env.borrow_mut().remove(&name.to_string());
        } else {
            env.borrow_mut().insert(name.to_string(), value.to_string());
        }
    });
}

fn optional_env_value(name: &str) -> Option<String> {
    if let Some(value) = ENV.with(|env| env.borrow().get(&name.to_string())) {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }
    #[cfg(test)]
    {
        None
    }
    #[cfg(not(test))]
    {
        if !ic_cdk::api::env_var_name_exists(name) {
            None
        } else {
            let value = ic_cdk::api::env_var_value(name);
            if value.trim().is_empty() {
                None
            } else {
                Some(value)
            }
        }
    }
}

fn batch_channel_storage_writer_principal() -> Result<Option<Principal>, String> {
    optional_env_value("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL")
        .map(|value| {
            let principal = value.trim();
            if principal == "2vxsx-fae" || principal == "aaaaa-aa" {
                return Err(
                    "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be a non-system IC principal"
                        .to_string(),
                );
            }
            Principal::from_text(principal).map_err(|_| {
                "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be an IC principal".to_string()
            })
        })
        .transpose()
}

fn required_batch_channel_storage_writer_principal() -> Result<Principal, String> {
    batch_channel_storage_writer_principal()?
        .ok_or_else(|| "missing required env: BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL".to_string())
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

fn put_batch_channel(channel_id: &str, channel: BatchChannel) -> Result<(), String> {
    BATCH_CHANNELS.with(|items| {
        let mut items = items.borrow_mut();
        let key = channel_id.to_ascii_lowercase();
        if !items.contains_key(&key) && items.len() >= MAX_BATCH_CHANNELS_STORED {
            return Err("batch channel storage limit reached".to_string());
        }
        items.insert(key, encode_stable(&channel));
        Ok(())
    })
}

fn get_batch_channel(channel_id: &str) -> Option<BatchChannel> {
    BATCH_CHANNELS.with(|items| {
        items
            .borrow()
            .get(&channel_id.to_ascii_lowercase())
            .map(decode_stable::<BatchChannel>)
    })
}

fn put_batch_deleted_channel(channel_id: &str, deleted: BatchDeletedChannel) {
    BATCH_DELETED_CHANNELS.with(|items| {
        let mut items = items.borrow_mut();
        let key = channel_id.to_ascii_lowercase();
        if !items.contains_key(&key) && items.len() >= MAX_BATCH_CHANNELS_STORED {
            if let Some(oldest_key) = items
                .iter()
                .map(|entry| {
                    (
                        entry.key().clone(),
                        decode_stable::<BatchDeletedChannel>(entry.value()).deleted_at,
                    )
                })
                .min_by_key(|(_, deleted_at)| *deleted_at)
                .map(|(key, _)| key)
            {
                items.remove(&oldest_key);
            }
        }
        items.insert(key, encode_stable(&deleted));
    });
}

fn get_batch_deleted_channel(channel_id: &str) -> Option<BatchDeletedChannel> {
    BATCH_DELETED_CHANNELS.with(|items| {
        items
            .borrow()
            .get(&channel_id.to_ascii_lowercase())
            .map(decode_stable::<BatchDeletedChannel>)
    })
}

#[cfg(test)]
fn batch_channel_update_caller_text() -> String {
    "test-caller".to_string()
}

#[cfg(not(test))]
fn batch_channel_update_caller_text() -> String {
    ic_cdk::api::msg_caller().to_text()
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

#[cfg(test)]
fn clear_batch_channels() {
    BATCH_CHANNELS.with(|items| {
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
    BATCH_DELETED_CHANNELS.with(|items| {
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
    for (key, channel) in state.batch_channels.unwrap_or_default() {
        put_batch_channel(&key, channel).expect("legacy batch channel storage exceeds limit");
    }
    for (key, deleted) in state.batch_deleted_channels.unwrap_or_default() {
        put_batch_deleted_channel(&key, deleted);
    }
}

fn route(request: HttpRequest, updated: bool) -> HttpResponse {
    match (request.method.as_str(), path(&request.url).as_str()) {
        ("GET", "/health") => json_response(200, &health()),
        ("GET", "/supported") => supported_response(),
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
        ("POST", "/verify") if !updated => HttpResponse {
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

fn supported_response() -> HttpResponse {
    let version = match env("JPYC_EIP712_VERSION") {
        Ok(version) => version,
        Err(message) => {
            return json_response(
                500,
                &serde_json::json!({ "error": "invalid_config", "message": message }),
            )
        }
    };
    let mut response = supported(facilitator_address(), &version);
    if let Some((receiver_authorizer, withdraw_delay)) = supported_batch_config() {
        response.kinds.push(SupportedKind {
            x402_version: 2,
            scheme: BATCH_SCHEME.to_string(),
            network: NETWORK.to_string(),
            extra: serde_json::json!({
                "receiverAuthorizer": receiver_authorizer,
                "withdrawDelay": withdraw_delay,
                "assetTransferMethod": "eip3009",
                "name": JPYC_EIP712_NAME,
                "version": version
            }),
        });
        response
            .signers
            .entry("eip155:*".to_string())
            .or_default()
            .push(facilitator_address());
    }
    json_response(200, &response)
}

fn supported_batch_config() -> Option<(String, u64)> {
    optional_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")?;
    let receiver_authorizer = batch_receiver_authorizer_address().ok()?;
    let withdraw_delay = batch_withdraw_delay_seconds().ok()?;
    configured_batch_settlement_contract().ok()?;
    required_positive_u128("BATCH_SETTLEMENT_FEE_AMOUNT").ok()?;
    required_batch_channel_storage_writer_principal().ok()?;
    validate_batch_key_separation(&receiver_authorizer).ok()?;
    Some((receiver_authorizer, withdraw_delay))
}

fn batch_withdraw_delay_seconds() -> Result<u64, String> {
    let value = optional_positive_u64(
        "BATCH_WITHDRAW_DELAY_SECONDS",
        DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS,
    )?;
    validate_withdraw_delay(value)?;
    Ok(value)
}

fn require_batch_settlement_enabled() -> Result<String, String> {
    let receiver_authorizer = batch_receiver_authorizer_address()?;
    batch_withdraw_delay_seconds()?;
    let contract = configured_batch_settlement_contract()?;
    required_positive_u128("BATCH_SETTLEMENT_FEE_AMOUNT")?;
    required_batch_channel_storage_writer_principal()?;
    validate_batch_key_separation(&receiver_authorizer)?;
    Ok(contract)
}

fn require_batch_settlement_enabled_except_fee() -> Result<String, String> {
    let receiver_authorizer = batch_receiver_authorizer_address()?;
    batch_withdraw_delay_seconds()?;
    let contract = configured_batch_settlement_contract()?;
    required_batch_channel_storage_writer_principal()?;
    validate_batch_key_separation(&receiver_authorizer)?;
    Ok(contract)
}

async fn verify_http(request: HttpRequest) -> HttpResponse {
    let value = match parse_json_value(&request) {
        Ok(value) => value,
        Err(message) => {
            return json_response(400, &verify_error("invalid_request", &message, None))
        }
    };
    let Some(scheme) = value
        .get("paymentRequirements")
        .and_then(|item| item.get("scheme"))
        .and_then(serde_json::Value::as_str)
    else {
        return json_response(
            400,
            &verify_error(
                "invalid_request",
                "missing paymentRequirements.scheme",
                None,
            ),
        );
    };
    if scheme != BATCH_SCHEME {
        return json_response(
            400,
            &verify_error(
                "unsupported_verify_scheme",
                "only batch-settlement supports /verify",
                None,
            ),
        );
    }
    let body = match serde_json::from_value::<BatchFacilitatorRequest>(value) {
        Ok(body) => body,
        Err(err) => {
            return json_response(
                400,
                &verify_error(
                    "invalid_request",
                    &format!("invalid batch JSON body: {err}"),
                    None,
                ),
            )
        }
    };
    let expected_version = match env("JPYC_EIP712_VERSION") {
        Ok(value) => value,
        Err(message) => return json_response(500, &verify_error("invalid_config", &message, None)),
    };
    let payload = match batch_payload(&body.payment_payload.payload) {
        Ok(payload) => payload,
        Err(message) => {
            return json_response(400, &verify_error("invalid_request", &message, None));
        }
    };
    let version_check = if requires_batch_eip712_version(&payload) {
        validate_batch_eip712_version(&body, &expected_version)
    } else {
        validate_optional_batch_eip712_version(&body, &expected_version)
    };
    if let Err(message) = version_check {
        return json_response(
            402,
            &verify_error("invalid_batch_settlement", &message, None),
        );
    }
    let channel_id = match voucher_channel_id(&payload) {
        Ok(channel_id) => channel_id,
        Err(message) => {
            return json_response(400, &verify_error("invalid_request", &message, None));
        }
    };
    let channel_id = channel_id.to_string();
    let contract = match require_batch_settlement_enabled() {
        Ok(contract) => contract,
        Err(message) => {
            return json_response(500, &verify_error("invalid_config", &message, None));
        }
    };
    let current = get_batch_channel(&channel_id);
    let verified = match validate_batch_request(&body, current.as_ref(), &contract) {
        Ok(verified) => verified,
        Err(message) => {
            if let Some(extra) = batch_corrective_verify_extra(current.as_ref(), &message) {
                return json_response(
                    402,
                    &VerifyResponse {
                        is_valid: false,
                        invalid_reason: Some("invalid_batch_settlement".to_string()),
                        invalid_message: Some(message),
                        payer: current.as_ref().and_then(batch_channel_payer),
                        extra: Some(extra),
                    },
                );
            }
            return json_response(
                402,
                &verify_error("invalid_batch_settlement", &message, None),
            );
        }
    };
    let Some(current) = current.as_ref() else {
        return json_response(
            402,
            &verify_error(
                "invalid_batch_settlement",
                "invalid_batch_settlement_evm_channel_not_found",
                Some(verified.payer),
            ),
        );
    };
    if let Err(message) = validate_batch_verify_pending(&payload, current) {
        return json_response(
            402,
            &verify_error("invalid_batch_settlement", &message, Some(verified.payer)),
        );
    }
    let snapshot = batch_channel_storage_snapshot(current);
    if let Err(message) = validate_batch_verify_snapshot(&payload, &snapshot) {
        return json_response(
            402,
            &verify_error("invalid_batch_settlement", &message, Some(verified.payer)),
        );
    }
    json_response(
        200,
        &VerifyResponse {
            is_valid: true,
            invalid_reason: None,
            invalid_message: None,
            payer: Some(verified.payer),
            extra: Some(batch_verify_success_extra(&snapshot)),
        },
    )
}

fn batch_verify_success_extra(snapshot: &BatchChannelSnapshot) -> serde_json::Value {
    let channel_state = snapshot.to_json();
    serde_json::json!({
        "channelId": snapshot.channel_id,
        "balance": snapshot.balance,
        "totalClaimed": snapshot.total_claimed,
        "withdrawRequestedAt": snapshot.withdraw_requested_at,
        "refundNonce": snapshot.refund_nonce,
        "channelState": channel_state
    })
}

fn batch_channel_storage_snapshot(channel: &BatchChannel) -> BatchChannelSnapshot {
    BatchChannelSnapshot {
        channel_id: channel.channel_id.clone(),
        balance: channel.balance.clone(),
        total_claimed: channel.total_claimed.clone(),
        withdraw_requested_at: channel.withdraw_requested_at,
        refund_nonce: channel.refund_nonce.clone(),
    }
}

async fn settle_http(request: HttpRequest) -> HttpResponse {
    let mut trace = CostTrace::for_request(&request);
    let value = match parse_json_value(&request) {
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
    if batch::is_batch_request(&value) {
        trace.step("settle.parse", 0);
        return batch_settle_http(value, &mut trace).await;
    }
    let body = match serde_json::from_value::<FacilitatorRequest>(value) {
        Ok(body) => body,
        Err(err) => {
            trace.step("settle.parse", 0);
            return json_response_with_cost(
                400,
                &settle_error(
                    "invalid_request",
                    &format!("invalid JSON body: {err}"),
                    None,
                ),
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

async fn batch_settle_http(value: serde_json::Value, trace: &mut CostTrace) -> HttpResponse {
    let body = match serde_json::from_value::<BatchFacilitatorRequest>(value) {
        Ok(body) => body,
        Err(err) => {
            return json_response_with_cost(
                400,
                &settle_error(
                    "invalid_request",
                    &format!("invalid batch JSON body: {err}"),
                    None,
                ),
                trace,
            )
        }
    };
    let payload = match batch_payload(&body.payment_payload.payload) {
        Ok(payload) => payload,
        Err(message) => {
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, None),
                trace,
            )
        }
    };
    if requires_batch_eip712_version(&payload) {
        let expected_version = match env("JPYC_EIP712_VERSION") {
            Ok(value) => value,
            Err(message) => {
                trace.step("batch_settle.validation", 0);
                return json_response_with_cost(
                    400,
                    &settle_error("invalid_config", &message, None),
                    trace,
                );
            }
        };
        if let Err(message) = validate_batch_eip712_version(&body, &expected_version) {
            trace.step("batch_settle.validation", 0);
            return json_response_with_cost(
                402,
                &settle_error("invalid_batch_settlement", &message, None),
                trace,
            );
        }
    } else {
        match env("JPYC_EIP712_VERSION") {
            Ok(expected_version) => {
                if let Err(message) =
                    validate_optional_batch_eip712_version(&body, &expected_version)
                {
                    trace.step("batch_settle.validation", 0);
                    return json_response_with_cost(
                        402,
                        &settle_error("invalid_batch_settlement", &message, None),
                        trace,
                    );
                }
            }
            Err(message)
                if body.payment_requirements.extra.get("version").is_some()
                    || body.payment_payload.accepted.extra.get("version").is_some() =>
            {
                trace.step("batch_settle.validation", 0);
                return json_response_with_cost(
                    400,
                    &settle_error("invalid_config", &message, None),
                    trace,
                );
            }
            Err(_) => {}
        }
    }
    let contract = match configured_batch_settlement_contract() {
        Ok(contract) => contract,
        Err(message) => {
            trace.step("batch_settle.config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, None),
                trace,
            );
        }
    };
    let current = batch_settle_current_channel(&payload);
    let verified = match validate_batch_settle_request(&body, current.as_ref(), &contract) {
        Ok(value) => value,
        Err(message) => {
            trace.step("batch_settle.validation", 0);
            return json_response_with_cost(
                402,
                &settle_error("invalid_batch_settlement", &message, None),
                trace,
            );
        }
    };
    trace.step("batch_settle.validation", 0);
    let payer = verified.payer.clone();
    let key = match batch_settlement_key(&body) {
        Ok(key) => key,
        Err(message) => {
            trace.step("batch_settle.key", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.key", 0);
    let expectation = match batch_contract_expectation(&payload, &contract) {
        Ok(expectation) => expectation,
        Err(message) => {
            trace.step("batch_settle.expectation", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.expectation", 0);
    purge_expired_settlements(now_seconds());
    if let Some(existing) = get_settlement(&key) {
        return cached_batch_settlement_response(
            &key,
            existing,
            &payload,
            &body.payment_requirements,
            &contract,
            &expectation,
            trace,
        )
        .await;
    }
    if let Err(message) = require_batch_settlement_enabled_except_fee().map(|_| ()) {
        trace.step("batch_settle.config", 0);
        return json_response_with_cost(
            400,
            &settle_error("invalid_config", &message, payer),
            trace,
        );
    }
    if let Err(error) = validate_batch_receiver_authorizer_config(&payload, &contract) {
        trace.step("batch_settle.authorizer_config", 0);
        let (status, reason, message) = match error {
            BatchAuthorizerValidationError::InvalidConfig(message) => {
                (400, "invalid_config", message)
            }
            BatchAuthorizerValidationError::InvalidSettlement(message) => {
                (402, "invalid_batch_settlement", message)
            }
        };
        return json_response_with_cost(status, &settle_error(reason, &message, payer), trace);
    }
    trace.step("batch_settle.authorizer_config", 0);
    let private_key = match env("FACILITATOR_EVM_PRIVATE_KEY") {
        Ok(value) => value,
        Err(message) => {
            trace.step("batch_settle.config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, payer),
                trace,
            );
        }
    };
    let from = match private_key_address(&private_key) {
        Ok(value) => value,
        Err(message) => {
            trace.step("batch_settle.config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.config", 0);
    let active_scope = match active_settlement_scope(&from, &verified.receiver) {
        Ok(value) => value,
        Err(message) => {
            trace.step("batch_settle.active_scope", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.active_scope", 0);
    if !acquire_active_settlement(&active_scope, &key) {
        trace.step("batch_settle.active_lock", 0);
        return json_response_with_cost(
            429,
            &settle_error(
                "settlement_queue_busy",
                "another settlement is active for this seller",
                payer,
            ),
            trace,
        );
    }
    trace.step("batch_settle.active_lock", 0);
    let fee = match required_positive_u128("BATCH_SETTLEMENT_FEE_AMOUNT") {
        Ok(value) => value,
        Err(message) => {
            release_active_settlement(&active_scope, &key);
            trace.step("batch_settle.fee_config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.fee_config", 0);
    if let Err(message) = reserve_seller_credit(&verified.receiver, fee) {
        release_active_settlement(&active_scope, &key);
        trace.step("batch_settle.reserve_seller_credit", 0);
        return json_response_with_cost(
            402,
            &settle_error("seller_insufficient_credit", &message, payer),
            trace,
        );
    }
    trace.step("batch_settle.reserve_seller_credit", 0);
    let ttl = match settlement_cache_ttl_seconds() {
        Ok(ttl) => ttl,
        Err(message) => {
            refund_seller_credit(&verified.receiver, fee);
            release_active_settlement(&active_scope, &key);
            trace.step("batch_settle.ttl", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.ttl", 0);
    let calldata = match batch_calldata(&payload, &contract) {
        Ok(calldata) => calldata,
        Err(message) => {
            refund_seller_credit(&verified.receiver, fee);
            release_active_settlement(&active_scope, &key);
            trace.step("batch_settle.calldata", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_request", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.calldata", 0);
    insert_settlement(
        &key,
        SettlementRecord::checking(
            payer.clone().unwrap_or_else(|| verified.receiver.clone()),
            verified.receiver.clone(),
            body.payment_requirements.amount.clone(),
            now_seconds(),
            ttl,
        ),
    );
    let config = match rpc_config() {
        Ok(config) => config,
        Err(message) => {
            remove_settlement(&key);
            refund_seller_credit(&verified.receiver, fee);
            release_active_settlement(&active_scope, &key);
            trace.step("batch_settle.rpc_config", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.rpc_config", 0);
    let rpc_nonce = match pending_nonce(&config, &from).await {
        Ok(nonce) => nonce,
        Err(message) => {
            remove_settlement(&key);
            refund_seller_credit(&verified.receiver, fee);
            release_active_settlement(&active_scope, &key);
            trace.step("batch_settle.pending_nonce", 1);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, payer),
                trace,
            );
        }
    };
    trace.step("batch_settle.pending_nonce", 1);
    let nonce = reserve_nonce(&from, rpc_nonce);
    let to = match parse_address(&contract, "BATCH_SETTLEMENT_CONTRACT") {
        Ok(to) => to,
        Err(message) => {
            remove_settlement(&key);
            rollback_reserved_nonce(&from, nonce);
            refund_seller_credit(&verified.receiver, fee);
            release_active_settlement(&active_scope, &key);
            trace.step("batch_settle.contract", 0);
            return json_response_with_cost(
                400,
                &settle_error("invalid_config", &message, payer),
                trace,
            );
        }
    };
    let pre_refund_snapshot = if payload.kind == "refund" {
        batch_payload_snapshot(&payload, Some((&config, &to))).await
    } else {
        None
    };
    match send_contract_transaction(&config, &private_key, to, calldata, nonce, &expectation).await
    {
        Ok(SettlementOutcome::Settled(tx)) => {
            trace.step("batch_settle.send", 5);
            if tx.is_empty() {
                rollback_reserved_nonce(&from, nonce);
                refund_seller_credit(&verified.receiver, fee);
            }
            let record = batch_settled_record(BatchSettleRecordInput {
                tx,
                payload: &payload,
                requirements: &body.payment_requirements,
                payer: payer.clone(),
                receiver: verified.receiver,
                now: now_seconds(),
                ttl,
                rpc: Some((&config, &to)),
                pre_refund_snapshot: pre_refund_snapshot.as_ref(),
            })
            .await;
            let record = insert_settlement(&key, record);
            release_active_settlement(&active_scope, &key);
            json_response_with_cost(record.status_code(), &record.response, trace)
        }
        Ok(SettlementOutcome::Pending { nonce, tx }) => {
            trace.step("batch_settle.send", 5);
            update_active_broadcast(&active_scope, &key, nonce, &tx);
            let record = SettlementRecord::broadcast(
                tx,
                payer.unwrap_or_else(|| verified.receiver.clone()),
                verified.receiver,
                body.payment_requirements.amount,
                now_seconds(),
                ttl,
            )
            .with_batch_pre_refund_snapshot(pre_refund_snapshot.as_ref());
            let record = insert_settlement(&key, record);
            json_response_with_cost(202, &record.response, trace)
        }
        Ok(SettlementOutcome::Failed { tx, message }) => {
            trace.step("batch_settle.send", 5);
            let record = SettlementRecord::failed(
                tx,
                message,
                payer.unwrap_or_else(|| verified.receiver.clone()),
                verified.receiver,
                now_seconds(),
                ttl,
            );
            let record = insert_settlement(&key, record);
            release_active_settlement(&active_scope, &key);
            json_response_with_cost(502, &record.response, trace)
        }
        Err(SettlementSendError::GasTooExpensive) => {
            trace.step("batch_settle.send", 2);
            remove_settlement(&key);
            rollback_reserved_nonce(&from, nonce);
            refund_seller_credit(&verified.receiver, fee);
            release_active_settlement(&active_scope, &key);
            json_response_with_cost(
                503,
                &settle_error("gas_too_expensive", GAS_TOO_EXPENSIVE_MESSAGE, payer),
                trace,
            )
        }
        Err(SettlementSendError::Other(message)) => {
            trace.step("batch_settle.send", 5);
            remove_settlement(&key);
            rollback_reserved_nonce(&from, nonce);
            refund_seller_credit(&verified.receiver, fee);
            release_active_settlement(&active_scope, &key);
            json_response_with_cost(
                502,
                &settle_error("settlement_failed", &message, payer),
                trace,
            )
        }
    }
}

fn batch_settle_current_channel(
    payload: &crate::batch::BatchRequestPayload,
) -> Option<BatchChannel> {
    match payload.kind.as_str() {
        "deposit" | "voucher" | "refund" => {
            voucher_channel_id(payload).ok().and_then(get_batch_channel)
        }
        _ => None,
    }
}

enum BatchAuthorizerValidationError {
    InvalidConfig(String),
    InvalidSettlement(String),
}

fn validate_batch_receiver_authorizer_config(
    payload: &crate::batch::BatchRequestPayload,
    contract: &str,
) -> Result<(), BatchAuthorizerValidationError> {
    match payload.kind.as_str() {
        "claim" => {
            let claims = payload.claims.as_deref().unwrap_or_default();
            if claims.is_empty() {
                return Ok(());
            }
            let expected = &claims[0].voucher.channel.receiver_authorizer;
            validate_batch_claim_authorizer(
                claims,
                payload.claim_authorizer_signature.as_deref(),
                expected,
                contract,
            )
        }
        "refund" => {
            let Some(config) = payload.channel_config.as_ref() else {
                return Ok(());
            };
            let Some(amount) = payload.amount.as_deref() else {
                return Ok(());
            };
            let Some(nonce) = payload.refund_nonce.as_deref() else {
                return Ok(());
            };
            validate_batch_refund_authorizer(
                config,
                amount,
                nonce,
                payload.refund_authorizer_signature.as_deref(),
                contract,
            )?;
            let claims = payload.claims.as_deref().unwrap_or_default();
            if claims.is_empty() {
                return Ok(());
            }
            validate_batch_claim_authorizer(
                claims,
                payload.claim_authorizer_signature.as_deref(),
                &config.receiver_authorizer,
                contract,
            )
        }
        _ => Ok(()),
    }
}

fn validate_batch_claim_authorizer(
    claims: &[crate::batch::BatchVoucherClaim],
    signature: Option<&str>,
    expected_authorizer: &str,
    contract: &str,
) -> Result<(), BatchAuthorizerValidationError> {
    if let Some(signature) = signature {
        let recovered = recover_batch_claim_authorizer(claims, signature, contract)
            .map_err(BatchAuthorizerValidationError::InvalidSettlement)?;
        if !same_address(&recovered, expected_authorizer) {
            return Err(BatchAuthorizerValidationError::InvalidSettlement(
                "batch claim authorizer signature mismatch".to_string(),
            ));
        }
        return Ok(());
    }
    validate_local_batch_receiver_authorizer(expected_authorizer)
}

fn validate_batch_refund_authorizer(
    config: &crate::batch::BatchChannelConfig,
    amount: &str,
    nonce: &str,
    signature: Option<&str>,
    contract: &str,
) -> Result<(), BatchAuthorizerValidationError> {
    if let Some(signature) = signature {
        let channel_id = compute_batch_channel_id(config, contract)
            .map_err(BatchAuthorizerValidationError::InvalidSettlement)?;
        let recovered =
            recover_batch_refund_authorizer(&channel_id, amount, nonce, signature, contract)
                .map_err(BatchAuthorizerValidationError::InvalidSettlement)?;
        if !same_address(&recovered, &config.receiver_authorizer) {
            return Err(BatchAuthorizerValidationError::InvalidSettlement(
                "batch refund authorizer signature mismatch".to_string(),
            ));
        }
        return Ok(());
    }
    validate_local_batch_receiver_authorizer(&config.receiver_authorizer)
}

fn validate_local_batch_receiver_authorizer(
    expected_authorizer: &str,
) -> Result<(), BatchAuthorizerValidationError> {
    let local = batch_receiver_authorizer_address()
        .map_err(BatchAuthorizerValidationError::InvalidConfig)?;
    if !same_address(&local, expected_authorizer) {
        return Err(BatchAuthorizerValidationError::InvalidConfig(
            "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY does not match receiverAuthorizer".to_string(),
        ));
    }
    Ok(())
}

fn batch_corrective_verify_extra(
    current: Option<&BatchChannel>,
    message: &str,
) -> Option<serde_json::Value> {
    if message != "invalid_batch_settlement_evm_cumulative_amount_mismatch" {
        return None;
    }
    let channel = current?;
    serde_json::to_value(SettleResponseExtra {
        settlement_key: None,
        charged_amount: None,
        channel_state: Some(SettleChannelStateExtra {
            channel_id: channel.channel_id.clone(),
            balance: channel.balance.clone(),
            total_claimed: channel.total_claimed.clone(),
            withdraw_requested_at: channel.withdraw_requested_at,
            refund_nonce: channel.refund_nonce.clone(),
            charged_cumulative_amount: Some(channel.charged_cumulative_amount.clone()),
        }),
        voucher_state: Some(SettleVoucherStateExtra {
            signed_max_claimable: Some(channel.signed_max_claimable.clone()),
            signature: Some(channel.signature.clone()),
        }),
    })
    .ok()
}

fn batch_channel_payer(channel: &BatchChannel) -> Option<String> {
    parse_address(&channel.channel_config.payer, "payer")
        .ok()
        .map(|address| address_hex(&address))
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

async fn cached_batch_settlement_response(
    key: &str,
    existing: SettlementRecord,
    payload: &crate::batch::BatchRequestPayload,
    requirements: &PaymentRequirements,
    contract: &str,
    expectation: &ContractExpectation,
    trace: &mut CostTrace,
) -> HttpResponse {
    let Some(details) = existing.broadcast_settlement() else {
        trace.step("batch_settle.cache_hit", 0);
        return json_response_with_cost(existing.status_code(), &existing.response, trace);
    };
    let config = match rpc_config() {
        Ok(config) => config,
        Err(_) => {
            trace.step("batch_settle.cache_config", 0);
            return json_response_with_cost(existing.status_code(), &existing.response, trace);
        }
    };
    trace.step("batch_settle.cache_config", 0);
    let to = match parse_address(contract, "BATCH_SETTLEMENT_CONTRACT") {
        Ok(to) => to,
        Err(_) => {
            trace.step("batch_settle.cache_contract", 0);
            return json_response_with_cost(existing.status_code(), &existing.response, trace);
        }
    };
    trace.step("batch_settle.cache_contract", 0);
    let expected_from = env("FACILITATOR_EVM_PRIVATE_KEY")
        .ok()
        .and_then(|key| private_key_address(&key).ok());
    let refreshed = match refresh_contract_settlement(
        &config,
        &details.tx,
        &to,
        expected_from.as_deref(),
        expectation,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(message) => {
            trace.step("batch_settle.refresh", 2);
            return json_response_with_cost(
                502,
                &settle_error("rpc_error", &message, Some(details.payer)),
                trace,
            );
        }
    };
    trace.step("batch_settle.refresh", 2);
    let ttl = match settlement_cache_ttl_seconds() {
        Ok(ttl) => ttl,
        Err(_) => {
            trace.step("batch_settle.cache_ttl", 0);
            return json_response_with_cost(existing.status_code(), &existing.response, trace);
        }
    };
    trace.step("batch_settle.cache_ttl", 0);
    match refreshed {
        SettlementOutcome::Settled(tx) => {
            let record = batch_settled_record(BatchSettleRecordInput {
                tx,
                payload,
                requirements,
                payer: Some(details.payer.clone()),
                receiver: details.pay_to.clone(),
                now: now_seconds(),
                ttl,
                rpc: Some((&config, &to)),
                pre_refund_snapshot: details.batch_pre_refund_snapshot.as_ref(),
            })
            .await;
            let record = insert_settlement(key, record);
            release_active_settlement_by_key(key);
            json_response_with_cost(record.status_code(), &record.response, trace)
        }
        SettlementOutcome::Pending { .. } => {
            json_response_with_cost(existing.status_code(), &existing.response, trace)
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

#[cfg(test)]
fn parse_request(request: &HttpRequest) -> Result<FacilitatorRequest, String> {
    serde_json::from_value(parse_json_value(request)?)
        .map_err(|err| format!("invalid JSON body: {err}"))
}

fn parse_json_value(request: &HttpRequest) -> Result<serde_json::Value, String> {
    if request.body.len() > MAX_REQUEST_BODY_BYTES {
        return Err("request body exceeds 64KiB".to_string());
    }
    serde_json::from_slice(&request.body).map_err(|err| format!("invalid JSON body: {err}"))
}

fn batch_settlement_key(body: &BatchFacilitatorRequest) -> Result<String, String> {
    let identity = serde_json::json!({
        "network": body.payment_requirements.network,
        "asset": body.payment_requirements.asset.to_ascii_lowercase(),
        "payTo": body.payment_requirements.pay_to.to_ascii_lowercase(),
        "payload": body.payment_payload.payload
    });
    let bytes = serde_json::to_vec(&identity).map_err(|err| format!("invalid batch key: {err}"))?;
    Ok(format!(
        "0x{}",
        hex::encode(keccak256(
            format!("batch|{}", hex::encode(bytes)).as_bytes()
        ))
    ))
}

fn batch_calldata(
    payload: &crate::batch::BatchRequestPayload,
    contract: &str,
) -> Result<Vec<u8>, String> {
    match payload.kind.as_str() {
        "deposit" => encode_batch_deposit_calldata(payload),
        "claim" => encode_batch_claim_calldata(
            payload,
            &batch_authorizer_private_key_for_claim(payload)?,
            contract,
        ),
        "settle" => encode_batch_settle_calldata(
            payload
                .receiver
                .as_deref()
                .ok_or_else(|| "batch settle receiver is required".to_string())?,
            payload
                .token
                .as_deref()
                .ok_or_else(|| "batch settle token is required".to_string())?,
        ),
        "refund" => encode_batch_refund_calldata(
            payload,
            &batch_authorizer_private_key_for_refund(payload)?,
            contract,
        ),
        other => Err(format!("unsupported batch payload type: {other}")),
    }
}

fn batch_authorizer_private_key_for_claim(
    payload: &crate::batch::BatchRequestPayload,
) -> Result<String, String> {
    if payload.claim_authorizer_signature.is_some() {
        return Ok(String::new());
    }
    env("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")
}

fn batch_authorizer_private_key_for_refund(
    payload: &crate::batch::BatchRequestPayload,
) -> Result<String, String> {
    let needs_refund_signature = payload.refund_authorizer_signature.is_none();
    let needs_claim_signature = payload
        .claims
        .as_deref()
        .is_some_and(|claims| !claims.is_empty())
        && payload.claim_authorizer_signature.is_none();
    if !needs_refund_signature && !needs_claim_signature {
        return Ok(String::new());
    }
    env("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")
}

struct BatchSettleRecordInput<'a> {
    tx: String,
    payload: &'a crate::batch::BatchRequestPayload,
    requirements: &'a PaymentRequirements,
    payer: Option<String>,
    receiver: String,
    now: u64,
    ttl: u64,
    rpc: Option<(&'a RpcConfig, &'a [u8; 20])>,
    pre_refund_snapshot: Option<&'a BatchChannelSnapshot>,
}

async fn batch_settled_record(input: BatchSettleRecordInput<'_>) -> SettlementRecord {
    let tx = input.tx;
    let error_payer = input
        .payer
        .clone()
        .unwrap_or_else(|| input.receiver.clone());
    match batch_success_response(
        tx.clone(),
        input.payload,
        input.requirements,
        input.payer,
        input.rpc,
        input.pre_refund_snapshot,
    )
    .await
    {
        Ok(response) => {
            SettlementRecord::settled_response(response, input.receiver, input.now, input.ttl)
        }
        Err(message) => SettlementRecord::failed(
            tx,
            message,
            error_payer,
            input.receiver,
            input.now,
            input.ttl,
        ),
    }
}

async fn batch_success_response(
    tx: String,
    payload: &crate::batch::BatchRequestPayload,
    requirements: &PaymentRequirements,
    payer: Option<String>,
    rpc: Option<(&RpcConfig, &[u8; 20])>,
    pre_refund_snapshot: Option<&BatchChannelSnapshot>,
) -> Result<SettleResponse, String> {
    let mut response = SettleResponse {
        success: true,
        transaction: tx.clone(),
        network: NETWORK.to_string(),
        payer,
        amount: Some(requirements.amount.clone()),
        error_reason: None,
        error_message: None,
        extra: None,
        extra_json: None,
    };
    match payload.kind.as_str() {
        "deposit" => {
            response.amount = payload
                .deposit
                .as_ref()
                .map(|deposit| deposit.amount.clone());
            response.extra_json = Some(
                batch_deposit_response_extra(payload, requirements, rpc)
                    .await
                    .ok_or_else(|| "batch deposit post-state snapshot unavailable".to_string())?,
            );
        }
        "claim" => {
            response.payer = None;
            response.amount = Some("0".to_string());
            let post = batch_payload_snapshot(payload, rpc).await;
            if batch_claim_requires_response_snapshot(payload) {
                response.extra_json = Some(
                    post.as_ref()
                        .and_then(|snapshot| batch_response_extra_json(snapshot, None, None))
                        .ok_or_else(|| "batch claim post-state snapshot unavailable".to_string())?,
                );
            } else {
                response.extra_json = post
                    .as_ref()
                    .and_then(|snapshot| batch_response_extra_json(snapshot, None, None));
            }
        }
        "settle" => {
            response.payer = None;
            response.amount = if tx.trim().is_empty() {
                Some("0".to_string())
            } else {
                Some(
                    batch_settle_response_amount(&tx, payload, rpc)
                        .await
                        .ok_or_else(|| "batch settle event amount unavailable".to_string())?,
                )
            };
        }
        "refund" => {
            response.payer = payload
                .channel_config
                .as_ref()
                .map(|config| config.payer.clone())
                .or(response.payer);
            let post = batch_payload_snapshot(payload, rpc).await;
            response.amount =
                batch_refund_response_amount(payload, pre_refund_snapshot, post.as_ref());
            response.extra_json = Some(
                post.as_ref()
                    .and_then(|snapshot| batch_response_extra_json(snapshot, None, None))
                    .ok_or_else(|| "batch refund post-state snapshot unavailable".to_string())?,
            );
        }
        _ => {}
    }
    Ok(response)
}

async fn batch_deposit_response_extra(
    payload: &crate::batch::BatchRequestPayload,
    requirements: &PaymentRequirements,
    rpc: Option<(&RpcConfig, &[u8; 20])>,
) -> Option<String> {
    let snapshot = batch_payload_snapshot(payload, rpc).await?;
    batch_response_extra_json(
        &snapshot,
        Some(requirements.amount.clone()),
        batch_deposit_charged_cumulative_amount(payload),
    )
}

fn batch_deposit_charged_cumulative_amount(
    payload: &crate::batch::BatchRequestPayload,
) -> Option<String> {
    if payload.kind != "deposit" {
        return None;
    }
    payload
        .voucher
        .as_ref()
        .map(|voucher| voucher.max_claimable_amount.clone())
}

async fn batch_payload_snapshot(
    payload: &crate::batch::BatchRequestPayload,
    rpc: Option<(&RpcConfig, &[u8; 20])>,
) -> Option<BatchChannelSnapshot> {
    let (config, contract) = rpc?;
    let channel_id = batch_payload_snapshot_channel_id(payload, contract)?;
    batch_channel_snapshot(config, contract, &channel_id)
        .await
        .ok()
}

fn batch_payload_snapshot_channel_id(
    payload: &crate::batch::BatchRequestPayload,
    contract: &[u8; 20],
) -> Option<String> {
    match payload.kind.as_str() {
        "deposit" | "voucher" | "refund" => payload
            .voucher
            .as_ref()
            .map(|voucher| voucher.channel_id.clone()),
        "claim" => {
            let claims = payload.claims.as_ref()?;
            if claims.len() != 1 {
                return None;
            }
            compute_batch_channel_id(&claims[0].voucher.channel, &address_hex(contract)).ok()
        }
        _ => None,
    }
}

fn batch_claim_requires_response_snapshot(payload: &crate::batch::BatchRequestPayload) -> bool {
    payload.kind == "claim"
        && payload
            .claims
            .as_ref()
            .is_some_and(|claims| claims.len() == 1)
}

async fn batch_settle_response_amount(
    tx: &str,
    payload: &crate::batch::BatchRequestPayload,
    rpc: Option<(&RpcConfig, &[u8; 20])>,
) -> Option<String> {
    let (config, contract) = rpc?;
    let receiver = payload.receiver.as_deref()?;
    let token = payload.token.as_deref()?;
    verified_batch_settle_amount(batch_settled_amount(config, tx, contract, receiver, token).await)
}

fn verified_batch_settle_amount(result: Result<String, String>) -> Option<String> {
    result.ok()
}

fn batch_refund_response_amount(
    _payload: &crate::batch::BatchRequestPayload,
    pre: Option<&BatchChannelSnapshot>,
    post: Option<&BatchChannelSnapshot>,
) -> Option<String> {
    if let (Some(pre), Some(post)) = (pre, post) {
        return decimal_sub_floor(&pre.balance, &post.balance);
    }
    None
}

fn validate_batch_verify_snapshot(
    payload: &crate::batch::BatchRequestPayload,
    snapshot: &BatchChannelSnapshot,
) -> Result<(), String> {
    let max_claimable = payload
        .voucher
        .as_ref()
        .map(|voucher| parse_batch_decimal("maxClaimableAmount", &voucher.max_claimable_amount))
        .transpose()?
        .ok_or_else(|| "batch voucher is required".to_string())?;
    let balance = parse_batch_decimal("balance", &snapshot.balance)?;
    let total_claimed = parse_batch_decimal("totalClaimed", &snapshot.total_claimed)?;

    match payload.kind.as_str() {
        "deposit" => {
            let deposit_amount = payload
                .deposit
                .as_ref()
                .map(|deposit| parse_batch_decimal("deposit.amount", &deposit.amount))
                .transpose()?
                .ok_or_else(|| "batch deposit payload is required".to_string())?;
            let effective_balance = balance
                .checked_add(deposit_amount)
                .ok_or_else(|| "batch deposit effective balance overflow".to_string())?;
            if max_claimable > effective_balance {
                return Err("invalid_batch_settlement_evm_cumulative_exceeds_balance".to_string());
            }
            if max_claimable <= total_claimed {
                return Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string());
            }
        }
        "voucher" => {
            if balance == 0 {
                return Err("invalid_batch_settlement_evm_channel_not_found".to_string());
            }
            if max_claimable > balance {
                return Err("invalid_batch_settlement_evm_cumulative_exceeds_balance".to_string());
            }
            if max_claimable <= total_claimed {
                return Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string());
            }
        }
        "refund" => {
            if balance == 0 {
                return Err("invalid_batch_settlement_evm_channel_not_found".to_string());
            }
            if max_claimable < total_claimed {
                return Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string());
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_batch_verify_pending(
    payload: &crate::batch::BatchRequestPayload,
    channel: &BatchChannel,
) -> Result<(), String> {
    let pending = channel
        .pending_request
        .as_ref()
        .ok_or_else(|| "invalid_batch_settlement_evm_channel_not_reserved".to_string())?;
    let expires_at = pending.expires_at;
    if expires_at <= now_seconds().saturating_mul(1_000) {
        return Err("invalid_batch_settlement_evm_channel_not_reserved".to_string());
    }
    let pending_signed =
        parse_batch_decimal("pending.signedMaxClaimable", &pending.signed_max_claimable)?;
    let max_claimable = payload
        .voucher
        .as_ref()
        .map(|voucher| parse_batch_decimal("maxClaimableAmount", &voucher.max_claimable_amount))
        .transpose()?
        .ok_or_else(|| "batch voucher is required".to_string())?;
    if pending_signed != max_claimable {
        return Err("invalid_batch_settlement_evm_pending_voucher_mismatch".to_string());
    }
    Ok(())
}

fn parse_batch_decimal(label: &str, value: &str) -> Result<u128, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label}: invalid decimal integer"));
    }
    value
        .parse::<u128>()
        .map_err(|_| format!("{label}: integer too large"))
}

fn batch_response_extra_json(
    snapshot: &BatchChannelSnapshot,
    charged_amount: Option<String>,
    charged_cumulative_amount: Option<String>,
) -> Option<String> {
    let extra = SettleResponseExtra {
        settlement_key: None,
        charged_amount,
        channel_state: Some(SettleChannelStateExtra {
            channel_id: snapshot.channel_id.clone(),
            balance: snapshot.balance.clone(),
            total_claimed: snapshot.total_claimed.clone(),
            withdraw_requested_at: snapshot.withdraw_requested_at,
            refund_nonce: snapshot.refund_nonce.clone(),
            charged_cumulative_amount,
        }),
        voucher_state: None,
    };
    serde_json::to_string(&extra).ok()
}

fn decimal_sub_floor(left: &str, right: &str) -> Option<String> {
    let left = left.parse::<u128>().ok()?;
    let right = right.parse::<u128>().ok()?;
    Some(left.saturating_sub(right).to_string())
}

fn batch_contract_expectation(
    payload: &crate::batch::BatchRequestPayload,
    contract: &str,
) -> Result<ContractExpectation, String> {
    match payload.kind.as_str() {
        "deposit" => {
            let config = payload
                .channel_config
                .as_ref()
                .ok_or_else(|| "batch deposit channelConfig is required".to_string())?;
            let channel_id = match &payload.voucher {
                Some(voucher) => voucher.channel_id.clone(),
                None => compute_batch_channel_id(config, contract)?,
            };
            validate_channel_id(&channel_id)?;
            let min_balance = payload
                .deposit
                .as_ref()
                .map(|deposit| deposit.amount.clone())
                .ok_or_else(|| "batch deposit payload is required".to_string())?;
            let max_claimable_amount = payload
                .voucher
                .as_ref()
                .map(|voucher| voucher.max_claimable_amount.clone())
                .ok_or_else(|| "batch voucher is required".to_string())?;
            Ok(ContractExpectation::Deposit {
                channel_id,
                payer: config.payer.clone(),
                token: config.token.clone(),
                deposit_amount: min_balance.clone(),
                max_claimable_amount,
                min_balance,
            })
        }
        "claim" => Ok(ContractExpectation::Claim {
            claims: expected_claim_states(payload.claims.as_deref(), contract)?,
        }),
        "settle" => Ok(ContractExpectation::Settle {
            receiver: payload
                .receiver
                .clone()
                .ok_or_else(|| "batch settle receiver is required".to_string())?,
            token: payload
                .token
                .clone()
                .ok_or_else(|| "batch settle token is required".to_string())?,
            expected_amount: None,
            min_total_settled: None,
        }),
        "refund" => {
            let config = payload
                .channel_config
                .as_ref()
                .ok_or_else(|| "batch refund channelConfig is required".to_string())?;
            let channel_id = compute_batch_channel_id(config, contract)?;
            let nonce = payload
                .refund_nonce
                .as_deref()
                .ok_or_else(|| "batch refund nonce is required".to_string())?;
            Ok(ContractExpectation::Refund {
                channel_id,
                refund_nonce: nonce.to_string(),
                min_refund_nonce: increment_decimal(nonce)?,
                claims: expected_claim_states(payload.claims.as_deref(), contract)?,
            })
        }
        other => Err(format!("unsupported batch payload type: {other}")),
    }
}

fn expected_claim_states(
    claims: Option<&[crate::batch::BatchVoucherClaim]>,
    contract: &str,
) -> Result<Vec<ExpectedClaimState>, String> {
    claims
        .unwrap_or_default()
        .iter()
        .map(|claim| {
            Ok(ExpectedClaimState {
                channel_id: compute_batch_channel_id(&claim.voucher.channel, contract)?,
                min_total_claimed: claim.total_claimed.clone(),
            })
        })
        .collect()
}

fn increment_decimal(value: &str) -> Result<String, String> {
    parse_u256_decimal(value, "batch refund nonce").map_err(|message| {
        if message.contains("invalid decimal integer") {
            "batch refund nonce must be a decimal integer".to_string()
        } else {
            "batch refund nonce overflow".to_string()
        }
    })?;
    let incremented = decimal_string_add_one(value)?;
    parse_u256_decimal(&incremented, "batch refund nonce")
        .map_err(|_| "batch refund nonce overflow".to_string())?;
    Ok(incremented)
}

fn decimal_string_add_one(value: &str) -> Result<String, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("batch refund nonce must be a decimal integer".to_string());
    }
    let mut out = value.as_bytes().to_vec();
    let mut index = out.len();
    while index > 0 {
        index -= 1;
        if out[index] == b'9' {
            out[index] = b'0';
        } else {
            out[index] += 1;
            return String::from_utf8(out).map_err(|_| "batch refund nonce overflow".to_string());
        }
    }
    out.insert(0, b'1');
    String::from_utf8(out).map_err(|_| "batch refund nonce overflow".to_string())
}

fn verify_error(reason: &str, message: &str, payer: Option<String>) -> VerifyResponse {
    VerifyResponse {
        is_valid: false,
        invalid_reason: Some(reason.to_string()),
        invalid_message: Some(message.to_string()),
        payer,
        extra: None,
    }
}

fn configured_batch_settlement_contract() -> Result<String, String> {
    let value = env("BATCH_SETTLEMENT_CONTRACT")?;
    let normalized = normalize_evm_address("BATCH_SETTLEMENT_CONTRACT", &value)?;
    if !same_address(&normalized, CANONICAL_BATCH_SETTLEMENT_CONTRACT) {
        return Err(format!(
            "BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS {CANONICAL_BATCH_SETTLEMENT_CONTRACT}"
        ));
    }
    Ok(normalized)
}

fn batch_receiver_authorizer_address() -> Result<String, String> {
    env("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY").and_then(|key| private_key_address(&key))
}

fn validate_batch_key_separation(receiver_authorizer: &str) -> Result<(), String> {
    let facilitator =
        env("FACILITATOR_EVM_PRIVATE_KEY").and_then(|key| private_key_address(&key))?;
    if same_address(receiver_authorizer, &facilitator) {
        return Err(
            "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address"
                .to_string(),
        );
    }
    Ok(())
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

#[query]
fn batch_channel(channel_id: String) -> Option<BatchChannel> {
    validate_channel_id(&channel_id)
        .map(|_| channel_id.to_ascii_lowercase())
        .ok()
        .and_then(|key| get_batch_channel(&key))
}

#[query]
fn batch_channel_count() -> u64 {
    BATCH_CHANNELS.with(|items| items.borrow().len())
}

#[query]
fn batch_deleted_channel(channel_id: String) -> Option<BatchDeletedChannel> {
    validate_channel_id(&channel_id)
        .map(|_| channel_id.to_ascii_lowercase())
        .ok()
        .and_then(|key| get_batch_deleted_channel(&key))
}

#[query]
fn batch_deleted_channel_count() -> u64 {
    BATCH_DELETED_CHANNELS.with(|items| items.borrow().len())
}

#[query]
fn batch_channel_storage_writer() -> Option<Principal> {
    batch_channel_storage_writer_principal().ok().flatten()
}

#[query]
fn batch_receiver_authorizer() -> Option<String> {
    batch_receiver_authorizer_address().ok()
}

#[query]
fn batch_settlement_contract() -> Option<String> {
    configured_batch_settlement_contract()
        .ok()
        .and_then(|value| normalize_evm_address("BATCH_SETTLEMENT_CONTRACT", &value).ok())
}

#[query]
fn batch_settlement_fee_amount() -> Option<String> {
    required_positive_u128("BATCH_SETTLEMENT_FEE_AMOUNT")
        .ok()
        .map(|value| value.to_string())
}

#[query]
fn batch_channels(limit: Option<u64>) -> Vec<BatchChannel> {
    let limit = limit
        .map(|value| value.min(MAX_BATCH_CHANNELS_LIST as u64) as usize)
        .unwrap_or(MAX_BATCH_CHANNELS_LIST);
    BATCH_CHANNELS.with(|items| {
        items
            .borrow()
            .iter()
            .take(limit)
            .map(|entry| decode_stable::<BatchChannel>(entry.value()))
            .collect()
    })
}

#[query]
fn batch_deleted_channels(limit: Option<u64>) -> Vec<BatchDeletedChannel> {
    let limit = limit
        .map(|value| value.min(MAX_BATCH_CHANNELS_LIST as u64) as usize)
        .unwrap_or(MAX_BATCH_CHANNELS_LIST);
    BATCH_DELETED_CHANNELS.with(|items| {
        items
            .borrow()
            .iter()
            .take(limit)
            .map(|entry| decode_stable::<BatchDeletedChannel>(entry.value()))
            .collect()
    })
}

#[update(guard = "require_batch_channel_storage_writer")]
fn batch_update_channel(
    channel_id: String,
    expected_revision: Option<u64>,
    update: BatchChannelUpdate,
) -> BatchChannelUpdateResult {
    if let Err(message) = validate_channel_id(&channel_id) {
        return BatchChannelUpdateResult {
            status: "invalid".to_string(),
            channel: None,
            current_revision: None,
            message: Some(message),
        };
    }
    let key = channel_id.to_ascii_lowercase();
    let current = get_batch_channel(&key);
    let current_revision = current.as_ref().map(|channel| channel.revision);
    if expected_revision != current_revision {
        return BatchChannelUpdateResult {
            status: "conflict".to_string(),
            channel: current,
            current_revision,
            message: Some("batch channel revision mismatch".to_string()),
        };
    }
    match update.channel {
        Some(mut channel) => {
            let contract = match configured_batch_settlement_contract() {
                Ok(contract) => contract,
                Err(message) => {
                    return BatchChannelUpdateResult {
                        status: "invalid".to_string(),
                        channel: current,
                        current_revision,
                        message: Some(message),
                    };
                }
            };
            if let Err(message) = validate_batch_channel(&key, &channel, &contract) {
                return BatchChannelUpdateResult {
                    status: "invalid".to_string(),
                    channel: current,
                    current_revision,
                    message: Some(message),
                };
            }
            if let Err(message) = validate_batch_channel_transition(current.as_ref(), &channel) {
                return BatchChannelUpdateResult {
                    status: "invalid".to_string(),
                    channel: current,
                    current_revision,
                    message: Some(message),
                };
            }
            channel.channel_id = key.clone();
            channel.revision = current_revision.unwrap_or(0).saturating_add(1);
            if let Err(message) = put_batch_channel(&key, channel.clone()) {
                return BatchChannelUpdateResult {
                    status: "invalid".to_string(),
                    channel: current,
                    current_revision,
                    message: Some(message),
                };
            }
            BatchChannelUpdateResult {
                status: "updated".to_string(),
                channel: Some(channel.clone()),
                current_revision: Some(channel.revision),
                message: None,
            }
        }
        None => {
            if let Some(channel) = current.as_ref() {
                let now_ms = now_seconds().saturating_mul(1_000);
                if channel
                    .pending_request
                    .as_ref()
                    .is_some_and(|pending| pending.expires_at > now_ms)
                    && !is_pending_only_provisional_channel(channel, now_ms)
                {
                    return BatchChannelUpdateResult {
                        status: "invalid".to_string(),
                        channel: current,
                        current_revision,
                        message: Some(
                            "batch channel delete requires no live pendingRequest".to_string(),
                        ),
                    };
                }
                put_batch_deleted_channel(
                    &key,
                    BatchDeletedChannel {
                        channel: channel.clone(),
                        deleted_at: now_seconds(),
                        deleted_by: batch_channel_update_caller_text(),
                    },
                );
                BATCH_CHANNELS.with(|items| {
                    items.borrow_mut().remove(&key);
                });
            }
            BatchChannelUpdateResult {
                status: if current.is_some() {
                    "deleted".to_string()
                } else {
                    "unchanged".to_string()
                },
                channel: None,
                current_revision: None,
                message: None,
            }
        }
    }
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
    let host = value
        .strip_prefix("https://")
        .ok_or_else(|| "FACILITATOR_PUBLIC_ORIGIN must be an https origin".to_string())?;
    if host.is_empty()
        || host.contains('@')
        || host.contains('/')
        || host.contains('?')
        || host.contains('#')
        || host.chars().any(char::is_whitespace)
    {
        return Err("FACILITATOR_PUBLIC_ORIGIN must be an https origin".to_string());
    }
    if let Some((hostname, port)) = host.rsplit_once(':') {
        if hostname.is_empty()
            || hostname.contains(':')
            || port.is_empty()
            || !port.chars().all(|ch| ch.is_ascii_digit())
        {
            return Err("FACILITATOR_PUBLIC_ORIGIN must be an https origin".to_string());
        }
    }
    Ok(value)
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
    fn public_origin_rejects_userinfo_path_query_fragment_and_trailing_slash() {
        for value in [
            "https://trusted.example@evil.example",
            "https://canister.example.test/path",
            "https://canister.example.test?x=1",
            "https://canister.example.test#x",
            "https://canister.example.test/",
        ] {
            clear_env_values();
            set_env_value("FACILITATOR_PUBLIC_ORIGIN", value);
            assert_eq!(
                public_origin().unwrap_err(),
                "FACILITATOR_PUBLIC_ORIGIN must be an https origin"
            );
        }
    }

    #[test]
    fn public_origin_accepts_https_host_and_port() {
        for value in [
            "https://canister.example.test",
            "https://canister.example.test:443",
        ] {
            clear_env_values();
            set_env_value("FACILITATOR_PUBLIC_ORIGIN", value);
            assert_eq!(public_origin().unwrap(), value);
        }
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
    use crate::batch::DEFAULT_BATCH_SETTLEMENT_CONTRACT;
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

    fn set_default_batch_contract() {
        set_env_value(
            "BATCH_SETTLEMENT_CONTRACT",
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
    }

    fn set_full_batch_config() {
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        set_default_batch_contract();
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value(
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL",
            "ryjl3-tyaaa-aaaaa-aaaba-cai",
        );
    }

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

    fn batch_requirements_json() -> serde_json::Value {
        json!({
            "scheme": BATCH_SCHEME,
            "network": NETWORK,
            "asset": JPYC_POLYGON_ADDRESS,
            "amount": "0",
            "payTo": PAY_TO,
            "maxTimeoutSeconds": 60,
            "extra": {
                "receiverAuthorizer": "0x2000000000000000000000000000000000000402",
                "withdrawDelay": DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS,
                "assetTransferMethod": "eip3009",
                "name": JPYC_EIP712_NAME,
                "version": "1"
            }
        })
    }

    fn batch_settle_json() -> serde_json::Value {
        json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": batch_requirements_json(),
                "payload": {
                    "type": "settle",
                    "receiver": PAY_TO,
                    "token": JPYC_POLYGON_ADDRESS
                }
            },
            "paymentRequirements": batch_requirements_json()
        })
    }

    fn batch_voucher_json(amount: &str, max_claimable: &str) -> serde_json::Value {
        let mut requirements = batch_requirements_json();
        requirements["amount"] = json!(amount);
        let mut channel_config = test_batch_channel_config();
        channel_config.payer = PAYER.to_string();
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let signature = crate::batch::sign_batch_voucher_for_test(
            &channel_id,
            max_claimable,
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": requirements.clone(),
                "resource": { "url": "https://example.test/report" },
                "payload": {
                    "type": "voucher",
                    "channelConfig": channel_config,
                    "voucher": {
                        "channelId": channel_id,
                        "maxClaimableAmount": max_claimable,
                        "signature": signature
                    }
                }
            },
            "paymentRequirements": requirements
        })
    }

    fn batch_claim_json(max_claimable: &str, total_claimed: &str) -> serde_json::Value {
        batch_claim_json_for_receiver_authorizer(max_claimable, total_claimed, None)
    }

    fn batch_claim_json_for_receiver_authorizer(
        max_claimable: &str,
        total_claimed: &str,
        receiver_authorizer: Option<&str>,
    ) -> serde_json::Value {
        let requirements = batch_requirements_json();
        let mut channel_config = test_batch_channel_config();
        channel_config.payer = PAYER.to_string();
        if let Some(receiver_authorizer) = receiver_authorizer {
            channel_config.receiver_authorizer = receiver_authorizer.to_string();
        }
        let mut requirements = requirements;
        requirements["extra"]["receiverAuthorizer"] =
            json!(channel_config.receiver_authorizer.clone());
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let signature = crate::batch::sign_batch_voucher_for_test(
            &channel_id,
            max_claimable,
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": requirements.clone(),
                "payload": {
                    "type": "claim",
                    "claims": [{
                        "voucher": {
                            "channel": channel_config,
                            "maxClaimableAmount": max_claimable
                        },
                        "signature": signature,
                        "totalClaimed": total_claimed
                    }]
                }
            },
            "paymentRequirements": requirements
        })
    }

    fn batch_refund_json(amount: &str, refund_nonce: &str) -> serde_json::Value {
        let mut body = batch_voucher_json("0", "0");
        body["paymentPayload"]["payload"]["type"] = json!("refund");
        body["paymentPayload"]["payload"]["amount"] = json!(amount);
        body["paymentPayload"]["payload"]["refundNonce"] = json!(refund_nonce);
        body
    }

    fn with_minimal_batch_operation_requirements(mut body: serde_json::Value) -> serde_json::Value {
        body["paymentRequirements"]["extra"] = json!({});
        body["paymentPayload"]["accepted"]["extra"] = json!({});
        body
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

    fn batch_settle_request(value: &serde_json::Value) -> HttpRequest {
        HttpRequest {
            method: "POST".to_string(),
            url: "/settle?debugCost=1".to_string(),
            headers: vec![],
            body: serde_json::to_vec(value).unwrap(),
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

    fn test_batch_channel(channel_id: &str, charged: &str) -> BatchChannel {
        test_batch_channel_for_config(channel_id, test_batch_channel_config(), charged)
    }

    fn test_batch_channel_for_config(
        channel_id: &str,
        channel_config: crate::batch::BatchChannelConfig,
        charged: &str,
    ) -> BatchChannel {
        BatchChannel {
            channel_id: channel_id.to_string(),
            channel_config,
            charged_cumulative_amount: charged.to_string(),
            signed_max_claimable: charged.to_string(),
            signature: crate::batch::sign_batch_voucher_for_test(
                channel_id,
                charged,
                PAYER_PRIVATE_KEY,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT,
            ),
            balance: "0".to_string(),
            total_claimed: "0".to_string(),
            withdraw_requested_at: 0,
            refund_nonce: "0".to_string(),
            onchain_synced_at: None,
            last_request_timestamp: 1,
            pending_request: None,
            revision: 0,
        }
    }

    fn test_initial_batch_channel(channel_id: &str, signed_max_claimable: &str) -> BatchChannel {
        test_initial_batch_channel_for_config(
            channel_id,
            test_batch_channel_config(),
            signed_max_claimable,
        )
    }

    fn test_initial_batch_channel_for_config(
        channel_id: &str,
        channel_config: crate::batch::BatchChannelConfig,
        signed_max_claimable: &str,
    ) -> BatchChannel {
        let mut channel = test_batch_channel_for_config(channel_id, channel_config, "0");
        channel.signed_max_claimable = signed_max_claimable.to_string();
        channel.signature = crate::batch::sign_batch_voucher_for_test(
            channel_id,
            signed_max_claimable,
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        channel.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: format!("request-{signed_max_claimable}"),
            signed_max_claimable: signed_max_claimable.to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        channel
    }

    fn test_batch_channel_config() -> crate::batch::BatchChannelConfig {
        crate::batch::BatchChannelConfig {
            payer: PAYER.to_string(),
            payer_authorizer: PAYER.to_string(),
            receiver: PAY_TO.to_string(),
            receiver_authorizer: "0x2000000000000000000000000000000000000402".to_string(),
            token: JPYC_POLYGON_ADDRESS.to_string(),
            withdraw_delay: DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS,
            salt: format!("0x{}", "33".repeat(32)),
        }
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
    fn batch_refund_amount_requires_post_state_delta() {
        let config = test_batch_channel_config();
        let channel_id =
            compute_batch_channel_id(&config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let payload = crate::batch::BatchRequestPayload {
            kind: "refund".to_string(),
            channel_config: Some(config.clone()),
            voucher: None,
            deposit: None,
            amount: Some("1000".to_string()),
            refund_nonce: Some("0".to_string()),
            claims: Some(vec![crate::batch::BatchVoucherClaim {
                voucher: crate::batch::BatchClaimVoucher {
                    channel: config,
                    max_claimable_amount: "700".to_string(),
                },
                signature: format!("0x{}", "11".repeat(65)),
                total_claimed: "700".to_string(),
            }]),
            refund_authorizer_signature: None,
            claim_authorizer_signature: None,
            receiver: None,
            token: None,
        };
        let pre = BatchChannelSnapshot {
            channel_id: channel_id.clone(),
            balance: "900".to_string(),
            total_claimed: "300".to_string(),
            withdraw_requested_at: 0,
            refund_nonce: "0".to_string(),
        };
        let post = BatchChannelSnapshot {
            channel_id,
            balance: "700".to_string(),
            total_claimed: "700".to_string(),
            withdraw_requested_at: 0,
            refund_nonce: "1".to_string(),
        };

        assert_eq!(
            batch_refund_response_amount(&payload, Some(&pre), None),
            None
        );
        assert_eq!(
            batch_refund_response_amount(&payload, Some(&pre), Some(&post)),
            Some("200".to_string())
        );
    }

    #[test]
    fn batch_deposit_response_extra_uses_voucher_cumulative_amount() {
        let channel_id = format!("0x{}", "11".repeat(32));
        let payload = crate::batch::BatchRequestPayload {
            kind: "deposit".to_string(),
            channel_config: None,
            voucher: Some(crate::batch::BatchVoucher {
                channel_id,
                max_claimable_amount: "3900".to_string(),
                signature: format!("0x{}", "11".repeat(65)),
            }),
            deposit: None,
            amount: None,
            refund_nonce: None,
            claims: None,
            refund_authorizer_signature: None,
            claim_authorizer_signature: None,
            receiver: None,
            token: None,
        };

        assert_eq!(
            batch_deposit_charged_cumulative_amount(&payload),
            Some("3900".to_string())
        );

        let mut voucher = payload;
        voucher.kind = "voucher".to_string();
        assert_eq!(batch_deposit_charged_cumulative_amount(&voucher), None);
    }

    #[test]
    fn batch_deposit_and_refund_success_response_require_post_state_snapshot() {
        let channel_id = format!("0x{}", "11".repeat(32));
        let mut payload = crate::batch::BatchRequestPayload {
            kind: "deposit".to_string(),
            channel_config: Some(test_batch_channel_config()),
            voucher: Some(crate::batch::BatchVoucher {
                channel_id,
                max_claimable_amount: "3900".to_string(),
                signature: format!("0x{}", "11".repeat(65)),
            }),
            deposit: None,
            amount: Some("100".to_string()),
            refund_nonce: Some("0".to_string()),
            claims: None,
            refund_authorizer_signature: None,
            claim_authorizer_signature: None,
            receiver: None,
            token: None,
        };
        let requirements: PaymentRequirements =
            serde_json::from_value(batch_requirements_json()).unwrap();

        assert_eq!(
            run_ready(batch_success_response(
                "0xtx".to_string(),
                &payload,
                &requirements,
                Some(PAYER.to_string()),
                None,
                None,
            ))
            .unwrap_err(),
            "batch deposit post-state snapshot unavailable"
        );

        payload.kind = "refund".to_string();
        assert_eq!(
            run_ready(batch_success_response(
                "0xtx".to_string(),
                &payload,
                &requirements,
                Some(PAYER.to_string()),
                None,
                None,
            ))
            .unwrap_err(),
            "batch refund post-state snapshot unavailable"
        );
    }

    #[test]
    fn batch_settled_record_uses_failed_status_when_success_evidence_is_missing() {
        let payload = crate::batch::BatchRequestPayload {
            kind: "deposit".to_string(),
            channel_config: Some(test_batch_channel_config()),
            voucher: Some(crate::batch::BatchVoucher {
                channel_id: format!("0x{}", "11".repeat(32)),
                max_claimable_amount: "3900".to_string(),
                signature: format!("0x{}", "11".repeat(65)),
            }),
            deposit: None,
            amount: Some("100".to_string()),
            refund_nonce: Some("0".to_string()),
            claims: None,
            refund_authorizer_signature: None,
            claim_authorizer_signature: None,
            receiver: None,
            token: None,
        };
        let requirements: PaymentRequirements =
            serde_json::from_value(batch_requirements_json()).unwrap();

        let record = run_ready(batch_settled_record(BatchSettleRecordInput {
            tx: "0xtx".to_string(),
            payload: &payload,
            requirements: &requirements,
            payer: Some(PAYER.to_string()),
            receiver: PAY_TO.to_string(),
            now: 1,
            ttl: 60,
            rpc: None,
            pre_refund_snapshot: None,
        }));

        assert_eq!(record.status_code(), 502);
        assert!(!record.response.success);
        assert_eq!(
            record.response.error_message,
            Some("batch deposit post-state snapshot unavailable".to_string())
        );
    }

    #[test]
    fn batch_settle_noop_success_response_returns_zero_without_tx() {
        let payload = crate::batch::BatchRequestPayload {
            kind: "settle".to_string(),
            channel_config: None,
            voucher: None,
            deposit: None,
            amount: None,
            refund_nonce: None,
            claims: None,
            refund_authorizer_signature: None,
            claim_authorizer_signature: None,
            receiver: Some(PAY_TO.to_string()),
            token: Some(JPYC_POLYGON_ADDRESS.to_string()),
        };
        let mut requirements_json = batch_requirements_json();
        requirements_json["amount"] = serde_json::json!("0");
        requirements_json["maxTimeoutSeconds"] = serde_json::json!(0);
        requirements_json["extra"] = serde_json::json!({});
        let requirements: PaymentRequirements = serde_json::from_value(requirements_json).unwrap();

        let response = run_ready(batch_success_response(
            String::new(),
            &payload,
            &requirements,
            None,
            None,
            None,
        ))
        .unwrap();

        assert!(response.success);
        assert_eq!(response.transaction, "");
        assert_eq!(response.payer, None);
        assert_eq!(response.amount, Some("0".to_string()));

        assert_eq!(
            run_ready(batch_success_response(
                "0xtx".to_string(),
                &payload,
                &requirements,
                None,
                None,
                None,
            ))
            .unwrap_err(),
            "batch settle event amount unavailable"
        );
    }

    #[test]
    fn batch_claim_response_snapshot_is_limited_to_single_channel() {
        let contract = parse_address(
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
            "BATCH_SETTLEMENT_CONTRACT",
        )
        .unwrap();
        let config = test_batch_channel_config();
        let channel_id =
            compute_batch_channel_id(&config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let claim = crate::batch::BatchVoucherClaim {
            voucher: crate::batch::BatchClaimVoucher {
                channel: config.clone(),
                max_claimable_amount: "100".to_string(),
            },
            signature: format!("0x{}", "11".repeat(65)),
            total_claimed: "100".to_string(),
        };
        let payload = crate::batch::BatchRequestPayload {
            kind: "claim".to_string(),
            channel_config: None,
            voucher: None,
            deposit: None,
            amount: None,
            refund_nonce: None,
            claims: Some(vec![claim.clone()]),
            refund_authorizer_signature: None,
            claim_authorizer_signature: None,
            receiver: None,
            token: None,
        };

        assert_eq!(
            batch_payload_snapshot_channel_id(&payload, &contract),
            Some(channel_id)
        );
        assert!(batch_claim_requires_response_snapshot(&payload));
        let requirements: PaymentRequirements =
            serde_json::from_value(batch_requirements_json()).unwrap();
        assert_eq!(
            run_ready(batch_success_response(
                "0xtx".to_string(),
                &payload,
                &requirements,
                None,
                None,
                None,
            ))
            .unwrap_err(),
            "batch claim post-state snapshot unavailable"
        );

        let mut multi = payload.clone();
        multi.claims = Some(vec![claim.clone(), claim]);
        assert_eq!(batch_payload_snapshot_channel_id(&multi, &contract), None);
        assert!(!batch_claim_requires_response_snapshot(&multi));
        let response = run_ready(batch_success_response(
            "0xtx".to_string(),
            &multi,
            &requirements,
            None,
            None,
            None,
        ))
        .unwrap();
        assert_eq!(response.amount, Some("0".to_string()));
        assert_eq!(response.extra_json, None);
    }

    #[test]
    fn batch_verify_snapshot_enforces_balance_and_claimed_bounds() {
        fn voucher_payload(
            kind: &str,
            channel_id: &str,
            max_claimable: &str,
        ) -> crate::batch::BatchRequestPayload {
            crate::batch::BatchRequestPayload {
                kind: kind.to_string(),
                channel_config: None,
                voucher: Some(crate::batch::BatchVoucher {
                    channel_id: channel_id.to_string(),
                    max_claimable_amount: max_claimable.to_string(),
                    signature: format!("0x{}", "11".repeat(65)),
                }),
                deposit: None,
                amount: None,
                refund_nonce: None,
                claims: None,
                refund_authorizer_signature: None,
                claim_authorizer_signature: None,
                receiver: None,
                token: None,
            }
        }

        let snapshot = BatchChannelSnapshot {
            channel_id: format!("0x{}", "11".repeat(32)),
            balance: "100".to_string(),
            total_claimed: "40".to_string(),
            withdraw_requested_at: 0,
            refund_nonce: "0".to_string(),
        };

        assert!(validate_batch_verify_snapshot(
            &voucher_payload("voucher", &snapshot.channel_id, "41"),
            &snapshot
        )
        .is_ok());
        assert_eq!(
            validate_batch_verify_snapshot(
                &voucher_payload("voucher", &snapshot.channel_id, "101"),
                &snapshot
            )
            .unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_exceeds_balance"
        );
        assert_eq!(
            validate_batch_verify_snapshot(
                &voucher_payload("voucher", &snapshot.channel_id, "40"),
                &snapshot
            )
            .unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_below_claimed"
        );
        assert!(validate_batch_verify_snapshot(
            &voucher_payload("refund", &snapshot.channel_id, "40"),
            &snapshot
        )
        .is_ok());
        assert_eq!(
            validate_batch_verify_snapshot(
                &voucher_payload("refund", &snapshot.channel_id, "39"),
                &snapshot
            )
            .unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_below_claimed"
        );

        let mut deposit = voucher_payload("deposit", &snapshot.channel_id, "140");
        deposit.deposit = Some(crate::batch::BatchDeposit {
            amount: "40".to_string(),
            authorization: crate::batch::BatchDepositAuthorization {
                erc3009_authorization: None,
            },
        });
        assert!(validate_batch_verify_snapshot(&deposit, &snapshot).is_ok());

        deposit.voucher.as_mut().unwrap().max_claimable_amount = "141".to_string();
        assert_eq!(
            validate_batch_verify_snapshot(&deposit, &snapshot).unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_exceeds_balance"
        );
        deposit.voucher.as_mut().unwrap().max_claimable_amount = "40".to_string();
        assert_eq!(
            validate_batch_verify_snapshot(&deposit, &snapshot).unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_below_claimed"
        );

        let empty_snapshot = BatchChannelSnapshot {
            balance: "0".to_string(),
            total_claimed: "0".to_string(),
            ..snapshot
        };
        let mut first_deposit = voucher_payload("deposit", &empty_snapshot.channel_id, "40");
        first_deposit.deposit = Some(crate::batch::BatchDeposit {
            amount: "40".to_string(),
            authorization: crate::batch::BatchDepositAuthorization {
                erc3009_authorization: None,
            },
        });
        assert!(validate_batch_verify_snapshot(&first_deposit, &empty_snapshot).is_ok());

        assert_eq!(
            validate_batch_verify_snapshot(
                &voucher_payload("voucher", &empty_snapshot.channel_id, "1"),
                &empty_snapshot
            )
            .unwrap_err(),
            "invalid_batch_settlement_evm_channel_not_found"
        );
    }

    #[test]
    fn batch_verify_pending_gate_applies_to_deposit_voucher_and_refund() {
        fn voucher_payload(
            kind: &str,
            channel_id: &str,
            max_claimable: &str,
        ) -> crate::batch::BatchRequestPayload {
            crate::batch::BatchRequestPayload {
                kind: kind.to_string(),
                channel_config: None,
                voucher: Some(crate::batch::BatchVoucher {
                    channel_id: channel_id.to_string(),
                    max_claimable_amount: max_claimable.to_string(),
                    signature: format!("0x{}", "11".repeat(65)),
                }),
                deposit: None,
                amount: None,
                refund_nonce: None,
                claims: None,
                refund_authorizer_signature: None,
                claim_authorizer_signature: None,
                receiver: None,
                token: None,
            }
        }

        let channel_id = format!("0x{}", "22".repeat(32));
        let mut channel = test_batch_channel(&channel_id, "25");
        for kind in ["deposit", "voucher", "refund"] {
            assert_eq!(
                validate_batch_verify_pending(&voucher_payload(kind, &channel_id, "25"), &channel)
                    .unwrap_err(),
                "invalid_batch_settlement_evm_channel_not_reserved"
            );
        }

        channel.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-1".to_string(),
            signed_max_claimable: "25".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        for kind in ["deposit", "voucher", "refund"] {
            assert!(validate_batch_verify_pending(
                &voucher_payload(kind, &channel_id, "25"),
                &channel
            )
            .is_ok());
        }
    }

    #[test]
    fn batch_verify_success_extra_wraps_channel_state_and_sdk_flat_fields() {
        let snapshot = BatchChannelSnapshot {
            channel_id: format!("0x{}", "11".repeat(32)),
            balance: "1000".to_string(),
            total_claimed: "300".to_string(),
            withdraw_requested_at: 42,
            refund_nonce: "2".to_string(),
        };

        let extra = batch_verify_success_extra(&snapshot);

        assert_eq!(extra["channelState"]["channelId"], snapshot.channel_id);
        assert_eq!(extra["channelState"]["balance"], "1000");
        assert_eq!(extra["channelState"]["totalClaimed"], "300");
        assert_eq!(extra["channelState"]["withdrawRequestedAt"], 42);
        assert_eq!(extra["channelState"]["refundNonce"], "2");
        assert_eq!(extra["channelId"], snapshot.channel_id);
        assert_eq!(extra["balance"], "1000");
        assert_eq!(extra["totalClaimed"], "300");
        assert_eq!(extra["withdrawRequestedAt"], 42);
        assert_eq!(extra["refundNonce"], "2");
    }

    #[test]
    fn batch_refund_nonce_increment_uses_uint256_width() {
        assert_eq!(increment_decimal("0").unwrap(), "1");
        assert_eq!(
            increment_decimal("340282366920938463463374607431768211456").unwrap(),
            "340282366920938463463374607431768211457"
        );

        let uint256_max =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(
            increment_decimal(uint256_max),
            Err("batch refund nonce overflow".to_string())
        );
        assert_eq!(
            increment_decimal("1.5"),
            Err("batch refund nonce must be a decimal integer".to_string())
        );
    }

    #[test]
    fn batch_verify_rejects_storage_miss_cumulative_mismatch_without_rpc() {
        clear_batch_channels();
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();

        let response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&batch_voucher_json("25", "50")).unwrap(),
            certificate_version: None,
        }));
        let value: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status_code, 402);
        assert_eq!(value["invalidReason"], "invalid_batch_settlement");
        assert_eq!(
            value["invalidMessage"],
            "invalid_batch_settlement_evm_cumulative_amount_mismatch"
        );
    }

    #[test]
    fn batch_corrective_verify_extra_uses_canister_channel_storage() {
        let mut channel_config = test_batch_channel_config();
        channel_config.payer = PAYER.to_string();
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let mut channel = test_batch_channel_for_config(&channel_id, channel_config, "3200");
        channel.balance = "100000".to_string();
        channel.total_claimed = "500".to_string();
        channel.refund_nonce = "1".to_string();
        channel.withdraw_requested_at = 0;

        let extra = batch_corrective_verify_extra(
            Some(&channel),
            "invalid_batch_settlement_evm_cumulative_amount_mismatch",
        )
        .unwrap();

        assert_eq!(extra["channelState"]["channelId"], channel_id);
        assert_eq!(extra["channelState"]["balance"], "100000");
        assert_eq!(extra["channelState"]["totalClaimed"], "500");
        assert_eq!(extra["channelState"]["refundNonce"], "1");
        assert_eq!(extra["channelState"]["chargedCumulativeAmount"], "3200");
        assert_eq!(extra["voucherState"]["signedMaxClaimable"], "3200");
        assert_eq!(extra["voucherState"]["signature"], channel.signature);
        assert!(
            batch_corrective_verify_extra(Some(&channel), "batch voucher signer mismatch")
                .is_none()
        );
    }

    #[test]
    fn batch_verify_corrective_402_uses_canister_channel_storage() {
        clear_batch_channels();
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let mut channel_config = test_batch_channel_config();
        channel_config.payer = PAYER.to_string();
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let mut channel = test_batch_channel_for_config(&channel_id, channel_config, "3200");
        channel.balance = "100000".to_string();
        channel.total_claimed = "500".to_string();
        channel.refund_nonce = "1".to_string();
        put_batch_channel(&channel_id, channel.clone()).unwrap();
        let before = get_batch_channel(&channel_id);
        assert_eq!(batch_channel_count(), 1);

        let response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&batch_voucher_json("25", "25")).unwrap(),
            certificate_version: None,
        }));
        let value: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status_code, 402);
        assert_eq!(value["invalidReason"], "invalid_batch_settlement");
        assert_eq!(
            value["invalidMessage"],
            "invalid_batch_settlement_evm_cumulative_amount_mismatch"
        );
        assert_eq!(value["payer"], PAYER.to_lowercase());
        assert_eq!(value["extra"]["channelState"]["channelId"], channel_id);
        assert_eq!(value["extra"]["channelState"]["balance"], "100000");
        assert_eq!(value["extra"]["channelState"]["totalClaimed"], "500");
        assert_eq!(value["extra"]["channelState"]["refundNonce"], "1");
        assert_eq!(
            value["extra"]["channelState"]["chargedCumulativeAmount"],
            "3200"
        );
        assert_eq!(value["extra"]["voucherState"]["signedMaxClaimable"], "3200");
        assert_eq!(
            value["extra"]["voucherState"]["signature"],
            channel.signature
        );
        assert_eq!(batch_channel_count(), 1);
        assert_eq!(get_batch_channel(&channel_id), before);
    }

    #[test]
    fn batch_verify_success_uses_canister_storage_without_rpc() {
        clear_batch_channels();
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        let body = batch_voucher_json("25", "25");

        let missing_response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            certificate_version: None,
        }));
        let missing_value: Value = serde_json::from_slice(&missing_response.body).unwrap();
        assert_eq!(missing_response.status_code, 402);
        assert_eq!(
            missing_value["invalidMessage"],
            "invalid_batch_settlement_evm_channel_not_found"
        );

        let mut channel = test_batch_channel(&channel_id, "0");
        channel.balance = "100".to_string();
        put_batch_channel(&channel_id, channel.clone()).unwrap();

        let unreserved_response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            certificate_version: None,
        }));
        let unreserved_value: Value = serde_json::from_slice(&unreserved_response.body).unwrap();
        assert_eq!(unreserved_response.status_code, 402);
        assert_eq!(
            unreserved_value["invalidMessage"],
            "invalid_batch_settlement_evm_channel_not_reserved"
        );

        let mut expired = channel.clone();
        expired.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-1".to_string(),
            signed_max_claimable: "25".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_sub(1),
        });
        put_batch_channel(&channel_id, expired).unwrap();
        let expired_response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            certificate_version: None,
        }));
        let expired_value: Value = serde_json::from_slice(&expired_response.body).unwrap();
        assert_eq!(expired_response.status_code, 402);
        assert_eq!(
            expired_value["invalidMessage"],
            "invalid_batch_settlement_evm_channel_not_reserved"
        );

        channel.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-1".to_string(),
            signed_max_claimable: "26".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        put_batch_channel(&channel_id, channel.clone()).unwrap();
        let mismatch_response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            certificate_version: None,
        }));
        let mismatch_value: Value = serde_json::from_slice(&mismatch_response.body).unwrap();
        assert_eq!(mismatch_response.status_code, 402);
        assert_eq!(
            mismatch_value["invalidMessage"],
            "invalid_batch_settlement_evm_pending_voucher_mismatch"
        );

        channel.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-1".to_string(),
            signed_max_claimable: "25".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        put_batch_channel(&channel_id, channel).unwrap();

        let response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            certificate_version: None,
        }));
        let value: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(value["isValid"], true);
        assert_eq!(value["payer"], PAYER.to_lowercase());
        assert_eq!(value["extra"]["channelState"]["channelId"], channel_id);
        assert_eq!(value["extra"]["channelState"]["balance"], "100");
        assert_eq!(value["extra"]["channelState"]["totalClaimed"], "0");
    }

    #[test]
    fn batch_settle_rejects_storage_miss_cumulative_mismatch_before_rpc() {
        clear_settlement_state();
        clear_batch_channels();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let mut body = batch_voucher_json("0", "100");
        body["paymentPayload"]["payload"]["type"] = json!("refund");
        body["paymentPayload"]["payload"]["amount"] = json!("1");
        body["paymentPayload"]["payload"]["refundNonce"] = json!("0");

        let response = run_ready(settle_http(batch_settle_request(&body)));
        let value: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status_code, 402);
        assert_eq!(value["result"]["errorReason"], "invalid_batch_settlement");
        assert_eq!(
            value["result"]["errorMessage"],
            "invalid_batch_settlement_evm_cumulative_amount_mismatch"
        );
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_amount_helper_requires_verified_event_amount() {
        assert_eq!(
            verified_batch_settle_amount(Err("expected batch Settled event not found".to_string())),
            None
        );
        assert_eq!(
            verified_batch_settle_amount(Ok("0".to_string())),
            Some("0".to_string())
        );
    }

    #[test]
    fn supported_omits_batch_for_invalid_partial_batch_config() {
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value("BATCH_WITHDRAW_DELAY_SECONDS", "2592001");

        let response = supported_response();
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        let kinds = value["kinds"].as_array().unwrap();

        assert_eq!(response.status_code, 200);
        assert!(kinds
            .iter()
            .any(|kind| kind["scheme"] == "exact" && kind["network"] == NETWORK));
        assert!(!kinds
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));
    }

    #[test]
    fn supported_requires_full_batch_settlement_config_before_advertising_batch() {
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        set_env_value("BATCH_WITHDRAW_DELAY_SECONDS", "900");

        let missing_contract = supported_response();
        let missing_contract_value: Value = serde_json::from_slice(&missing_contract.body).unwrap();
        assert_eq!(missing_contract.status_code, 200);
        assert!(!missing_contract_value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));

        set_default_batch_contract();
        let missing_fee = supported_response();
        let missing_fee_value: Value = serde_json::from_slice(&missing_fee.body).unwrap();
        assert_eq!(missing_fee.status_code, 200);
        assert!(!missing_fee_value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));

        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "0");
        let invalid_fee = supported_response();
        let invalid_fee_value: Value = serde_json::from_slice(&invalid_fee.body).unwrap();
        assert_eq!(invalid_fee.status_code, 200);
        assert!(!invalid_fee_value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));

        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value("BATCH_SETTLEMENT_CONTRACT", "not an address");
        let invalid_contract = supported_response();
        let invalid_contract_value: Value = serde_json::from_slice(&invalid_contract.body).unwrap();
        assert_eq!(invalid_contract.status_code, 200);
        assert!(!invalid_contract_value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));

        set_env_value(
            "BATCH_SETTLEMENT_CONTRACT",
            "0x0000000000000000000000000000000000000001",
        );
        let wrong_contract = supported_response();
        let wrong_contract_value: Value = serde_json::from_slice(&wrong_contract.body).unwrap();
        assert_eq!(wrong_contract.status_code, 200);
        assert!(!wrong_contract_value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));

        set_default_batch_contract();
        let missing_writer = supported_response();
        let missing_writer_value: Value = serde_json::from_slice(&missing_writer.body).unwrap();
        assert_eq!(missing_writer.status_code, 200);
        assert!(!missing_writer_value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));

        set_env_value("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "2vxsx-fae");
        let invalid_writer = supported_response();
        let invalid_writer_value: Value = serde_json::from_slice(&invalid_writer.body).unwrap();
        assert_eq!(invalid_writer.status_code, 200);
        assert!(!invalid_writer_value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));
    }

    #[test]
    fn supported_omits_batch_when_receiver_authorizer_key_is_unset() {
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_default_batch_contract();
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value(
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL",
            "ryjl3-tyaaa-aaaaa-aaaba-cai",
        );

        let response = supported_response();
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        let kinds = value["kinds"].as_array().unwrap();

        assert_eq!(response.status_code, 200);
        assert!(kinds
            .iter()
            .any(|kind| kind["scheme"] == "exact" && kind["network"] == NETWORK));
        assert!(!kinds
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));
    }

    #[test]
    fn empty_env_value_removes_stale_batch_config() {
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_full_batch_config();

        let enabled = supported_response();
        let enabled_value: Value = serde_json::from_slice(&enabled.body).unwrap();
        let enabled_kinds = enabled_value["kinds"].as_array().unwrap();
        assert_eq!(enabled.status_code, 200);
        assert!(enabled_kinds
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));

        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "");
        assert!(optional_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY").is_none());

        let disabled = supported_response();
        let disabled_value: Value = serde_json::from_slice(&disabled.body).unwrap();
        let disabled_kinds = disabled_value["kinds"].as_array().unwrap();
        assert_eq!(disabled.status_code, 200);
        assert!(!disabled_kinds
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));
    }

    #[test]
    fn supported_omits_batch_for_invalid_batch_receiver_authorizer_key() {
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "not a private key");

        let response = supported_response();
        let value: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status_code, 200);
        assert!(!value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));
    }

    #[test]
    fn supported_omits_batch_when_receiver_authorizer_key_matches_facilitator_key() {
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", SELLER_PRIVATE_KEY);

        let response = supported_response();
        let value: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status_code, 200);
        assert!(!value["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind["scheme"] == BATCH_SCHEME && kind["network"] == NETWORK));
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
        assert!(decoded.batch_channels.is_none());
    }

    #[test]
    fn legacy_restore_is_attempted_only_when_stable_structures_are_empty() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        clear_batch_channels();
        assert!(stable_structures_empty());

        set_env_value("JPYC_EIP712_VERSION", "1");
        assert!(!stable_structures_empty());

        clear_env_values();
        assert!(stable_structures_empty());

        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        put_batch_channel(&channel_id, test_batch_channel(&channel_id, "100")).unwrap();
        assert!(!stable_structures_empty());
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
    fn verify_rejects_exact_scheme() {
        let response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&request_json()).unwrap(),
            certificate_version: None,
        }));
        let value: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status_code, 400);
        assert_eq!(value["invalidReason"], "unsupported_verify_scheme");
    }

    #[test]
    fn batch_verify_requires_full_batch_settlement_config() {
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        let request = || HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&batch_voucher_json("25", "25")).unwrap(),
            certificate_version: None,
        };

        let missing_key = run_ready(verify_http(request()));
        let missing_key_value: Value = serde_json::from_slice(&missing_key.body).unwrap();
        assert_eq!(missing_key.status_code, 500);
        assert_eq!(missing_key_value["invalidReason"], "invalid_config");
        assert!(missing_key_value["invalidMessage"]
            .as_str()
            .unwrap()
            .contains("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"));

        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        let missing_contract = run_ready(verify_http(request()));
        let missing_contract_value: Value = serde_json::from_slice(&missing_contract.body).unwrap();
        assert_eq!(missing_contract.status_code, 500);
        assert_eq!(
            missing_contract_value["invalidMessage"],
            "missing required env: BATCH_SETTLEMENT_CONTRACT"
        );

        set_default_batch_contract();
        let missing_fee = run_ready(verify_http(request()));
        let missing_fee_value: Value = serde_json::from_slice(&missing_fee.body).unwrap();
        assert_eq!(missing_fee.status_code, 500);
        assert_eq!(
            missing_fee_value["invalidMessage"],
            "missing required env: BATCH_SETTLEMENT_FEE_AMOUNT"
        );

        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        let missing_writer = run_ready(verify_http(request()));
        let missing_writer_value: Value = serde_json::from_slice(&missing_writer.body).unwrap();
        assert_eq!(missing_writer.status_code, 500);
        assert_eq!(
            missing_writer_value["invalidMessage"],
            "missing required env: BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL"
        );
    }

    #[test]
    fn batch_settle_requires_full_batch_settlement_config_before_credit_or_rpc() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);
        set_default_batch_contract();

        let missing_key = run_ready(settle_http(batch_settle_request(&batch_settle_json())));
        let missing_key_value: Value = serde_json::from_slice(&missing_key.body).unwrap();
        assert_eq!(missing_key.status_code, 400);
        assert_eq!(missing_key_value["result"]["errorReason"], "invalid_config");
        assert!(missing_key_value["result"]["errorMessage"]
            .as_str()
            .unwrap()
            .contains("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"));
        assert_eq!(seller_credit_balance_for(&seller), 100);
        assert_eq!(missing_key_value["cost"]["rpcCalls"], 0);
        assert!(missing_key_value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));

        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        set_default_batch_contract();
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        let missing_writer = run_ready(settle_http(batch_settle_request(&batch_settle_json())));
        let missing_writer_value: Value = serde_json::from_slice(&missing_writer.body).unwrap();
        assert_eq!(missing_writer.status_code, 400);
        assert_eq!(
            missing_writer_value["result"]["errorReason"],
            "invalid_config"
        );
        assert_eq!(
            missing_writer_value["result"]["errorMessage"],
            "missing required env: BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL"
        );
        assert_eq!(seller_credit_balance_for(&seller), 100);
        assert_eq!(missing_writer_value["cost"]["rpcCalls"], 0);
        assert!(missing_writer_value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_verify_and_settle_reject_eip712_version_before_rpc_or_credit() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let mut body = batch_refund_json("1", "0");
        body["paymentRequirements"]["extra"]["version"] = json!("2");
        body["paymentPayload"]["accepted"]["extra"]["version"] = json!("2");

        let verify_response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
            certificate_version: None,
        }));
        let verify_value: Value = serde_json::from_slice(&verify_response.body).unwrap();
        assert_eq!(verify_response.status_code, 402);
        assert_eq!(verify_value["invalidReason"], "invalid_batch_settlement");
        assert_eq!(
            verify_value["invalidMessage"],
            "invalid_batch_settlement_evm_eip712_version"
        );

        let settle_response = run_ready(settle_http(batch_settle_request(&body)));
        let settle_value: Value = serde_json::from_slice(&settle_response.body).unwrap();
        assert_eq!(settle_response.status_code, 402);
        assert_eq!(
            settle_value["result"]["errorReason"],
            "invalid_batch_settlement"
        );
        assert_eq!(
            settle_value["result"]["errorMessage"],
            "invalid_batch_settlement_evm_eip712_version"
        );
        assert_eq!(settle_value["cost"]["rpcCalls"], 0);
        assert_eq!(seller_credit_balance_for(&seller), 100);
    }

    #[test]
    fn batch_verify_allows_minimal_operation_requirements_before_kind_validation() {
        clear_batch_channels();
        clear_env_values();
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();

        let claim = with_minimal_batch_operation_requirements(batch_claim_json("100", "75"));
        let claim_response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&claim).unwrap(),
            certificate_version: None,
        }));
        let claim_value: Value = serde_json::from_slice(&claim_response.body).unwrap();
        assert_ne!(
            claim_value["invalidMessage"],
            "invalid_batch_settlement_evm_eip712_version"
        );

        let settle = with_minimal_batch_operation_requirements(batch_settle_json());
        let settle_response = run_ready(verify_http(HttpRequest {
            method: "POST".to_string(),
            url: "/verify".to_string(),
            headers: vec![],
            body: serde_json::to_vec(&settle).unwrap(),
            certificate_version: None,
        }));
        let settle_value: Value = serde_json::from_slice(&settle_response.body).unwrap();
        assert_ne!(
            settle_value["invalidMessage"],
            "invalid_batch_settlement_evm_eip712_version"
        );
    }

    #[test]
    fn batch_settle_accepts_official_manager_minimal_claim_and_settle_requirements() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let receiver_authorizer = private_key_address(OTHER_PRIVATE_KEY).unwrap();

        let claim = with_minimal_batch_operation_requirements(
            batch_claim_json_for_receiver_authorizer("100", "75", Some(&receiver_authorizer)),
        );
        let claim_response = run_ready(settle_http(batch_settle_request(&claim)));
        let claim_value: Value = serde_json::from_slice(&claim_response.body).unwrap();
        assert_eq!(claim_response.status_code, 402);
        assert_eq!(
            claim_value["result"]["errorReason"],
            "seller_insufficient_credit"
        );
        assert!(claim_value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["name"] == "batch_settle.reserve_seller_credit"));

        let settle = with_minimal_batch_operation_requirements(batch_settle_json());
        let settle_response = run_ready(settle_http(batch_settle_request(&settle)));
        let settle_value: Value = serde_json::from_slice(&settle_response.body).unwrap();
        assert_eq!(settle_response.status_code, 402);
        assert_eq!(
            settle_value["result"]["errorReason"],
            "seller_insufficient_credit"
        );
        assert!(settle_value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["name"] == "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_rejects_optional_operation_version_mismatch_before_credit() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let receiver_authorizer = private_key_address(OTHER_PRIVATE_KEY).unwrap();
        let mut claim =
            batch_claim_json_for_receiver_authorizer("100", "75", Some(&receiver_authorizer));
        claim["paymentRequirements"]["extra"]["version"] = json!("2");
        claim["paymentPayload"]["accepted"]["extra"]["version"] = json!("2");

        let claim_response = run_ready(settle_http(batch_settle_request(&claim)));
        let claim_value: Value = serde_json::from_slice(&claim_response.body).unwrap();
        assert_eq!(claim_response.status_code, 402);
        assert_eq!(
            claim_value["result"]["errorReason"],
            "invalid_batch_settlement"
        );
        assert_eq!(
            claim_value["result"]["errorMessage"],
            "invalid_batch_settlement_evm_eip712_version"
        );
        assert_eq!(claim_value["cost"]["rpcCalls"], 0);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        assert!(claim_value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_channel_update_uses_revision_cas() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        let channel = test_initial_batch_channel(&channel_id, "200");

        let missing_pending = batch_update_channel(
            channel_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(test_batch_channel(&channel_id, "100")),
            },
        );
        assert_eq!(missing_pending.status, "invalid");
        assert_eq!(
            missing_pending.message,
            Some("batch channel create requires pendingRequest".to_string())
        );

        let mut expired_pending = test_batch_channel(&channel_id, "100");
        expired_pending.signed_max_claimable = "200".to_string();
        expired_pending.signature = crate::batch::sign_batch_voucher_for_test(
            &channel_id,
            "200",
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        expired_pending.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-expired".to_string(),
            signed_max_claimable: "200".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_sub(1),
        });
        let expired_create = batch_update_channel(
            channel_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(expired_pending),
            },
        );
        assert_eq!(expired_create.status, "invalid");
        assert_eq!(
            expired_create.message,
            Some("batch channel create requires live pendingRequest".to_string())
        );

        let mut mismatch_pending = test_batch_channel(&channel_id, "100");
        mismatch_pending.signed_max_claimable = "200".to_string();
        mismatch_pending.signature = crate::batch::sign_batch_voucher_for_test(
            &channel_id,
            "200",
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        mismatch_pending.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-mismatch".to_string(),
            signed_max_claimable: "201".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        let mismatch_create = batch_update_channel(
            channel_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(mismatch_pending),
            },
        );
        assert_eq!(mismatch_create.status, "invalid");
        assert_eq!(
            mismatch_create.message,
            Some(
                "batch channel signedMaxClaimable must match pendingRequest.signedMaxClaimable when creating"
                    .to_string()
            )
        );

        let initial_invariant_cases: [(&str, fn(&mut BatchChannel)); 6] = [
            (
                "batch channel create requires chargedCumulativeAmount 0",
                |channel: &mut BatchChannel| channel.charged_cumulative_amount = "1".to_string(),
            ),
            (
                "batch channel create requires balance 0",
                |channel: &mut BatchChannel| channel.balance = "1".to_string(),
            ),
            (
                "batch channel create requires totalClaimed 0",
                |channel: &mut BatchChannel| {
                    channel.total_claimed = "1".to_string();
                    channel.balance = "1".to_string();
                },
            ),
            (
                "batch channel create requires refundNonce 0",
                |channel: &mut BatchChannel| channel.refund_nonce = "1".to_string(),
            ),
            (
                "batch channel create requires withdrawRequestedAt 0",
                |channel: &mut BatchChannel| channel.withdraw_requested_at = 1,
            ),
            (
                "batch channel create requires onchainSyncedAt empty",
                |channel: &mut BatchChannel| channel.onchain_synced_at = Some(1),
            ),
        ];
        for (message, mutate) in initial_invariant_cases {
            let mut invalid_initial = test_initial_batch_channel(&channel_id, "200");
            mutate(&mut invalid_initial);
            let result = batch_update_channel(
                channel_id.clone(),
                None,
                BatchChannelUpdate {
                    channel: Some(invalid_initial),
                },
            );
            assert_eq!(result.status, "invalid");
            assert_eq!(result.message, Some(message.to_string()));
        }

        let missing_delete = batch_update_channel(
            channel_id.clone(),
            None,
            BatchChannelUpdate { channel: None },
        );
        assert_eq!(missing_delete.status, "unchanged");
        assert_eq!(missing_delete.current_revision, None);

        let created = batch_update_channel(
            channel_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(channel),
            },
        );
        assert_eq!(created.status, "updated");
        assert_eq!(created.current_revision, Some(1));
        assert_eq!(batch_channel_count(), 1);

        let conflict = batch_update_channel(
            channel_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(test_batch_channel(&channel_id, "200")),
            },
        );
        assert_eq!(conflict.status, "conflict");
        assert_eq!(conflict.current_revision, Some(1));

        let updated = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate {
                channel: Some(test_batch_channel(&channel_id, "200")),
            },
        );
        assert_eq!(updated.status, "updated");
        assert_eq!(updated.current_revision, Some(2));
        assert_eq!(
            batch_channel(channel_id.clone())
                .unwrap()
                .charged_cumulative_amount,
            "200"
        );
        let upper_channel_id = format!("0x{}", channel_id[2..].to_ascii_uppercase());
        assert_eq!(
            batch_channel(upper_channel_id)
                .unwrap()
                .charged_cumulative_amount,
            "200"
        );

        let deleted = batch_update_channel(
            channel_id.clone(),
            Some(2),
            BatchChannelUpdate { channel: None },
        );
        assert_eq!(deleted.status, "deleted");
        assert_eq!(batch_channel(channel_id.clone()), None);
        let audit = batch_deleted_channel(channel_id.clone()).unwrap();
        assert_eq!(audit.channel.channel_id, channel_id);
        assert_eq!(audit.channel.charged_cumulative_amount, "200");
        assert!(!audit.deleted_by.is_empty());
        assert_eq!(batch_deleted_channel_count(), 1);
        assert_eq!(batch_deleted_channels(Some(1)).len(), 1);
    }

    #[test]
    fn batch_channel_update_allows_official_manager_delete() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        let mut stored = test_batch_channel(&channel_id, "100");
        stored.revision = 1;
        put_batch_channel(&channel_id, stored).unwrap();

        let deleted = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate { channel: None },
        );
        assert_eq!(deleted.status, "deleted");
        assert_eq!(batch_channel(channel_id.clone()), None);
        assert_eq!(
            batch_deleted_channel(channel_id)
                .unwrap()
                .channel
                .charged_cumulative_amount,
            "100"
        );
    }

    #[test]
    fn batch_deleted_channel_audit_retention_keeps_existing_key_updates() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();

        let deleted = |channel_id: &str, deleted_at: u64| BatchDeletedChannel {
            channel: test_batch_channel(channel_id, "100"),
            deleted_at,
            deleted_by: "test-writer".to_string(),
        };

        let mut config_a = test_batch_channel_config();
        config_a.salt = format!("0x{}", "45".repeat(32));
        let id_a = compute_batch_channel_id(&config_a, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let mut config_b = test_batch_channel_config();
        config_b.salt = format!("0x{}", "46".repeat(32));
        let id_b = compute_batch_channel_id(&config_b, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let mut config_c = test_batch_channel_config();
        config_c.salt = format!("0x{}", "47".repeat(32));
        let id_c = compute_batch_channel_id(&config_c, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();

        put_batch_deleted_channel(&id_a, deleted(&id_a, 10));
        put_batch_deleted_channel(&id_b, deleted(&id_b, 20));
        put_batch_deleted_channel(&id_b, deleted(&id_b, 30));

        assert_eq!(batch_deleted_channel_count(), 2);
        assert_eq!(batch_deleted_channel(id_a.clone()).unwrap().deleted_at, 10);
        assert_eq!(batch_deleted_channel(id_b.clone()).unwrap().deleted_at, 30);

        put_batch_deleted_channel(&id_c, deleted(&id_c, 40));

        assert_eq!(batch_deleted_channel_count(), 2);
        assert!(batch_deleted_channel(id_a).is_none());
        assert_eq!(batch_deleted_channel(id_b).unwrap().deleted_at, 30);
        assert_eq!(batch_deleted_channel(id_c).unwrap().deleted_at, 40);
    }

    #[test]
    fn batch_channel_update_rejects_delete_with_live_pending_request() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        let mut channel = test_batch_channel(&channel_id, "100");
        channel.revision = 1;
        channel.balance = "100".to_string();
        channel.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-live".to_string(),
            signed_max_claimable: "100".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        put_batch_channel(&channel_id, channel).unwrap();

        let rejected = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate { channel: None },
        );
        assert_eq!(rejected.status, "invalid");
        assert_eq!(
            rejected.message,
            Some("batch channel delete requires no live pendingRequest".to_string())
        );
        assert!(batch_channel(channel_id.clone()).is_some());

        let mut expired = batch_channel(channel_id.clone()).unwrap();
        expired.revision = 1;
        expired.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-expired".to_string(),
            signed_max_claimable: "100".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_sub(1),
        });
        put_batch_channel(&channel_id, expired).unwrap();

        let deleted = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate { channel: None },
        );
        assert_eq!(deleted.status, "deleted");
        assert_eq!(batch_channel(channel_id), None);
    }

    #[test]
    fn batch_channel_update_allows_delete_of_pending_only_provisional_channel() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        let channel = test_initial_batch_channel(&channel_id, "100");

        let created = batch_update_channel(
            channel_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(channel),
            },
        );
        assert_eq!(created.status, "updated");

        let deleted = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate { channel: None },
        );
        assert_eq!(deleted.status, "deleted");
        assert_eq!(batch_channel(channel_id), None);
    }

    #[test]
    fn batch_channel_update_rejects_monotonic_state_rollbacks() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        let mut current = test_batch_channel(&channel_id, "200");
        current.charged_cumulative_amount = "100".to_string();
        current.balance = "50".to_string();
        current.total_claimed = "50".to_string();
        current.refund_nonce = "3".to_string();
        current.revision = 1;
        put_batch_channel(&channel_id, current).unwrap();

        for (mut rollback, expected_message) in [
            (
                {
                    let mut channel = test_batch_channel(&channel_id, "200");
                    channel.charged_cumulative_amount = "99".to_string();
                    channel
                },
                "batch channel chargedCumulativeAmount must not decrease",
            ),
            (
                {
                    let mut channel = test_batch_channel(&channel_id, "150");
                    channel.charged_cumulative_amount = "100".to_string();
                    channel
                },
                "batch channel signedMaxClaimable must not decrease",
            ),
            (
                {
                    let mut channel = test_batch_channel(&channel_id, "200");
                    channel.charged_cumulative_amount = "100".to_string();
                    channel.balance = "49".to_string();
                    channel.total_claimed = "49".to_string();
                    channel
                },
                "batch channel totalClaimed must not decrease",
            ),
            (
                {
                    let mut channel = test_batch_channel(&channel_id, "200");
                    channel.charged_cumulative_amount = "100".to_string();
                    channel.balance = "50".to_string();
                    channel.total_claimed = "50".to_string();
                    channel.refund_nonce = "2".to_string();
                    channel
                },
                "batch channel refundNonce must not decrease",
            ),
            (
                {
                    let mut channel = test_batch_channel(&channel_id, "200");
                    channel.charged_cumulative_amount = "100".to_string();
                    channel.balance = "50".to_string();
                    channel.total_claimed = "50".to_string();
                    channel.refund_nonce = "3".to_string();
                    channel.last_request_timestamp = 0;
                    channel
                },
                "batch channel lastRequestTimestamp must not decrease",
            ),
        ] {
            rollback.revision = 1;
            let result = batch_update_channel(
                channel_id.clone(),
                Some(1),
                BatchChannelUpdate {
                    channel: Some(rollback),
                },
            );
            assert_eq!(result.status, "invalid");
            assert_eq!(result.message, Some(expected_message.to_string()));
        }

        let stored = batch_channel(channel_id).unwrap();
        assert_eq!(stored.charged_cumulative_amount, "100");
        assert_eq!(stored.signed_max_claimable, "200");
        assert_eq!(stored.total_claimed, "50");
        assert_eq!(stored.refund_nonce, "3");
    }

    #[test]
    fn batch_channel_update_requires_pending_request_for_charge_increase() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();

        let mut current = test_batch_channel(&channel_id, "100");
        current.revision = 1;
        put_batch_channel(&channel_id, current).unwrap();

        let without_pending = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate {
                channel: Some(test_batch_channel(&channel_id, "125")),
            },
        );
        assert_eq!(without_pending.status, "invalid");
        assert_eq!(
            without_pending.message,
            Some("batch channel charge increase requires pendingRequest".to_string())
        );

        let mut expired_current = test_batch_channel(&channel_id, "100");
        expired_current.revision = 1;
        expired_current.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-expired".to_string(),
            signed_max_claimable: "125".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_sub(1),
        });
        put_batch_channel(&channel_id, expired_current).unwrap();
        let expired = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate {
                channel: Some(test_batch_channel(&channel_id, "125")),
            },
        );
        assert_eq!(expired.status, "invalid");
        assert_eq!(
            expired.message,
            Some("batch channel charge increase requires live pendingRequest".to_string())
        );

        let mut mismatch_current = test_batch_channel(&channel_id, "100");
        mismatch_current.revision = 1;
        mismatch_current.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-130".to_string(),
            signed_max_claimable: "130".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        put_batch_channel(&channel_id, mismatch_current).unwrap();
        let mismatch = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate {
                channel: Some(test_batch_channel(&channel_id, "125")),
            },
        );
        assert_eq!(mismatch.status, "invalid");
        assert_eq!(
            mismatch.message,
            Some(
                "batch channel signedMaxClaimable must match pendingRequest.signedMaxClaimable when charge increases"
                    .to_string()
            )
        );

        let mut unconsumed_current = test_batch_channel(&channel_id, "100");
        unconsumed_current.revision = 1;
        unconsumed_current.pending_request = Some(crate::batch::BatchPendingRequest {
            pending_id: "request-125".to_string(),
            signed_max_claimable: "125".to_string(),
            expires_at: now_seconds().saturating_mul(1_000).saturating_add(60_000),
        });
        put_batch_channel(&channel_id, unconsumed_current.clone()).unwrap();
        let mut unconsumed_next = test_batch_channel(&channel_id, "125");
        unconsumed_next.pending_request = unconsumed_current.pending_request;
        let unconsumed = batch_update_channel(
            channel_id.clone(),
            Some(1),
            BatchChannelUpdate {
                channel: Some(unconsumed_next),
            },
        );
        assert_eq!(unconsumed.status, "invalid");
        assert_eq!(
            unconsumed.message,
            Some("batch channel charge increase must consume pendingRequest".to_string())
        );
    }

    #[test]
    fn batch_channel_update_rejects_config_mismatch_and_storage_limit() {
        clear_batch_channels();
        clear_env_values();
        set_default_batch_contract();
        let channel_id = compute_batch_channel_id(
            &test_batch_channel_config(),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        let mut mismatch = test_batch_channel(&channel_id, "100");
        mismatch.channel_config.salt = format!("0x{}", "44".repeat(32));

        let invalid = batch_update_channel(
            channel_id,
            None,
            BatchChannelUpdate {
                channel: Some(mismatch),
            },
        );
        assert_eq!(invalid.status, "invalid");
        assert_eq!(
            invalid.message,
            Some("batch channel config does not match channel id".to_string())
        );

        let mut created_ids = Vec::new();
        for salt in ["45", "46"] {
            let mut config = test_batch_channel_config();
            config.salt = format!("0x{}", salt.repeat(32));
            let id = compute_batch_channel_id(&config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
            let channel = test_initial_batch_channel_for_config(&id, config, "100");
            let created = batch_update_channel(
                id.clone(),
                None,
                BatchChannelUpdate {
                    channel: Some(channel),
                },
            );
            assert_eq!(created.status, "updated");
            created_ids.push(id);
        }

        let mut existing_update = batch_channel(created_ids[0].clone()).unwrap();
        existing_update.charged_cumulative_amount = "100".to_string();
        existing_update.pending_request = None;
        let updated_at_limit = batch_update_channel(
            created_ids[0].clone(),
            Some(1),
            BatchChannelUpdate {
                channel: Some(existing_update),
            },
        );
        assert_eq!(updated_at_limit.status, "updated");
        assert_eq!(updated_at_limit.current_revision, Some(2));

        let mut extra_config = test_batch_channel_config();
        extra_config.salt = format!("0x{}", "47".repeat(32));
        let extra_id =
            compute_batch_channel_id(&extra_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let over_limit = batch_update_channel(
            extra_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(test_initial_batch_channel_for_config(
                    &extra_id,
                    extra_config,
                    "100",
                )),
            },
        );
        assert_eq!(over_limit.status, "invalid");
        assert_eq!(
            over_limit.message,
            Some("batch channel storage limit reached".to_string())
        );

        let deleted = batch_update_channel(
            created_ids[1].clone(),
            Some(1),
            BatchChannelUpdate { channel: None },
        );
        assert_eq!(deleted.status, "deleted");

        let mut replacement_config = test_batch_channel_config();
        replacement_config.salt = format!("0x{}", "48".repeat(32));
        let replacement_id =
            compute_batch_channel_id(&replacement_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap();
        let replacement = batch_update_channel(
            replacement_id.clone(),
            None,
            BatchChannelUpdate {
                channel: Some(test_initial_batch_channel_for_config(
                    &replacement_id,
                    replacement_config,
                    "100",
                )),
            },
        );
        assert_eq!(replacement.status, "updated");
    }

    #[test]
    fn batch_channel_storage_writer_principal_must_be_valid() {
        clear_env_values();
        assert_eq!(batch_channel_storage_writer_principal().unwrap(), None);

        set_env_value(
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL",
            "ryjl3-tyaaa-aaaaa-aaaba-cai",
        );
        assert_eq!(
            batch_channel_storage_writer_principal().unwrap(),
            Some(Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap())
        );
        assert_eq!(
            batch_channel_storage_writer(),
            Some(Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap())
        );

        set_env_value("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "2vxsx-fae");
        assert_eq!(
            batch_channel_storage_writer_principal().unwrap_err(),
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be a non-system IC principal"
        );
        assert_eq!(batch_channel_storage_writer(), None);

        set_env_value("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "not a principal");
        assert_eq!(
            batch_channel_storage_writer_principal().unwrap_err(),
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be an IC principal"
        );
    }

    #[test]
    fn batch_channel_storage_writer_guard_authorizes_only_controller_or_configured_writer() {
        clear_env_values();
        let writer = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
        let other = Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap();

        assert_eq!(
            authorize_batch_channel_storage_writer(Principal::anonymous(), false).unwrap_err(),
            "anonymous caller is not authorized to update batch channel storage"
        );
        assert!(authorize_batch_channel_storage_writer(other, true).is_ok());
        assert_eq!(
            authorize_batch_channel_storage_writer(other, false).unwrap_err(),
            "caller is not authorized to update batch channel storage"
        );

        set_env_value("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", &writer.to_text());
        assert!(authorize_batch_channel_storage_writer(writer, false).is_ok());
        assert_eq!(
            authorize_batch_channel_storage_writer(other, false).unwrap_err(),
            "caller is not authorized to update batch channel storage"
        );

        set_env_value("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "not a principal");
        assert_eq!(
            authorize_batch_channel_storage_writer(writer, false).unwrap_err(),
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be an IC principal"
        );
    }

    #[test]
    fn batch_settlement_fee_amount_exposes_only_valid_public_fee() {
        clear_env_values();
        assert_eq!(batch_settlement_fee_amount(), None);

        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        assert_eq!(batch_settlement_fee_amount(), Some("100".to_string()));

        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "0");
        assert_eq!(batch_settlement_fee_amount(), None);

        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "1.5");
        assert_eq!(batch_settlement_fee_amount(), None);
    }

    #[test]
    fn batch_settlement_contract_exposes_only_valid_public_contract() {
        clear_env_values();
        assert_eq!(batch_settlement_contract(), None);

        set_default_batch_contract();
        assert_eq!(
            batch_settlement_contract(),
            Some(DEFAULT_BATCH_SETTLEMENT_CONTRACT.to_ascii_lowercase())
        );

        set_env_value(
            "BATCH_SETTLEMENT_CONTRACT",
            "0x0000000000000000000000000000000000000000",
        );
        assert_eq!(batch_settlement_contract(), None);

        set_env_value("BATCH_SETTLEMENT_CONTRACT", "not an address");
        assert_eq!(batch_settlement_contract(), None);

        set_env_value(
            "BATCH_SETTLEMENT_CONTRACT",
            "0x0000000000000000000000000000000000000001",
        );
        assert_eq!(batch_settlement_contract(), None);
    }

    #[test]
    fn batch_receiver_authorizer_exposes_only_derived_public_address() {
        clear_env_values();
        assert_eq!(batch_receiver_authorizer(), None);

        set_env_value(
            "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY",
            "0x2222222222222222222222222222222222222222222222222222222222222222",
        );
        assert_eq!(
            batch_receiver_authorizer(),
            Some("0x1563915e194d8cfba1943570603f7606a3115508".to_string())
        );

        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "not a private key");
        assert_eq!(batch_receiver_authorizer(), None);
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
    fn batch_settle_rejects_insufficient_seller_credit_before_rpc() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();

        let response = run_ready(settle_http(batch_settle_request(&batch_settle_json())));

        assert_eq!(response.status_code, 402);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "seller_insufficient_credit");
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["name"] == "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_busy_lock_wins_before_credit_reserve() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        let from = private_key_address(SELLER_PRIVATE_KEY).unwrap();
        let scope = active_settlement_scope(&from, &seller).unwrap();
        add_seller_credit(&seller, 50);
        assert!(acquire_active_settlement(&scope, "busy-batch"));

        let response = run_ready(settle_http(batch_settle_request(&batch_settle_json())));

        release_active_settlement(&scope, "busy-batch");
        assert_eq!(response.status_code, 429);
        assert_eq!(seller_credit_balance_for(&seller), 50);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "settlement_queue_busy");
        assert_eq!(value["cost"]["rpcCalls"], 0);
        let steps = value["cost"]["steps"].as_array().unwrap();
        assert!(steps
            .iter()
            .any(|step| step["name"] == "batch_settle.active_lock"));
        assert!(steps
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_missing_fee_config_releases_active_lock_before_reserve() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        remove_env_value("BATCH_SETTLEMENT_FEE_AMOUNT");
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let response = run_ready(settle_http(batch_settle_request(&batch_settle_json())));

        assert_eq!(response.status_code, 400);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        assert_eq!(active_settlement_count(), 0);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_config");
        assert_eq!(value["cost"]["rpcCalls"], 0);
        let steps = value["cost"]["steps"].as_array().unwrap();
        assert!(steps
            .iter()
            .any(|step| step["name"] == "batch_settle.active_lock"));
        assert!(steps
            .iter()
            .any(|step| step["name"] == "batch_settle.fee_config"));
        assert!(steps
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_cache_hit_does_not_require_full_batch_config_or_credit() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_default_batch_contract();
        let body = batch_settle_json();
        let parsed: BatchFacilitatorRequest = serde_json::from_value(body.clone()).unwrap();
        let key = batch_settlement_key(&parsed).unwrap();
        insert_settlement(
            &key,
            SettlementRecord::settled(
                "0xsettled".to_string(),
                PAY_TO.to_string(),
                PAY_TO.to_string(),
                "0".to_string(),
                now_seconds(),
                60,
            ),
        );

        let response = run_ready(settle_http(batch_settle_request(&body)));

        assert_eq!(response.status_code, 200);
        assert_eq!(seller_credit_balance_for(PAY_TO), 0);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        let steps = value["cost"]["steps"].as_array().unwrap();
        assert!(steps
            .iter()
            .any(|step| step["name"] == "batch_settle.cache_hit"));
        assert!(steps
            .iter()
            .all(|step| step["name"] != "batch_settle.authorizer_config"));
        assert!(steps
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_refunds_credit_on_config_failure_before_rpc() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let response = run_ready(settle_http(batch_settle_request(&batch_settle_json())));

        assert_eq!(response.status_code, 400);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_config");
        assert_eq!(value["cost"]["rpcCalls"], 0);
    }

    #[test]
    fn batch_settle_requires_receiver_authorizer_key_before_reserve_when_signature_missing() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_default_batch_contract();
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let response = run_ready(settle_http(batch_settle_request(&batch_claim_json(
            "100", "75",
        ))));

        assert_eq!(response.status_code, 400);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_config");
        assert!(value["result"]["errorMessage"]
            .as_str()
            .unwrap()
            .contains("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"));
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_rejects_receiver_authorizer_key_matching_facilitator_key_before_reserve() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let response = run_ready(settle_http(batch_settle_request(&batch_settle_json())));

        assert_eq!(response.status_code, 400);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_config");
        assert_eq!(
            value["result"]["errorMessage"],
            "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address"
        );
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_rejects_mismatched_local_receiver_authorizer_key_before_reserve() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_default_batch_contract();
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        set_env_value(
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL",
            "ryjl3-tyaaa-aaaaa-aaaba-cai",
        );
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let response = run_ready(settle_http(batch_settle_request(&batch_claim_json(
            "100", "75",
        ))));

        assert_eq!(response.status_code, 400);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_config");
        assert_eq!(
            value["result"]["errorMessage"],
            "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY does not match receiverAuthorizer"
        );
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_refund_rejects_mismatched_local_receiver_authorizer_key_before_reserve() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_default_batch_contract();
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value("FACILITATOR_EVM_PRIVATE_KEY", SELLER_PRIVATE_KEY);
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", OTHER_PRIVATE_KEY);
        set_env_value(
            "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL",
            "ryjl3-tyaaa-aaaaa-aaaba-cai",
        );
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);

        let response = run_ready(settle_http(batch_settle_request(&batch_refund_json(
            "1", "0",
        ))));

        assert_eq!(response.status_code, 400);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_config");
        assert_eq!(
            value["result"]["errorMessage"],
            "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY does not match receiverAuthorizer"
        );
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_settle_rejects_bad_supplied_receiver_authorizer_signature_before_reserve() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);
        let receiver_authorizer = private_key_address(OTHER_PRIVATE_KEY).unwrap();
        let mut body =
            batch_claim_json_for_receiver_authorizer("100", "75", Some(&receiver_authorizer));
        let payload = batch_payload(&body["paymentPayload"]["payload"]).unwrap();
        let bad_signature = crate::tx::sign_batch_claims(
            payload.claims.as_deref().unwrap(),
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        body["paymentPayload"]["payload"]["claimAuthorizerSignature"] = json!(bad_signature);

        let response = run_ready(settle_http(batch_settle_request(&body)));

        assert_eq!(response.status_code, 402);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_batch_settlement");
        assert_eq!(
            value["result"]["errorMessage"],
            "batch claim authorizer signature mismatch"
        );
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
    }

    #[test]
    fn batch_calldata_uses_supplied_authorizer_signatures_without_local_key() {
        clear_env_values();
        let receiver_authorizer = private_key_address(OTHER_PRIVATE_KEY).unwrap();
        let mut claim_body =
            batch_claim_json_for_receiver_authorizer("100", "75", Some(&receiver_authorizer));
        let claim_payload = batch_payload(&claim_body["paymentPayload"]["payload"]).unwrap();
        let claim_signature = crate::tx::sign_batch_claims(
            claim_payload.claims.as_deref().unwrap(),
            OTHER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        claim_body["paymentPayload"]["payload"]["claimAuthorizerSignature"] =
            json!(claim_signature);
        let claim_payload = batch_payload(&claim_body["paymentPayload"]["payload"]).unwrap();
        assert_eq!(
            batch_authorizer_private_key_for_claim(&claim_payload).unwrap(),
            ""
        );
        assert!(batch_calldata(&claim_payload, DEFAULT_BATCH_SETTLEMENT_CONTRACT).is_ok());

        let mut refund_body = batch_refund_json("1", "0");
        refund_body["paymentPayload"]["payload"]["refundAuthorizerSignature"] =
            json!(format!("0x{}", "11".repeat(65)));
        let refund_payload = batch_payload(&refund_body["paymentPayload"]["payload"]).unwrap();
        assert_eq!(
            batch_authorizer_private_key_for_refund(&refund_payload).unwrap(),
            ""
        );
        assert!(batch_calldata(&refund_payload, DEFAULT_BATCH_SETTLEMENT_CONTRACT).is_ok());
    }

    #[test]
    fn batch_calldata_requires_local_authorizer_key_for_missing_signatures() {
        clear_env_values();
        let claim_payload =
            batch_payload(&batch_claim_json("100", "75")["paymentPayload"]["payload"]).unwrap();
        assert!(batch_authorizer_private_key_for_claim(&claim_payload)
            .unwrap_err()
            .contains("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"));

        let refund_payload =
            batch_payload(&batch_refund_json("1", "0")["paymentPayload"]["payload"]).unwrap();
        assert!(batch_authorizer_private_key_for_refund(&refund_payload)
            .unwrap_err()
            .contains("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"));
    }

    #[test]
    fn batch_refund_rejects_bad_supplied_receiver_authorizer_signature_before_reserve() {
        clear_settlement_state();
        clear_seller_credits();
        clear_env_values();
        set_env_value("FACILITATOR_DEBUG_COST", "1");
        set_env_value("JPYC_EIP712_VERSION", "1");
        set_full_batch_config();
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        add_seller_credit(&seller, 100);
        let mut body = batch_refund_json("1", "0");
        let payload = batch_payload(&body["paymentPayload"]["payload"]).unwrap();
        let config = payload.channel_config.as_ref().unwrap();
        let channel_id =
            compute_batch_channel_id(config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let bad_signature = crate::tx::sign_batch_refund(
            &channel_id,
            payload.amount.as_deref().unwrap(),
            payload.refund_nonce.as_deref().unwrap(),
            OTHER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        )
        .unwrap();
        body["paymentPayload"]["payload"]["refundAuthorizerSignature"] = json!(bad_signature);

        let response = run_ready(settle_http(batch_settle_request(&body)));

        assert_eq!(response.status_code, 402);
        assert_eq!(seller_credit_balance_for(&seller), 100);
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["result"]["errorReason"], "invalid_batch_settlement");
        assert_eq!(
            value["result"]["errorMessage"],
            "batch refund authorizer signature mismatch"
        );
        assert_eq!(value["cost"]["rpcCalls"], 0);
        assert!(value["cost"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["name"] != "batch_settle.reserve_seller_credit"));
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
    fn batch_settle_noop_rollback_restores_fee_nonce_and_active_lock() {
        clear_active_state();
        clear_seller_credits();
        let from = "0x0000000000000000000000000000000000000402";
        let seller = normalize_evm_address("seller", PAY_TO).unwrap();
        let scope = active_settlement_scope(from, &seller).unwrap();
        add_seller_credit(&seller, 500);

        assert!(acquire_active_settlement(&scope, "batch-noop"));
        reserve_seller_credit(&seller, 100).unwrap();
        let nonce = reserve_nonce(from, 7);
        assert_eq!(seller_credit_balance_for(&seller), 400);
        assert!(!acquire_active_settlement(&scope, "batch-next"));

        rollback_reserved_nonce(from, nonce);
        refund_seller_credit(&seller, 100);
        release_active_settlement(&scope, "batch-noop");

        assert_eq!(seller_credit_balance_for(&seller), 500);
        assert_eq!(reserve_nonce(from, 7), 7);
        assert!(acquire_active_settlement(&scope, "batch-next"));
        release_active_settlement(&scope, "batch-next");
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
