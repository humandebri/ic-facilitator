// rust/facilitator/src/rpc.rs: EVM RPC canister 経由で Polygon の読取・署名済みtx送信を実行する。
use candid::{CandidType, Deserialize as CandidDeserialize};
use canhttp::{
    cycles::{ChargeMyself, CyclesAccountingServiceBuilder},
    http::HttpConversionLayer,
    Client, IsReplicatedRequestExtension, MaxResponseBytesRequestExtension,
};
use http::Request;
use serde_json::{json, Value};
use tower::{Service, ServiceBuilder, ServiceExt};

#[cfg(test)]
use crate::hexutil::JPYC_POLYGON_ADDRESS;
use crate::hexutil::{address_word, parse_address};
use crate::hexutil::{parse_hex, parse_u256_hex, selector};
use crate::tx::{encode_settle_calldata, settle_to_address, sign_eip1559_tx, Eip1559Tx};
use crate::types::FacilitatorRequest;

const BLOCK_NUMBER_RESPONSE_SIZE_BYTES: u64 = 128;
const CALL_RESPONSE_SIZE_BYTES: u64 = 192;
const FEE_HISTORY_RESPONSE_SIZE_BYTES: u64 = 320;
// Polygon実測はログ0件相当1,031 bytes、3ログ最大3,258 bytes。現行batch ABIのclaimはイベントをemitしない。
const RECEIPT_RESPONSE_SIZE_BYTES: u64 = 4_096;
const SEND_RAW_TRANSACTION_RESPONSE_SIZE_BYTES: u64 = 512;
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const SETTLED_TOPIC: &str = "0x7337b4386b690fdb8ba66905b92b9d45d33bc6626ee2620c905fb150ec0cc47d";

pub struct RpcConfig {
    pub max_gas: u128,
    pub max_settlement_fee_wei: u128,
    pub min_confirmations: u64,
    pub url: String,
}

pub enum SettlementOutcome {
    Settled(String),
    Pending { nonce: u128, tx: String },
    Failed { tx: String, message: String },
}

pub enum ContractSettlementOutcome {
    Settled {
        tx: String,
        settled_amount: Option<String>,
    },
    Pending {
        nonce: u128,
        tx: String,
    },
    Failed {
        tx: String,
        message: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastedTransaction {
    pub nonce: u128,
    pub tx: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SettlementSendError {
    GasTooExpensive,
    Other(String),
}

impl From<String> for SettlementSendError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedTransfer {
    pub amount: String,
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeQuote {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractExpectation {
    Deposit,
    Claim,
    Settle { receiver: String, token: String },
    Refund,
}

#[derive(Clone, Debug, Eq, PartialEq, CandidType, CandidDeserialize)]
pub struct BatchChannelSnapshot {
    pub channel_id: String,
    pub balance: String,
    pub total_claimed: String,
    pub withdraw_requested_at: u64,
    pub refund_nonce: String,
}

impl BatchChannelSnapshot {
    pub fn to_json(&self) -> Value {
        json!({
            "channelId": self.channel_id,
            "balance": self.balance,
            "totalClaimed": self.total_claimed,
            "withdrawRequestedAt": self.withdraw_requested_at,
            "refundNonce": self.refund_nonce
        })
    }
}

pub async fn batch_unsettled_amount(
    config: &RpcConfig,
    contract: &[u8; 20],
    receiver: &str,
    token: &str,
) -> Result<Option<String>, String> {
    let state = batch_receiver_state(config, contract, receiver, token).await?;
    if !settle_has_unsettled_amount(&state.total_claimed, &state.total_settled) {
        return Ok(None);
    }
    decimal_sub(&state.total_claimed, &state.total_settled).map(Some)
}

pub async fn broadcast_settlement(
    config: &RpcConfig,
    private_key: &str,
    request: &FacilitatorRequest,
    nonce: u128,
) -> Result<BroadcastedTransaction, SettlementSendError> {
    let data = encode_settle_calldata(&request.payment_payload.payload)?;
    let from = crate::private_key_address(private_key)?;
    let fees = fee_quote(config).await?;
    let to = settle_to_address()?;
    let estimate = rpc_hex_u128(
        config,
        "eth_estimateGas",
        json!([{
            "from": from,
            "to": crate::hexutil::address_hex(&to),
            "data": format!("0x{}", hex::encode(&data))
        }]),
    )
    .await?;
    let gas_limit = estimate.saturating_mul(12) / 10;
    if gas_limit > config.max_gas {
        return Err("estimated settlement gas exceeds FACILITATOR_MAX_GAS"
            .to_string()
            .into());
    }
    ensure_settlement_fee_cap(
        gas_limit,
        fees.max_fee_per_gas,
        config.max_settlement_fee_wei,
    )?;
    let raw = sign_eip1559_tx(
        &Eip1559Tx {
            nonce,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit,
            to,
            value: 0,
            data,
            chain_id: crate::configured_chain_id(),
        },
        private_key,
    )?;
    let tx = send_raw_transaction(config, &raw).await?;
    Ok(BroadcastedTransaction { nonce, tx })
}

pub async fn confirm_settlement_broadcast(
    config: &RpcConfig,
    request: &FacilitatorRequest,
    broadcast: &BroadcastedTransaction,
) -> SettlementOutcome {
    let status = receipt_status_for_tx(config, &broadcast.tx, &expected_transfer(request)).await;
    post_broadcast_outcome(broadcast.tx.clone(), broadcast.nonce, status)
}

pub async fn broadcast_contract_transaction(
    config: &RpcConfig,
    private_key: &str,
    to: [u8; 20],
    data: Vec<u8>,
    nonce: u128,
) -> Result<BroadcastedTransaction, SettlementSendError> {
    let from = crate::private_key_address(private_key)?;
    let fees = fee_quote(config).await?;
    let estimate = rpc_hex_u128(
        config,
        "eth_estimateGas",
        json!([{
            "from": from,
            "to": crate::hexutil::address_hex(&to),
            "data": format!("0x{}", hex::encode(&data))
        }]),
    )
    .await?;
    let gas_limit = estimate.saturating_mul(12) / 10;
    if gas_limit > config.max_gas {
        return Err("estimated settlement gas exceeds FACILITATOR_MAX_GAS"
            .to_string()
            .into());
    }
    ensure_settlement_fee_cap(
        gas_limit,
        fees.max_fee_per_gas,
        config.max_settlement_fee_wei,
    )?;
    let raw = sign_eip1559_tx(
        &Eip1559Tx {
            nonce,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit,
            to,
            value: 0,
            data,
            chain_id: crate::configured_chain_id(),
        },
        private_key,
    )?;
    let tx = send_raw_transaction(config, &raw).await?;
    Ok(BroadcastedTransaction { nonce, tx })
}

pub async fn confirm_contract_broadcast(
    config: &RpcConfig,
    broadcast: &BroadcastedTransaction,
    to: &[u8; 20],
    expected_from: Option<&str>,
    expectation: &ContractExpectation,
) -> ContractSettlementOutcome {
    let status =
        receipt_status_for_contract_tx(config, &broadcast.tx, to, expected_from, expectation).await;
    post_contract_broadcast_outcome(broadcast.tx.clone(), broadcast.nonce, status)
}

fn ensure_settlement_fee_cap(
    gas_limit: u128,
    max_fee_per_gas: u128,
    cap_wei: u128,
) -> Result<(), SettlementSendError> {
    let Some(estimated_fee) = gas_limit.checked_mul(max_fee_per_gas) else {
        return Err(SettlementSendError::GasTooExpensive);
    };
    if estimated_fee > cap_wei {
        return Err(SettlementSendError::GasTooExpensive);
    }
    Ok(())
}

pub async fn refresh_settlement(
    config: &RpcConfig,
    tx: &str,
    expected: &ExpectedTransfer,
) -> Result<SettlementOutcome, String> {
    match receipt_status_for_tx(config, tx, expected).await? {
        ReceiptStatus::Success => Ok(SettlementOutcome::Settled(tx.to_string())),
        ReceiptStatus::Pending => Ok(SettlementOutcome::Pending {
            nonce: 0,
            tx: tx.to_string(),
        }),
        ReceiptStatus::Failed(message) => Ok(SettlementOutcome::Failed {
            tx: tx.to_string(),
            message,
        }),
    }
}

pub async fn refresh_contract_settlement(
    config: &RpcConfig,
    tx: &str,
    expected_to: &[u8; 20],
    expected_from: Option<&str>,
    expectation: &ContractExpectation,
) -> Result<ContractSettlementOutcome, String> {
    match receipt_status_for_contract_tx(config, tx, expected_to, expected_from, expectation)
        .await?
    {
        ContractReceiptStatus::Success { settled_amount } => {
            Ok(ContractSettlementOutcome::Settled {
                tx: tx.to_string(),
                settled_amount,
            })
        }
        ContractReceiptStatus::Pending => Ok(ContractSettlementOutcome::Pending {
            nonce: 0,
            tx: tx.to_string(),
        }),
        ContractReceiptStatus::Failed(message) => Ok(ContractSettlementOutcome::Failed {
            tx: tx.to_string(),
            message,
        }),
    }
}

async fn receipt_status_for_tx(
    config: &RpcConfig,
    tx: &str,
    expected: &ExpectedTransfer,
) -> Result<ReceiptStatus, String> {
    let result = rpc_value(config, "eth_getTransactionReceipt", json!([tx])).await?;
    if result.is_null() {
        return Ok(ReceiptStatus::Pending);
    }
    require_receipt_transaction_hash(&result, tx)?;
    let latest_block = rpc_hex_u128(config, "eth_blockNumber", json!([])).await?;
    Ok(receipt_status(
        &result,
        expected,
        latest_block,
        config.min_confirmations,
    ))
}

async fn receipt_status_for_contract_tx(
    config: &RpcConfig,
    tx: &str,
    expected_to: &[u8; 20],
    expected_from: Option<&str>,
    expectation: &ContractExpectation,
) -> Result<ContractReceiptStatus, String> {
    let result = rpc_value(config, "eth_getTransactionReceipt", json!([tx])).await?;
    if result.is_null() {
        return Ok(ContractReceiptStatus::Pending);
    }
    require_receipt_transaction_hash(&result, tx)?;
    let latest_block = rpc_hex_u128(config, "eth_blockNumber", json!([])).await?;
    Ok(receipt_status_for_contract(
        &result,
        expected_to,
        expected_from,
        expectation,
        latest_block,
        config.min_confirmations,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReceiptStatus {
    Success,
    Failed(String),
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContractReceiptStatus {
    Success { settled_amount: Option<String> },
    Failed(String),
    Pending,
}

fn post_broadcast_outcome(
    tx: String,
    nonce: u128,
    status: Result<ReceiptStatus, String>,
) -> SettlementOutcome {
    match status {
        Ok(ReceiptStatus::Success) => SettlementOutcome::Settled(tx),
        Ok(ReceiptStatus::Pending) | Err(_) => SettlementOutcome::Pending { nonce, tx },
        Ok(ReceiptStatus::Failed(message)) => SettlementOutcome::Failed { tx, message },
    }
}

fn post_contract_broadcast_outcome(
    tx: String,
    nonce: u128,
    status: Result<ContractReceiptStatus, String>,
) -> ContractSettlementOutcome {
    match status {
        Ok(ContractReceiptStatus::Success { settled_amount }) => {
            ContractSettlementOutcome::Settled { tx, settled_amount }
        }
        Ok(ContractReceiptStatus::Pending) | Err(_) => {
            ContractSettlementOutcome::Pending { nonce, tx }
        }
        Ok(ContractReceiptStatus::Failed(message)) => {
            ContractSettlementOutcome::Failed { tx, message }
        }
    }
}

fn require_receipt_transaction_hash(receipt: &Value, expected: &str) -> Result<(), String> {
    if receipt
        .get("transactionHash")
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
    {
        return Ok(());
    }
    Err("eth_getTransactionReceipt: transaction hash mismatch".to_string())
}

fn receipt_status(
    result: &Value,
    expected: &ExpectedTransfer,
    latest_block: u128,
    min_confirmations: u64,
) -> ReceiptStatus {
    match result.get("status").and_then(Value::as_str) {
        Some("0x0") => return ReceiptStatus::Failed("settlement tx failed".to_string()),
        Some("0x1") => {}
        _ => return ReceiptStatus::Pending,
    }
    let Some(block_number) = result
        .get("blockNumber")
        .and_then(Value::as_str)
        .and_then(|value| parse_hex_quantity("blockNumber", value).ok())
    else {
        return ReceiptStatus::Pending;
    };
    let confirmations = latest_block.saturating_sub(block_number).saturating_add(1);
    if confirmations < u128::from(min_confirmations) {
        return ReceiptStatus::Pending;
    }
    let expected_to = match settle_to_address().map(|address| crate::hexutil::address_hex(&address))
    {
        Ok(value) => value,
        Err(message) => return ReceiptStatus::Failed(message),
    };
    if !result
        .get("to")
        .and_then(Value::as_str)
        .map(|to| crate::hexutil::same_address(to, &expected_to))
        .unwrap_or(false)
    {
        return ReceiptStatus::Failed("settlement tx recipient mismatch".to_string());
    }
    if !has_expected_transfer(result, expected) {
        return ReceiptStatus::Failed("expected JPYC transfer log not found".to_string());
    }
    ReceiptStatus::Success
}

fn receipt_status_for_contract(
    result: &Value,
    expected_to: &[u8; 20],
    expected_from: Option<&str>,
    expectation: &ContractExpectation,
    latest_block: u128,
    min_confirmations: u64,
) -> ContractReceiptStatus {
    match result.get("status").and_then(Value::as_str) {
        Some("0x0") => return ContractReceiptStatus::Failed("settlement tx failed".to_string()),
        Some("0x1") => {}
        _ => return ContractReceiptStatus::Pending,
    }
    let Some(block_number) = result
        .get("blockNumber")
        .and_then(Value::as_str)
        .and_then(|value| parse_hex_quantity("blockNumber", value).ok())
    else {
        return ContractReceiptStatus::Pending;
    };
    let confirmations = latest_block.saturating_sub(block_number).saturating_add(1);
    if confirmations < u128::from(min_confirmations) {
        return ContractReceiptStatus::Pending;
    }
    let expected_to_address = crate::hexutil::address_hex(expected_to);
    if !result
        .get("to")
        .and_then(Value::as_str)
        .map(|to| crate::hexutil::same_address(to, &expected_to_address))
        .unwrap_or(false)
    {
        return ContractReceiptStatus::Failed("settlement tx recipient mismatch".to_string());
    }
    if expected_from.is_some_and(|from| {
        !result
            .get("from")
            .and_then(Value::as_str)
            .map(|actual| crate::hexutil::same_address(actual, from))
            .unwrap_or(false)
    }) {
        return ContractReceiptStatus::Failed("settlement tx sender mismatch".to_string());
    }
    let mut settled_amount = None;
    if let ContractExpectation::Settle { receiver, token } = expectation {
        let Some(amount) = settled_event_amount(result, expected_to, receiver, token) else {
            return ContractReceiptStatus::Failed(
                "expected batch Settled event not found".to_string(),
            );
        };
        if !decimal_greater(&amount, "0") {
            return ContractReceiptStatus::Failed("batch settled amount mismatch".to_string());
        }
        settled_amount = Some(amount);
    }
    ContractReceiptStatus::Success { settled_amount }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BatchReceiverState {
    total_claimed: String,
    total_settled: String,
}

async fn batch_receiver_state(
    config: &RpcConfig,
    contract: &[u8; 20],
    receiver: &str,
    token: &str,
) -> Result<BatchReceiverState, String> {
    let receiver = parse_address(receiver, "receiver")?;
    let token = parse_address(token, "token")?;
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&selector("receivers(address,address)"));
    data.extend_from_slice(&address_word(&receiver));
    data.extend_from_slice(&address_word(&token));
    let result = eth_call(config, contract, data).await?;
    let words = parse_words(&result, 2, "receivers")?;
    Ok(BatchReceiverState {
        total_claimed: uint128_hex_decimal_word(&words[0], "receivers.totalClaimed")?,
        total_settled: uint128_hex_decimal_word(&words[1], "receivers.totalSettled")?,
    })
}

async fn eth_call(
    config: &RpcConfig,
    contract: &[u8; 20],
    data: Vec<u8>,
) -> Result<String, String> {
    rpc_string(
        config,
        "eth_call",
        json!([{
            "to": crate::hexutil::address_hex(contract),
            "data": format!("0x{}", hex::encode(data))
        }, "latest"]),
    )
    .await
}

pub async fn pending_nonce(config: &RpcConfig, from: &str) -> Result<u128, String> {
    rpc_hex_u128(config, "eth_getTransactionCount", json!([from, "pending"])).await
}

async fn fee_quote(config: &RpcConfig) -> Result<FeeQuote, String> {
    let value = rpc_value(config, "eth_feeHistory", json!(["0x1", "latest", [50]])).await?;
    fee_quote_from_history(&value)
}

fn fee_quote_from_history(value: &Value) -> Result<FeeQuote, String> {
    let base_fee = value
        .get("baseFeePerGas")
        .and_then(Value::as_array)
        .and_then(|items| items.last())
        .and_then(Value::as_str)
        .ok_or_else(|| "eth_feeHistory: missing next baseFeePerGas".to_string())
        .and_then(|value| parse_hex_quantity("baseFeePerGas", value))?;
    let priority_fee = value
        .get("reward")
        .and_then(Value::as_array)
        .and_then(|rows| rows.first())
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .ok_or_else(|| "eth_feeHistory: missing reward percentile".to_string())
        .and_then(|value| parse_hex_quantity("reward", value))?;
    Ok(FeeQuote {
        max_fee_per_gas: base_fee.saturating_mul(2).saturating_add(priority_fee),
        max_priority_fee_per_gas: priority_fee,
    })
}

async fn rpc_hex_u128(config: &RpcConfig, method: &str, params: Value) -> Result<u128, String> {
    let value = rpc_string(config, method, params).await?;
    parse_hex_quantity(method, &value)
}

fn parse_hex_quantity(label: &str, value: &str) -> Result<u128, String> {
    let raw = value.trim_start_matches("0x");
    if raw.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(raw, 16).map_err(|_| format!("{label}: invalid hex quantity"))
}

async fn rpc_string(config: &RpcConfig, method: &str, params: Value) -> Result<String, String> {
    rpc_value(config, method, params)
        .await?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{method}: result is not a string"))
}

async fn rpc_value(config: &RpcConfig, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let text = rpc_post(config, method, &body, response_size_for_method(method)?).await?;
    parse_rpc_value(method, &text)
}

fn parse_rpc_value(method: &str, text: &str) -> Result<Value, String> {
    let value: Value =
        serde_json::from_str(&text).map_err(|_| format!("invalid rpc json: {text}"))?;
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || value.get("id").and_then(Value::as_u64) != Some(1)
    {
        return Err(format!("{method}: invalid JSON-RPC envelope"));
    }
    if let Some(error) = value.get("error") {
        return Err(format!("{method}: {error}"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: missing result"))
}

async fn send_raw_transaction(config: &RpcConfig, raw: &str) -> Result<String, String> {
    let fallback_hash = raw_transaction_hash(raw)?;
    parse_hex(raw, None).map_err(|err| format!("eth_sendRawTransaction: {err}"))?;
    match rpc_string(config, "eth_sendRawTransaction", json!([raw])).await {
        Ok(returned_hash) if returned_hash.eq_ignore_ascii_case(&fallback_hash) => {
            Ok(fallback_hash)
        }
        Ok(returned_hash) => Err(format!(
            "eth_sendRawTransaction: returned transaction hash mismatch: {returned_hash}"
        )),
        Err(message) if message.to_ascii_lowercase().contains("already known") => Ok(fallback_hash),
        Err(message) => Err(message),
    }
}

fn raw_transaction_hash(raw: &str) -> Result<String, String> {
    let bytes = crate::hexutil::parse_hex(raw, None)?;
    Ok(format!(
        "0x{}",
        hex::encode(crate::hexutil::keccak256(&bytes))
    ))
}

fn response_size_for_method(method: &str) -> Result<u64, String> {
    Ok(match method {
        "eth_blockNumber" | "eth_estimateGas" | "eth_getTransactionCount" => {
            BLOCK_NUMBER_RESPONSE_SIZE_BYTES
        }
        "eth_call" => CALL_RESPONSE_SIZE_BYTES,
        "eth_feeHistory" => FEE_HISTORY_RESPONSE_SIZE_BYTES,
        "eth_getTransactionReceipt" => RECEIPT_RESPONSE_SIZE_BYTES,
        "eth_sendRawTransaction" => SEND_RAW_TRANSACTION_RESPONSE_SIZE_BYTES,
        _ => return Err(format!("unsupported RPC method: {method}")),
    })
}

async fn rpc_post(
    config: &RpcConfig,
    method: &str,
    body: &Value,
    max_response_bytes: u64,
) -> Result<String, String> {
    let request = build_rpc_request(&config.url, method, body, max_response_bytes)?;
    let mut service = ServiceBuilder::new()
        .layer(HttpConversionLayer)
        .cycles_accounting(ChargeMyself::default())
        .service(Client::new_with_box_error());
    let response = service
        .ready()
        .await
        .map_err(|err| format!("{method}: HTTPS outcall unavailable: {err}"))?
        .call(request)
        .await
        .map_err(|err| format!("{method}: HTTPS outcall failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("{method}: RPC HTTP status {}", response.status()));
    }
    String::from_utf8(response.into_body())
        .map_err(|_| format!("{method}: RPC response is not UTF-8"))
}

fn build_rpc_request(
    url: &str,
    method: &str,
    body: &Value,
    max_response_bytes: u64,
) -> Result<Request<Vec<u8>>, String> {
    validate_rpc_url(url)?;
    Request::post(url)
        .header("content-type", "application/json")
        .max_response_bytes(max_response_bytes)
        .replicated(false)
        .body(serde_json::to_vec(body).map_err(|err| format!("{method}: {err}"))?)
        .map_err(|err| format!("{method}: invalid HTTP request: {err}"))
}

fn validate_rpc_url(value: &str) -> Result<(), String> {
    let uri = value.parse::<http::Uri>().map_err(|_| {
        "POLYGON_RPC_URL must be a HTTPS URL without userinfo or fragment".to_string()
    })?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || value.contains('#')
    {
        return Err("POLYGON_RPC_URL must be a HTTPS URL without userinfo or fragment".to_string());
    }
    Ok(())
}

pub fn expected_transfer(request: &FacilitatorRequest) -> ExpectedTransfer {
    let auth = &request.payment_payload.payload.authorization;
    ExpectedTransfer {
        amount: request.payment_requirements.amount.clone(),
        from: auth.from.clone(),
        to: request.payment_requirements.pay_to.clone(),
    }
}

fn has_expected_transfer(receipt: &Value, expected: &ExpectedTransfer) -> bool {
    let Some(logs) = receipt.get("logs").and_then(Value::as_array) else {
        return false;
    };
    logs.iter().any(|log| transfer_log_matches(log, expected))
}

fn transfer_log_matches(log: &Value, expected: &ExpectedTransfer) -> bool {
    if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
        return false;
    }
    if !log
        .get("address")
        .and_then(Value::as_str)
        .map(|address| {
            crate::configured_token_address()
                .is_ok_and(|token| crate::hexutil::same_address(address, &token))
        })
        .unwrap_or(false)
    {
        return false;
    }
    let Some(topics) = log.get("topics").and_then(Value::as_array) else {
        return false;
    };
    if topics.len() < 3 {
        return false;
    }
    if !topics[0]
        .as_str()
        .map(|topic| topic.eq_ignore_ascii_case(TRANSFER_TOPIC))
        .unwrap_or(false)
    {
        return false;
    }
    let Some(from) = topics[1].as_str().and_then(topic_address) else {
        return false;
    };
    let Some(to) = topics[2].as_str().and_then(topic_address) else {
        return false;
    };
    let Some(amount) = log
        .get("data")
        .and_then(Value::as_str)
        .and_then(uint256_hex_decimal)
    else {
        return false;
    };
    crate::hexutil::same_address(&from, &expected.from)
        && crate::hexutil::same_address(&to, &expected.to)
        && amount == expected.amount
}

fn settled_event_amount(
    receipt: &Value,
    contract: &[u8; 20],
    receiver: &str,
    token: &str,
) -> Option<String> {
    let logs = receipt.get("logs").and_then(Value::as_array)?;
    let sender = receipt.get("from").and_then(Value::as_str)?;
    let contract = crate::hexutil::address_hex(contract);
    let mut total = String::from("0");
    let mut matched = false;
    for log in logs {
        let Some(amount) = settled_log_amount(log, &contract, receiver, token, sender) else {
            continue;
        };
        total = decimal_add(&total, &amount).ok()?;
        matched = true;
    }
    matched.then_some(total)
}

fn settled_log_amount(
    log: &Value,
    contract: &str,
    receiver: &str,
    token: &str,
    sender: &str,
) -> Option<String> {
    if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    if !log
        .get("address")
        .and_then(Value::as_str)
        .map(|address| crate::hexutil::same_address(address, contract))
        .unwrap_or(false)
    {
        return None;
    }
    let topics = log.get("topics").and_then(Value::as_array)?;
    if topics.len() < 4 {
        return None;
    }
    if !topics[0]
        .as_str()
        .map(|topic| topic.eq_ignore_ascii_case(SETTLED_TOPIC))
        .unwrap_or(false)
    {
        return None;
    }
    let log_receiver = topics[1].as_str().and_then(topic_address)?;
    let log_token = topics[2].as_str().and_then(topic_address)?;
    let log_sender = topics[3].as_str().and_then(topic_address)?;
    if !crate::hexutil::same_address(&log_receiver, receiver)
        || !crate::hexutil::same_address(&log_token, token)
        || !crate::hexutil::same_address(&log_sender, sender)
    {
        return None;
    }
    log.get("data")
        .and_then(Value::as_str)
        .and_then(uint256_hex_decimal)
}

fn topic_address(topic: &str) -> Option<String> {
    let raw = crate::hexutil::strip_0x(topic);
    if raw.len() != 64 {
        return None;
    }
    Some(format!("0x{}", &raw[24..]))
}

fn uint256_hex_decimal(value: &str) -> Option<String> {
    let bytes = parse_u256_hex(value, "uint256").ok()?;
    Some(uint256_hex_decimal_word(&bytes))
}

fn uint256_hex_decimal_word(bytes: &[u8; 32]) -> String {
    let mut decimal = String::from("0");
    for byte in bytes {
        decimal = decimal_mul_small(&decimal, 256);
        decimal = decimal_add_small(&decimal, *byte);
    }
    decimal
}

fn uint128_hex_decimal_word(bytes: &[u8; 32], label: &str) -> Result<String, String> {
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return Err(format!("{label} exceeds uint128"));
    }
    Ok(uint256_hex_decimal_word(bytes))
}

fn parse_words(value: &str, count: usize, label: &str) -> Result<Vec<[u8; 32]>, String> {
    let bytes = parse_hex(value, Some(32 * count)).map_err(|err| format!("{label}: {err}"))?;
    Ok(bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut word = [0u8; 32];
            word.copy_from_slice(chunk);
            word
        })
        .collect())
}

fn decimal_at_least(left: &str, right: &str) -> bool {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    let left = if left.is_empty() { "0" } else { left };
    let right = if right.is_empty() { "0" } else { right };
    left.len() > right.len() || (left.len() == right.len() && left >= right)
}

fn decimal_greater(left: &str, right: &str) -> bool {
    decimal_at_least(left, right) && decimal_normalize(left) != decimal_normalize(right)
}

fn decimal_normalize(value: &str) -> &str {
    let value = value.trim_start_matches('0');
    if value.is_empty() {
        "0"
    } else {
        value
    }
}

fn decimal_add(left: &str, right: &str) -> Result<String, String> {
    if !left.bytes().all(|byte| byte.is_ascii_digit())
        || !right.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("decimal value must contain only digits".to_string());
    }
    let mut carry = 0u16;
    let mut out = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut left = left.bytes().rev();
    let mut right = right.bytes().rev();
    loop {
        let next_left = left.next();
        let next_right = right.next();
        if next_left.is_none() && next_right.is_none() && carry == 0 {
            break;
        }
        let a = next_left.map(|byte| u16::from(byte - b'0')).unwrap_or(0);
        let b = next_right.map(|byte| u16::from(byte - b'0')).unwrap_or(0);
        let next = a + b + carry;
        out.push((next % 10) as u8 + b'0');
        carry = next / 10;
    }
    out.reverse();
    String::from_utf8(out).map_err(|_| "decimal addition failed".to_string())
}

fn decimal_sub(left: &str, right: &str) -> Result<String, String> {
    if !left.bytes().all(|byte| byte.is_ascii_digit())
        || !right.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("decimal value must contain only digits".to_string());
    }
    if !decimal_at_least(left, right) {
        return Err("decimal subtraction underflow".to_string());
    }
    let mut borrow = 0i16;
    let mut out = Vec::with_capacity(left.len());
    let mut left = left.bytes().rev();
    let mut right = right.bytes().rev();
    loop {
        let next_left = left.next();
        let next_right = right.next();
        if next_left.is_none() && next_right.is_none() {
            break;
        }
        let mut a = next_left.map(|byte| i16::from(byte - b'0')).unwrap_or(0) - borrow;
        let b = next_right.map(|byte| i16::from(byte - b'0')).unwrap_or(0);
        if a < b {
            a += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push((a - b) as u8 + b'0');
    }
    while out.len() > 1 && out.last() == Some(&b'0') {
        out.pop();
    }
    out.reverse();
    String::from_utf8(out).map_err(|_| "decimal subtraction failed".to_string())
}

fn settle_has_unsettled_amount(total_claimed: &str, total_settled: &str) -> bool {
    decimal_greater(total_claimed, total_settled)
}

fn decimal_mul_small(value: &str, factor: u16) -> String {
    let mut carry = 0u16;
    let mut out = Vec::with_capacity(value.len() + 3);
    for ch in value.bytes().rev() {
        let next = u16::from(ch - b'0') * factor + carry;
        out.push((next % 10) as u8 + b'0');
        carry = next / 10;
    }
    while carry > 0 {
        out.push((carry % 10) as u8 + b'0');
        carry /= 10;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
}

fn decimal_add_small(value: &str, addend: u8) -> String {
    let mut carry = u16::from(addend);
    let mut out = Vec::with_capacity(value.len() + 3);
    for ch in value.bytes().rev() {
        let next = u16::from(ch - b'0') + carry;
        out.push((next % 10) as u8 + b'0');
        carry = next / 10;
    }
    while carry > 0 {
        out.push((carry % 10) as u8 + b'0');
        carry /= 10;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_conservative_response_size_by_rpc_method() {
        for method in [
            "eth_blockNumber",
            "eth_estimateGas",
            "eth_getTransactionCount",
        ] {
            assert_eq!(
                response_size_for_method(method).unwrap(),
                BLOCK_NUMBER_RESPONSE_SIZE_BYTES
            );
        }
        assert_eq!(
            response_size_for_method("eth_call").unwrap(),
            CALL_RESPONSE_SIZE_BYTES
        );
        assert_eq!(
            response_size_for_method("eth_feeHistory").unwrap(),
            FEE_HISTORY_RESPONSE_SIZE_BYTES
        );
        assert_eq!(
            response_size_for_method("eth_getTransactionReceipt").unwrap(),
            RECEIPT_RESPONSE_SIZE_BYTES
        );
        assert_eq!(
            response_size_for_method("eth_sendRawTransaction").unwrap(),
            SEND_RAW_TRANSACTION_RESPONSE_SIZE_BYTES
        );
        assert!(response_size_for_method("eth_unknownMethod").is_err());
    }

    #[test]
    fn rpc_url_must_be_https_without_credentials_or_fragment() {
        assert!(validate_rpc_url("https://polygon.example").is_ok());
        assert!(validate_rpc_url("https://polygon.example:443").is_ok());
        assert!(validate_rpc_url("https://polygon.example/v1/key?mode=fast").is_ok());
        assert!(validate_rpc_url("").is_err());
        assert!(validate_rpc_url("http://polygon.example").is_err());
        assert!(validate_rpc_url("https://trusted.example@evil.example").is_err());
        assert!(validate_rpc_url("https://polygon.example#x").is_err());
    }

    #[test]
    fn rpc_request_is_non_replicated_and_has_method_response_limit() {
        let request = build_rpc_request(
            "https://polygon.example/v1/key",
            "eth_blockNumber",
            &json!({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}),
            BLOCK_NUMBER_RESPONSE_SIZE_BYTES,
        )
        .unwrap();
        assert_eq!(request.get_is_replicated(), Some(false));
        assert_eq!(
            request.get_max_response_bytes(),
            Some(BLOCK_NUMBER_RESPONSE_SIZE_BYTES)
        );
        assert_eq!(
            request.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn rpc_response_rejects_invalid_json_rpc_envelopes_and_errors() {
        assert_eq!(
            parse_rpc_value(
                "eth_blockNumber",
                r#"{"jsonrpc":"2.0","id":2,"result":"0x1"}"#
            )
            .unwrap_err(),
            "eth_blockNumber: invalid JSON-RPC envelope"
        );
        assert!(parse_rpc_value(
            "eth_blockNumber",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"failed"}}"#
        )
        .unwrap_err()
        .contains("failed"));
        assert!(parse_rpc_value("eth_blockNumber", "not-json")
            .unwrap_err()
            .starts_with("invalid rpc json"));
        assert_eq!(
            parse_rpc_value(
                "eth_blockNumber",
                r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#
            )
            .unwrap(),
            json!("0x1")
        );
    }

    #[test]
    fn verifies_receipt_transfer() {
        let expected = ExpectedTransfer {
            amount: "100".to_string(),
            from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
            to: "0x1000000000000000000000000000000000000402".to_string(),
        };
        let success_receipt = json!({
            "status":"0x1",
            "blockNumber":"0x64",
            "to": JPYC_POLYGON_ADDRESS,
            "logs": [{
                "address": JPYC_POLYGON_ADDRESS,
                "topics": [
                    TRANSFER_TOPIC,
                    "0x000000000000000000000000b51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
                    "0x0000000000000000000000001000000000000000000000000000000000000402"
                ],
                "data": "0x64"
            }]
        });
        assert_eq!(
            receipt_status(&success_receipt, &expected, 102, 3),
            ReceiptStatus::Success
        );
        assert_eq!(
            receipt_status(&success_receipt, &expected, 101, 3),
            ReceiptStatus::Pending
        );
        assert_eq!(
            receipt_status(&json!({"status":"0x0"}), &expected, 102, 3),
            ReceiptStatus::Failed("settlement tx failed".to_string())
        );
        assert_eq!(
            receipt_status(&json!({"status":"0x1"}), &expected, 102, 3),
            ReceiptStatus::Pending
        );
        assert_eq!(
            receipt_status(
                &json!({"status":"0x1","blockNumber":"0x64","to":JPYC_POLYGON_ADDRESS,"logs":[]}),
                &expected,
                102,
                3
            ),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );
        assert_eq!(
            receipt_status(
                &json!({"status":"0x1","blockNumber":"0x64","to":"0x0000000000000000000000000000000000000001","logs":[]}),
                &expected,
                102,
                3
            ),
            ReceiptStatus::Failed("settlement tx recipient mismatch".to_string())
        );

        let mut token_mismatch = success_receipt.clone();
        token_mismatch["logs"][0]["address"] = json!("0x0000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status(&token_mismatch, &expected, 102, 3),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );

        let mut from_mismatch = success_receipt.clone();
        from_mismatch["logs"][0]["topics"][1] =
            json!("0x000000000000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status(&from_mismatch, &expected, 102, 3),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );

        let mut to_mismatch = success_receipt.clone();
        to_mismatch["logs"][0]["topics"][2] =
            json!("0x000000000000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status(&to_mismatch, &expected, 102, 3),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );

        let mut amount_mismatch = success_receipt;
        amount_mismatch["logs"][0]["data"] = json!("0x65");
        assert_eq!(
            receipt_status(&amount_mismatch, &expected, 102, 3),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );

        let mut removed_transfer = json!({
            "status":"0x1",
            "blockNumber":"0x64",
            "to": JPYC_POLYGON_ADDRESS,
            "logs": [{
                "removed": true,
                "address": JPYC_POLYGON_ADDRESS,
                "topics": [
                    TRANSFER_TOPIC,
                    "0x000000000000000000000000b51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
                    "0x0000000000000000000000001000000000000000000000000000000000000402"
                ],
                "data": "0x64"
            }]
        });
        assert_eq!(
            receipt_status(&removed_transfer, &expected, 102, 3),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );
        removed_transfer["logs"][0]["removed"] = json!(false);
        assert_eq!(
            receipt_status(&removed_transfer, &expected, 102, 3),
            ReceiptStatus::Success
        );
    }

    #[test]
    fn post_broadcast_rpc_error_keeps_settlement_pending() {
        match post_broadcast_outcome(
            "0xabc".to_string(),
            7,
            Err("eth_getTransactionReceipt: provider unavailable".to_string()),
        ) {
            SettlementOutcome::Pending { nonce, tx } => {
                assert_eq!(nonce, 7);
                assert_eq!(tx, "0xabc");
            }
            _ => panic!("expected pending outcome"),
        }

        match post_broadcast_outcome(
            "0xdef".to_string(),
            8,
            Ok(ReceiptStatus::Failed("settlement tx failed".to_string())),
        ) {
            SettlementOutcome::Failed { tx, message } => {
                assert_eq!(tx, "0xdef");
                assert_eq!(message, "settlement tx failed");
            }
            _ => panic!("expected failed outcome"),
        }

        match post_broadcast_outcome("0x123".to_string(), 9, Ok(ReceiptStatus::Success)) {
            SettlementOutcome::Settled(tx) => assert_eq!(tx, "0x123"),
            _ => panic!("expected settled outcome"),
        }
    }

    #[test]
    fn batch_settle_receipt_requires_settled_event() {
        let contract =
            crate::hexutil::parse_address("0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003", "contract")
                .unwrap();
        let expectation = ContractExpectation::Settle {
            receiver: "0x1000000000000000000000000000000000000402".to_string(),
            token: JPYC_POLYGON_ADDRESS.to_string(),
        };
        let success_receipt = json!({
            "status":"0x1",
            "blockNumber":"0x64",
            "from":"0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
            "to":"0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003",
            "logs": [{
                "address": "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003",
                "topics": [
                    SETTLED_TOPIC,
                    "0x0000000000000000000000001000000000000000000000000000000000000402",
                    "0x000000000000000000000000431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
                    "0x000000000000000000000000b51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"
                ],
                "data": "0x64"
            }]
        });

        assert_eq!(
            receipt_status_for_contract(
                &success_receipt,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Success {
                settled_amount: Some("100".to_string())
            }
        );

        let mut split_events = success_receipt.clone();
        split_events["logs"][0]["data"] = json!("0x28");
        let mut second_event = split_events["logs"][0].clone();
        second_event["data"] = json!("0x3c");
        split_events["logs"] = json!([split_events["logs"][0].clone(), second_event]);
        assert_eq!(
            receipt_status_for_contract(
                &split_events,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Success {
                settled_amount: Some("100".to_string())
            }
        );

        let mut receipt_sender_mismatch = success_receipt.clone();
        receipt_sender_mismatch["from"] = json!("0x0000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status_for_contract(
                &receipt_sender_mismatch,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Failed("settlement tx sender mismatch".to_string())
        );

        let mut removed_event = success_receipt.clone();
        removed_event["logs"][0]["removed"] = json!(true);
        assert_eq!(
            receipt_status_for_contract(
                &removed_event,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Failed("expected batch Settled event not found".to_string())
        );

        let mut missing_event = success_receipt.clone();
        missing_event["logs"] = json!([]);
        assert_eq!(
            receipt_status_for_contract(
                &missing_event,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Failed("expected batch Settled event not found".to_string())
        );

        let mut sender_mismatch = success_receipt.clone();
        sender_mismatch["logs"][0]["topics"][3] =
            json!("0x000000000000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status_for_contract(
                &sender_mismatch,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Failed("expected batch Settled event not found".to_string())
        );

        let mut different_amount = success_receipt.clone();
        different_amount["logs"][0]["data"] = json!("0x63");
        assert_eq!(
            receipt_status_for_contract(
                &different_amount,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Success {
                settled_amount: Some("99".to_string())
            }
        );

        let mut zero_amount = success_receipt.clone();
        zero_amount["logs"][0]["data"] = json!("0x0");
        assert_eq!(
            receipt_status_for_contract(
                &zero_amount,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Failed("batch settled amount mismatch".to_string())
        );

        let mut token_mismatch = success_receipt;
        token_mismatch["logs"][0]["topics"][2] =
            json!("0x000000000000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status_for_contract(
                &token_mismatch,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ContractReceiptStatus::Failed("expected batch Settled event not found".to_string())
        );
    }

    #[test]
    fn parses_batch_post_state_words_and_decimal_comparison() {
        let words = parse_words(
            "0x0000000000000000000000000000000000000000000000000000000000000064\
              000000000000000000000000000000000000000000000000000000000000000a",
            2,
            "channels",
        )
        .unwrap();

        assert_eq!(uint256_hex_decimal_word(&words[0]), "100");
        assert_eq!(
            uint128_hex_decimal_word(&words[0], "channels.balance").unwrap(),
            "100"
        );
        assert_eq!(uint256_hex_decimal_word(&words[1]), "10");
        assert!(decimal_at_least("100", "99"));
        assert!(decimal_at_least("00100", "100"));
        assert!(!decimal_at_least("99", "100"));
        assert_eq!(decimal_sub("100", "001").unwrap(), "99");
        assert_eq!(decimal_sub("100", "100").unwrap(), "0");
        assert_eq!(
            decimal_sub("99", "100"),
            Err("decimal subtraction underflow".to_string())
        );
        assert_eq!(
            decimal_sub("1x", "1"),
            Err("decimal value must contain only digits".to_string())
        );
        let mut over_uint128 = [0u8; 32];
        over_uint128[15] = 1;
        assert_eq!(
            uint128_hex_decimal_word(&over_uint128, "channels.balance"),
            Err("channels.balance exceeds uint128".to_string())
        );
    }

    #[test]
    fn batch_channel_snapshot_serializes_verify_extra_shape() {
        let snapshot = BatchChannelSnapshot {
            channel_id: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            balance: "1000".to_string(),
            total_claimed: "300".to_string(),
            withdraw_requested_at: 42,
            refund_nonce: "2".to_string(),
        };

        assert_eq!(
            snapshot.to_json(),
            json!({
                "channelId": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "balance": "1000",
                "totalClaimed": "300",
                "withdrawRequestedAt": 42,
                "refundNonce": "2"
            })
        );
    }

    #[test]
    fn validates_batch_settle_noop_state() {
        assert!(settle_has_unsettled_amount("300", "100"));
        assert!(!settle_has_unsettled_amount("300", "300"));
        assert!(!settle_has_unsettled_amount("299", "300"));
    }

    #[test]
    fn fee_history_quote_uses_next_base_fee_and_reward() {
        let quote = fee_quote_from_history(&json!({
            "oldestBlock": "0x1",
            "baseFeePerGas": ["0xa", "0x14"],
            "gasUsedRatio": [0.5],
            "reward": [["0x3"]]
        }))
        .unwrap();
        assert_eq!(
            quote,
            FeeQuote {
                max_fee_per_gas: 43,
                max_priority_fee_per_gas: 3,
            }
        );
    }

    #[test]
    fn fee_history_quote_requires_base_fee_and_reward() {
        assert_eq!(
            fee_quote_from_history(&json!({"reward":[["0x1"]]})).unwrap_err(),
            "eth_feeHistory: missing next baseFeePerGas"
        );
        assert_eq!(
            fee_quote_from_history(&json!({"baseFeePerGas":["0x1"]})).unwrap_err(),
            "eth_feeHistory: missing reward percentile"
        );
    }

    #[test]
    fn calldata_uses_transfer_with_authorization_call() {
        let request: FacilitatorRequest = serde_json::from_value(json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "accepted": {
                    "scheme": "exact",
                    "network": "eip155:137",
                    "asset": JPYC_POLYGON_ADDRESS,
                    "amount": "100",
                    "payTo": "0x1000000000000000000000000000000000000402",
                    "maxTimeoutSeconds": 60,
                    "extra": { "assetTransferMethod": "eip3009", "name": "JPY Coin", "version": "1" }
                },
                "payload": {
                    "signature": format!("0x{}1b", "11".repeat(64)),
                    "authorization": {
                        "from": "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
                        "to": "0x1000000000000000000000000000000000000402",
                        "value": "100",
                        "validAfter": "1",
                        "validBefore": "9999999999",
                        "nonce": format!("0x{}", "22".repeat(32))
                    }
                }
            },
            "paymentRequirements": {
                "scheme": "exact",
                "network": "eip155:137",
                "asset": JPYC_POLYGON_ADDRESS,
                "amount": "100",
                "payTo": "0x1000000000000000000000000000000000000402",
                "maxTimeoutSeconds": 60,
                "extra": { "assetTransferMethod": "eip3009", "name": "JPY Coin", "version": "1" }
            }
        }))
        .unwrap();
        let data = encode_settle_calldata(&request.payment_payload.payload).unwrap();
        assert_eq!(
            &data[..4],
            &selector(
                "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
            )
        );
        assert_ne!(&data[..4], &selector("balanceOf(address)"));
        assert_ne!(&data[..4], &selector("authorizationState(address,bytes32)"));
    }

    #[test]
    fn gas_cap_allows_fee_equal_to_cap() {
        assert_eq!(ensure_settlement_fee_cap(3, 10, 30), Ok(()));
    }

    #[test]
    fn gas_cap_rejects_fee_above_cap() {
        assert_eq!(
            ensure_settlement_fee_cap(3, 11, 30),
            Err(SettlementSendError::GasTooExpensive)
        );
    }

    #[test]
    fn gas_cap_rejects_overflow() {
        assert_eq!(
            ensure_settlement_fee_cap(u128::MAX, 2, u128::MAX),
            Err(SettlementSendError::GasTooExpensive)
        );
    }
}
