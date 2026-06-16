// rust/facilitator/src/rpc.rs: EVM RPC canister 経由で Polygon の読取・署名済みtx送信を実行する。
use candid::Principal;
use evm_rpc_client::{EvmRpcClient, EVM_RPC_CANISTER};
use evm_rpc_types::{
    ConsensusStrategy, Hex, MultiRpcResult, RpcApi, RpcServices, SendRawTransactionStatus,
};
use ic_canister_runtime::IcRuntime;
use serde_json::{json, Value};
use std::str::FromStr;

#[cfg(test)]
use crate::hexutil::selector;
use crate::hexutil::{parse_u256_hex, JPYC_POLYGON_ADDRESS};
use crate::tx::{encode_settle_calldata, settle_to_address, sign_eip1559_tx, Eip1559Tx};
use crate::types::FacilitatorRequest;

const POLYGON_CHAIN_ID: u64 = 137;
const RESPONSE_SIZE_BYTES: u64 = 20_000;
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

pub struct RpcConfig {
    pub max_gas: u128,
    pub max_settlement_fee_wei: u128,
    pub services: String,
}

pub enum SettlementOutcome {
    Settled(String),
    Pending { nonce: u128, tx: String },
    Failed { tx: String, message: String },
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

pub async fn send_settlement(
    config: &RpcConfig,
    private_key: &str,
    request: &FacilitatorRequest,
    nonce: u128,
) -> Result<SettlementOutcome, SettlementSendError> {
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
            chain_id: POLYGON_CHAIN_ID,
        },
        private_key,
    )?;
    let tx = send_raw_transaction(config, &raw).await?;
    match receipt_status_for_tx(config, &tx, &expected_transfer(request)).await? {
        ReceiptStatus::Success => Ok(SettlementOutcome::Settled(tx)),
        ReceiptStatus::Pending => Ok(SettlementOutcome::Pending { nonce, tx }),
        ReceiptStatus::Failed(message) => Ok(SettlementOutcome::Failed { tx, message }),
    }
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

async fn receipt_status_for_tx(
    config: &RpcConfig,
    tx: &str,
    expected: &ExpectedTransfer,
) -> Result<ReceiptStatus, String> {
    let result = rpc_value(config, "eth_getTransactionReceipt", json!([tx])).await?;
    Ok(receipt_status(&result, expected))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReceiptStatus {
    Success,
    Failed(String),
    Pending,
}

fn receipt_status(result: &Value, expected: &ExpectedTransfer) -> ReceiptStatus {
    if result.is_null() {
        return ReceiptStatus::Pending;
    }
    match result.get("status").and_then(Value::as_str) {
        Some("0x0") => return ReceiptStatus::Failed("settlement tx failed".to_string()),
        Some("0x1") => {}
        _ => return ReceiptStatus::Pending,
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
    let text = client(config)?
        .multi_request(body)
        .send()
        .await
        .pipe(consistent_result)
        .map_err(|err| format!("{method}: {err}"))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|_| format!("invalid rpc json: {text}"))?;
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
    let raw = Hex::from_str(raw).map_err(|err| format!("eth_sendRawTransaction: {err}"))?;
    let result = client(config)?
        .send_raw_transaction(raw)
        .send()
        .await
        .pipe(consistent_result)
        .map_err(|err| format!("eth_sendRawTransaction: {err}"))?;

    match result {
        SendRawTransactionStatus::Ok(Some(tx)) => Ok(tx.to_string()),
        SendRawTransactionStatus::Ok(None) => Ok(fallback_hash),
        SendRawTransactionStatus::InsufficientFunds => {
            Err("eth_sendRawTransaction: insufficient funds".to_string())
        }
        SendRawTransactionStatus::NonceTooLow => {
            Err("eth_sendRawTransaction: nonce too low".to_string())
        }
        SendRawTransactionStatus::NonceTooHigh => {
            Err("eth_sendRawTransaction: nonce too high".to_string())
        }
    }
}

fn raw_transaction_hash(raw: &str) -> Result<String, String> {
    let bytes = crate::hexutil::parse_hex(raw, None)?;
    Ok(format!(
        "0x{}",
        hex::encode(crate::hexutil::keccak256(&bytes))
    ))
}

fn client(
    config: &RpcConfig,
) -> Result<
    EvmRpcClient<
        ic_canister_runtime::IcRuntime,
        evm_rpc_client::CandidResponseConverter,
        evm_rpc_client::NoRetry,
    >,
    String,
> {
    let canister_id = evm_rpc_canister_id()?;
    Ok(EvmRpcClient::builder(IcRuntime::new(), canister_id)
        .with_rpc_sources(rpc_services(&config.services)?)
        .with_consensus_strategy(ConsensusStrategy::Threshold {
            total: Some(1),
            min: 1,
        })
        .with_response_size_estimate(RESPONSE_SIZE_BYTES)
        .build())
}

fn evm_rpc_canister_id() -> Result<Principal, String> {
    let value = ic_cdk::api::env_var_value("PUBLIC_CANISTER_ID:evm_rpc");
    if value.trim().is_empty() {
        return Ok(EVM_RPC_CANISTER);
    }
    Principal::from_text(value).map_err(|err| format!("invalid PUBLIC_CANISTER_ID:evm_rpc: {err}"))
}

fn rpc_services(value: &str) -> Result<RpcServices, String> {
    let url = single_rpc_url(value)?;
    Ok(RpcServices::Custom {
        chain_id: POLYGON_CHAIN_ID,
        services: vec![RpcApi { url, headers: None }],
    })
}

fn single_rpc_url(value: &str) -> Result<String, String> {
    let services = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if services.is_empty() {
        return Err("POLYGON_RPC_SERVICES must contain one HTTPS RPC URL".to_string());
    }
    if services.len() != 1 {
        return Err("POLYGON_RPC_SERVICES must contain exactly one HTTPS RPC URL".to_string());
    }
    let url = services[0];
    if !url.starts_with("https://") {
        return Err("POLYGON_RPC_SERVICES must be an HTTPS RPC URL".to_string());
    }
    Ok(url.to_string())
}

fn consistent_result<T: std::fmt::Debug>(result: MultiRpcResult<T>) -> Result<T, String> {
    match result {
        MultiRpcResult::Consistent(Ok(value)) => Ok(value),
        MultiRpcResult::Consistent(Err(err)) => Err(format!("{err:?}")),
        MultiRpcResult::Inconsistent(items) => Err(format!("inconsistent RPC result: {items:?}")),
    }
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
    if !log
        .get("address")
        .and_then(Value::as_str)
        .map(|address| crate::hexutil::same_address(address, JPYC_POLYGON_ADDRESS))
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

fn topic_address(topic: &str) -> Option<String> {
    let raw = crate::hexutil::strip_0x(topic);
    if raw.len() != 64 {
        return None;
    }
    Some(format!("0x{}", &raw[24..]))
}

fn uint256_hex_decimal(value: &str) -> Option<String> {
    let bytes = parse_u256_hex(value, "uint256").ok()?;
    let mut decimal = String::from("0");
    for byte in bytes {
        decimal = decimal_mul_small(&decimal, 256);
        decimal = decimal_add_small(&decimal, byte);
    }
    Some(decimal)
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

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_polygon_rpc_services() {
        let services = rpc_services("https://polygon.example").unwrap();
        match services {
            RpcServices::Custom { chain_id, services } => {
                assert_eq!(chain_id, POLYGON_CHAIN_ID);
                assert_eq!(services.len(), 1);
                assert_eq!(services[0].url, "https://polygon.example");
            }
            _ => panic!("expected custom services"),
        }
    }

    #[test]
    fn rpc_url_must_be_single_https_url() {
        assert!(single_rpc_url("https://polygon.example").is_ok());
        assert!(single_rpc_url("").is_err());
        assert!(single_rpc_url("https://one.example,https://two.example").is_err());
        assert!(single_rpc_url("http://polygon.example").is_err());
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
            receipt_status(&Value::Null, &expected),
            ReceiptStatus::Pending
        );
        assert_eq!(
            receipt_status(&success_receipt, &expected),
            ReceiptStatus::Success
        );
        assert_eq!(
            receipt_status(&json!({"status":"0x0"}), &expected),
            ReceiptStatus::Failed("settlement tx failed".to_string())
        );
        assert_eq!(
            receipt_status(
                &json!({"status":"0x1","to":JPYC_POLYGON_ADDRESS,"logs":[]}),
                &expected
            ),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );
        assert_eq!(
            receipt_status(
                &json!({"status":"0x1","to":"0x0000000000000000000000000000000000000001","logs":[]}),
                &expected
            ),
            ReceiptStatus::Failed("settlement tx recipient mismatch".to_string())
        );

        let mut token_mismatch = success_receipt.clone();
        token_mismatch["logs"][0]["address"] = json!("0x0000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status(&token_mismatch, &expected),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );

        let mut from_mismatch = success_receipt.clone();
        from_mismatch["logs"][0]["topics"][1] =
            json!("0x000000000000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status(&from_mismatch, &expected),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );

        let mut to_mismatch = success_receipt.clone();
        to_mismatch["logs"][0]["topics"][2] =
            json!("0x000000000000000000000000000000000000000000000001");
        assert_eq!(
            receipt_status(&to_mismatch, &expected),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );

        let mut amount_mismatch = success_receipt;
        amount_mismatch["logs"][0]["data"] = json!("0x65");
        assert_eq!(
            receipt_status(&amount_mismatch, &expected),
            ReceiptStatus::Failed("expected JPYC transfer log not found".to_string())
        );
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
