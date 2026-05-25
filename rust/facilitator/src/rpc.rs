// rust/facilitator/src/rpc.rs: EVM RPC canister 経由で Polygon の読取・署名済みtx送信を実行する。
use candid::Principal;
use canhttp::Client;
use evm_rpc_client::{EvmRpcClient, EVM_RPC_CANISTER};
use evm_rpc_types::{ConsensusStrategy, MultiRpcResult, RpcApi, RpcServices};
use ic_canister_runtime::IcRuntime;
use ic_cdk_management_canister::{
    transform_context_from_query, HttpHeader, HttpMethod, HttpRequestArgs,
};
use serde_json::{json, Value};
use tower::Service;

use crate::facilitator::VerifySnapshot;
use crate::hexutil::{
    address_word, parse_address, parse_u256_decimal, parse_u256_hex, selector, u256_gte,
    JPYC_POLYGON_ADDRESS, PERMIT2_ADDRESS,
};
use crate::tx::{encode_settle_calldata, settle_to_address, sign_legacy_tx, LegacyTx};
use crate::types::FacilitatorRequest;

const POLYGON_CHAIN_ID: u64 = 137;
const RESPONSE_SIZE_BYTES: u64 = 20_000;

pub struct RpcConfig {
    pub services: String,
    pub max_gas: u128,
    pub confirmation_timeout_seconds: u64,
}

pub enum SettlementOutcome {
    Settled(String),
    Pending(String),
    Failed { tx: String, message: String },
}

pub async fn snapshot(
    config: &RpcConfig,
    request: &FacilitatorRequest,
) -> Result<VerifySnapshot, String> {
    let auth = &request.payment_payload.payload.permit2_authorization;
    let owner = parse_address(&auth.from, "payer")?;
    let required = parse_u256_decimal(&request.payment_requirements.amount, "amount")?;
    let permit2 = parse_address(PERMIT2_ADDRESS, "Permit2")?;
    let balance = eth_call_u256(config, JPYC_POLYGON_ADDRESS, &erc20_balance_of(&owner)).await?;
    let allowance = eth_call_u256(
        config,
        JPYC_POLYGON_ADDRESS,
        &erc20_allowance(&owner, &permit2),
    )
    .await?;
    let settle_data = encode_settle_calldata(&request.payment_payload.payload)?;
    let settle_simulates = eth_call(
        config,
        &crate::hexutil::address_hex(&settle_to_address()?),
        &settle_data,
    )
    .await
    .is_ok();
    Ok(VerifySnapshot {
        has_balance: u256_gte(&balance, &required),
        has_allowance: u256_gte(&allowance, &required),
        settle_simulates,
    })
}

pub async fn send_settlement(
    config: &RpcConfig,
    private_key: &str,
    request: &FacilitatorRequest,
) -> Result<SettlementOutcome, String> {
    let data = encode_settle_calldata(&request.payment_payload.payload)?;
    let from = crate::private_key_address(private_key)?;
    let nonce = rpc_hex_u128(config, "eth_getTransactionCount", json!([from, "pending"])).await?;
    let gas_price = rpc_hex_u128(config, "eth_gasPrice", json!([])).await?;
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
        return Err("estimated settlement gas exceeds FACILITATOR_MAX_GAS".to_string());
    }
    let raw = sign_legacy_tx(
        &LegacyTx {
            nonce,
            gas_price,
            gas_limit,
            to,
            value: 0,
            data,
            chain_id: POLYGON_CHAIN_ID,
        },
        private_key,
    )?;
    let tx = send_raw_transaction(config, &raw).await?;
    match wait_receipt_status(config, &tx).await? {
        ReceiptStatus::Success => Ok(SettlementOutcome::Settled(tx)),
        ReceiptStatus::Pending => Ok(SettlementOutcome::Pending(tx)),
        ReceiptStatus::Failed => Ok(SettlementOutcome::Failed {
            tx,
            message: "settlement tx failed".to_string(),
        }),
    }
}

pub async fn refresh_settlement(config: &RpcConfig, tx: &str) -> Result<SettlementOutcome, String> {
    match receipt_status_for_tx(config, tx).await? {
        ReceiptStatus::Success => Ok(SettlementOutcome::Settled(tx.to_string())),
        ReceiptStatus::Pending => Ok(SettlementOutcome::Pending(tx.to_string())),
        ReceiptStatus::Failed => Ok(SettlementOutcome::Failed {
            tx: tx.to_string(),
            message: "settlement tx failed".to_string(),
        }),
    }
}

async fn wait_receipt_status(config: &RpcConfig, tx: &str) -> Result<ReceiptStatus, String> {
    let start = crate::now_seconds();
    let max_attempts = config.confirmation_timeout_seconds.saturating_mul(2).max(1);
    for _ in 0..max_attempts {
        match receipt_status_for_tx(config, tx).await? {
            ReceiptStatus::Pending => {
                if crate::now_seconds().saturating_sub(start) >= config.confirmation_timeout_seconds
                {
                    return Ok(ReceiptStatus::Pending);
                }
            }
            status => return Ok(status),
        }
    }
    Ok(ReceiptStatus::Pending)
}

async fn receipt_status_for_tx(config: &RpcConfig, tx: &str) -> Result<ReceiptStatus, String> {
    let result = rpc_value(config, "eth_getTransactionReceipt", json!([tx])).await?;
    Ok(receipt_status(&result))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptStatus {
    Success,
    Failed,
    Pending,
}

fn receipt_status(result: &Value) -> ReceiptStatus {
    if result.is_null() {
        return ReceiptStatus::Pending;
    }
    match result.get("status").and_then(Value::as_str) {
        Some("0x1") => ReceiptStatus::Success,
        Some("0x0") => ReceiptStatus::Failed,
        _ => ReceiptStatus::Pending,
    }
}

async fn eth_call_u256(config: &RpcConfig, to: &str, data: &[u8]) -> Result<[u8; 32], String> {
    let result = eth_call(config, to, data).await?;
    parse_u256_hex(&result, "eth_call")
}

async fn eth_call(config: &RpcConfig, to: &str, data: &[u8]) -> Result<String, String> {
    rpc_string(
        config,
        "eth_call",
        json!([{ "to": to, "data": format!("0x{}", hex::encode(data)) }, "latest"]),
    )
    .await
}

async fn rpc_hex_u128(config: &RpcConfig, method: &str, params: Value) -> Result<u128, String> {
    let value = rpc_string(config, method, params).await?;
    u128::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|_| format!("{method}: invalid hex quantity"))
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
    let result = send_raw_transaction_once(config, raw).await?;
    let fallback_hash = raw_transaction_hash(raw)?;
    if let Some(error) = result.get("error") {
        let message = error.to_string();
        if is_duplicate_transaction_error(&message) {
            return Ok(fallback_hash);
        }
        return Err(format!("eth_sendRawTransaction: {message}"));
    }
    let tx = result
        .get("result")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "eth_sendRawTransaction: missing result".to_string())?;
    Ok(tx.to_string())
}

async fn send_raw_transaction_once(config: &RpcConfig, raw: &str) -> Result<Value, String> {
    let url = single_rpc_url(&config.services)?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": [raw]
    })
    .to_string();
    let mut client = Client;
    let response = client
        .call(HttpRequestArgs {
            url,
            max_response_bytes: Some(20_000),
            method: HttpMethod::POST,
            headers: vec![
                HttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                HttpHeader {
                    name: "idempotency-key".to_string(),
                    value: raw_transaction_hash(raw)?,
                },
            ],
            body: Some(body.into_bytes()),
            transform: Some(transform_context_from_query(
                "transform_rpc".to_string(),
                vec![],
            )),
            is_replicated: Some(false),
        })
        .await
        .map_err(|err| format!("eth_sendRawTransaction outcall failed: {err:?}"))?;
    if response.status != candid::Nat::from(200_u64) {
        return Err(format!(
            "eth_sendRawTransaction HTTP status {}",
            response.status
        ));
    }
    let text =
        String::from_utf8(response.body).map_err(|_| "rpc response is not utf8".to_string())?;
    serde_json::from_str(&text).map_err(|_| format!("invalid rpc json: {text}"))
}

fn raw_transaction_hash(raw: &str) -> Result<String, String> {
    let bytes = crate::hexutil::parse_hex(raw, None)?;
    Ok(format!(
        "0x{}",
        hex::encode(crate::hexutil::keccak256(&bytes))
    ))
}

fn is_duplicate_transaction_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("already known") || lower.contains("known transaction")
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

fn erc20_balance_of(owner: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector("balanceOf(address)"));
    data.extend_from_slice(&address_word(owner));
    data
}

fn erc20_allowance(owner: &[u8; 20], spender: &[u8; 20]) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&selector("allowance(address,address)"));
    data.extend_from_slice(&address_word(owner));
    data.extend_from_slice(&address_word(spender));
    data
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
        let services = rpc_services("https://one.example").unwrap();
        match services {
            RpcServices::Custom { chain_id, services } => {
                assert_eq!(chain_id, POLYGON_CHAIN_ID);
                assert_eq!(services.len(), 1);
            }
            _ => panic!("expected custom services"),
        }
    }

    #[test]
    fn rejects_empty_rpc_services() {
        assert!(rpc_services(" , ").is_err());
    }

    #[test]
    fn classifies_duplicate_send_errors() {
        assert!(is_duplicate_transaction_error(
            "JsonRpcError: already known"
        ));
        assert!(is_duplicate_transaction_error("known transaction"));
        assert!(!is_duplicate_transaction_error("Nonce too low"));
        assert!(!is_duplicate_transaction_error("insufficient funds"));
    }

    #[test]
    fn rpc_url_must_be_single_https_url() {
        assert_eq!(
            single_rpc_url("https://polygon.example").unwrap(),
            "https://polygon.example"
        );
        assert!(single_rpc_url("https://one.example,https://two.example").is_err());
        assert!(single_rpc_url("http://polygon.example").is_err());
    }

    #[test]
    fn maps_receipt_status() {
        assert_eq!(receipt_status(&Value::Null), ReceiptStatus::Pending);
        assert_eq!(
            receipt_status(&json!({"status":"0x1"})),
            ReceiptStatus::Success
        );
        assert_eq!(
            receipt_status(&json!({"status":"0x0"})),
            ReceiptStatus::Failed
        );
    }
}
