// rust/facilitator/src/rpc.rs: EVM RPC canister 経由で Polygon の読取・署名済みtx送信を実行する。
use candid::{CandidType, Deserialize as CandidDeserialize, Principal};
use evm_rpc_client::{EvmRpcClient, EVM_RPC_CANISTER};
use evm_rpc_types::{Hex, MultiRpcResult, RpcApi, RpcServices, SendRawTransactionStatus};
use ic_canister_runtime::IcRuntime;
use serde_json::{json, Value};
use std::str::FromStr;

use crate::hexutil::{address_word, parse_address};
use crate::hexutil::{parse_hex, parse_u256_hex, selector, JPYC_POLYGON_ADDRESS};
use crate::tx::{encode_settle_calldata, settle_to_address, sign_eip1559_tx, Eip1559Tx};
use crate::types::FacilitatorRequest;

const POLYGON_CHAIN_ID: u64 = 137;
const RESPONSE_SIZE_BYTES: u64 = 20_000;
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const SETTLED_TOPIC: &str = "0x7337b4386b690fdb8ba66905b92b9d45d33bc6626ee2620c905fb150ec0cc47d";

pub struct RpcConfig {
    pub max_gas: u128,
    pub max_settlement_fee_wei: u128,
    pub min_confirmations: u64,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractExpectation {
    Deposit {
        channel_id: String,
        payer: String,
        token: String,
        deposit_amount: String,
        max_claimable_amount: String,
        min_balance: String,
    },
    Claim {
        claims: Vec<ExpectedClaimState>,
    },
    Settle {
        receiver: String,
        token: String,
        expected_amount: Option<String>,
        min_total_settled: Option<String>,
    },
    Refund {
        channel_id: String,
        refund_nonce: String,
        min_refund_nonce: String,
        claims: Vec<ExpectedClaimState>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedClaimState {
    pub channel_id: String,
    pub min_total_claimed: String,
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

pub async fn batch_channel_snapshot(
    config: &RpcConfig,
    contract: &[u8; 20],
    channel_id: &str,
) -> Result<BatchChannelSnapshot, String> {
    let channel = batch_channel_state(config, contract, channel_id).await?;
    let withdraw_requested_at = batch_pending_withdrawal(config, contract, channel_id).await?;
    let refund_nonce = batch_refund_nonce(config, contract, channel_id).await?;
    Ok(BatchChannelSnapshot {
        channel_id: channel_id.to_string(),
        balance: channel.balance,
        total_claimed: channel.total_claimed,
        withdraw_requested_at,
        refund_nonce,
    })
}

pub async fn batch_settled_amount(
    config: &RpcConfig,
    tx: &str,
    contract: &[u8; 20],
    receiver: &str,
    token: &str,
) -> Result<String, String> {
    let result = rpc_value(config, "eth_getTransactionReceipt", json!([tx])).await?;
    if result.is_null() {
        return Err("settlement receipt is pending".to_string());
    }
    settled_event_amount(&result, contract, receiver, token)
        .ok_or_else(|| "expected batch Settled event not found".to_string())
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
    let status = receipt_status_for_tx(config, &tx, &expected_transfer(request)).await;
    Ok(post_broadcast_outcome(tx, nonce, status))
}

pub async fn send_contract_transaction(
    config: &RpcConfig,
    private_key: &str,
    to: [u8; 20],
    data: Vec<u8>,
    nonce: u128,
    expectation: &ContractExpectation,
) -> Result<SettlementOutcome, SettlementSendError> {
    let from = crate::private_key_address(private_key)?;
    let expectation = match preflight_contract_expectation(config, &to, expectation).await? {
        ContractPreflight::Ready(expectation) => expectation,
        ContractPreflight::Noop => return Ok(SettlementOutcome::Settled(String::new())),
    };
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
            chain_id: POLYGON_CHAIN_ID,
        },
        private_key,
    )?;
    let tx = send_raw_transaction(config, &raw).await?;
    let status = receipt_status_for_contract_tx(config, &tx, &to, Some(&from), &expectation).await;
    Ok(post_broadcast_outcome(tx, nonce, status))
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
) -> Result<SettlementOutcome, String> {
    match receipt_status_for_contract_tx(config, tx, expected_to, expected_from, expectation)
        .await?
    {
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
    if result.is_null() {
        return Ok(ReceiptStatus::Pending);
    }
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
) -> Result<ReceiptStatus, String> {
    let result = rpc_value(config, "eth_getTransactionReceipt", json!([tx])).await?;
    if result.is_null() {
        return Ok(ReceiptStatus::Pending);
    }
    let latest_block = rpc_hex_u128(config, "eth_blockNumber", json!([])).await?;
    let status = receipt_status_for_contract(
        &result,
        expected_to,
        expected_from,
        expectation,
        latest_block,
        config.min_confirmations,
    );
    if status != ReceiptStatus::Success {
        return Ok(status);
    }
    let settled_event_amount = contract_settle_event_amount(&result, expected_to, expectation);
    post_state_status(
        config,
        expected_to,
        expectation,
        settled_event_amount.as_deref(),
    )
    .await
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReceiptStatus {
    Success,
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
    let expected_to_address = crate::hexutil::address_hex(expected_to);
    if !result
        .get("to")
        .and_then(Value::as_str)
        .map(|to| crate::hexutil::same_address(to, &expected_to_address))
        .unwrap_or(false)
    {
        return ReceiptStatus::Failed("settlement tx recipient mismatch".to_string());
    }
    if expected_from.is_some_and(|from| {
        !result
            .get("from")
            .and_then(Value::as_str)
            .map(|actual| crate::hexutil::same_address(actual, from))
            .unwrap_or(false)
    }) {
        return ReceiptStatus::Failed("settlement tx sender mismatch".to_string());
    }
    if let ContractExpectation::Settle {
        receiver,
        token,
        expected_amount,
        ..
    } = expectation
    {
        let Some(amount) = settled_event_amount(result, expected_to, receiver, token) else {
            return ReceiptStatus::Failed("expected batch Settled event not found".to_string());
        };
        if !decimal_greater(&amount, "0")
            || expected_amount
                .as_ref()
                .is_some_and(|expected| !decimal_equal(&amount, expected))
        {
            return ReceiptStatus::Failed("batch settled amount mismatch".to_string());
        }
    }
    ReceiptStatus::Success
}

fn contract_settle_event_amount(
    result: &Value,
    expected_to: &[u8; 20],
    expectation: &ContractExpectation,
) -> Option<String> {
    if let ContractExpectation::Settle {
        receiver, token, ..
    } = expectation
    {
        return settled_event_amount(result, expected_to, receiver, token);
    }
    None
}

async fn post_state_status(
    config: &RpcConfig,
    contract: &[u8; 20],
    expectation: &ContractExpectation,
    settled_event_amount: Option<&str>,
) -> Result<ReceiptStatus, String> {
    match expectation {
        ContractExpectation::Deposit {
            channel_id,
            min_balance,
            ..
        } => {
            let state = batch_channel_state(config, contract, channel_id).await?;
            if decimal_at_least(&state.balance, min_balance) {
                Ok(ReceiptStatus::Success)
            } else {
                Ok(ReceiptStatus::Failed(
                    "batch deposit post-state balance mismatch".to_string(),
                ))
            }
        }
        ContractExpectation::Claim { claims } => {
            if batch_claims_reached(config, contract, claims).await? {
                Ok(ReceiptStatus::Success)
            } else {
                Ok(ReceiptStatus::Failed(
                    "batch claim post-state totalClaimed mismatch".to_string(),
                ))
            }
        }
        ContractExpectation::Settle {
            receiver,
            token,
            min_total_settled,
            ..
        } => {
            let state = batch_receiver_state(config, contract, receiver, token).await?;
            Ok(settle_post_state_status(
                &state,
                min_total_settled.as_ref(),
                settled_event_amount,
            ))
        }
        ContractExpectation::Refund {
            channel_id,
            refund_nonce: _,
            min_refund_nonce,
            claims,
        } => {
            if !claims.is_empty() && !batch_claims_reached(config, contract, claims).await? {
                return Ok(ReceiptStatus::Failed(
                    "batch refund claim post-state totalClaimed mismatch".to_string(),
                ));
            }
            let nonce = batch_refund_nonce(config, contract, channel_id).await?;
            if decimal_at_least(&nonce, min_refund_nonce) {
                Ok(ReceiptStatus::Success)
            } else {
                Ok(ReceiptStatus::Failed(
                    "batch refund post-state nonce mismatch".to_string(),
                ))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContractPreflight {
    Ready(ContractExpectation),
    Noop,
}

async fn preflight_contract_expectation(
    config: &RpcConfig,
    contract: &[u8; 20],
    expectation: &ContractExpectation,
) -> Result<ContractPreflight, String> {
    match expectation {
        ContractExpectation::Deposit {
            channel_id,
            payer,
            token,
            deposit_amount,
            max_claimable_amount,
            ..
        } => {
            let state = batch_channel_state(config, contract, channel_id).await?;
            let payer_balance = erc20_balance(config, token, payer).await?;
            let effective_balance = validate_deposit_pre_state(
                &payer_balance,
                &state.balance,
                &state.total_claimed,
                deposit_amount,
                max_claimable_amount,
            )?;
            Ok(ContractPreflight::Ready(ContractExpectation::Deposit {
                channel_id: channel_id.clone(),
                payer: payer.clone(),
                token: token.clone(),
                deposit_amount: deposit_amount.clone(),
                max_claimable_amount: max_claimable_amount.clone(),
                min_balance: effective_balance,
            }))
        }
        ContractExpectation::Claim { claims } => {
            preflight_claims(config, contract, claims).await?;
            Ok(ContractPreflight::Ready(expectation.clone()))
        }
        ContractExpectation::Settle {
            receiver, token, ..
        } => {
            let state = batch_receiver_state(config, contract, receiver, token).await?;
            if !settle_has_unsettled_amount(&state.total_claimed, &state.total_settled) {
                return Ok(ContractPreflight::Noop);
            }
            let expected_amount = decimal_sub(&state.total_claimed, &state.total_settled)?;
            Ok(ContractPreflight::Ready(ContractExpectation::Settle {
                receiver: receiver.clone(),
                token: token.clone(),
                expected_amount: Some(expected_amount),
                min_total_settled: Some(state.total_claimed),
            }))
        }
        ContractExpectation::Refund {
            channel_id,
            refund_nonce,
            min_refund_nonce: _,
            claims,
        } => {
            let nonce = batch_refund_nonce(config, contract, channel_id).await?;
            validate_refund_pre_state(&nonce, refund_nonce)?;
            if !claims.is_empty() {
                preflight_claims(config, contract, claims).await?;
            }
            Ok(ContractPreflight::Ready(expectation.clone()))
        }
    }
}

async fn preflight_claims(
    config: &RpcConfig,
    contract: &[u8; 20],
    claims: &[ExpectedClaimState],
) -> Result<(), String> {
    for claim in claims {
        let state = batch_channel_state(config, contract, &claim.channel_id).await?;
        validate_claim_pre_state(
            &state.balance,
            &state.total_claimed,
            &claim.min_total_claimed,
        )?;
    }
    Ok(())
}

async fn batch_claims_reached(
    config: &RpcConfig,
    contract: &[u8; 20],
    claims: &[ExpectedClaimState],
) -> Result<bool, String> {
    for claim in claims {
        let state = batch_channel_state(config, contract, &claim.channel_id).await?;
        if !decimal_at_least(&state.total_claimed, &claim.min_total_claimed) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BatchChannelState {
    balance: String,
    total_claimed: String,
}

async fn batch_channel_state(
    config: &RpcConfig,
    contract: &[u8; 20],
    channel_id: &str,
) -> Result<BatchChannelState, String> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector("channels(bytes32)"));
    data.extend_from_slice(&parse_hex(channel_id, Some(32))?);
    let result = eth_call(config, contract, data).await?;
    let words = parse_words(&result, 2, "channels")?;
    Ok(BatchChannelState {
        balance: uint128_hex_decimal_word(&words[0], "channels.balance")?,
        total_claimed: uint128_hex_decimal_word(&words[1], "channels.totalClaimed")?,
    })
}

async fn batch_refund_nonce(
    config: &RpcConfig,
    contract: &[u8; 20],
    channel_id: &str,
) -> Result<String, String> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector("refundNonce(bytes32)"));
    data.extend_from_slice(&parse_hex(channel_id, Some(32))?);
    let result = eth_call(config, contract, data).await?;
    let words = parse_words(&result, 1, "refundNonce")?;
    Ok(uint256_hex_decimal_word(&words[0]))
}

async fn batch_pending_withdrawal(
    config: &RpcConfig,
    contract: &[u8; 20],
    channel_id: &str,
) -> Result<u64, String> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector("pendingWithdrawals(bytes32)"));
    data.extend_from_slice(&parse_hex(channel_id, Some(32))?);
    let result = eth_call(config, contract, data).await?;
    let words = parse_words(&result, 2, "pendingWithdrawals")?;
    uint256_hex_decimal_word(&words[1])
        .parse::<u64>()
        .map_err(|_| "pendingWithdrawals.initiatedAt overflow".to_string())
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

async fn erc20_balance(config: &RpcConfig, token: &str, owner: &str) -> Result<String, String> {
    let token = parse_address(token, "token")?;
    let owner = parse_address(owner, "owner")?;
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&selector("balanceOf(address)"));
    data.extend_from_slice(&address_word(&owner));
    let result = eth_call(config, &token, data).await?;
    let words = parse_words(&result, 1, "balanceOf")?;
    Ok(uint256_hex_decimal_word(&words[0]))
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
    if !is_https_rpc_origin(url) {
        return Err(
            "POLYGON_RPC_SERVICES must be a single https://host[:port] RPC origin".to_string(),
        );
    }
    Ok(url.to_string())
}

fn is_https_rpc_origin(value: &str) -> bool {
    if !value.starts_with("https://") || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return false;
    }
    let host_port = &value["https://".len()..];
    if host_port.is_empty()
        || host_port.contains('/')
        || host_port.contains('?')
        || host_port.contains('#')
        || host_port.contains('@')
    {
        return false;
    }
    match host_port.split_once(':') {
        Some((host, port)) => {
            !host.is_empty()
                && !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
        }
        None => !host_port.contains(':'),
    }
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
    if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
        return false;
    }
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

fn decimal_equal(left: &str, right: &str) -> bool {
    decimal_normalize(left) == decimal_normalize(right)
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

fn validate_deposit_pre_state(
    payer_balance: &str,
    channel_balance: &str,
    total_claimed: &str,
    deposit_amount: &str,
    max_claimable_amount: &str,
) -> Result<String, String> {
    if !decimal_at_least(payer_balance, deposit_amount) {
        return Err("invalid_batch_settlement_evm_insufficient_balance".to_string());
    }
    let effective_balance = decimal_add(channel_balance, deposit_amount)?;
    if !decimal_at_least(&effective_balance, max_claimable_amount) {
        return Err("invalid_batch_settlement_evm_cumulative_exceeds_balance".to_string());
    }
    if !decimal_greater(max_claimable_amount, total_claimed) {
        return Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string());
    }
    Ok(effective_balance)
}

fn validate_claim_pre_state(
    balance: &str,
    total_claimed: &str,
    min_total_claimed: &str,
) -> Result<(), String> {
    if !decimal_greater(min_total_claimed, total_claimed) {
        return Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string());
    }
    if !decimal_at_least(balance, min_total_claimed) {
        return Err("invalid_batch_settlement_evm_cumulative_exceeds_balance".to_string());
    }
    Ok(())
}

fn settle_has_unsettled_amount(total_claimed: &str, total_settled: &str) -> bool {
    decimal_greater(total_claimed, total_settled)
}

fn settle_post_state_status(
    state: &BatchReceiverState,
    min_total_settled: Option<&String>,
    settled_event_amount: Option<&str>,
) -> ReceiptStatus {
    if decimal_greater(&state.total_settled, &state.total_claimed) {
        return ReceiptStatus::Failed("batch receiver totalClaimed below totalSettled".to_string());
    }
    if settled_event_amount.is_some_and(|amount| !decimal_at_least(&state.total_settled, amount)) {
        return ReceiptStatus::Failed("batch receiver totalSettled below event amount".to_string());
    }
    if min_total_settled.is_some_and(|minimum| !decimal_at_least(&state.total_settled, minimum)) {
        return ReceiptStatus::Failed("batch receiver totalSettled mismatch".to_string());
    }
    ReceiptStatus::Success
}

fn validate_refund_pre_state(onchain_nonce: &str, refund_nonce: &str) -> Result<(), String> {
    if !decimal_equal(onchain_nonce, refund_nonce) {
        return Err("invalid_batch_settlement_evm_refund_payload".to_string());
    }
    Ok(())
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
        assert!(single_rpc_url("https://polygon.example:443").is_ok());
        assert!(single_rpc_url("").is_err());
        assert!(single_rpc_url("https://one.example,https://two.example").is_err());
        assert!(single_rpc_url("http://polygon.example").is_err());
        assert!(single_rpc_url("https://trusted.example@evil.example").is_err());
        assert!(single_rpc_url("https://polygon.example/path").is_err());
        assert!(single_rpc_url("https://polygon.example?x=1").is_err());
        assert!(single_rpc_url("https://polygon.example#x").is_err());
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
            expected_amount: Some("100".to_string()),
            min_total_settled: Some("100".to_string()),
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
            ReceiptStatus::Success
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
            ReceiptStatus::Success
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
            ReceiptStatus::Failed("settlement tx sender mismatch".to_string())
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
            ReceiptStatus::Failed("expected batch Settled event not found".to_string())
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
            ReceiptStatus::Failed("expected batch Settled event not found".to_string())
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
            ReceiptStatus::Failed("expected batch Settled event not found".to_string())
        );

        let mut amount_mismatch = success_receipt.clone();
        amount_mismatch["logs"][0]["data"] = json!("0x63");
        assert_eq!(
            receipt_status_for_contract(
                &amount_mismatch,
                &contract,
                Some("0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993"),
                &expectation,
                102,
                3
            ),
            ReceiptStatus::Failed("batch settled amount mismatch".to_string())
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
            ReceiptStatus::Failed("batch settled amount mismatch".to_string())
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
            ReceiptStatus::Failed("expected batch Settled event not found".to_string())
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
        assert_eq!(
            settle_post_state_status(
                &BatchReceiverState {
                    total_claimed: "100".to_string(),
                    total_settled: "100".to_string(),
                },
                Some(&"100".to_string()),
                Some("100")
            ),
            ReceiptStatus::Success
        );
        assert_eq!(
            settle_post_state_status(
                &BatchReceiverState {
                    total_claimed: "100".to_string(),
                    total_settled: "99".to_string(),
                },
                None,
                Some("100")
            ),
            ReceiptStatus::Failed("batch receiver totalSettled below event amount".to_string())
        );
        assert_eq!(
            settle_post_state_status(
                &BatchReceiverState {
                    total_claimed: "100".to_string(),
                    total_settled: "99".to_string(),
                },
                Some(&"100".to_string()),
                Some("99")
            ),
            ReceiptStatus::Failed("batch receiver totalSettled mismatch".to_string())
        );
        assert_eq!(
            settle_post_state_status(
                &BatchReceiverState {
                    total_claimed: "99".to_string(),
                    total_settled: "100".to_string(),
                },
                None,
                None
            ),
            ReceiptStatus::Failed("batch receiver totalClaimed below totalSettled".to_string())
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
    fn validates_batch_deposit_pre_state() {
        assert_eq!(
            validate_deposit_pre_state("1000", "100", "50", "200", "250").unwrap(),
            "300"
        );
        assert_eq!(
            validate_deposit_pre_state("1000", "100", "250", "200", "250"),
            Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string())
        );
        assert_eq!(
            validate_deposit_pre_state("199", "100", "50", "200", "250"),
            Err("invalid_batch_settlement_evm_insufficient_balance".to_string())
        );
        assert_eq!(
            validate_deposit_pre_state("1000", "100", "50", "100", "250"),
            Err("invalid_batch_settlement_evm_cumulative_exceeds_balance".to_string())
        );
        assert_eq!(
            validate_deposit_pre_state("1000", "100", "251", "200", "250"),
            Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string())
        );
    }

    #[test]
    fn validates_batch_claim_and_settle_pre_state() {
        assert!(validate_claim_pre_state("300", "100", "250").is_ok());
        assert_eq!(
            validate_claim_pre_state("300", "250", "250"),
            Err("invalid_batch_settlement_evm_cumulative_below_claimed".to_string())
        );
        assert_eq!(
            validate_claim_pre_state("249", "100", "250"),
            Err("invalid_batch_settlement_evm_cumulative_exceeds_balance".to_string())
        );

        assert!(settle_has_unsettled_amount("300", "100"));
        assert!(!settle_has_unsettled_amount("300", "300"));
        assert!(!settle_has_unsettled_amount("299", "300"));
    }

    #[test]
    fn validates_batch_refund_nonce_exactly_before_broadcast() {
        assert!(validate_refund_pre_state("3", "3").is_ok());
        assert!(validate_refund_pre_state("0003", "3").is_ok());
        assert_eq!(
            validate_refund_pre_state("2", "3"),
            Err("invalid_batch_settlement_evm_refund_payload".to_string())
        );
        assert_eq!(
            validate_refund_pre_state("4", "3"),
            Err("invalid_batch_settlement_evm_refund_payload".to_string())
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
