// rust/facilitator/src/batch.rs: x402 batch-settlement の channel/voucher 検証と stable storage 型を定義する。
use candid::CandidType;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize as SerdeDeserialize, Serialize};
use serde_json::Value;

use crate::hexutil::{
    address_hex, address_word, keccak256, parse_address, parse_hex, parse_u128_decimal_word,
    parse_u256_decimal, same_address, u256_word, JPYC_EIP712_NAME,
};
#[cfg(test)]
use crate::hexutil::{JPYC_POLYGON_ADDRESS, NETWORK};
use crate::tx::ERC3009_DEPOSIT_COLLECTOR_ADDRESS;
use crate::types::{PaymentRequirements, ResourceInfo};

pub const BATCH_SCHEME: &str = "batch-settlement";
pub const CANONICAL_BATCH_SETTLEMENT_CONTRACT: &str = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";
#[cfg(test)]
pub const DEFAULT_BATCH_SETTLEMENT_CONTRACT: &str = CANONICAL_BATCH_SETTLEMENT_CONTRACT;
pub const BATCH_DOMAIN_NAME: &str = "x402 Batch Settlement";
pub const BATCH_DOMAIN_VERSION: &str = "1";
pub const DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS: u64 = 900;
pub const MIN_BATCH_WITHDRAW_DELAY_SECONDS: u64 = 900;
pub const MAX_BATCH_WITHDRAW_DELAY_SECONDS: u64 = 2_592_000;
pub const MAX_BATCH_CHANNELS_LIST: usize = 1_000;
#[cfg(not(test))]
pub const MAX_BATCH_CHANNELS_STORED: u64 = MAX_BATCH_CHANNELS_LIST as u64;
#[cfg(test)]
pub const MAX_BATCH_CHANNELS_STORED: u64 = 2;
pub const MAX_BATCH_CHANNEL_ID_BYTES: usize = 32;
pub const MAX_BATCH_STRING_BYTES: usize = 512;

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const CHANNEL_CONFIG_TYPE: &str = "ChannelConfig(address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt)";
const VOUCHER_TYPE: &str = "Voucher(bytes32 channelId,uint128 maxClaimableAmount)";
const RECEIVE_WITH_AUTHORIZATION_TYPE: &str = "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

#[derive(Clone, Debug, CandidType, SerdeDeserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchChannelConfig {
    pub payer: String,
    #[serde(alias = "payer_authorizer")]
    pub payer_authorizer: String,
    pub receiver: String,
    #[serde(alias = "receiver_authorizer")]
    pub receiver_authorizer: String,
    pub token: String,
    #[serde(alias = "withdraw_delay")]
    pub withdraw_delay: u64,
    pub salt: String,
}

#[derive(Clone, Debug, CandidType, SerdeDeserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BatchPendingRequest {
    #[serde(alias = "pending_id")]
    pub pending_id: String,
    #[serde(alias = "signed_max_claimable")]
    pub signed_max_claimable: String,
    #[serde(alias = "expires_at")]
    pub expires_at: u64,
}

#[derive(Clone, Debug, CandidType, SerdeDeserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BatchChannel {
    #[serde(alias = "channel_id")]
    pub channel_id: String,
    #[serde(alias = "channel_config")]
    pub channel_config: BatchChannelConfig,
    #[serde(alias = "charged_cumulative_amount")]
    pub charged_cumulative_amount: String,
    #[serde(alias = "signed_max_claimable")]
    pub signed_max_claimable: String,
    pub signature: String,
    pub balance: String,
    #[serde(alias = "total_claimed")]
    pub total_claimed: String,
    #[serde(alias = "withdraw_requested_at")]
    pub withdraw_requested_at: u64,
    #[serde(alias = "refund_nonce")]
    pub refund_nonce: String,
    #[serde(alias = "onchain_synced_at")]
    pub onchain_synced_at: Option<u64>,
    #[serde(alias = "last_request_timestamp")]
    pub last_request_timestamp: u64,
    #[serde(alias = "pending_request")]
    pub pending_request: Option<BatchPendingRequest>,
    pub revision: u64,
}

#[derive(Clone, Debug, CandidType, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchChannelUpdate {
    pub channel: Option<BatchChannel>,
}

#[derive(Clone, Debug, CandidType, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchChannelUpdateResult {
    pub status: String,
    pub channel: Option<BatchChannel>,
    #[serde(alias = "current_revision")]
    pub current_revision: Option<u64>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchFacilitatorRequest {
    pub x402_version: u64,
    pub payment_payload: BatchPaymentPayload,
    pub payment_requirements: PaymentRequirements,
}

#[derive(Clone, Debug, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPaymentPayload {
    pub x402_version: u64,
    #[serde(default)]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: Value,
    #[serde(default)]
    pub extensions: Option<Value>,
}

#[derive(Clone, Debug, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchVoucher {
    pub channel_id: String,
    pub max_claimable_amount: String,
    pub signature: String,
}

#[derive(Clone, Debug, SerdeDeserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchRequestPayload {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub channel_config: Option<BatchChannelConfig>,
    #[serde(default)]
    pub voucher: Option<BatchVoucher>,
    #[serde(default)]
    pub deposit: Option<BatchDeposit>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub refund_nonce: Option<String>,
    #[serde(default)]
    pub claims: Option<Vec<BatchVoucherClaim>>,
    #[serde(default)]
    pub receiver: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub claim_authorizer_signature: Option<String>,
    #[serde(default)]
    pub refund_authorizer_signature: Option<String>,
}

#[derive(Clone, Debug, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchDeposit {
    pub amount: String,
    pub authorization: BatchDepositAuthorization,
}

#[derive(Clone, Debug, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchDepositAuthorization {
    pub erc3009_authorization: Option<BatchErc3009Authorization>,
}

#[derive(Clone, Debug, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchErc3009Authorization {
    pub valid_after: String,
    pub valid_before: String,
    pub salt: String,
    pub signature: String,
}

#[derive(Clone, Debug, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchVoucherClaim {
    pub voucher: BatchClaimVoucher,
    pub signature: String,
    pub total_claimed: String,
}

#[derive(Clone, Debug, SerdeDeserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchClaimVoucher {
    pub channel: BatchChannelConfig,
    pub max_claimable_amount: String,
}

#[derive(Clone, Debug)]
pub struct BatchVerification {
    pub payer: String,
    pub receiver: String,
}

#[derive(Clone, Debug)]
pub struct BatchSettleValidation {
    pub payer: Option<String>,
    pub receiver: String,
}

pub fn is_batch_request(value: &Value) -> bool {
    value
        .get("paymentRequirements")
        .and_then(|item| item.get("scheme"))
        .and_then(Value::as_str)
        == Some(BATCH_SCHEME)
}

pub fn validate_batch_request(
    request: &BatchFacilitatorRequest,
    current: Option<&BatchChannel>,
    contract: &str,
) -> Result<BatchVerification, String> {
    let current_charged = current
        .map(|item| item.charged_cumulative_amount.as_str())
        .unwrap_or("0");
    validate_batch_request_with_charged(request, current_charged, contract)
}

pub fn validate_batch_request_with_charged(
    request: &BatchFacilitatorRequest,
    charged_cumulative_amount: &str,
    contract: &str,
) -> Result<BatchVerification, String> {
    if request.x402_version != 2 || request.payment_payload.x402_version != 2 {
        return Err("x402Version must be 2".to_string());
    }
    let payload = batch_payload(&request.payment_payload.payload)?;
    validate_batch_requirements(&request.payment_requirements)?;
    validate_batch_requirements(&request.payment_payload.accepted)?;
    validate_requirements_match(
        &request.payment_requirements,
        &request.payment_payload.accepted,
    )?;
    validate_payload_matches_requirements(&payload, &request.payment_requirements)?;
    validate_payload_metadata(&request.payment_payload)?;
    validate_payload_kind_fields(&payload)?;
    let channel_config = payload
        .channel_config
        .as_ref()
        .ok_or_else(|| "batch channelConfig is required".to_string())?;
    let voucher = payload
        .voucher
        .as_ref()
        .ok_or_else(|| "batch voucher is required".to_string())?;
    let channel_id = compute_batch_channel_id(channel_config, contract)?;
    if !same_bytes32(&channel_id, &voucher.channel_id) {
        return Err("batch voucher channelId mismatch".to_string());
    }
    if is_zero_address(&channel_config.payer_authorizer) {
        return Err("unsupported_batch_eip1271".to_string());
    }
    let recovered = recover_voucher_signer(voucher, contract)?;
    if !same_address(&recovered, &channel_config.payer_authorizer) {
        return Err("batch voucher signer mismatch".to_string());
    }
    if payload.kind == "deposit" {
        let deposit = payload
            .deposit
            .as_ref()
            .ok_or_else(|| "batch deposit payload is required".to_string())?;
        validate_deposit_authorization_time_window(deposit, &request.payment_requirements)?;
        let signer = recover_deposit_authorization_signer(
            deposit,
            channel_config,
            &request.payment_requirements,
        )?;
        if !same_address(&signer, &channel_config.payer) {
            return Err("batch deposit authorization signer mismatch".to_string());
        }
    }
    validate_decimal("chargedCumulativeAmount", charged_cumulative_amount)?;
    let expected = match payload.kind.as_str() {
        "deposit" | "voucher" => add_decimal_strings(
            charged_cumulative_amount,
            &request.payment_requirements.amount,
        )?,
        "refund" => charged_cumulative_amount.to_string(),
        other => return Err(format!("unsupported batch payload type: {other}")),
    };
    if voucher.max_claimable_amount != expected {
        return Err("invalid_batch_settlement_evm_cumulative_amount_mismatch".to_string());
    }
    Ok(BatchVerification {
        payer: normalize_address_allow_zero(&channel_config.payer)?,
        receiver: normalize_address_allow_zero(&channel_config.receiver)?,
    })
}

pub fn validate_batch_eip712_version(
    request: &BatchFacilitatorRequest,
    expected: &str,
) -> Result<(), String> {
    let requirement_version = request
        .payment_requirements
        .extra
        .get("version")
        .and_then(Value::as_str);
    let accepted_version = request
        .payment_payload
        .accepted
        .extra
        .get("version")
        .and_then(Value::as_str);
    if requirement_version != Some(expected) || accepted_version != Some(expected) {
        return Err("invalid_batch_settlement_evm_eip712_version".to_string());
    }
    Ok(())
}

pub fn validate_optional_batch_eip712_version(
    request: &BatchFacilitatorRequest,
    expected: &str,
) -> Result<(), String> {
    let requirement_version = request
        .payment_requirements
        .extra
        .get("version")
        .and_then(Value::as_str);
    let accepted_version = request
        .payment_payload
        .accepted
        .extra
        .get("version")
        .and_then(Value::as_str);
    if requirement_version.is_some() || accepted_version.is_some() {
        validate_batch_eip712_version(request, expected)?;
    }
    Ok(())
}

pub fn requires_batch_eip712_version(payload: &BatchRequestPayload) -> bool {
    matches!(payload.kind.as_str(), "deposit" | "voucher" | "refund")
}

pub fn validate_batch_settle_request(
    request: &BatchFacilitatorRequest,
    current: Option<&BatchChannel>,
    contract: &str,
) -> Result<BatchSettleValidation, String> {
    let current_charged = current
        .map(|item| item.charged_cumulative_amount.as_str())
        .unwrap_or("0");
    validate_batch_settle_request_with_charged(request, current_charged, contract)
}

pub fn validate_batch_settle_request_with_charged(
    request: &BatchFacilitatorRequest,
    charged_cumulative_amount: &str,
    contract: &str,
) -> Result<BatchSettleValidation, String> {
    if request.x402_version != 2 || request.payment_payload.x402_version != 2 {
        return Err("x402Version must be 2".to_string());
    }
    let payload = batch_payload(&request.payment_payload.payload)?;
    validate_payload_metadata(&request.payment_payload)?;
    validate_payload_kind_fields(&payload)?;
    match payload.kind.as_str() {
        "deposit" | "refund" => {
            validate_batch_requirements(&request.payment_requirements)?;
            validate_batch_requirements(&request.payment_payload.accepted)?;
            validate_requirements_match(
                &request.payment_requirements,
                &request.payment_payload.accepted,
            )?;
            let verified =
                validate_batch_request_with_charged(request, charged_cumulative_amount, contract)?;
            if payload.kind == "refund" {
                require_present(payload.amount.as_ref(), "batch refund amount")?;
                require_present(payload.refund_nonce.as_ref(), "batch refund refundNonce")?;
                validate_refund_claims_match_channel(&payload, contract)?;
                for claim in payload.claims.as_deref().unwrap_or_default() {
                    validate_claim_matches_requirements(
                        claim,
                        &request.payment_requirements,
                        contract,
                    )?;
                }
            }
            Ok(BatchSettleValidation {
                payer: Some(verified.payer),
                receiver: verified.receiver,
            })
        }
        "claim" => {
            validate_batch_operation_requirements(&request.payment_requirements)?;
            validate_batch_operation_requirements(&request.payment_payload.accepted)?;
            validate_requirements_match(
                &request.payment_requirements,
                &request.payment_payload.accepted,
            )?;
            let claims = payload
                .claims
                .as_ref()
                .filter(|claims| !claims.is_empty())
                .ok_or_else(|| "batch claims are required".to_string())?;
            let first = &claims[0].voucher.channel;
            for claim in claims {
                validate_claim_matches_operation_requirements(
                    claim,
                    &request.payment_requirements,
                    contract,
                )?;
                if !same_address(
                    &claim.voucher.channel.receiver_authorizer,
                    &first.receiver_authorizer,
                ) {
                    return Err("batch claim receiverAuthorizer mismatch".to_string());
                }
                if claim.voucher.channel.withdraw_delay != first.withdraw_delay {
                    return Err("batch claim withdrawDelay mismatch".to_string());
                }
            }
            Ok(BatchSettleValidation {
                payer: None,
                receiver: normalize_address_allow_zero(&request.payment_requirements.pay_to)?,
            })
        }
        "settle" => {
            validate_batch_operation_requirements(&request.payment_requirements)?;
            validate_batch_operation_requirements(&request.payment_payload.accepted)?;
            validate_requirements_match(
                &request.payment_requirements,
                &request.payment_payload.accepted,
            )?;
            let receiver = payload
                .receiver
                .as_deref()
                .ok_or_else(|| "batch settle receiver is required".to_string())?;
            let token = payload
                .token
                .as_deref()
                .ok_or_else(|| "batch settle token is required".to_string())?;
            if !same_address(receiver, &request.payment_requirements.pay_to) {
                return Err("batch settle receiver must match payTo".to_string());
            }
            if !same_address(token, &request.payment_requirements.asset) {
                return Err("batch settle token must match asset".to_string());
            }
            Ok(BatchSettleValidation {
                payer: None,
                receiver: normalize_address_allow_zero(receiver)?,
            })
        }
        other => Err(format!("unsupported batch payload type: {other}")),
    }
}

fn validate_refund_claims_match_channel(
    payload: &BatchRequestPayload,
    contract: &str,
) -> Result<(), String> {
    let Some(claims) = payload.claims.as_deref() else {
        return Ok(());
    };
    if claims.is_empty() {
        return Ok(());
    }
    let config = payload
        .channel_config
        .as_ref()
        .ok_or_else(|| "batch refund channelConfig is required".to_string())?;
    let refund_channel_id = compute_batch_channel_id(config, contract)?;
    for claim in claims {
        let claim_channel_id = compute_batch_channel_id(&claim.voucher.channel, contract)?;
        if !same_bytes32(&claim_channel_id, &refund_channel_id) {
            return Err("batch refund claim channelId mismatch".to_string());
        }
    }
    Ok(())
}

fn validate_batch_operation_requirements(requirements: &PaymentRequirements) -> Result<(), String> {
    if requirements.scheme != BATCH_SCHEME {
        return Err("scheme must be batch-settlement".to_string());
    }
    let network = crate::configured_network();
    if requirements.network != network {
        return Err(format!("batch network must be {network}"));
    }
    let token = crate::configured_token_address()?;
    if !same_address(&requirements.asset, &token) {
        return Err("batch asset does not match the active network profile".to_string());
    }
    if requirements.amount != "0" {
        return Err("batch operation amount must be 0".to_string());
    }
    parse_address(&requirements.pay_to, "payTo")?;
    validate_optional_batch_extra(&requirements.extra)?;
    Ok(())
}

fn validate_optional_batch_extra(extra: &Value) -> Result<(), String> {
    if let Some(method) = extra.get("assetTransferMethod") {
        if method.as_str() != Some("eip3009") {
            return Err("batch assetTransferMethod must be eip3009".to_string());
        }
    }
    if let Some(receiver_authorizer) = extra.get("receiverAuthorizer") {
        let receiver_authorizer = receiver_authorizer
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "batch extra.receiverAuthorizer must be a string".to_string())?;
        parse_address(receiver_authorizer, "receiverAuthorizer")?;
    }
    if let Some(withdraw_delay) = extra.get("withdrawDelay") {
        let withdraw_delay = withdraw_delay
            .as_u64()
            .ok_or_else(|| "batch withdrawDelay must be a number".to_string())?;
        validate_withdraw_delay(withdraw_delay)?;
    }
    if let Some(name) = extra.get("name") {
        if name.as_str() != Some(JPYC_EIP712_NAME) {
            return Err("batch EIP-712 name mismatch".to_string());
        }
    }
    if let Some(version) = extra.get("version") {
        if version
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .is_none()
        {
            return Err("batch EIP-712 version must be a string".to_string());
        }
    }
    Ok(())
}

fn validate_payload_metadata(payload: &BatchPaymentPayload) -> Result<(), String> {
    if let Some(resource) = &payload.resource {
        validate_limited_string("resource.url", &resource.url)?;
    }
    if let Some(extensions) = &payload.extensions {
        validate_limited_string("extensions", &extensions.to_string())?;
    }
    Ok(())
}

fn validate_payload_kind_fields(payload: &BatchRequestPayload) -> Result<(), String> {
    match payload.kind.as_str() {
        "deposit" => {
            require_present(
                payload.channel_config.as_ref(),
                "batch deposit channelConfig",
            )?;
            require_present(payload.voucher.as_ref(), "batch deposit voucher")?;
            let deposit = payload
                .deposit
                .as_ref()
                .ok_or_else(|| "batch deposit payload is required".to_string())?;
            validate_deposit_authorization(deposit)?;
            reject_present(payload.amount.as_ref(), "batch deposit amount")?;
            reject_present(payload.refund_nonce.as_ref(), "batch deposit refundNonce")?;
            reject_present(payload.claims.as_ref(), "batch deposit claims")?;
            reject_present(payload.receiver.as_ref(), "batch deposit receiver")?;
            reject_present(payload.token.as_ref(), "batch deposit token")?;
            reject_present(
                payload.claim_authorizer_signature.as_ref(),
                "batch deposit claimAuthorizerSignature",
            )?;
            reject_present(
                payload.refund_authorizer_signature.as_ref(),
                "batch deposit refundAuthorizerSignature",
            )?;
        }
        "voucher" => {
            require_present(
                payload.channel_config.as_ref(),
                "batch voucher channelConfig",
            )?;
            require_present(payload.voucher.as_ref(), "batch voucher voucher")?;
            reject_present(payload.deposit.as_ref(), "batch voucher deposit")?;
            reject_present(payload.amount.as_ref(), "batch voucher amount")?;
            reject_present(payload.refund_nonce.as_ref(), "batch voucher refundNonce")?;
            reject_present(payload.claims.as_ref(), "batch voucher claims")?;
            reject_present(payload.receiver.as_ref(), "batch voucher receiver")?;
            reject_present(payload.token.as_ref(), "batch voucher token")?;
            reject_present(
                payload.claim_authorizer_signature.as_ref(),
                "batch voucher claimAuthorizerSignature",
            )?;
            reject_present(
                payload.refund_authorizer_signature.as_ref(),
                "batch voucher refundAuthorizerSignature",
            )?;
        }
        "refund" => {
            require_present(
                payload.channel_config.as_ref(),
                "batch refund channelConfig",
            )?;
            require_present(payload.voucher.as_ref(), "batch refund voucher")?;
            reject_present(payload.deposit.as_ref(), "batch refund deposit")?;
            reject_present(payload.receiver.as_ref(), "batch refund receiver")?;
            reject_present(payload.token.as_ref(), "batch refund token")?;
            if let Some(refund_nonce) = &payload.refund_nonce {
                validate_decimal("refundNonce", refund_nonce)?;
            }
            if let Some(signature) = &payload.claim_authorizer_signature {
                validate_hex("batch refund claimAuthorizerSignature", signature, 65)?;
            }
            if let Some(signature) = &payload.refund_authorizer_signature {
                validate_hex("batch refund refundAuthorizerSignature", signature, 65)?;
            }
        }
        "claim" => {
            if payload.claims.as_ref().map(Vec::is_empty).unwrap_or(true) {
                return Err("batch claims are required".to_string());
            }
            reject_present(payload.channel_config.as_ref(), "batch claim channelConfig")?;
            reject_present(payload.voucher.as_ref(), "batch claim voucher")?;
            reject_present(payload.deposit.as_ref(), "batch claim deposit")?;
            reject_present(payload.amount.as_ref(), "batch claim amount")?;
            reject_present(payload.refund_nonce.as_ref(), "batch claim refundNonce")?;
            reject_present(payload.receiver.as_ref(), "batch claim receiver")?;
            reject_present(payload.token.as_ref(), "batch claim token")?;
            reject_present(
                payload.refund_authorizer_signature.as_ref(),
                "batch claim refundAuthorizerSignature",
            )?;
            if let Some(signature) = &payload.claim_authorizer_signature {
                validate_hex("batch claim claimAuthorizerSignature", signature, 65)?;
            }
        }
        "settle" => {
            require_present(payload.receiver.as_ref(), "batch settle receiver")?;
            require_present(payload.token.as_ref(), "batch settle token")?;
            reject_present(
                payload.channel_config.as_ref(),
                "batch settle channelConfig",
            )?;
            reject_present(payload.voucher.as_ref(), "batch settle voucher")?;
            reject_present(payload.deposit.as_ref(), "batch settle deposit")?;
            reject_present(payload.amount.as_ref(), "batch settle amount")?;
            reject_present(payload.refund_nonce.as_ref(), "batch settle refundNonce")?;
            reject_present(payload.claims.as_ref(), "batch settle claims")?;
            reject_present(
                payload.claim_authorizer_signature.as_ref(),
                "batch settle claimAuthorizerSignature",
            )?;
            reject_present(
                payload.refund_authorizer_signature.as_ref(),
                "batch settle refundAuthorizerSignature",
            )?;
        }
        other => return Err(format!("unsupported batch payload type: {other}")),
    }
    if let Some(amount) = &payload.amount {
        if payload.kind == "refund" {
            validate_positive_uint128_decimal("payload.amount", amount)?;
        } else {
            validate_uint128_decimal("payload.amount", amount)?;
        }
    }
    Ok(())
}

fn require_present<T>(value: Option<&T>, label: &str) -> Result<(), String> {
    value
        .map(|_| ())
        .ok_or_else(|| format!("{label} is required"))
}

fn reject_present<T>(value: Option<&T>, label: &str) -> Result<(), String> {
    if value.is_some() {
        return Err(format!("{label} is not allowed"));
    }
    Ok(())
}

fn validate_deposit_authorization(deposit: &BatchDeposit) -> Result<(), String> {
    validate_uint128_decimal("deposit.amount", &deposit.amount)?;
    let authorization = deposit
        .authorization
        .erc3009_authorization
        .as_ref()
        .ok_or_else(|| "batch deposit erc3009Authorization is required".to_string())?;
    validate_decimal("validAfter", &authorization.valid_after)?;
    validate_decimal("validBefore", &authorization.valid_before)?;
    validate_hex("deposit salt", &authorization.salt, 32)?;
    validate_hex("deposit signature", &authorization.signature, 65)?;
    Ok(())
}

pub fn batch_payload(value: &Value) -> Result<BatchRequestPayload, String> {
    serde_json::from_value(value.clone()).map_err(|err| format!("invalid batch payload: {err}"))
}

pub fn voucher_channel_id(payload: &BatchRequestPayload) -> Result<&str, String> {
    payload
        .voucher
        .as_ref()
        .map(|voucher| voucher.channel_id.as_str())
        .ok_or_else(|| "batch voucher is required".to_string())
}

pub fn validate_batch_channel(
    channel_id: &str,
    channel: &BatchChannel,
    contract: &str,
) -> Result<(), String> {
    validate_channel_id(channel_id)?;
    if !same_bytes32(channel_id, &channel.channel_id) {
        return Err("batch channel id mismatch".to_string());
    }
    validate_channel_config(&channel.channel_config)?;
    let computed_channel_id = compute_batch_channel_id(&channel.channel_config, contract)?;
    if !same_bytes32(channel_id, &computed_channel_id) {
        return Err("batch channel config does not match channel id".to_string());
    }
    validate_decimal(
        "chargedCumulativeAmount",
        &channel.charged_cumulative_amount,
    )?;
    validate_decimal("signedMaxClaimable", &channel.signed_max_claimable)?;
    validate_uint128_decimal("balance", &channel.balance)?;
    validate_decimal("totalClaimed", &channel.total_claimed)?;
    validate_decimal("refundNonce", &channel.refund_nonce)?;
    validate_hex("signature", &channel.signature, 65)?;
    validate_stored_channel_voucher(channel, contract)?;
    if let Some(pending) = &channel.pending_request {
        validate_limited_string("pendingId", &pending.pending_id)?;
        if pending.pending_id.trim().is_empty() {
            return Err("pendingId must not be empty".to_string());
        }
        validate_decimal("pending.signedMaxClaimable", &pending.signed_max_claimable)?;
        let pending_signed =
            parse_u128_decimal("pending.signedMaxClaimable", &pending.signed_max_claimable)?;
        let charged = parse_u128_decimal(
            "chargedCumulativeAmount",
            &channel.charged_cumulative_amount,
        )?;
        if pending_signed < charged {
            return Err(
                "pending signedMaxClaimable must be at least chargedCumulativeAmount".to_string(),
            );
        }
        if pending.expires_at == 0 {
            return Err("pending expiresAt must be positive".to_string());
        }
    }
    Ok(())
}

pub fn validate_batch_channel_transition(
    current: Option<&BatchChannel>,
    next: &BatchChannel,
) -> Result<(), String> {
    let Some(current) = current else {
        return validate_initial_channel_create(next);
    };
    validate_charge_increase_consumes_pending(current, next)?;
    require_monotonic_decimal(
        "chargedCumulativeAmount",
        &current.charged_cumulative_amount,
        &next.charged_cumulative_amount,
    )?;
    require_monotonic_decimal(
        "signedMaxClaimable",
        &current.signed_max_claimable,
        &next.signed_max_claimable,
    )?;
    require_monotonic_decimal("totalClaimed", &current.total_claimed, &next.total_claimed)?;
    require_monotonic_decimal("refundNonce", &current.refund_nonce, &next.refund_nonce)?;
    if next.last_request_timestamp < current.last_request_timestamp {
        return Err("batch channel lastRequestTimestamp must not decrease".to_string());
    }
    Ok(())
}

pub fn is_pending_only_provisional_channel(channel: &BatchChannel, now_ms: u64) -> bool {
    channel.pending_request.as_ref().is_some_and(|pending| {
        pending.expires_at > now_ms && pending.signed_max_claimable == channel.signed_max_claimable
    }) && channel.charged_cumulative_amount == "0"
        && channel.balance == "0"
        && channel.total_claimed == "0"
        && channel.refund_nonce == "0"
        && channel.withdraw_requested_at == 0
        && channel.onchain_synced_at.is_none()
}

fn validate_initial_channel_create(next: &BatchChannel) -> Result<(), String> {
    let pending = next
        .pending_request
        .as_ref()
        .ok_or_else(|| "batch channel create requires pendingRequest".to_string())?;
    if pending.expires_at <= crate::now_seconds().saturating_mul(1_000) {
        return Err("batch channel create requires live pendingRequest".to_string());
    }
    if next.signed_max_claimable != pending.signed_max_claimable {
        return Err(
            "batch channel signedMaxClaimable must match pendingRequest.signedMaxClaimable when creating"
                .to_string(),
        );
    }
    if next.charged_cumulative_amount != "0" {
        return Err("batch channel create requires chargedCumulativeAmount 0".to_string());
    }
    if next.total_claimed != "0" {
        return Err("batch channel create requires totalClaimed 0".to_string());
    }
    if next.refund_nonce != "0" {
        return Err("batch channel create requires refundNonce 0".to_string());
    }
    if next.balance != "0" {
        return Err("batch channel create requires balance 0".to_string());
    }
    if next.withdraw_requested_at != 0 {
        return Err("batch channel create requires withdrawRequestedAt 0".to_string());
    }
    if next.onchain_synced_at.is_some() {
        return Err("batch channel create requires onchainSyncedAt empty".to_string());
    }
    Ok(())
}

fn validate_charge_increase_consumes_pending(
    current: &BatchChannel,
    next: &BatchChannel,
) -> Result<(), String> {
    let current_charged = parse_u128_decimal(
        "chargedCumulativeAmount",
        &current.charged_cumulative_amount,
    )?;
    let next_charged =
        parse_u128_decimal("chargedCumulativeAmount", &next.charged_cumulative_amount)?;
    if next_charged <= current_charged {
        return Ok(());
    }
    let pending = current
        .pending_request
        .as_ref()
        .ok_or_else(|| "batch channel charge increase requires pendingRequest".to_string())?;
    if pending.expires_at <= crate::now_seconds().saturating_mul(1_000) {
        return Err("batch channel charge increase requires live pendingRequest".to_string());
    }
    if next.pending_request.is_some() {
        return Err("batch channel charge increase must consume pendingRequest".to_string());
    }
    if next.signed_max_claimable != pending.signed_max_claimable {
        return Err(
            "batch channel signedMaxClaimable must match pendingRequest.signedMaxClaimable when charge increases"
                .to_string(),
        );
    }
    if next.charged_cumulative_amount != pending.signed_max_claimable {
        return Err(
            "batch channel chargedCumulativeAmount must match pendingRequest.signedMaxClaimable when charge increases"
                .to_string(),
        );
    }
    Ok(())
}

fn require_monotonic_decimal(label: &str, current: &str, next: &str) -> Result<(), String> {
    let current = parse_u256_decimal(current, label)?;
    let next = parse_u256_decimal(next, label)?;
    if next < current {
        return Err(format!("batch channel {label} must not decrease"));
    }
    Ok(())
}

pub fn validate_channel_id(channel_id: &str) -> Result<(), String> {
    validate_hex("channelId", channel_id, MAX_BATCH_CHANNEL_ID_BYTES)
}

fn validate_stored_channel_voucher(channel: &BatchChannel, contract: &str) -> Result<(), String> {
    let charged = parse_u128_decimal(
        "chargedCumulativeAmount",
        &channel.charged_cumulative_amount,
    )?;
    let signed = parse_u128_decimal("signedMaxClaimable", &channel.signed_max_claimable)?;
    let total_claimed = parse_u128_decimal("totalClaimed", &channel.total_claimed)?;
    let balance = parse_u128_decimal("balance", &channel.balance)?;
    if charged > signed {
        return Err("batch channel chargedCumulativeAmount exceeds signedMaxClaimable".to_string());
    }
    if total_claimed > signed {
        return Err("batch channel totalClaimed exceeds signedMaxClaimable".to_string());
    }
    if total_claimed > balance {
        return Err("batch channel totalClaimed exceeds balance".to_string());
    }
    if is_zero_address(&channel.channel_config.payer_authorizer) {
        return Err("unsupported_batch_eip1271".to_string());
    }
    let voucher = BatchVoucher {
        channel_id: channel.channel_id.clone(),
        max_claimable_amount: channel.signed_max_claimable.clone(),
        signature: channel.signature.clone(),
    };
    let recovered = recover_voucher_signer(&voucher, contract)?;
    if !same_address(&recovered, &channel.channel_config.payer_authorizer) {
        return Err("batch channel voucher signer mismatch".to_string());
    }
    Ok(())
}

fn validate_batch_requirements(requirements: &PaymentRequirements) -> Result<(), String> {
    if requirements.scheme != BATCH_SCHEME {
        return Err("scheme must be batch-settlement".to_string());
    }
    let network = crate::configured_network();
    if requirements.network != network {
        return Err(format!("batch network must be {network}"));
    }
    let token = crate::configured_token_address()?;
    if !same_address(&requirements.asset, &token) {
        return Err("batch asset does not match the active network profile".to_string());
    }
    if requirements
        .extra
        .get("assetTransferMethod")
        .and_then(Value::as_str)
        != Some("eip3009")
    {
        return Err("batch assetTransferMethod must be eip3009".to_string());
    }
    let receiver_authorizer = required_extra_string(&requirements.extra, "receiverAuthorizer")?;
    parse_address(receiver_authorizer, "receiverAuthorizer")?;
    let withdraw_delay = requirements
        .extra
        .get("withdrawDelay")
        .and_then(Value::as_u64)
        .ok_or_else(|| "batch withdrawDelay is required".to_string())?;
    validate_withdraw_delay(withdraw_delay)?;
    if requirements.extra.get("name").and_then(Value::as_str) != Some(JPYC_EIP712_NAME) {
        return Err("batch EIP-712 name mismatch".to_string());
    }
    if requirements
        .extra
        .get("version")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err("batch EIP-712 version is required".to_string());
    }
    validate_uint128_decimal("amount", &requirements.amount)?;
    parse_address(&requirements.pay_to, "payTo")?;
    Ok(())
}

fn validate_requirements_match(
    left: &PaymentRequirements,
    right: &PaymentRequirements,
) -> Result<(), String> {
    if left.scheme != right.scheme
        || left.network != right.network
        || !same_address(&left.asset, &right.asset)
        || !same_address(&left.pay_to, &right.pay_to)
        || left.amount != right.amount
        || left.max_timeout_seconds != right.max_timeout_seconds
        || left.extra != right.extra
    {
        return Err("paymentPayload.accepted must match paymentRequirements".to_string());
    }
    Ok(())
}

fn validate_payload_matches_requirements(
    payload: &BatchRequestPayload,
    requirements: &PaymentRequirements,
) -> Result<(), String> {
    let Some(channel_config) = payload.channel_config.as_ref() else {
        return Ok(());
    };
    validate_channel_config(channel_config)?;
    if !same_address(&channel_config.receiver, &requirements.pay_to) {
        return Err("batch channel receiver must match payTo".to_string());
    }
    if !same_address(&channel_config.token, &requirements.asset) {
        return Err("batch channel token must match asset".to_string());
    }
    let receiver_authorizer = required_extra_string(&requirements.extra, "receiverAuthorizer")?;
    if !same_address(&channel_config.receiver_authorizer, receiver_authorizer) {
        return Err("batch receiverAuthorizer mismatch".to_string());
    }
    let withdraw_delay = requirements
        .extra
        .get("withdrawDelay")
        .and_then(Value::as_u64)
        .ok_or_else(|| "batch withdrawDelay is required".to_string())?;
    if channel_config.withdraw_delay != withdraw_delay {
        return Err("batch withdrawDelay mismatch".to_string());
    }
    Ok(())
}

fn validate_claim_matches_requirements(
    claim: &BatchVoucherClaim,
    requirements: &PaymentRequirements,
    contract: &str,
) -> Result<(), String> {
    validate_channel_config(&claim.voucher.channel)?;
    if !same_address(&claim.voucher.channel.receiver, &requirements.pay_to) {
        return Err("batch claim receiver must match payTo".to_string());
    }
    if !same_address(&claim.voucher.channel.token, &requirements.asset) {
        return Err("batch claim token must match asset".to_string());
    }
    let receiver_authorizer = required_extra_string(&requirements.extra, "receiverAuthorizer")?;
    if !same_address(
        &claim.voucher.channel.receiver_authorizer,
        receiver_authorizer,
    ) {
        return Err("batch claim receiverAuthorizer mismatch".to_string());
    }
    let withdraw_delay = requirements
        .extra
        .get("withdrawDelay")
        .and_then(Value::as_u64)
        .ok_or_else(|| "batch withdrawDelay is required".to_string())?;
    if claim.voucher.channel.withdraw_delay != withdraw_delay {
        return Err("batch claim withdrawDelay mismatch".to_string());
    }
    validate_claim_voucher_signature(claim, contract)
}

fn validate_claim_matches_operation_requirements(
    claim: &BatchVoucherClaim,
    requirements: &PaymentRequirements,
    contract: &str,
) -> Result<(), String> {
    validate_channel_config(&claim.voucher.channel)?;
    if !same_address(&claim.voucher.channel.receiver, &requirements.pay_to) {
        return Err("batch claim receiver must match payTo".to_string());
    }
    if !same_address(&claim.voucher.channel.token, &requirements.asset) {
        return Err("batch claim token must match asset".to_string());
    }
    if let Some(receiver_authorizer) = requirements.extra.get("receiverAuthorizer") {
        let receiver_authorizer = receiver_authorizer
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "batch extra.receiverAuthorizer must be a string".to_string())?;
        if !same_address(
            &claim.voucher.channel.receiver_authorizer,
            receiver_authorizer,
        ) {
            return Err("batch claim receiverAuthorizer mismatch".to_string());
        }
    }
    if let Some(withdraw_delay) = requirements.extra.get("withdrawDelay") {
        let withdraw_delay = withdraw_delay
            .as_u64()
            .ok_or_else(|| "batch withdrawDelay must be a number".to_string())?;
        if claim.voucher.channel.withdraw_delay != withdraw_delay {
            return Err("batch claim withdrawDelay mismatch".to_string());
        }
    }
    validate_claim_voucher_signature(claim, contract)
}

fn validate_claim_voucher_signature(
    claim: &BatchVoucherClaim,
    contract: &str,
) -> Result<(), String> {
    let max_claimable =
        parse_u128_decimal("maxClaimableAmount", &claim.voucher.max_claimable_amount)?;
    let total_claimed = parse_u128_decimal("totalClaimed", &claim.total_claimed)?;
    if total_claimed > max_claimable {
        return Err("batch claim totalClaimed exceeds maxClaimableAmount".to_string());
    }
    validate_hex("signature", &claim.signature, 65)?;
    if is_zero_address(&claim.voucher.channel.payer_authorizer) {
        return Err("unsupported_batch_eip1271".to_string());
    }
    let channel_id = compute_batch_channel_id(&claim.voucher.channel, contract)?;
    let voucher = BatchVoucher {
        channel_id,
        max_claimable_amount: claim.voucher.max_claimable_amount.clone(),
        signature: claim.signature.clone(),
    };
    let recovered = recover_voucher_signer(&voucher, contract)?;
    if !same_address(&recovered, &claim.voucher.channel.payer_authorizer) {
        return Err("batch claim voucher signer mismatch".to_string());
    }
    Ok(())
}

fn validate_channel_config(config: &BatchChannelConfig) -> Result<(), String> {
    parse_address(&config.payer, "payer")?;
    normalize_address_allow_zero(&config.payer_authorizer)?;
    parse_address(&config.receiver, "receiver")?;
    parse_address(&config.receiver_authorizer, "receiverAuthorizer")?;
    parse_address(&config.token, "token")?;
    validate_hex("salt", &config.salt, 32)?;
    validate_withdraw_delay(config.withdraw_delay)?;
    Ok(())
}

pub fn validate_withdraw_delay(value: u64) -> Result<(), String> {
    if !(MIN_BATCH_WITHDRAW_DELAY_SECONDS..=MAX_BATCH_WITHDRAW_DELAY_SECONDS).contains(&value) {
        return Err(format!(
            "batch withdrawDelay must be between {MIN_BATCH_WITHDRAW_DELAY_SECONDS} and {MAX_BATCH_WITHDRAW_DELAY_SECONDS} seconds"
        ));
    }
    Ok(())
}

pub fn compute_batch_channel_id(
    config: &BatchChannelConfig,
    contract: &str,
) -> Result<String, String> {
    let domain = batch_domain_separator(contract)?;
    let message = channel_config_hash(config)?;
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain);
    encoded.extend_from_slice(&message);
    Ok(format!("0x{}", hex::encode(keccak256(&encoded))))
}

fn recover_voucher_signer(voucher: &BatchVoucher, contract: &str) -> Result<String, String> {
    let domain = batch_domain_separator(contract)?;
    let message = voucher_hash(voucher)?;
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain);
    encoded.extend_from_slice(&message);
    let digest = keccak256(&encoded);
    let sig = parse_hex(&voucher.signature, Some(65))?;
    let signature =
        Signature::try_from(&sig[..64]).map_err(|_| "invalid batch voucher signature")?;
    let recovery = recovery_id(sig[64])?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery)
        .map_err(|_| "invalid batch voucher signature")?;
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address_hex(&address))
}

fn recover_deposit_authorization_signer(
    deposit: &BatchDeposit,
    config: &BatchChannelConfig,
    requirements: &PaymentRequirements,
) -> Result<String, String> {
    let authorization = deposit
        .authorization
        .erc3009_authorization
        .as_ref()
        .ok_or_else(|| "batch deposit erc3009Authorization is required".to_string())?;
    let digest =
        deposit_authorization_digest(authorization, config, &deposit.amount, requirements)?;
    let sig = parse_hex(&authorization.signature, Some(65))
        .map_err(|err| format!("deposit signature: {err}"))?;
    let signature =
        Signature::try_from(&sig[..64]).map_err(|_| "invalid batch deposit signature")?;
    let recovery = recovery_id(sig[64])?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery)
        .map_err(|_| "invalid batch deposit signature")?;
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address_hex(&address))
}

fn validate_deposit_authorization_time_window(
    deposit: &BatchDeposit,
    requirements: &PaymentRequirements,
) -> Result<(), String> {
    let authorization = deposit
        .authorization
        .erc3009_authorization
        .as_ref()
        .ok_or_else(|| "batch deposit erc3009Authorization is required".to_string())?;
    let now = crate::now_seconds();
    let valid_before = authorization.valid_before.parse::<u64>().unwrap_or(0);
    let valid_after = authorization.valid_after.parse::<u64>().unwrap_or(u64::MAX);
    if valid_before < now.saturating_add(6) {
        return Err("batch deposit EIP-3009 validBefore is expired".to_string());
    }
    if valid_after > now {
        return Err("batch deposit EIP-3009 validAfter is in the future".to_string());
    }
    if valid_before
        > now
            .saturating_add(requirements.max_timeout_seconds)
            .saturating_add(6)
    {
        return Err("batch deposit EIP-3009 validBefore exceeds maxTimeoutSeconds".to_string());
    }
    Ok(())
}

fn deposit_authorization_digest(
    authorization: &BatchErc3009Authorization,
    config: &BatchChannelConfig,
    amount: &str,
    requirements: &PaymentRequirements,
) -> Result<[u8; 32], String> {
    let domain = erc3009_domain_separator(requirements)?;
    let message = deposit_authorization_hash(authorization, config, amount)?;
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain);
    encoded.extend_from_slice(&message);
    Ok(keccak256(&encoded))
}

fn erc3009_domain_separator(requirements: &PaymentRequirements) -> Result<[u8; 32], String> {
    let name = required_extra_string(&requirements.extra, "name")?;
    let version = required_extra_string(&requirements.extra, "version")?;
    let verifying_contract = parse_address(&requirements.asset, "asset")?;
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    encoded.extend_from_slice(&keccak256(name.as_bytes()));
    encoded.extend_from_slice(&keccak256(version.as_bytes()));
    encoded.extend_from_slice(&u256_word(137));
    encoded.extend_from_slice(&address_word(&verifying_contract));
    Ok(keccak256(&encoded))
}

fn deposit_authorization_hash(
    authorization: &BatchErc3009Authorization,
    config: &BatchChannelConfig,
    amount: &str,
) -> Result<[u8; 32], String> {
    let from = parse_address(&config.payer, "payer")?;
    let to = parse_address(
        ERC3009_DEPOSIT_COLLECTOR_ADDRESS,
        "ERC3009 deposit collector",
    )?;
    let value = parse_u256_decimal(amount, "deposit.amount")?;
    let valid_after = parse_u256_decimal(&authorization.valid_after, "validAfter")?;
    let valid_before = parse_u256_decimal(&authorization.valid_before, "validBefore")?;
    let nonce =
        parse_hex(&authorization.salt, Some(32)).map_err(|err| format!("deposit salt: {err}"))?;
    let mut encoded = Vec::with_capacity(224);
    encoded.extend_from_slice(&keccak256(RECEIVE_WITH_AUTHORIZATION_TYPE.as_bytes()));
    encoded.extend_from_slice(&address_word(&from));
    encoded.extend_from_slice(&address_word(&to));
    encoded.extend_from_slice(&value);
    encoded.extend_from_slice(&valid_after);
    encoded.extend_from_slice(&valid_before);
    encoded.extend_from_slice(&nonce);
    Ok(keccak256(&encoded))
}

fn batch_domain_separator(contract: &str) -> Result<[u8; 32], String> {
    let verifying_contract = parse_address(contract, "BATCH_SETTLEMENT_CONTRACT")?;
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    encoded.extend_from_slice(&keccak256(BATCH_DOMAIN_NAME.as_bytes()));
    encoded.extend_from_slice(&keccak256(BATCH_DOMAIN_VERSION.as_bytes()));
    encoded.extend_from_slice(&u256_word(137));
    encoded.extend_from_slice(&address_word(&verifying_contract));
    Ok(keccak256(&encoded))
}

fn channel_config_hash(config: &BatchChannelConfig) -> Result<[u8; 32], String> {
    let payer = parse_address(&config.payer, "payer")?;
    let payer_authorizer = parse_address_allow_zero(&config.payer_authorizer, "payerAuthorizer")?;
    let receiver = parse_address(&config.receiver, "receiver")?;
    let receiver_authorizer = parse_address(&config.receiver_authorizer, "receiverAuthorizer")?;
    let token = parse_address(&config.token, "token")?;
    let salt = parse_hex(&config.salt, Some(32)).map_err(|err| format!("salt: {err}"))?;
    let mut encoded = Vec::with_capacity(256);
    encoded.extend_from_slice(&keccak256(CHANNEL_CONFIG_TYPE.as_bytes()));
    encoded.extend_from_slice(&address_word(&payer));
    encoded.extend_from_slice(&address_word(&payer_authorizer));
    encoded.extend_from_slice(&address_word(&receiver));
    encoded.extend_from_slice(&address_word(&receiver_authorizer));
    encoded.extend_from_slice(&address_word(&token));
    encoded.extend_from_slice(&u256_word(config.withdraw_delay as u128));
    encoded.extend_from_slice(&salt);
    Ok(keccak256(&encoded))
}

fn voucher_hash(voucher: &BatchVoucher) -> Result<[u8; 32], String> {
    let channel_id =
        parse_hex(&voucher.channel_id, Some(32)).map_err(|err| format!("channelId: {err}"))?;
    let max_claimable =
        parse_u128_decimal_word(&voucher.max_claimable_amount, "maxClaimableAmount")?;
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(&keccak256(VOUCHER_TYPE.as_bytes()));
    encoded.extend_from_slice(&channel_id);
    encoded.extend_from_slice(&max_claimable);
    Ok(keccak256(&encoded))
}

fn add_decimal_strings(left: &str, right: &str) -> Result<String, String> {
    let left = parse_u128_decimal("left", left)?;
    let right = parse_u128_decimal("right", right)?;
    left.checked_add(right)
        .map(|value| value.to_string())
        .ok_or_else(|| "batch cumulative amount overflow".to_string())
}

fn parse_u128_decimal(label: &str, value: &str) -> Result<u128, String> {
    validate_limited_string(label, value)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label}: invalid decimal integer"));
    }
    value
        .parse::<u128>()
        .map_err(|_| format!("{label}: integer too large"))
}

fn validate_decimal(label: &str, value: &str) -> Result<(), String> {
    validate_limited_string(label, value)?;
    parse_u256_decimal(value, label)?;
    Ok(())
}

fn validate_uint128_decimal(label: &str, value: &str) -> Result<(), String> {
    parse_u128_decimal(label, value)?;
    Ok(())
}

fn validate_positive_uint128_decimal(label: &str, value: &str) -> Result<(), String> {
    if parse_u128_decimal(label, value)? == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn validate_limited_string(label: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_BATCH_STRING_BYTES {
        return Err(format!("{label} exceeds {MAX_BATCH_STRING_BYTES} bytes"));
    }
    Ok(())
}

fn validate_hex(label: &str, value: &str, bytes: usize) -> Result<(), String> {
    validate_limited_string(label, value)?;
    parse_hex(value, Some(bytes))
        .map(|_| ())
        .map_err(|err| format!("{label}: {err}"))
}

fn required_extra_string<'a>(extra: &'a Value, name: &str) -> Result<&'a str, String> {
    extra
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("batch extra.{name} is required"))
}

fn same_bytes32(left: &str, right: &str) -> bool {
    let Ok(left) = parse_hex(left, Some(32)) else {
        return false;
    };
    let Ok(right) = parse_hex(right, Some(32)) else {
        return false;
    };
    left == right
}

fn is_zero_address(value: &str) -> bool {
    crate::hexutil::strip_0x(value).eq_ignore_ascii_case("0000000000000000000000000000000000000000")
}

fn normalize_address_allow_zero(value: &str) -> Result<String, String> {
    parse_address_allow_zero(value, "address").map(|address| address_hex(&address))
}

fn parse_address_allow_zero(value: &str, label: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex(value, Some(20)).map_err(|err| format!("{label}: {err}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
pub(crate) fn sign_batch_voucher_for_test(
    channel_id: &str,
    max_claimable_amount: &str,
    private_key: &str,
    contract: &str,
) -> String {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;

    let voucher = BatchVoucher {
        channel_id: channel_id.to_string(),
        max_claimable_amount: max_claimable_amount.to_string(),
        signature: "0x".to_string(),
    };
    let domain = batch_domain_separator(contract).unwrap();
    let message = voucher_hash(&voucher).unwrap();
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain);
    encoded.extend_from_slice(&message);
    let digest = keccak256(&encoded);
    let key = SigningKey::from_slice(&parse_hex(private_key, Some(32)).unwrap()).unwrap();
    let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash(&digest).unwrap();
    let mut bytes = Vec::with_capacity(65);
    bytes.extend_from_slice(&signature.to_bytes());
    bytes.push(u8::from(recovery) + 27);
    format!("0x{}", hex::encode(bytes))
}

fn recovery_id(value: u8) -> Result<RecoveryId, String> {
    let normalized = match value {
        0 | 1 => value,
        27 | 28 => value - 27,
        _ => return Err("invalid signature recovery id".to_string()),
    };
    RecoveryId::try_from(normalized).map_err(|_| "invalid signature recovery id".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;
    use serde_json::json;

    const PAYER_PRIVATE_KEY: &str =
        "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
    const OTHER_PRIVATE_KEY: &str =
        "0x2222222222222222222222222222222222222222222222222222222222222222";
    const RECEIVER: &str = "0x1000000000000000000000000000000000000402";
    const RECEIVER_AUTHORIZER: &str = "0x2000000000000000000000000000000000000402";

    fn signer_address(private_key: &str) -> String {
        let key = SigningKey::from_slice(&parse_hex(private_key, Some(32)).unwrap()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address_hex(&address)
    }

    fn sign_voucher(voucher: &BatchVoucher, private_key: &str) -> String {
        let domain = batch_domain_separator(DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let message = voucher_hash(voucher).unwrap();
        let mut encoded = Vec::with_capacity(66);
        encoded.extend_from_slice(b"\x19\x01");
        encoded.extend_from_slice(&domain);
        encoded.extend_from_slice(&message);
        let digest = keccak256(&encoded);
        let key = SigningKey::from_slice(&parse_hex(private_key, Some(32)).unwrap()).unwrap();
        let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash(&digest).unwrap();
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.push(u8::from(recovery) + 27);
        format!("0x{}", hex::encode(bytes))
    }

    fn requirements(amount: &str) -> PaymentRequirements {
        PaymentRequirements {
            scheme: BATCH_SCHEME.to_string(),
            network: NETWORK.to_string(),
            asset: JPYC_POLYGON_ADDRESS.to_string(),
            amount: amount.to_string(),
            pay_to: RECEIVER.to_string(),
            max_timeout_seconds: 60,
            extra: json!({
                "receiverAuthorizer": RECEIVER_AUTHORIZER,
                "withdrawDelay": DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS,
                "assetTransferMethod": "eip3009",
                "name": JPYC_EIP712_NAME,
                "version": "1"
            }),
        }
    }

    fn request(amount: &str, signer_key: &str) -> BatchFacilitatorRequest {
        let channel_config = BatchChannelConfig {
            payer: signer_address(PAYER_PRIVATE_KEY),
            payer_authorizer: signer_address(PAYER_PRIVATE_KEY),
            receiver: RECEIVER.to_string(),
            receiver_authorizer: RECEIVER_AUTHORIZER.to_string(),
            token: JPYC_POLYGON_ADDRESS.to_string(),
            withdraw_delay: DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS,
            salt: format!("0x{}", "33".repeat(32)),
        };
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let mut voucher = BatchVoucher {
            channel_id,
            max_claimable_amount: amount.to_string(),
            signature: "0x".to_string(),
        };
        voucher.signature = sign_voucher(&voucher, signer_key);
        let requirements = requirements(amount);
        BatchFacilitatorRequest {
            x402_version: 2,
            payment_payload: BatchPaymentPayload {
                x402_version: 2,
                resource: Some(ResourceInfo {
                    url: "https://example.test/resource".to_string(),
                    description: None,
                    mime_type: None,
                }),
                accepted: requirements.clone(),
                payload: json!({
                    "type": "voucher",
                    "channelConfig": channel_config,
                    "voucher": voucher
                }),
                extensions: None,
            },
            payment_requirements: requirements,
        }
    }

    fn set_voucher_max_claimable(request: &mut BatchFacilitatorRequest, amount: &str) {
        let mut payload = batch_payload(&request.payment_payload.payload).unwrap();
        let voucher = payload.voucher.as_mut().unwrap();
        voucher.max_claimable_amount = amount.to_string();
        voucher.signature = sign_voucher(voucher, PAYER_PRIVATE_KEY);
        let payload = request.payment_payload.payload.as_object_mut().unwrap();
        let voucher_json = payload.get_mut("voucher").unwrap().as_object_mut().unwrap();
        voucher_json.insert(
            "maxClaimableAmount".to_string(),
            json!(voucher.max_claimable_amount),
        );
        voucher_json.insert("signature".to_string(), json!(voucher.signature));
    }

    fn set_payload_type(request: &mut BatchFacilitatorRequest, kind: &str) {
        request
            .payment_payload
            .payload
            .as_object_mut()
            .unwrap()
            .insert("type".to_string(), json!(kind));
    }

    fn set_deposit_payload(request: &mut BatchFacilitatorRequest, amount: &str) {
        let parsed = batch_payload(&request.payment_payload.payload).unwrap();
        let channel_config = parsed.channel_config.as_ref().unwrap();
        let authorization = BatchErc3009Authorization {
            valid_after: "0".to_string(),
            valid_before: crate::now_seconds().saturating_add(60).to_string(),
            salt: format!("0x{}", "44".repeat(32)),
            signature: "0x".to_string(),
        };
        let signature = sign_deposit_authorization(
            &authorization,
            channel_config,
            amount,
            &request.payment_requirements,
            PAYER_PRIVATE_KEY,
        );
        let payload = request.payment_payload.payload.as_object_mut().unwrap();
        payload.insert("type".to_string(), json!("deposit"));
        payload.insert(
            "deposit".to_string(),
            json!({
                "amount": amount,
                "authorization": {
                    "erc3009Authorization": {
                        "validAfter": authorization.valid_after,
                        "validBefore": authorization.valid_before,
                        "salt": authorization.salt,
                        "signature": signature
                    }
                }
            }),
        );
    }

    fn sign_deposit_authorization(
        authorization: &BatchErc3009Authorization,
        config: &BatchChannelConfig,
        amount: &str,
        requirements: &PaymentRequirements,
        private_key: &str,
    ) -> String {
        let digest =
            deposit_authorization_digest(authorization, config, amount, requirements).unwrap();
        let key = SigningKey::from_slice(&parse_hex(private_key, Some(32)).unwrap()).unwrap();
        let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash(&digest).unwrap();
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.push(u8::from(recovery) + 27);
        format!("0x{}", hex::encode(bytes))
    }

    fn claim_request(
        max_claimable: &str,
        total_claimed: &str,
        signer_key: &str,
    ) -> BatchFacilitatorRequest {
        let mut request = request("0", PAYER_PRIVATE_KEY);
        let payload = batch_payload(&request.payment_payload.payload).unwrap();
        let channel_config = payload.channel_config.unwrap();
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let mut voucher = BatchVoucher {
            channel_id,
            max_claimable_amount: max_claimable.to_string(),
            signature: "0x".to_string(),
        };
        voucher.signature = sign_voucher(&voucher, signer_key);
        request.payment_payload.payload = json!({
            "type": "claim",
            "claims": [{
                "voucher": {
                    "channel": channel_config,
                    "maxClaimableAmount": max_claimable
                },
                "signature": voucher.signature,
                "totalClaimed": total_claimed
            }]
        });
        request
    }

    fn channel_for_request(request: &BatchFacilitatorRequest, charged: &str) -> BatchChannel {
        let payload = batch_payload(&request.payment_payload.payload).unwrap();
        let channel_config = payload.channel_config.unwrap();
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        BatchChannel {
            channel_id: channel_id.clone(),
            channel_config,
            charged_cumulative_amount: charged.to_string(),
            signed_max_claimable: charged.to_string(),
            signature: sign_batch_voucher_for_test(
                &channel_id,
                charged,
                PAYER_PRIVATE_KEY,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT,
            ),
            balance: "1000".to_string(),
            total_claimed: "0".to_string(),
            withdraw_requested_at: 0,
            refund_nonce: "0".to_string(),
            onchain_synced_at: None,
            last_request_timestamp: 1,
            pending_request: None,
            revision: 1,
        }
    }

    #[test]
    fn validates_eoa_voucher_and_channel_state() {
        let request = request("100", PAYER_PRIVATE_KEY);
        let verified =
            validate_batch_request(&request, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();

        assert_eq!(verified.receiver, RECEIVER.to_lowercase());
        assert_eq!(verified.payer, signer_address(PAYER_PRIVATE_KEY));
    }

    #[test]
    fn rejects_zero_payer_channel_config() {
        let mut zero_payer_request = request("100", PAYER_PRIVATE_KEY);
        zero_payer_request.payment_payload.payload["channelConfig"]["payer"] =
            json!("0x0000000000000000000000000000000000000000");

        assert_eq!(
            validate_batch_request(&zero_payer_request, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "payer: zero address"
        );

        let mut channel = channel_for_request(&request("100", PAYER_PRIVATE_KEY), "100");
        channel.channel_config.payer = "0x0000000000000000000000000000000000000000".to_string();
        assert_eq!(
            validate_batch_channel(
                &channel.channel_id,
                &channel,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "payer: zero address"
        );
    }

    #[test]
    fn validates_stored_channel_voucher_signature_and_bounds() {
        let request = request("100", PAYER_PRIVATE_KEY);
        let channel = channel_for_request(&request, "100");

        assert!(validate_batch_channel(
            &channel.channel_id,
            &channel,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT
        )
        .is_ok());

        let mut bad_signature = channel.clone();
        bad_signature.signature = sign_batch_voucher_for_test(
            &bad_signature.channel_id,
            &bad_signature.signed_max_claimable,
            OTHER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        assert_eq!(
            validate_batch_channel(
                &bad_signature.channel_id,
                &bad_signature,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch channel voucher signer mismatch"
        );

        let mut over_charged = channel.clone();
        over_charged.charged_cumulative_amount = "101".to_string();
        assert_eq!(
            validate_batch_channel(
                &over_charged.channel_id,
                &over_charged,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch channel chargedCumulativeAmount exceeds signedMaxClaimable"
        );

        let mut over_claimed = channel;
        over_claimed.total_claimed = "101".to_string();
        assert_eq!(
            validate_batch_channel(
                &over_claimed.channel_id,
                &over_claimed,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch channel totalClaimed exceeds signedMaxClaimable"
        );

        let mut claimed_over_balance = over_claimed.clone();
        claimed_over_balance.total_claimed = "50".to_string();
        claimed_over_balance.balance = "49".to_string();
        assert_eq!(
            validate_batch_channel(
                &claimed_over_balance.channel_id,
                &claimed_over_balance,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch channel totalClaimed exceeds balance"
        );

        let mut over_balance = over_claimed.clone();
        over_balance.total_claimed = "0".to_string();
        over_balance.balance = "340282366920938463463374607431768211456".to_string();
        assert_eq!(
            validate_batch_channel(
                &over_balance.channel_id,
                &over_balance,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "balance: integer too large"
        );

        let mut oversized_refund_nonce = over_claimed.clone();
        oversized_refund_nonce.total_claimed = "0".to_string();
        oversized_refund_nonce.refund_nonce = "1".repeat(MAX_BATCH_STRING_BYTES + 1);
        assert_eq!(
            validate_batch_channel(
                &oversized_refund_nonce.channel_id,
                &oversized_refund_nonce,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "refundNonce exceeds 512 bytes"
        );

        let mut oversized_charged = over_claimed.clone();
        oversized_charged.charged_cumulative_amount = "1".repeat(MAX_BATCH_STRING_BYTES + 1);
        assert_eq!(
            validate_batch_channel(
                &oversized_charged.channel_id,
                &oversized_charged,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "chargedCumulativeAmount exceeds 512 bytes"
        );

        let mut valid_pending = over_claimed.clone();
        valid_pending.total_claimed = "0".to_string();
        valid_pending.pending_request = Some(BatchPendingRequest {
            pending_id: "request-1".to_string(),
            signed_max_claimable: "125".to_string(),
            expires_at: 1,
        });
        assert!(validate_batch_channel(
            &valid_pending.channel_id,
            &valid_pending,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT
        )
        .is_ok());

        let mut empty_pending_id = valid_pending.clone();
        empty_pending_id
            .pending_request
            .as_mut()
            .unwrap()
            .pending_id = " ".to_string();
        assert_eq!(
            validate_batch_channel(
                &empty_pending_id.channel_id,
                &empty_pending_id,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "pendingId must not be empty"
        );

        let mut stale_pending = valid_pending.clone();
        stale_pending
            .pending_request
            .as_mut()
            .unwrap()
            .signed_max_claimable = "99".to_string();
        assert_eq!(
            validate_batch_channel(
                &stale_pending.channel_id,
                &stale_pending,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "pending signedMaxClaimable must be at least chargedCumulativeAmount"
        );

        let mut no_expiry = valid_pending;
        no_expiry.pending_request.as_mut().unwrap().expires_at = 0;
        assert_eq!(
            validate_batch_channel(
                &no_expiry.channel_id,
                &no_expiry,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "pending expiresAt must be positive"
        );
    }

    #[test]
    fn batch_settle_rejects_voucher_and_uses_current_channel_for_cumulative_actions() {
        let voucher = request("25", PAYER_PRIVATE_KEY);
        assert_eq!(
            validate_batch_settle_request(&voucher, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "unsupported batch payload type: voucher"
        );

        let mut top_up = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut top_up, "250");
        set_voucher_max_claimable(&mut top_up, "125");
        let current = channel_for_request(&top_up, "100");
        assert_eq!(
            validate_batch_settle_request(&top_up, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_amount_mismatch"
        );
        assert!(validate_batch_settle_request(
            &top_up,
            Some(&current),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT
        )
        .is_ok());

        let mut refund = request("25", PAYER_PRIVATE_KEY);
        set_payload_type(&mut refund, "refund");
        set_voucher_max_claimable(&mut refund, "100");
        let current = channel_for_request(&refund, "100");
        assert_eq!(
            validate_batch_settle_request(&refund, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_amount_mismatch"
        );
        assert_eq!(
            validate_batch_settle_request(
                &refund,
                Some(&current),
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch refund amount is required"
        );
        refund.payment_payload.payload["amount"] = json!("0");
        assert_eq!(
            validate_batch_settle_request(
                &refund,
                Some(&current),
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "payload.amount must be positive"
        );
        refund.payment_payload.payload["amount"] = json!("10");
        assert_eq!(
            validate_batch_settle_request(
                &refund,
                Some(&current),
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch refund refundNonce is required"
        );
        refund.payment_payload.payload["refundNonce"] = json!("0");
        assert!(validate_batch_settle_request(
            &refund,
            Some(&current),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT
        )
        .is_ok());

        let channel_config: BatchChannelConfig =
            serde_json::from_value(refund.payment_payload.payload["channelConfig"].clone())
                .unwrap();
        let channel_id =
            compute_batch_channel_id(&channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let claim_signature = sign_batch_voucher_for_test(
            &channel_id,
            "100",
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        refund.payment_payload.payload["claims"] = json!([{
            "voucher": {
                "channel": channel_config,
                "maxClaimableAmount": "100"
            },
            "signature": claim_signature,
            "totalClaimed": "75"
        }]);
        assert!(validate_batch_settle_request(
            &refund,
            Some(&current),
            DEFAULT_BATCH_SETTLEMENT_CONTRACT
        )
        .is_ok());

        let mut other_channel_config: BatchChannelConfig =
            serde_json::from_value(refund.payment_payload.payload["channelConfig"].clone())
                .unwrap();
        other_channel_config.salt = format!("0x{}", "44".repeat(32));
        let other_channel_id =
            compute_batch_channel_id(&other_channel_config, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap();
        let other_claim_signature = sign_batch_voucher_for_test(
            &other_channel_id,
            "100",
            PAYER_PRIVATE_KEY,
            DEFAULT_BATCH_SETTLEMENT_CONTRACT,
        );
        refund.payment_payload.payload["claims"][0]["voucher"]["channel"] =
            serde_json::to_value(other_channel_config).unwrap();
        refund.payment_payload.payload["claims"][0]["signature"] = json!(other_claim_signature);
        assert_eq!(
            validate_batch_settle_request(
                &refund,
                Some(&current),
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch refund claim channelId mismatch"
        );
    }

    #[test]
    fn rejects_zero_receiver_authorizer_in_batch_requirements() {
        let mut settle = request("0", PAYER_PRIVATE_KEY);
        settle.payment_requirements.extra["receiverAuthorizer"] =
            json!("0x0000000000000000000000000000000000000000");
        settle.payment_payload.accepted = settle.payment_requirements.clone();
        settle.payment_payload.payload = json!({
            "type": "settle",
            "receiver": RECEIVER,
            "token": JPYC_POLYGON_ADDRESS
        });

        assert_eq!(
            validate_batch_settle_request(&settle, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "receiverAuthorizer: zero address"
        );
    }

    #[test]
    fn batch_claim_validates_voucher_signature_and_claim_bounds() {
        let valid = claim_request("100", "75", PAYER_PRIVATE_KEY);
        assert!(
            validate_batch_settle_request(&valid, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).is_ok()
        );

        let bad_signer = claim_request("100", "75", OTHER_PRIVATE_KEY);
        assert_eq!(
            validate_batch_settle_request(&bad_signer, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "batch claim voucher signer mismatch"
        );

        let over_claimed = claim_request("100", "101", PAYER_PRIVATE_KEY);
        assert_eq!(
            validate_batch_settle_request(&over_claimed, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "batch claim totalClaimed exceeds maxClaimableAmount"
        );

        let mut eip1271 = claim_request("100", "75", PAYER_PRIVATE_KEY);
        eip1271.payment_payload.payload["claims"][0]["voucher"]["channel"]["payerAuthorizer"] =
            json!("0x0000000000000000000000000000000000000000");
        assert_eq!(
            validate_batch_settle_request(&eip1271, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "unsupported_batch_eip1271"
        );
    }

    #[test]
    fn batch_deposit_requires_eip3009_authorization_before_rpc() {
        let mut deposit = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut deposit, "100");
        deposit.payment_payload.payload["deposit"]["authorization"]["erc3009Authorization"] =
            json!(null);

        assert_eq!(
            validate_batch_request(&deposit, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "batch deposit erc3009Authorization is required"
        );

        let mut invalid_signature = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut invalid_signature, "100");
        invalid_signature.payment_payload.payload["deposit"]["authorization"]
            ["erc3009Authorization"]["signature"] = json!("0x01");
        assert_eq!(
            validate_batch_request(&invalid_signature, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "deposit signature: hex must be 65 bytes"
        );

        let mut signer_mismatch = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut signer_mismatch, "100");
        let payload = batch_payload(&signer_mismatch.payment_payload.payload).unwrap();
        let channel_config = payload.channel_config.as_ref().unwrap();
        let authorization = payload
            .deposit
            .as_ref()
            .unwrap()
            .authorization
            .erc3009_authorization
            .as_ref()
            .unwrap();
        signer_mismatch.payment_payload.payload["deposit"]["authorization"]
            ["erc3009Authorization"]["signature"] = json!(sign_deposit_authorization(
            authorization,
            channel_config,
            "100",
            &signer_mismatch.payment_requirements,
            OTHER_PRIVATE_KEY
        ));
        assert_eq!(
            validate_batch_request(&signer_mismatch, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "batch deposit authorization signer mismatch"
        );

        let mut expired = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut expired, "100");
        expired.payment_payload.payload["deposit"]["authorization"]["erc3009Authorization"]
            ["validBefore"] = json!(crate::now_seconds().saturating_add(5).to_string());
        assert_eq!(
            validate_batch_request(&expired, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "batch deposit EIP-3009 validBefore is expired"
        );

        let mut future = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut future, "100");
        future.payment_payload.payload["deposit"]["authorization"]["erc3009Authorization"]
            ["validAfter"] = json!(crate::now_seconds().saturating_add(1).to_string());
        assert_eq!(
            validate_batch_request(&future, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "batch deposit EIP-3009 validAfter is in the future"
        );

        let mut too_long = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut too_long, "100");
        too_long.payment_payload.payload["deposit"]["authorization"]["erc3009Authorization"]
            ["validBefore"] = json!(crate::now_seconds().saturating_add(67).to_string());
        assert_eq!(
            validate_batch_request(&too_long, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "batch deposit EIP-3009 validBefore exceeds maxTimeoutSeconds"
        );

        let mut permit2 = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut permit2, "100");
        permit2.payment_payload.payload["deposit"]["authorization"]["permit2Authorization"] =
            json!({});
        assert!(
            validate_batch_request(&permit2, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err()
                .contains("unknown field `permit2Authorization`")
        );

        let mut extra_field = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut extra_field, "100");
        extra_field.payment_payload.payload["deposit"]["authorization"]["erc3009Authorization"]
            ["extra"] = json!("ignored");
        assert!(
            validate_batch_request(&extra_field, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err()
                .contains("unknown field `extra`")
        );
    }

    #[test]
    fn batch_payload_rejects_type_inappropriate_fields() {
        let mut voucher = request("25", PAYER_PRIVATE_KEY);
        voucher.payment_payload.payload["amount"] = json!("1");
        assert_eq!(
            validate_batch_request(&voucher, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "batch voucher amount is not allowed"
        );

        let mut deposit = request("25", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut deposit, "100");
        deposit.payment_payload.payload["receiver"] = json!(RECEIVER);
        assert_eq!(
            validate_batch_request(&deposit, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "batch deposit receiver is not allowed"
        );

        let mut config_extra = request("25", PAYER_PRIVATE_KEY);
        config_extra.payment_payload.payload["channelConfig"]["unexpected"] = json!(true);
        assert!(
            validate_batch_request(&config_extra, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err()
                .contains("unknown field `unexpected`")
        );

        let mut claim = claim_request("100", "75", PAYER_PRIVATE_KEY);
        claim.payment_payload.payload["token"] = json!(JPYC_POLYGON_ADDRESS);
        assert_eq!(
            validate_batch_settle_request(&claim, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "batch claim token is not allowed"
        );

        let mut bad_claim_signature = claim_request("100", "75", PAYER_PRIVATE_KEY);
        bad_claim_signature.payment_payload.payload["claimAuthorizerSignature"] = json!("0x01");
        assert_eq!(
            validate_batch_settle_request(
                &bad_claim_signature,
                None,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch claim claimAuthorizerSignature: hex must be 65 bytes"
        );

        let mut bad_refund_signature = request("25", PAYER_PRIVATE_KEY);
        bad_refund_signature.payment_payload.payload["type"] = json!("refund");
        bad_refund_signature.payment_payload.payload["refundAuthorizerSignature"] = json!("0x01");
        assert_eq!(
            validate_batch_request(
                &bad_refund_signature,
                None,
                DEFAULT_BATCH_SETTLEMENT_CONTRACT
            )
            .unwrap_err(),
            "batch refund refundAuthorizerSignature: hex must be 65 bytes"
        );

        let mut settle = request("0", PAYER_PRIVATE_KEY);
        settle.payment_payload.payload = json!({
            "type": "settle",
            "receiver": RECEIVER,
            "token": JPYC_POLYGON_ADDRESS,
            "voucher": {
                "channelId": format!("0x{}", "11".repeat(32)),
                "maxClaimableAmount": "0",
                "signature": format!("0x{}", "11".repeat(65))
            }
        });
        assert_eq!(
            validate_batch_settle_request(&settle, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "batch settle voucher is not allowed"
        );

        let mut unknown = request("25", PAYER_PRIVATE_KEY);
        unknown.payment_payload.payload["unexpected"] = json!(true);
        assert!(
            validate_batch_request(&unknown, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err()
                .contains("unknown field `unexpected`")
        );
    }

    #[test]
    fn rejects_signer_and_cumulative_mismatch() {
        let bad_signer = request("100", OTHER_PRIVATE_KEY);
        assert_eq!(
            validate_batch_request(&bad_signer, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "batch voucher signer mismatch"
        );

        let mut bad_amount = request("100", PAYER_PRIVATE_KEY);
        bad_amount.payment_requirements.amount = "101".to_string();
        bad_amount.payment_payload.accepted.amount = "101".to_string();
        assert_eq!(
            validate_batch_request(&bad_amount, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "invalid_batch_settlement_evm_cumulative_amount_mismatch"
        );
    }

    #[test]
    fn rejects_batch_amounts_above_uint128() {
        let over_uint128 = "340282366920938463463374607431768211456";

        let mut deposit = request("100", PAYER_PRIVATE_KEY);
        set_deposit_payload(&mut deposit, over_uint128);
        assert_eq!(
            validate_batch_request(&deposit, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "deposit.amount: integer too large"
        );

        let mut refund = request("100", PAYER_PRIVATE_KEY);
        refund.payment_payload.payload["type"] = json!("refund");
        refund.payment_payload.payload["amount"] = json!(over_uint128);
        assert_eq!(
            validate_batch_request(&refund, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "payload.amount: integer too large"
        );

        let mut requirement = request("100", PAYER_PRIVATE_KEY);
        requirement.payment_requirements.amount = over_uint128.to_string();
        requirement.payment_payload.accepted.amount = over_uint128.to_string();
        assert_eq!(
            validate_batch_request(&requirement, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "amount: integer too large"
        );
    }

    #[test]
    fn rejects_withdraw_delay_outside_official_range() {
        let mut too_short = request("100", PAYER_PRIVATE_KEY);
        too_short.payment_requirements.extra["withdrawDelay"] = json!(899);
        too_short.payment_payload.accepted.extra = too_short.payment_requirements.extra.clone();
        assert_eq!(
            validate_batch_request(&too_short, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT)
                .unwrap_err(),
            "batch withdrawDelay must be between 900 and 2592000 seconds"
        );

        let mut too_long = request("100", PAYER_PRIVATE_KEY);
        too_long.payment_requirements.extra["withdrawDelay"] = json!(2_592_001);
        too_long.payment_payload.accepted.extra = too_long.payment_requirements.extra.clone();
        assert_eq!(
            validate_batch_request(&too_long, None, DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap_err(),
            "batch withdrawDelay must be between 900 and 2592000 seconds"
        );
    }

    #[test]
    fn rejects_batch_eip712_version_mismatch() {
        let request = request("100", PAYER_PRIVATE_KEY);
        assert!(validate_batch_eip712_version(&request, "1").is_ok());

        let mut requirements_mismatch = request.clone();
        requirements_mismatch.payment_requirements.extra["version"] = json!("2");
        assert_eq!(
            validate_batch_eip712_version(&requirements_mismatch, "1").unwrap_err(),
            "invalid_batch_settlement_evm_eip712_version"
        );

        let mut accepted_mismatch = request;
        accepted_mismatch.payment_payload.accepted.extra["version"] = json!("2");
        assert_eq!(
            validate_batch_eip712_version(&accepted_mismatch, "1").unwrap_err(),
            "invalid_batch_settlement_evm_eip712_version"
        );
    }
}
