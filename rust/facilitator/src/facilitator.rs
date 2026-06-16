// rust/facilitator/src/facilitator.rs: JPYC exact EIP-3009 facilitator の検証と settle 応答を構築する。
use serde_json::json;

use crate::eip712::recover_eip3009_signer;
use crate::hexutil::{same_address, JPYC_EIP712_NAME, JPYC_POLYGON_ADDRESS, NETWORK};
use crate::types::{
    FacilitatorRequest, PaymentPayload, PaymentRequirements, SettleResponse, SupportedKind,
    SupportedResponse,
};

pub fn supported(facilitator_address: String, eip712_version: &str) -> SupportedResponse {
    let mut signers = std::collections::BTreeMap::new();
    signers.insert(NETWORK.to_string(), vec![facilitator_address]);
    SupportedResponse {
        kinds: vec![SupportedKind {
            x402_version: 2,
            scheme: "exact".to_string(),
            network: NETWORK.to_string(),
            extra: json!({
                "assetTransferMethod": "eip3009",
                "name": JPYC_EIP712_NAME,
                "version": eip712_version
            }),
        }],
        extensions: vec![],
        signers,
    }
}

pub fn validate_request(request: &FacilitatorRequest) -> Result<String, VerifyFailure> {
    if request.x402_version != 2 || request.payment_payload.x402_version != 2 {
        return Err(fail("invalid_x402_version", "x402Version must be 2", None));
    }
    validate_requirements(&request.payment_requirements)?;
    validate_payload_matches_requirements(&request.payment_payload, &request.payment_requirements)?;
    let recovered = recover_eip3009_signer(&request.payment_payload)
        .map_err(|message| fail("invalid_exact_evm_signature", &message, None))?;
    let payer = request.payment_payload.payload.authorization.from.clone();
    if !same_address(&recovered, &payer) {
        return Err(fail(
            "invalid_exact_evm_signature",
            "EIP-3009 signer does not match payer",
            Some(payer),
        ));
    }
    validate_time_window(&request.payment_payload, &request.payment_requirements)?;
    Ok(payer)
}

pub fn failed_settlement(
    network: &str,
    reason: &str,
    message: &str,
    payer: Option<String>,
) -> SettleResponse {
    SettleResponse {
        success: false,
        transaction: String::new(),
        network: network.to_string(),
        payer,
        amount: None,
        error_reason: Some(reason.to_string()),
        error_message: Some(message.to_string()),
    }
}

pub fn successful_settlement(tx: String, payer: String, amount: String) -> SettleResponse {
    SettleResponse {
        success: true,
        transaction: tx,
        network: NETWORK.to_string(),
        payer: Some(payer),
        amount: Some(amount),
        error_reason: None,
        error_message: None,
    }
}

#[derive(Clone, Debug)]
pub struct VerifyFailure {
    pub reason: String,
    pub message: String,
    pub payer: Option<String>,
}

fn fail(reason: &str, message: &str, payer: Option<String>) -> VerifyFailure {
    VerifyFailure {
        reason: reason.to_string(),
        message: message.to_string(),
        payer,
    }
}

fn validate_requirements(requirements: &PaymentRequirements) -> Result<(), VerifyFailure> {
    if requirements.scheme != "exact" {
        return Err(fail(
            "invalid_exact_evm_scheme",
            "scheme must be exact",
            None,
        ));
    }
    if requirements.network != NETWORK {
        return Err(fail(
            "invalid_exact_evm_network_mismatch",
            "network must be eip155:137",
            None,
        ));
    }
    if !same_address(&requirements.asset, JPYC_POLYGON_ADDRESS) {
        return Err(fail(
            "invalid_exact_evm_asset",
            "asset must be JPYC on Polygon",
            None,
        ));
    }
    if !matches!(
        requirements
            .extra
            .get("assetTransferMethod")
            .and_then(|v| v.as_str()),
        Some("eip3009")
    ) {
        return Err(fail(
            "invalid_exact_evm_transfer_method",
            "assetTransferMethod must be eip3009",
            None,
        ));
    }
    if !matches!(
        requirements.extra.get("name").and_then(|v| v.as_str()),
        Some(JPYC_EIP712_NAME)
    ) {
        return Err(fail(
            "invalid_exact_evm_missing_eip712_domain",
            "EIP-712 domain name must be JPY Coin",
            None,
        ));
    }
    if requirements
        .extra
        .get("version")
        .and_then(|v| v.as_str())
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        return Err(fail(
            "invalid_exact_evm_missing_eip712_domain",
            "EIP-712 domain version is required",
            None,
        ));
    }
    Ok(())
}

fn validate_payload_matches_requirements(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<(), VerifyFailure> {
    let auth = &payload.payload.authorization;
    if payload.accepted.scheme != requirements.scheme
        || payload.accepted.network != requirements.network
    {
        return Err(fail(
            "invalid_exact_evm_payload_accepted",
            "accepted requirement mismatch",
            Some(auth.from.clone()),
        ));
    }
    if payload.accepted.amount != requirements.amount || auth.value != requirements.amount {
        return Err(fail(
            "invalid_exact_evm_payload_amount",
            "amount mismatch",
            Some(auth.from.clone()),
        ));
    }
    if !same_address(&payload.accepted.asset, &requirements.asset) {
        return Err(fail(
            "invalid_exact_evm_payload_token",
            "token mismatch",
            Some(auth.from.clone()),
        ));
    }
    if !same_address(&payload.accepted.pay_to, &requirements.pay_to)
        || !same_address(&auth.to, &requirements.pay_to)
    {
        return Err(fail(
            "invalid_exact_evm_payload_recipient",
            "recipient mismatch",
            Some(auth.from.clone()),
        ));
    }
    if payload.accepted.max_timeout_seconds != requirements.max_timeout_seconds {
        return Err(fail(
            "invalid_exact_evm_payload_timeout",
            "maxTimeoutSeconds mismatch",
            Some(auth.from.clone()),
        ));
    }
    if payload.accepted.extra != requirements.extra {
        return Err(fail(
            "invalid_exact_evm_payload_accepted",
            "accepted requirement extra mismatch",
            Some(auth.from.clone()),
        ));
    }
    Ok(())
}

fn validate_time_window(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<(), VerifyFailure> {
    let auth = &payload.payload.authorization;
    let now = crate::now_seconds();
    let valid_before = auth.valid_before.parse::<u64>().unwrap_or(0);
    let valid_after = auth.valid_after.parse::<u64>().unwrap_or(u64::MAX);
    if valid_before < now + 6 {
        return Err(fail(
            "invalid_exact_evm_payload_authorization_valid_before",
            "EIP-3009 validBefore is expired",
            Some(auth.from.clone()),
        ));
    }
    if valid_after > now {
        return Err(fail(
            "invalid_exact_evm_payload_authorization_valid_after",
            "EIP-3009 validAfter is in the future",
            Some(auth.from.clone()),
        ));
    }
    if valid_before
        > now
            .saturating_add(requirements.max_timeout_seconds)
            .saturating_add(6)
    {
        return Err(fail(
            "invalid_exact_evm_payload_timeout",
            "EIP-3009 validBefore exceeds maxTimeoutSeconds",
            Some(auth.from.clone()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Eip3009Authorization, Eip3009Payload};

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".to_string(),
            network: NETWORK.to_string(),
            asset: JPYC_POLYGON_ADDRESS.to_string(),
            amount: "100".to_string(),
            pay_to: "0x1000000000000000000000000000000000000402".to_string(),
            max_timeout_seconds: 60,
            extra: json!({
                "assetTransferMethod":"eip3009",
                "name":"JPY Coin",
                "version":"1"
            }),
        }
    }

    fn payment(valid_before: u64, valid_after: u64) -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: requirements(),
            payload: Eip3009Payload {
                signature: "0x".to_string(),
                authorization: Eip3009Authorization {
                    from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                    to: "0x1000000000000000000000000000000000000402".to_string(),
                    value: "100".to_string(),
                    valid_after: valid_after.to_string(),
                    valid_before: valid_before.to_string(),
                    nonce: format!("0x{}", "11".repeat(32)),
                },
            },
            extensions: None,
        }
    }

    #[test]
    fn rejects_valid_before_beyond_max_timeout() {
        let now = crate::now_seconds();
        let err = validate_time_window(&payment(now + 600, now), &requirements()).unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_payload_timeout");
    }

    #[test]
    fn accepts_valid_before_within_max_timeout() {
        let now = crate::now_seconds();
        validate_time_window(&payment(now + 60, now), &requirements()).unwrap();
    }

    #[test]
    fn requires_eip3009_domain_version() {
        let mut item = requirements();
        item.extra = json!({"assetTransferMethod":"eip3009","name":"JPY Coin"});
        let err = validate_requirements(&item).unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_missing_eip712_domain");
    }
}
