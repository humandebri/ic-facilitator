// rust/facilitator/src/facilitator.rs: JPYC exact Permit2 facilitator の検証と settle 応答を構築する。
use serde_json::json;

use crate::eip712::recover_permit2_signer;
use crate::hexutil::{same_address, JPYC_POLYGON_ADDRESS, NETWORK, X402_EXACT_PERMIT2_PROXY};
use crate::types::{
    FacilitatorRequest, PaymentPayload, PaymentRequirements, SettleResponse, SupportedKind,
    SupportedResponse, VerifyResponse,
};

#[derive(Clone, Debug, Default)]
pub struct VerifySnapshot {
    pub has_balance: bool,
    pub has_allowance: bool,
    pub settle_simulates: bool,
}

pub fn supported(facilitator_address: String) -> SupportedResponse {
    let mut signers = std::collections::BTreeMap::new();
    signers.insert("eip155:*".to_string(), vec![facilitator_address]);
    SupportedResponse {
        kinds: vec![SupportedKind {
            x402_version: 2,
            scheme: "exact".to_string(),
            network: NETWORK.to_string(),
            extra: json!({ "assetTransferMethod": "permit2" }),
        }],
        extensions: vec![],
        signers,
    }
}

pub fn verify_request(
    request: &FacilitatorRequest,
    snapshot: Option<&VerifySnapshot>,
) -> VerifyResponse {
    match validate_request(request, snapshot) {
        Ok(payer) => VerifyResponse {
            is_valid: true,
            invalid_reason: None,
            invalid_message: None,
            payer: Some(payer),
        },
        Err(err) => VerifyResponse {
            is_valid: false,
            invalid_reason: Some(err.reason),
            invalid_message: Some(err.message),
            payer: err.payer,
        },
    }
}

pub fn validate_request(
    request: &FacilitatorRequest,
    snapshot: Option<&VerifySnapshot>,
) -> Result<String, VerifyFailure> {
    if request.x402_version != 2 || request.payment_payload.x402_version != 2 {
        return Err(fail("invalid_x402_version", "x402Version must be 2", None));
    }
    validate_requirements(&request.payment_requirements)?;
    validate_payload_matches_requirements(&request.payment_payload, &request.payment_requirements)?;
    let recovered = recover_permit2_signer(&request.payment_payload).map_err(|message| {
        fail(
            "invalid_exact_evm_payload_authorization_valid",
            &message,
            None,
        )
    })?;
    let payer = request
        .payment_payload
        .payload
        .permit2_authorization
        .from
        .clone();
    if !same_address(&recovered, &payer) {
        return Err(fail(
            "invalid_exact_evm_payload_authorization_valid",
            "Permit2 signer does not match payer",
            Some(payer),
        ));
    }
    validate_time_window(&request.payment_payload, &request.payment_requirements)?;
    if let Some(state) = snapshot {
        if !state.has_balance {
            return Err(fail(
                "invalid_exact_evm_insufficient_funds",
                "payer JPYC balance is below payment amount",
                Some(payer),
            ));
        }
        if !state.has_allowance {
            return Err(fail(
                "invalid_exact_evm_insufficient_allowance",
                "payer JPYC Permit2 allowance is below payment amount",
                Some(payer),
            ));
        }
        if !state.settle_simulates {
            return Err(fail(
                "invalid_exact_evm_simulation_failed",
                "x402 Permit2 settle simulation failed",
                Some(payer),
            ));
        }
    }
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
        Some("permit2")
    ) {
        return Err(fail(
            "invalid_exact_evm_transfer_method",
            "assetTransferMethod must be permit2",
            None,
        ));
    }
    Ok(())
}

fn validate_payload_matches_requirements(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<(), VerifyFailure> {
    let auth = &payload.payload.permit2_authorization;
    if payload.accepted.scheme != requirements.scheme
        || payload.accepted.network != requirements.network
    {
        return Err(fail(
            "invalid_exact_evm_payload_accepted",
            "accepted requirement mismatch",
            Some(auth.from.clone()),
        ));
    }
    if payload.accepted.amount != requirements.amount
        || auth.permitted.amount != requirements.amount
    {
        return Err(fail(
            "invalid_exact_evm_payload_amount",
            "amount mismatch",
            Some(auth.from.clone()),
        ));
    }
    if !same_address(&payload.accepted.asset, &requirements.asset)
        || !same_address(&auth.permitted.token, &requirements.asset)
    {
        return Err(fail(
            "invalid_exact_evm_payload_token",
            "token mismatch",
            Some(auth.from.clone()),
        ));
    }
    if !same_address(&payload.accepted.pay_to, &requirements.pay_to)
        || !same_address(&auth.witness.to, &requirements.pay_to)
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
    if !same_address(&auth.spender, X402_EXACT_PERMIT2_PROXY) {
        return Err(fail(
            "invalid_exact_evm_payload_spender",
            "spender must be x402 exact Permit2 proxy",
            Some(auth.from.clone()),
        ));
    }
    Ok(())
}

fn validate_time_window(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<(), VerifyFailure> {
    let auth = &payload.payload.permit2_authorization;
    let now = crate::now_seconds();
    let deadline = auth.deadline.parse::<u64>().unwrap_or(0);
    let valid_after = auth.witness.valid_after.parse::<u64>().unwrap_or(u64::MAX);
    if deadline < now + 6 {
        return Err(fail(
            "invalid_exact_evm_payload_authorization_valid_before",
            "Permit2 deadline is expired",
            Some(auth.from.clone()),
        ));
    }
    if valid_after > now {
        return Err(fail(
            "invalid_exact_evm_payload_authorization_valid_after",
            "Permit2 validAfter is in the future",
            Some(auth.from.clone()),
        ));
    }
    if deadline
        > now
            .saturating_add(requirements.max_timeout_seconds)
            .saturating_add(6)
    {
        return Err(fail(
            "invalid_exact_evm_payload_timeout",
            "Permit2 deadline exceeds maxTimeoutSeconds",
            Some(auth.from.clone()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Permit2Authorization, Permit2Payload, Permit2Permitted, Permit2Witness};

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".to_string(),
            network: NETWORK.to_string(),
            asset: JPYC_POLYGON_ADDRESS.to_string(),
            amount: "100".to_string(),
            pay_to: "0x1000000000000000000000000000000000000402".to_string(),
            max_timeout_seconds: 60,
            extra: json!({"assetTransferMethod":"permit2"}),
        }
    }

    fn payment(deadline: u64, valid_after: u64) -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: requirements(),
            payload: Permit2Payload {
                signature: "0x".to_string(),
                permit2_authorization: Permit2Authorization {
                    from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                    permitted: Permit2Permitted {
                        token: JPYC_POLYGON_ADDRESS.to_string(),
                        amount: "100".to_string(),
                    },
                    spender: X402_EXACT_PERMIT2_PROXY.to_string(),
                    nonce: "1".to_string(),
                    deadline: deadline.to_string(),
                    witness: Permit2Witness {
                        to: "0x1000000000000000000000000000000000000402".to_string(),
                        valid_after: valid_after.to_string(),
                    },
                },
            },
            extensions: None,
        }
    }

    #[test]
    fn rejects_deadline_beyond_max_timeout() {
        let now = crate::now_seconds();
        let err = validate_time_window(&payment(now + 600, now), &requirements()).unwrap_err();
        assert_eq!(err.reason, "invalid_exact_evm_payload_timeout");
    }

    #[test]
    fn accepts_deadline_within_max_timeout() {
        let now = crate::now_seconds();
        validate_time_window(&payment(now + 60, now), &requirements()).unwrap();
    }
}
