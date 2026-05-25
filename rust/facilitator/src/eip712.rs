// rust/facilitator/src/eip712.rs: JPYC exact Permit2 の EIP-712 digest と署名復元を実装する。
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::hexutil::{
    address_hex, address_word, keccak256, parse_address, parse_hex, parse_u256_decimal,
    parse_u64_decimal, u256_word, PERMIT2_ADDRESS,
};
use crate::types::{PaymentPayload, Permit2Authorization};

const DOMAIN_TYPE: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
const PERMIT_TYPE: &str = "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,uint256 validAfter)";
const TOKEN_TYPE: &str = "TokenPermissions(address token,uint256 amount)";
const WITNESS_TYPE: &str = "Witness(address to,uint256 validAfter)";

pub fn permit2_digest(payload: &PaymentPayload) -> Result<[u8; 32], String> {
    let auth = &payload.payload.permit2_authorization;
    let domain = domain_separator()?;
    let message = permit_hash(auth)?;
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(b"\x19\x01");
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(&message);
    Ok(keccak256(&bytes))
}

pub fn recover_permit2_signer(payload: &PaymentPayload) -> Result<String, String> {
    let digest = permit2_digest(payload)?;
    let sig = parse_hex(&payload.payload.signature, None)?;
    if sig.len() != 65 {
        return Err("invalid Permit2 signature length".to_string());
    }
    let signature = Signature::try_from(&sig[..64]).map_err(|_| "invalid Permit2 signature")?;
    let recovery = recovery_id(sig[64])?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery)
        .map_err(|_| "invalid Permit2 signature")?;
    Ok(address_from_key(&key))
}

fn recovery_id(value: u8) -> Result<RecoveryId, String> {
    let normalized = match value {
        0 | 1 => value,
        27 | 28 => value - 27,
        _ => return Err("invalid signature recovery id".to_string()),
    };
    RecoveryId::try_from(normalized).map_err(|_| "invalid signature recovery id".to_string())
}

fn address_from_key(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address_hex(&address)
}

fn domain_separator() -> Result<[u8; 32], String> {
    let verifying_contract = parse_address(PERMIT2_ADDRESS, "Permit2 verifying contract")?;
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    encoded.extend_from_slice(&keccak256(b"Permit2"));
    encoded.extend_from_slice(&u256_word(137));
    encoded.extend_from_slice(&address_word(&verifying_contract));
    Ok(keccak256(&encoded))
}

fn permit_hash(auth: &Permit2Authorization) -> Result<[u8; 32], String> {
    let token_hash = token_permissions_hash(auth)?;
    let witness_hash = witness_hash(auth)?;
    let spender = parse_address(&auth.spender, "permit2.spender")?;
    let nonce = parse_u256_decimal(&auth.nonce, "permit2.nonce")?;
    let deadline = parse_u256_decimal(&auth.deadline, "permit2.deadline")?;
    let mut encoded = Vec::with_capacity(192);
    encoded.extend_from_slice(&keccak256(PERMIT_TYPE.as_bytes()));
    encoded.extend_from_slice(&token_hash);
    encoded.extend_from_slice(&address_word(&spender));
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&deadline);
    encoded.extend_from_slice(&witness_hash);
    Ok(keccak256(&encoded))
}

fn token_permissions_hash(auth: &Permit2Authorization) -> Result<[u8; 32], String> {
    let token = parse_address(&auth.permitted.token, "permit2.permitted.token")?;
    let amount = parse_u256_decimal(&auth.permitted.amount, "permit2.permitted.amount")?;
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(&keccak256(TOKEN_TYPE.as_bytes()));
    encoded.extend_from_slice(&address_word(&token));
    encoded.extend_from_slice(&amount);
    Ok(keccak256(&encoded))
}

fn witness_hash(auth: &Permit2Authorization) -> Result<[u8; 32], String> {
    let to = parse_address(&auth.witness.to, "permit2.witness.to")?;
    let valid_after = parse_u64_decimal(&auth.witness.valid_after, "permit2.witness.validAfter")?;
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(&keccak256(WITNESS_TYPE.as_bytes()));
    encoded.extend_from_slice(&address_word(&to));
    encoded.extend_from_slice(&u256_word(valid_after as u128));
    Ok(keccak256(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use serde_json::json;

    fn payload() -> PaymentPayload {
        PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: PaymentRequirements {
                scheme: "exact".to_string(),
                network: "eip155:137".to_string(),
                asset: crate::hexutil::JPYC_POLYGON_ADDRESS.to_string(),
                amount: "1000000000000000000".to_string(),
                pay_to: "0x1000000000000000000000000000000000000402".to_string(),
                max_timeout_seconds: 60,
                extra: json!({"assetTransferMethod":"permit2"}),
            },
            payload: Permit2Payload {
                signature: format!("0x{}1b", "11".repeat(64)),
                permit2_authorization: Permit2Authorization {
                    from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                    permitted: Permit2Permitted {
                        token: crate::hexutil::JPYC_POLYGON_ADDRESS.to_string(),
                        amount: "1000000000000000000".to_string(),
                    },
                    spender: crate::hexutil::X402_EXACT_PERMIT2_PROXY.to_string(),
                    nonce: "115792089237316195423570985008687907853269984665640564039457584007913129639935".to_string(),
                    deadline: "9999999999".to_string(),
                    witness: Permit2Witness {
                        to: "0x1000000000000000000000000000000000000402".to_string(),
                        valid_after: "0".to_string(),
                    },
                },
            },
            extensions: None,
        }
    }

    #[test]
    fn builds_digest() {
        assert_eq!(permit2_digest(&payload()).unwrap().len(), 32);
    }
}
