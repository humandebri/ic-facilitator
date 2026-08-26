// rust/facilitator/src/eip712.rs: JPYC exact EIP-3009 の EIP-712 digest と署名復元を実装する。
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::hexutil::{
    address_hex, address_word, keccak256, parse_address, parse_hex, parse_u256_decimal, u256_word,
    JPYC_POLYGON_ADDRESS,
};
use crate::types::{Eip3009Authorization, PaymentPayload};

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const TRANSFER_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

pub fn eip3009_digest(payload: &PaymentPayload) -> Result<[u8; 32], String> {
    let auth = &payload.payload.authorization;
    let domain = domain_separator(&payload.accepted)?;
    let message = transfer_hash(auth)?;
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(b"\x19\x01");
    bytes.extend_from_slice(&domain);
    bytes.extend_from_slice(&message);
    Ok(keccak256(&bytes))
}

pub fn recover_eip3009_signer(payload: &PaymentPayload) -> Result<String, String> {
    let digest = eip3009_digest(payload)?;
    let sig = parse_hex(&payload.payload.signature, None)?;
    if sig.len() != 65 {
        return Err("invalid EIP-3009 signature length".to_string());
    }
    let signature = Signature::try_from(&sig[..64]).map_err(|_| "invalid EIP-3009 signature")?;
    let recovery = recovery_id(sig[64])?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery)
        .map_err(|_| "invalid EIP-3009 signature")?;
    Ok(address_from_key(&key))
}

pub fn recover_eip191_signer(message: &str, signature_hex: &str) -> Result<String, String> {
    let digest = eip191_digest(message);
    let sig = parse_hex(signature_hex, None)?;
    if sig.len() != 65 {
        return Err("invalid EIP-191 signature length".to_string());
    }
    let signature = Signature::try_from(&sig[..64]).map_err(|_| "invalid EIP-191 signature")?;
    let recovery = recovery_id(sig[64])?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery)
        .map_err(|_| "invalid EIP-191 signature")?;
    Ok(address_from_key(&key))
}

pub fn eip191_digest(message: &str) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut bytes = Vec::with_capacity(prefix.len() + message.len());
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.extend_from_slice(message.as_bytes());
    keccak256(&bytes)
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

fn domain_separator(requirements: &crate::types::PaymentRequirements) -> Result<[u8; 32], String> {
    let name = requirements
        .extra
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing EIP-712 domain name".to_string())?;
    let version = requirements
        .extra
        .get("version")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "missing EIP-712 domain version".to_string())?;
    let verifying_contract = parse_address(JPYC_POLYGON_ADDRESS, "JPYC verifying contract")?;
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    encoded.extend_from_slice(&keccak256(name.as_bytes()));
    encoded.extend_from_slice(&keccak256(version.as_bytes()));
    encoded.extend_from_slice(&u256_word(137));
    encoded.extend_from_slice(&address_word(&verifying_contract));
    Ok(keccak256(&encoded))
}

fn transfer_hash(auth: &Eip3009Authorization) -> Result<[u8; 32], String> {
    let from = parse_address(&auth.from, "authorization.from")?;
    let to = parse_address(&auth.to, "authorization.to")?;
    let value = parse_u256_decimal(&auth.value, "authorization.value")?;
    let valid_after = parse_u256_decimal(&auth.valid_after, "authorization.validAfter")?;
    let valid_before = parse_u256_decimal(&auth.valid_before, "authorization.validBefore")?;
    let nonce =
        parse_hex(&auth.nonce, Some(32)).map_err(|err| format!("authorization.nonce: {err}"))?;
    let mut encoded = Vec::with_capacity(224);
    encoded.extend_from_slice(&keccak256(TRANSFER_TYPE.as_bytes()));
    encoded.extend_from_slice(&address_word(&from));
    encoded.extend_from_slice(&address_word(&to));
    encoded.extend_from_slice(&value);
    encoded.extend_from_slice(&valid_after);
    encoded.extend_from_slice(&valid_before);
    encoded.extend_from_slice(&nonce);
    Ok(keccak256(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::SigningKey;
    use serde_json::json;

    fn payload(signature: String) -> PaymentPayload {
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
                extra: json!({
                    "assetTransferMethod":"eip3009",
                    "name":"JPY Coin",
                    "version":"1"
                }),
            },
            payload: Eip3009Payload {
                signature,
                authorization: Eip3009Authorization {
                    from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                    to: "0x1000000000000000000000000000000000000402".to_string(),
                    value: "1000000000000000000".to_string(),
                    valid_after: "0".to_string(),
                    valid_before: "9999999999".to_string(),
                    nonce: format!("0x{}", "11".repeat(32)),
                },
            },
            extensions: None,
        }
    }

    #[test]
    fn builds_digest() {
        assert_eq!(
            eip3009_digest(&payload("0x".to_string())).unwrap().len(),
            32
        );
    }

    #[test]
    fn recovers_authorization_signer_with_standard_and_raw_recovery_id() {
        let key = SigningKey::from_slice(
            &crate::hexutil::parse_hex(
                "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e",
                Some(32),
            )
            .unwrap(),
        )
        .unwrap();
        let digest = eip3009_digest(&payload("0x".to_string())).unwrap();
        let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash(&digest).unwrap();
        for recovery_id in [u8::from(recovery), u8::from(recovery) + 27] {
            let mut bytes = Vec::with_capacity(65);
            bytes.extend_from_slice(&signature.to_bytes());
            bytes.push(recovery_id);
            let recovered =
                recover_eip3009_signer(&payload(format!("0x{}", hex::encode(bytes)))).unwrap();
            assert_eq!(
                recovered.to_lowercase(),
                "0xb51afb2cba39fb1e3e2b3d1df337579896fba993"
            );
        }
    }

    #[test]
    fn recovers_eip191_signer() {
        let key = SigningKey::from_slice(
            &crate::hexutil::parse_hex(
                "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e",
                Some(32),
            )
            .unwrap(),
        )
        .unwrap();
        let message = "IC_JPYC_X402_SELLER_AUTH_V1\nseller=0x01";
        let digest = eip191_digest(message);
        let (signature, recovery): (Signature, RecoveryId) = key.sign_prehash(&digest).unwrap();
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.push(u8::from(recovery) + 27);

        let recovered =
            recover_eip191_signer(message, &format!("0x{}", hex::encode(bytes))).unwrap();

        assert_eq!(
            recovered.to_lowercase(),
            "0xb51afb2cba39fb1e3e2b3d1df337579896fba993"
        );
    }

    #[test]
    fn rejects_short_nonce() {
        let mut item = payload("0x".to_string());
        item.payload.authorization.nonce = "0x01".to_string();
        assert!(eip3009_digest(&item).is_err());
    }
}
