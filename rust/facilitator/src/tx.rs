// rust/facilitator/src/tx.rs: JPYC EIP-3009 calldata と Polygon EIP-1559 tx 署名を生成する。
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use rlp::RlpStream;

use crate::hexutil::{
    address_word, keccak256, parse_address, parse_hex, parse_u256_decimal, selector, u256_word,
    JPYC_POLYGON_ADDRESS,
};
use crate::types::Eip3009Payload;

pub struct Eip1559Tx {
    pub nonce: u128,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u128,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

pub fn encode_settle_calldata(payload: &Eip3009Payload) -> Result<Vec<u8>, String> {
    let auth = &payload.authorization;
    let mut out = Vec::new();
    out.extend_from_slice(&selector(
        "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)",
    ));
    let from = parse_address(&auth.from, "authorization.from")?;
    let to = parse_address(&auth.to, "authorization.to")?;
    let value = parse_u256_decimal(&auth.value, "authorization.value")?;
    let valid_after = parse_u256_decimal(&auth.valid_after, "authorization.validAfter")?;
    let valid_before = parse_u256_decimal(&auth.valid_before, "authorization.validBefore")?;
    let nonce =
        parse_hex(&auth.nonce, Some(32)).map_err(|err| format!("authorization.nonce: {err}"))?;
    let signature = parse_hex(&payload.signature, Some(65))?;

    out.extend_from_slice(&address_word(&from));
    out.extend_from_slice(&address_word(&to));
    out.extend_from_slice(&value);
    out.extend_from_slice(&valid_after);
    out.extend_from_slice(&valid_before);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&u256_word(normalize_eip3009_v(signature[64])? as u128));
    out.extend_from_slice(&signature[..32]);
    out.extend_from_slice(&signature[32..64]);
    Ok(out)
}

fn normalize_eip3009_v(v: u8) -> Result<u8, String> {
    match v {
        0 | 1 => Ok(v + 27),
        27 | 28 => Ok(v),
        _ => Err("invalid signature recovery id".to_string()),
    }
}

pub fn sign_eip1559_tx(tx: &Eip1559Tx, private_key: &str) -> Result<String, String> {
    let key_bytes = parse_hex(private_key, Some(32))?;
    let key = SigningKey::from_slice(&key_bytes).map_err(|_| "invalid facilitator private key")?;
    let sighash = unsigned_hash(tx);
    let (signature, recovery): (Signature, RecoveryId) = key
        .sign_prehash(&sighash)
        .map_err(|_| "failed to sign settlement tx")?;

    let mut stream = base_tx_stream(tx, 12);
    append_u128(&mut stream, u8::from(recovery) as u128);
    append_bytes_trimmed(&mut stream, &signature.r().to_bytes());
    append_bytes_trimmed(&mut stream, &signature.s().to_bytes());
    let mut out = Vec::with_capacity(stream.as_raw().len() + 1);
    out.push(0x02);
    out.extend_from_slice(&stream.out());
    Ok(format!("0x{}", hex::encode(out)))
}

fn unsigned_hash(tx: &Eip1559Tx) -> [u8; 32] {
    let stream = base_tx_stream(tx, 9);
    let mut payload = Vec::with_capacity(stream.as_raw().len() + 1);
    payload.push(0x02);
    payload.extend_from_slice(&stream.out());
    keccak256(&payload)
}

fn base_tx_stream(tx: &Eip1559Tx, list_len: usize) -> RlpStream {
    let mut stream = RlpStream::new_list(list_len);
    append_u128(&mut stream, tx.chain_id as u128);
    append_u128(&mut stream, tx.nonce);
    append_u128(&mut stream, tx.max_priority_fee_per_gas);
    append_u128(&mut stream, tx.max_fee_per_gas);
    append_u128(&mut stream, tx.gas_limit);
    stream.append(&tx.to.as_ref());
    append_u128(&mut stream, tx.value);
    stream.append(&tx.data);
    stream.begin_list(0);
    stream
}

fn append_u128(stream: &mut RlpStream, value: u128) {
    if value == 0 {
        stream.append_empty_data();
        return;
    }
    append_bytes_trimmed(stream, &value.to_be_bytes());
}

fn append_bytes_trimmed(stream: &mut RlpStream, value: &[u8]) {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    stream.append(&value[first..].as_ref());
}

pub fn settle_to_address() -> Result<[u8; 20], String> {
    parse_address(JPYC_POLYGON_ADDRESS, "JPYC token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Eip3009Authorization, Eip3009Payload};

    #[test]
    fn calldata_starts_with_transfer_with_authorization_selector() {
        let auth = Eip3009Payload {
            signature: format!("0x{}1b", "11".repeat(64)),
            authorization: Eip3009Authorization {
                from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                to: "0x1000000000000000000000000000000000000402".to_string(),
                value: "1000000000000000000".to_string(),
                valid_after: "0".to_string(),
                valid_before: "9999999999".to_string(),
                nonce: format!("0x{}", "22".repeat(32)),
            },
        };
        let data = encode_settle_calldata(&auth).unwrap();
        assert_eq!(
            &data[..4],
            &selector(
                "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
            )
        );
    }

    #[test]
    fn calldata_normalizes_eip3009_recovery_id_for_token_contract() {
        for (input, expected) in [(0u8, 27u8), (1, 28), (27, 27), (28, 28)] {
            let auth = Eip3009Payload {
                signature: format!("0x{}{:02x}", "11".repeat(64), input),
                authorization: Eip3009Authorization {
                    from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                    to: "0x1000000000000000000000000000000000000402".to_string(),
                    value: "1000000000000000000".to_string(),
                    valid_after: "0".to_string(),
                    valid_before: "9999999999".to_string(),
                    nonce: format!("0x{}", "22".repeat(32)),
                },
            };
            let data = encode_settle_calldata(&auth).unwrap();
            let v_word = &data[4 + (32 * 6)..4 + (32 * 7)];
            assert!(v_word[..31].iter().all(|byte| *byte == 0));
            assert_eq!(v_word[31], expected);
        }
    }

    #[test]
    fn calldata_rejects_invalid_eip3009_recovery_id() {
        let auth = Eip3009Payload {
            signature: format!("0x{}02", "11".repeat(64)),
            authorization: Eip3009Authorization {
                from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                to: "0x1000000000000000000000000000000000000402".to_string(),
                value: "1000000000000000000".to_string(),
                valid_after: "0".to_string(),
                valid_before: "9999999999".to_string(),
                nonce: format!("0x{}", "22".repeat(32)),
            },
        };

        assert_eq!(
            encode_settle_calldata(&auth).unwrap_err(),
            "invalid signature recovery id"
        );
    }

    #[test]
    fn signs_eip1559_tx() {
        let tx = Eip1559Tx {
            nonce: 1,
            max_priority_fee_per_gas: 30_000_000_000,
            max_fee_per_gas: 60_000_000_000,
            gas_limit: 200_000,
            to: settle_to_address().unwrap(),
            value: 0,
            data: vec![1, 2, 3],
            chain_id: 137,
        };
        let raw = sign_eip1559_tx(
            &tx,
            "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e",
        )
        .unwrap();
        assert_eq!(
            raw,
            "0x02f8718189018506fc23ac00850df847580083030d4094431d5dff03120afa4bdf332c61a6e1766ef37bdb8083010203c080a06531df411b595d71b87b6cb67a3ec112aa6dcd87fb842c7dfe8789fc11f55b53a07ac9f4e5e86bff2a964138a158841213c84a4607a97ba1280b7964af46e5ba73"
        );
    }
}
