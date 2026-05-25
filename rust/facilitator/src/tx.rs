// rust/facilitator/src/tx.rs: x402 exact Permit2 settle calldata と Polygon legacy tx 署名を生成する。
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use rlp::RlpStream;

use crate::hexutil::{
    address_word, keccak256, parse_address, parse_hex, parse_u256_decimal, selector, u256_word,
    X402_EXACT_PERMIT2_PROXY,
};
use crate::types::Permit2Payload;

pub struct LegacyTx {
    pub nonce: u128,
    pub gas_price: u128,
    pub gas_limit: u128,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

pub fn encode_settle_calldata(payload: &Permit2Payload) -> Result<Vec<u8>, String> {
    let auth = &payload.permit2_authorization;
    let mut out = Vec::new();
    out.extend_from_slice(&selector(
        "settle(((address,uint256),uint256,uint256),address,(address,uint256),bytes)",
    ));
    let token = parse_address(&auth.permitted.token, "permit.token")?;
    let owner = parse_address(&auth.from, "owner")?;
    let to = parse_address(&auth.witness.to, "witness.to")?;
    let amount = parse_u256_decimal(&auth.permitted.amount, "permit.amount")?;
    let nonce = parse_u256_decimal(&auth.nonce, "permit.nonce")?;
    let deadline = parse_u256_decimal(&auth.deadline, "permit.deadline")?;
    let valid_after = parse_u256_decimal(&auth.witness.valid_after, "witness.validAfter")?;
    let signature = parse_hex(&payload.signature, None)?;

    out.extend_from_slice(&address_word(&token));
    out.extend_from_slice(&amount);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&deadline);
    out.extend_from_slice(&address_word(&owner));
    out.extend_from_slice(&address_word(&to));
    out.extend_from_slice(&valid_after);
    out.extend_from_slice(&u256_word(256));
    out.extend_from_slice(&u256_word(signature.len() as u128));
    out.extend_from_slice(&pad_right(&signature));
    Ok(out)
}

pub fn sign_legacy_tx(tx: &LegacyTx, private_key: &str) -> Result<String, String> {
    let key_bytes = parse_hex(private_key, Some(32))?;
    let key = SigningKey::from_slice(&key_bytes).map_err(|_| "invalid facilitator private key")?;
    let sighash = unsigned_hash(tx);
    let (signature, recovery): (Signature, RecoveryId) = key
        .sign_prehash(&sighash)
        .map_err(|_| "failed to sign settlement tx")?;
    let v = tx.chain_id as u128 * 2 + 35 + u8::from(recovery) as u128;
    let mut stream = base_tx_stream(tx, 9);
    append_u128(&mut stream, v);
    append_bytes_trimmed(&mut stream, &signature.r().to_bytes());
    append_bytes_trimmed(&mut stream, &signature.s().to_bytes());
    Ok(format!("0x{}", hex::encode(stream.out())))
}

fn unsigned_hash(tx: &LegacyTx) -> [u8; 32] {
    let mut stream = base_tx_stream(tx, 9);
    append_u128(&mut stream, tx.chain_id as u128);
    append_u128(&mut stream, 0);
    append_u128(&mut stream, 0);
    keccak256(&stream.out())
}

fn base_tx_stream(tx: &LegacyTx, list_len: usize) -> RlpStream {
    let mut stream = RlpStream::new_list(list_len);
    append_u128(&mut stream, tx.nonce);
    append_u128(&mut stream, tx.gas_price);
    append_u128(&mut stream, tx.gas_limit);
    stream.append(&tx.to.as_ref());
    append_u128(&mut stream, tx.value);
    stream.append(&tx.data);
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

fn pad_right(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len().div_ceil(32) * 32;
    let mut out = vec![0u8; len];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

pub fn settle_to_address() -> Result<[u8; 20], String> {
    parse_address(X402_EXACT_PERMIT2_PROXY, "x402 exact Permit2 proxy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Permit2Authorization, Permit2Permitted, Permit2Witness};

    #[test]
    fn calldata_starts_with_settle_selector() {
        let auth = Permit2Payload {
            signature: format!("0x{}1b", "11".repeat(64)),
            permit2_authorization: Permit2Authorization {
                from: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
                permitted: Permit2Permitted {
                    token: crate::hexutil::JPYC_POLYGON_ADDRESS.to_string(),
                    amount: "1000000000000000000".to_string(),
                },
                spender: crate::hexutil::X402_EXACT_PERMIT2_PROXY.to_string(),
                nonce:
                    "115792089237316195423570985008687907853269984665640564039457584007913129639935"
                        .to_string(),
                deadline: "9999999999".to_string(),
                witness: Permit2Witness {
                    to: "0x1000000000000000000000000000000000000402".to_string(),
                    valid_after: "0".to_string(),
                },
            },
        };
        let data = encode_settle_calldata(&auth).unwrap();
        assert_eq!(
            &data[..4],
            &selector(
                "settle(((address,uint256),uint256,uint256),address,(address,uint256),bytes)"
            )
        );
    }

    #[test]
    fn signs_legacy_tx() {
        let tx = LegacyTx {
            nonce: 1,
            gas_price: 30_000_000_000,
            gas_limit: 200_000,
            to: settle_to_address().unwrap(),
            value: 0,
            data: vec![1, 2, 3],
            chain_id: 137,
        };
        let raw = sign_legacy_tx(
            &tx,
            "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e",
        )
        .unwrap();
        assert!(raw.starts_with("0x"));
        assert!(raw.len() > 100);
    }
}
