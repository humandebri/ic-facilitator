// rust/facilitator/src/tx.rs: JPYC EIP-3009 calldata と Polygon EIP-1559 tx 署名を生成する。
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey, VerifyingKey,
};
use rlp::RlpStream;

use crate::batch::{
    compute_batch_channel_id, BatchChannelConfig, BatchErc3009Authorization, BatchRequestPayload,
    BatchVoucherClaim,
};
use crate::hexutil::{
    address_hex, address_word, keccak256, parse_address, parse_hex, parse_u128_decimal_word,
    parse_u256_decimal, selector, u256_word, JPYC_POLYGON_ADDRESS,
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

pub fn encode_batch_deposit_calldata(payload: &BatchRequestPayload) -> Result<Vec<u8>, String> {
    let config = payload
        .channel_config
        .as_ref()
        .ok_or_else(|| "batch deposit channelConfig is required".to_string())?;
    let deposit = payload
        .deposit
        .as_ref()
        .ok_or_else(|| "batch deposit payload is required".to_string())?;
    let authorization = deposit
        .authorization
        .erc3009_authorization
        .as_ref()
        .ok_or_else(|| "batch eip3009 authorization is required".to_string())?;
    let collector = parse_address(
        ERC3009_DEPOSIT_COLLECTOR_ADDRESS,
        "ERC3009 deposit collector",
    )?;
    let collector_data = encode_erc3009_collector_data(authorization)?;
    encode_batch_deposit_call(config, &deposit.amount, &collector, &collector_data)
}

pub fn encode_batch_claim_calldata(
    payload: &BatchRequestPayload,
    authorizer_private_key: &str,
    contract: &str,
) -> Result<Vec<u8>, String> {
    let claims = payload
        .claims
        .as_ref()
        .filter(|claims| !claims.is_empty())
        .ok_or_else(|| "batch claims are required".to_string())?;
    let signature = match &payload.claim_authorizer_signature {
        Some(signature) => parse_hex(signature, None)?,
        None => parse_hex(
            &sign_batch_claims(claims, authorizer_private_key, contract)?,
            None,
        )?,
    };
    encode_claim_with_signature_call(claims, &signature)
}

pub fn encode_batch_settle_calldata(receiver: &str, token: &str) -> Result<Vec<u8>, String> {
    let receiver = parse_address(receiver, "batch receiver")?;
    let token = parse_address(token, "batch token")?;
    let mut out = Vec::new();
    out.extend_from_slice(&selector("settle(address,address)"));
    out.extend_from_slice(&address_word(&receiver));
    out.extend_from_slice(&address_word(&token));
    Ok(out)
}

pub fn encode_batch_refund_calldata(
    payload: &BatchRequestPayload,
    authorizer_private_key: &str,
    contract: &str,
) -> Result<Vec<u8>, String> {
    let config = payload
        .channel_config
        .as_ref()
        .ok_or_else(|| "batch refund channelConfig is required".to_string())?;
    let amount = payload
        .amount
        .as_deref()
        .ok_or_else(|| "batch refund amount is required".to_string())?;
    let nonce = payload
        .refund_nonce
        .as_deref()
        .ok_or_else(|| "batch refund nonce is required".to_string())?;
    let channel_id = compute_batch_channel_id(config, contract)?;
    let signature = match &payload.refund_authorizer_signature {
        Some(signature) => parse_hex(signature, None)?,
        None => parse_hex(
            &sign_batch_refund(&channel_id, amount, nonce, authorizer_private_key, contract)?,
            None,
        )?,
    };
    let refund_call = encode_refund_with_signature_call(config, amount, nonce, &signature)?;
    let claims = payload.claims.as_deref().unwrap_or(&[]);
    if claims.is_empty() {
        return Ok(refund_call);
    }
    let claim_signature = match &payload.claim_authorizer_signature {
        Some(signature) => parse_hex(signature, None)?,
        None => parse_hex(
            &sign_batch_claims(claims, authorizer_private_key, contract)?,
            None,
        )?,
    };
    let claim_call = encode_claim_with_signature_call(claims, &claim_signature)?;
    encode_multicall(vec![claim_call, refund_call])
}

pub fn sign_batch_claims(
    claims: &[BatchVoucherClaim],
    private_key: &str,
    contract: &str,
) -> Result<String, String> {
    sign_batch_typed_hash(
        batch_claims_message_hash(claims, contract)?,
        private_key,
        contract,
    )
}

pub fn recover_batch_claim_authorizer(
    claims: &[BatchVoucherClaim],
    signature: &str,
    contract: &str,
) -> Result<String, String> {
    recover_batch_typed_signer(
        batch_claims_message_hash(claims, contract)?,
        signature,
        contract,
    )
}

fn batch_claims_message_hash(
    claims: &[BatchVoucherClaim],
    contract: &str,
) -> Result<[u8; 32], String> {
    let mut hashes = Vec::with_capacity(claims.len() * 32);
    for claim in claims {
        let channel_id = compute_batch_channel_id(&claim.voucher.channel, contract)?;
        let mut encoded = Vec::with_capacity(128);
        encoded.extend_from_slice(&keccak256(
            b"ClaimEntry(bytes32 channelId,uint128 maxClaimableAmount,uint128 totalClaimed)",
        ));
        encoded.extend_from_slice(&parse_hex(&channel_id, Some(32))?);
        encoded.extend_from_slice(&parse_u128_decimal_word(
            &claim.voucher.max_claimable_amount,
            "maxClaimableAmount",
        )?);
        encoded.extend_from_slice(&parse_u128_decimal_word(
            &claim.total_claimed,
            "totalClaimed",
        )?);
        hashes.extend_from_slice(&keccak256(&encoded));
    }
    let claims_hash = keccak256(&hashes);
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(&keccak256(
        b"ClaimBatch(ClaimEntry[] claims)ClaimEntry(bytes32 channelId,uint128 maxClaimableAmount,uint128 totalClaimed)",
    ));
    encoded.extend_from_slice(&claims_hash);
    Ok(keccak256(&encoded))
}

pub fn sign_batch_refund(
    channel_id: &str,
    amount: &str,
    nonce: &str,
    private_key: &str,
    contract: &str,
) -> Result<String, String> {
    sign_batch_typed_hash(
        batch_refund_message_hash(channel_id, amount, nonce)?,
        private_key,
        contract,
    )
}

pub fn recover_batch_refund_authorizer(
    channel_id: &str,
    amount: &str,
    nonce: &str,
    signature: &str,
    contract: &str,
) -> Result<String, String> {
    recover_batch_typed_signer(
        batch_refund_message_hash(channel_id, amount, nonce)?,
        signature,
        contract,
    )
}

fn batch_refund_message_hash(
    channel_id: &str,
    amount: &str,
    nonce: &str,
) -> Result<[u8; 32], String> {
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(&keccak256(
        b"Refund(bytes32 channelId,uint256 nonce,uint128 amount)",
    ));
    encoded.extend_from_slice(&parse_hex(channel_id, Some(32))?);
    encoded.extend_from_slice(&parse_uint_word(nonce, "refundNonce")?);
    encoded.extend_from_slice(&parse_u128_decimal_word(amount, "refund amount")?);
    Ok(keccak256(&encoded))
}

pub const ERC3009_DEPOSIT_COLLECTOR_ADDRESS: &str = "0x4020806089470a89826cB9fB1f4059150b550004";

fn encode_batch_deposit_call(
    config: &BatchChannelConfig,
    amount: &str,
    collector: &[u8; 20],
    collector_data: &[u8],
) -> Result<Vec<u8>, String> {
    let mut head = Vec::with_capacity(32 * 10);
    head.extend_from_slice(&encode_channel_config(config)?);
    head.extend_from_slice(&parse_u128_decimal_word(amount, "deposit amount")?);
    head.extend_from_slice(&address_word(collector));
    head.extend_from_slice(&u256_word(32 * 10));
    let mut out = Vec::new();
    out.extend_from_slice(&selector(
        "deposit((address,address,address,address,address,uint40,bytes32),uint128,address,bytes)",
    ));
    out.extend_from_slice(&head);
    out.extend_from_slice(&encode_bytes(collector_data));
    Ok(out)
}

fn encode_claim_with_signature_call(
    claims: &[BatchVoucherClaim],
    authorizer_signature: &[u8],
) -> Result<Vec<u8>, String> {
    let claims_data = encode_claims_array(claims)?;
    let signature_data = encode_bytes(authorizer_signature);
    let claims_offset = 64usize;
    let signature_offset = claims_offset + claims_data.len();
    let mut out = Vec::new();
    out.extend_from_slice(&selector(
        "claimWithSignature((((address,address,address,address,address,uint40,bytes32),uint128),bytes,uint128)[],bytes)",
    ));
    out.extend_from_slice(&u256_word(claims_offset as u128));
    out.extend_from_slice(&u256_word(signature_offset as u128));
    out.extend_from_slice(&claims_data);
    out.extend_from_slice(&signature_data);
    Ok(out)
}

fn encode_refund_with_signature_call(
    config: &BatchChannelConfig,
    amount: &str,
    nonce: &str,
    signature: &[u8],
) -> Result<Vec<u8>, String> {
    let mut head = Vec::with_capacity(32 * 10);
    head.extend_from_slice(&encode_channel_config(config)?);
    head.extend_from_slice(&parse_u128_decimal_word(amount, "refund amount")?);
    head.extend_from_slice(&parse_uint_word(nonce, "refundNonce")?);
    head.extend_from_slice(&u256_word(32 * 10));
    let mut out = Vec::new();
    out.extend_from_slice(&selector(
        "refundWithSignature((address,address,address,address,address,uint40,bytes32),uint128,uint256,bytes)",
    ));
    out.extend_from_slice(&head);
    out.extend_from_slice(&encode_bytes(signature));
    Ok(out)
}

fn encode_multicall(calls: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    let data = encode_bytes_array(&calls);
    let mut out = Vec::new();
    out.extend_from_slice(&selector("multicall(bytes[])"));
    out.extend_from_slice(&u256_word(32));
    out.extend_from_slice(&data);
    Ok(out)
}

fn encode_erc3009_collector_data(auth: &BatchErc3009Authorization) -> Result<Vec<u8>, String> {
    let signature = parse_hex(&auth.signature, None)?;
    let signature_data = encode_bytes(&signature);
    let mut out = Vec::with_capacity(32 * 4 + signature_data.len());
    out.extend_from_slice(&parse_u256_decimal(&auth.valid_after, "validAfter")?);
    out.extend_from_slice(&parse_u256_decimal(&auth.valid_before, "validBefore")?);
    out.extend_from_slice(&parse_uint_word(&auth.salt, "deposit salt")?);
    out.extend_from_slice(&u256_word(32 * 4));
    out.extend_from_slice(&signature_data);
    Ok(out)
}

fn encode_claims_array(claims: &[BatchVoucherClaim]) -> Result<Vec<u8>, String> {
    let mut tails = Vec::with_capacity(claims.len());
    for claim in claims {
        tails.push(encode_claim_tuple(claim)?);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&u256_word(claims.len() as u128));
    let mut offset = 32 * claims.len();
    for tail in &tails {
        out.extend_from_slice(&u256_word(offset as u128));
        offset += tail.len();
    }
    for tail in tails {
        out.extend_from_slice(&tail);
    }
    Ok(out)
}

fn encode_claim_tuple(claim: &BatchVoucherClaim) -> Result<Vec<u8>, String> {
    let signature = parse_hex(&claim.signature, None)?;
    let mut out = Vec::new();
    out.extend_from_slice(&encode_channel_config(&claim.voucher.channel)?);
    out.extend_from_slice(&parse_u128_decimal_word(
        &claim.voucher.max_claimable_amount,
        "maxClaimableAmount",
    )?);
    out.extend_from_slice(&u256_word(32 * 10));
    out.extend_from_slice(&parse_u128_decimal_word(
        &claim.total_claimed,
        "totalClaimed",
    )?);
    out.extend_from_slice(&encode_bytes(&signature));
    Ok(out)
}

fn encode_channel_config(config: &BatchChannelConfig) -> Result<Vec<u8>, String> {
    let payer = parse_address(&config.payer, "payer")?;
    let payer_authorizer = parse_address(&config.payer_authorizer, "payerAuthorizer")?;
    let receiver = parse_address(&config.receiver, "receiver")?;
    let receiver_authorizer = parse_address(&config.receiver_authorizer, "receiverAuthorizer")?;
    let token = parse_address(&config.token, "token")?;
    let salt = parse_hex(&config.salt, Some(32)).map_err(|err| format!("salt: {err}"))?;
    let mut out = Vec::with_capacity(32 * 7);
    out.extend_from_slice(&address_word(&payer));
    out.extend_from_slice(&address_word(&payer_authorizer));
    out.extend_from_slice(&address_word(&receiver));
    out.extend_from_slice(&address_word(&receiver_authorizer));
    out.extend_from_slice(&address_word(&token));
    out.extend_from_slice(&u256_word(config.withdraw_delay as u128));
    out.extend_from_slice(&salt);
    Ok(out)
}

fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + padded_len(bytes.len()));
    out.extend_from_slice(&u256_word(bytes.len() as u128));
    out.extend_from_slice(bytes);
    out.resize(32 + padded_len(bytes.len()), 0);
    out
}

fn encode_bytes_array(items: &[Vec<u8>]) -> Vec<u8> {
    let tails = items
        .iter()
        .map(|item| encode_bytes(item))
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    out.extend_from_slice(&u256_word(items.len() as u128));
    let mut offset = 32 * items.len();
    for tail in &tails {
        out.extend_from_slice(&u256_word(offset as u128));
        offset += tail.len();
    }
    for tail in tails {
        out.extend_from_slice(&tail);
    }
    out
}

fn padded_len(len: usize) -> usize {
    len.div_ceil(32) * 32
}

fn parse_uint_word(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.starts_with("0x") || value.starts_with("0X") {
        let bytes = parse_hex(value, None).map_err(|err| format!("{label}: {err}"))?;
        if bytes.len() > 32 {
            return Err(format!("{label}: integer too large"));
        }
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        return Ok(out);
    }
    parse_u256_decimal(value, label)
}

fn sign_batch_typed_hash(
    message_hash: [u8; 32],
    private_key: &str,
    contract: &str,
) -> Result<String, String> {
    sign_digest(&batch_typed_digest(message_hash, contract)?, private_key)
}

fn recover_batch_typed_signer(
    message_hash: [u8; 32],
    signature: &str,
    contract: &str,
) -> Result<String, String> {
    let digest = batch_typed_digest(message_hash, contract)?;
    let sig = parse_hex(signature, Some(65))?;
    let signature =
        Signature::try_from(&sig[..64]).map_err(|_| "invalid batch authorizer signature")?;
    let recovery = recovery_id(sig[64])?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery)
        .map_err(|_| "invalid batch authorizer signature")?;
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address_hex(&address))
}

fn batch_typed_digest(message_hash: [u8; 32], contract: &str) -> Result<[u8; 32], String> {
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ));
    encoded.extend_from_slice(&keccak256(b"x402 Batch Settlement"));
    encoded.extend_from_slice(&keccak256(b"1"));
    encoded.extend_from_slice(&u256_word(137));
    encoded.extend_from_slice(&address_word(&parse_address(
        contract,
        "BATCH_SETTLEMENT_CONTRACT",
    )?));
    let domain = keccak256(&encoded);
    let mut digest_input = Vec::with_capacity(66);
    digest_input.extend_from_slice(b"\x19\x01");
    digest_input.extend_from_slice(&domain);
    digest_input.extend_from_slice(&message_hash);
    Ok(keccak256(&digest_input))
}

fn sign_digest(digest: &[u8; 32], private_key: &str) -> Result<String, String> {
    let key_bytes = parse_hex(private_key, Some(32))?;
    let key = SigningKey::from_slice(&key_bytes).map_err(|_| "invalid batch authorizer key")?;
    let (signature, recovery): (Signature, RecoveryId) = key
        .sign_prehash(digest)
        .map_err(|_| "failed to sign batch authorization")?;
    let mut bytes = Vec::with_capacity(65);
    bytes.extend_from_slice(&signature.to_bytes());
    bytes.push(u8::from(recovery) + 27);
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn normalize_eip3009_v(v: u8) -> Result<u8, String> {
    match v {
        0 | 1 => Ok(v + 27),
        27 | 28 => Ok(v),
        _ => Err("invalid signature recovery id".to_string()),
    }
}

fn recovery_id(value: u8) -> Result<RecoveryId, String> {
    let normalized = match value {
        0 | 1 => value,
        27 | 28 => value - 27,
        _ => return Err("invalid signature recovery id".to_string()),
    };
    RecoveryId::try_from(normalized).map_err(|_| "invalid signature recovery id".to_string())
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
    use crate::batch::{
        BatchClaimVoucher, BatchDeposit, BatchDepositAuthorization, BatchErc3009Authorization,
        BatchRequestPayload, BatchVoucher, BatchVoucherClaim, DEFAULT_BATCH_SETTLEMENT_CONTRACT,
    };
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

    fn batch_config() -> BatchChannelConfig {
        BatchChannelConfig {
            payer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
            payer_authorizer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993".to_string(),
            receiver: "0x1000000000000000000000000000000000000402".to_string(),
            receiver_authorizer: "0x2000000000000000000000000000000000000402".to_string(),
            token: JPYC_POLYGON_ADDRESS.to_string(),
            withdraw_delay: 900,
            salt: format!("0x{}", "33".repeat(32)),
        }
    }

    fn batch_signature() -> String {
        format!("0x{}", "11".repeat(65))
    }

    fn batch_voucher_claim() -> BatchVoucherClaim {
        BatchVoucherClaim {
            voucher: BatchClaimVoucher {
                channel: batch_config(),
                max_claimable_amount: "100".to_string(),
            },
            signature: batch_signature(),
            total_claimed: "0".to_string(),
        }
    }

    #[test]
    fn batch_settle_calldata_matches_viem() {
        let data = encode_batch_settle_calldata(
            "0x1000000000000000000000000000000000000402",
            JPYC_POLYGON_ADDRESS,
        )
        .unwrap();

        assert_eq!(
            format!("0x{}", hex::encode(data)),
            "0x9db32a8f0000000000000000000000001000000000000000000000000000000000000402000000000000000000000000431d5dff03120afa4bdf332c61a6e1766ef37bdb"
        );
    }

    #[test]
    fn batch_refund_calldata_matches_viem() {
        let payload = BatchRequestPayload {
            kind: "refund".to_string(),
            channel_config: Some(batch_config()),
            voucher: None,
            deposit: None,
            amount: Some("10".to_string()),
            refund_nonce: Some("3".to_string()),
            claims: None,
            receiver: None,
            token: None,
            claim_authorizer_signature: None,
            refund_authorizer_signature: Some(batch_signature()),
        };

        let data =
            encode_batch_refund_calldata(&payload, "", DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();

        assert_eq!(
            format!("0x{}", hex::encode(data)),
            "0xb77433e9000000000000000000000000b51afb2cba39fb1e3e2b3d1df337579896fba993000000000000000000000000b51afb2cba39fb1e3e2b3d1df337579896fba99300000000000000000000000010000000000000000000000000000000000004020000000000000000000000002000000000000000000000000000000000000402000000000000000000000000431d5dff03120afa4bdf332c61a6e1766ef37bdb00000000000000000000000000000000000000000000000000000000000003843333333333333333333333333333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000041111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn batch_claim_calldata_matches_viem() {
        let payload = BatchRequestPayload {
            kind: "claim".to_string(),
            channel_config: None,
            voucher: None,
            deposit: None,
            amount: None,
            refund_nonce: None,
            claims: Some(vec![batch_voucher_claim()]),
            receiver: None,
            token: None,
            claim_authorizer_signature: Some(batch_signature()),
            refund_authorizer_signature: None,
        };

        let data =
            encode_batch_claim_calldata(&payload, "", DEFAULT_BATCH_SETTLEMENT_CONTRACT).unwrap();

        assert_eq!(
            format!("0x{}", hex::encode(data)),
            "0xe43ce1f20000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000b51afb2cba39fb1e3e2b3d1df337579896fba993000000000000000000000000b51afb2cba39fb1e3e2b3d1df337579896fba99300000000000000000000000010000000000000000000000000000000000004020000000000000000000000002000000000000000000000000000000000000402000000000000000000000000431d5dff03120afa4bdf332c61a6e1766ef37bdb0000000000000000000000000000000000000000000000000000000000000384333333333333333333333333333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000411111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn batch_deposit_calldata_matches_viem() {
        let payload = BatchRequestPayload {
            kind: "deposit".to_string(),
            channel_config: Some(batch_config()),
            voucher: Some(BatchVoucher {
                channel_id: format!("0x{}", "44".repeat(32)),
                max_claimable_amount: "100".to_string(),
                signature: batch_signature(),
            }),
            deposit: Some(BatchDeposit {
                amount: "100".to_string(),
                authorization: BatchDepositAuthorization {
                    erc3009_authorization: Some(BatchErc3009Authorization {
                        valid_after: "0".to_string(),
                        valid_before: "9999999999".to_string(),
                        salt: "0x22".to_string(),
                        signature: batch_signature(),
                    }),
                },
            }),
            amount: None,
            refund_nonce: None,
            claims: None,
            receiver: None,
            token: None,
            claim_authorizer_signature: None,
            refund_authorizer_signature: None,
        };

        let data = encode_batch_deposit_calldata(&payload).unwrap();

        assert_eq!(
            format!("0x{}", hex::encode(data)),
            "0x140f1e75000000000000000000000000b51afb2cba39fb1e3e2b3d1df337579896fba993000000000000000000000000b51afb2cba39fb1e3e2b3d1df337579896fba99300000000000000000000000010000000000000000000000000000000000004020000000000000000000000002000000000000000000000000000000000000402000000000000000000000000431d5dff03120afa4bdf332c61a6e1766ef37bdb0000000000000000000000000000000000000000000000000000000000000384333333333333333333333333333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000000640000000000000000000000004020806089470a89826cb9fb1f4059150b55000400000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002540be3ff000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn batch_calldata_rejects_uint128_overflow_fields() {
        let over_uint128 = "340282366920938463463374607431768211456";

        let deposit = BatchRequestPayload {
            kind: "deposit".to_string(),
            channel_config: Some(batch_config()),
            voucher: Some(BatchVoucher {
                channel_id: format!("0x{}", "44".repeat(32)),
                max_claimable_amount: "100".to_string(),
                signature: batch_signature(),
            }),
            deposit: Some(BatchDeposit {
                amount: over_uint128.to_string(),
                authorization: BatchDepositAuthorization {
                    erc3009_authorization: Some(BatchErc3009Authorization {
                        valid_after: "0".to_string(),
                        valid_before: "9999999999".to_string(),
                        salt: "0x22".to_string(),
                        signature: batch_signature(),
                    }),
                },
            }),
            amount: None,
            refund_nonce: None,
            claims: None,
            receiver: None,
            token: None,
            claim_authorizer_signature: None,
            refund_authorizer_signature: None,
        };
        assert_eq!(
            encode_batch_deposit_calldata(&deposit),
            Err("deposit amount: integer too large".to_string())
        );

        let refund = BatchRequestPayload {
            kind: "refund".to_string(),
            channel_config: Some(batch_config()),
            voucher: None,
            deposit: None,
            amount: Some(over_uint128.to_string()),
            refund_nonce: Some("3".to_string()),
            claims: None,
            receiver: None,
            token: None,
            claim_authorizer_signature: None,
            refund_authorizer_signature: Some(batch_signature()),
        };
        assert_eq!(
            encode_batch_refund_calldata(&refund, "", DEFAULT_BATCH_SETTLEMENT_CONTRACT),
            Err("refund amount: integer too large".to_string())
        );

        let mut claim = batch_voucher_claim();
        claim.voucher.max_claimable_amount = over_uint128.to_string();
        let claim_payload = BatchRequestPayload {
            kind: "claim".to_string(),
            channel_config: None,
            voucher: None,
            deposit: None,
            amount: None,
            refund_nonce: None,
            claims: Some(vec![claim]),
            receiver: None,
            token: None,
            claim_authorizer_signature: Some(batch_signature()),
            refund_authorizer_signature: None,
        };
        assert_eq!(
            encode_batch_claim_calldata(&claim_payload, "", DEFAULT_BATCH_SETTLEMENT_CONTRACT),
            Err("maxClaimableAmount: integer too large".to_string())
        );
    }
}
