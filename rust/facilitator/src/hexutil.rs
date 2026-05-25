// rust/facilitator/src/hexutil.rs: EVM address/hex/uint の正規化を一箇所に集約する。
use sha3::{Digest, Keccak256};

pub const JPYC_POLYGON_ADDRESS: &str = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
pub const PERMIT2_ADDRESS: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
pub const X402_EXACT_PERMIT2_PROXY: &str = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001";
pub const NETWORK: &str = "eip155:137";

pub fn strip_0x(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}

pub fn parse_hex(value: &str, expected_len: Option<usize>) -> Result<Vec<u8>, String> {
    let raw = strip_0x(value);
    if raw.len() % 2 != 0 {
        return Err("hex length must be even".to_string());
    }
    let bytes = hex::decode(raw).map_err(|_| "invalid hex".to_string())?;
    if let Some(len) = expected_len {
        if bytes.len() != len {
            return Err(format!("hex must be {len} bytes"));
        }
    }
    Ok(bytes)
}

pub fn parse_address(value: &str, label: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex(value, Some(20)).map_err(|err| format!("{label}: {err}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    if out == [0u8; 20] {
        return Err(format!("{label}: zero address"));
    }
    Ok(out)
}

pub fn address_hex(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

pub fn same_address(left: &str, right: &str) -> bool {
    strip_0x(left).eq_ignore_ascii_case(strip_0x(right))
}

pub fn parse_u256_decimal(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.is_empty() || !value.bytes().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("{label}: invalid decimal integer"));
    }
    let mut out = [0u8; 32];
    for ch in value.bytes() {
        let digit = ch - b'0';
        mul_small(&mut out, 10).map_err(|_| format!("{label}: integer too large"))?;
        add_small(&mut out, digit).map_err(|_| format!("{label}: integer too large"))?;
    }
    Ok(out)
}

pub fn parse_u64_decimal(value: &str, label: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("{label}: invalid decimal integer"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{label}: integer too large"))
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

pub fn left_pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

pub fn parse_u256_hex(value: &str, label: &str) -> Result<[u8; 32], String> {
    let raw = strip_0x(value);
    if raw.len() > 64 {
        return Err(format!("{label}: integer too large"));
    }
    if raw.is_empty() {
        return Ok([0u8; 32]);
    }
    let padded = if raw.len() % 2 == 0 {
        raw.to_string()
    } else {
        format!("0{raw}")
    };
    let bytes = hex::decode(&padded).map_err(|_| format!("{label}: invalid hex integer"))?;
    Ok(left_pad_32(&bytes))
}

pub fn u256_gte(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left >= right
}

pub fn u256_word(value: u128) -> [u8; 32] {
    left_pad_32(&value.to_be_bytes())
}

pub fn address_word(value: &[u8; 20]) -> [u8; 32] {
    left_pad_32(value)
}

fn mul_small(value: &mut [u8; 32], factor: u8) -> Result<(), ()> {
    let mut carry = 0u16;
    for byte in value.iter_mut().rev() {
        let next = u16::from(*byte) * u16::from(factor) + carry;
        *byte = next as u8;
        carry = next >> 8;
    }
    if carry == 0 {
        Ok(())
    } else {
        Err(())
    }
}

fn add_small(value: &mut [u8; 32], addend: u8) -> Result<(), ()> {
    let mut carry = u16::from(addend);
    for byte in value.iter_mut().rev() {
        let next = u16::from(*byte) + carry;
        *byte = next as u8;
        carry = next >> 8;
        if carry == 0 {
            return Ok(());
        }
    }
    if carry == 0 {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_width_u256_decimal() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(parse_u256_decimal(max, "max").unwrap(), [0xff; 32]);
        let too_big =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(parse_u256_decimal(too_big, "too_big").is_err());
    }

    #[test]
    fn compares_u256_words() {
        let one = parse_u256_decimal("1", "one").unwrap();
        let two = parse_u256_decimal("2", "two").unwrap();
        assert!(u256_gte(&two, &one));
        assert!(u256_gte(&two, &two));
        assert!(!u256_gte(&one, &two));
    }
}
