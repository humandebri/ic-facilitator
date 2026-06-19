#!/usr/bin/env bash
# scripts/set_canister_env.sh: Rust facilitator canister に runtime env を注入する。
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ENVIRONMENT="${1:-local}"
readonly CANISTER="${2:-edge}"
readonly DEFAULT_FACILITATOR_MAX_GAS="500000"
readonly DEFAULT_FACILITATOR_MAX_SETTLEMENT_FEE_WEI="30000000000000000"
readonly DEFAULT_SETTLE_CONFIRMATION_TIMEOUT_SECONDS="60"
readonly DEFAULT_SETTLE_MIN_CONFIRMATIONS="3"
readonly DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS="86400"
readonly DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS="900"
readonly MIN_BATCH_WITHDRAW_DELAY_SECONDS="900"
readonly MAX_BATCH_WITHDRAW_DELAY_SECONDS="2592000"
readonly CANONICAL_BATCH_SETTLEMENT_CONTRACT="0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003"
readonly UINT128_MAX="340282366920938463463374607431768211455"
readonly ENV_FILE="${DOTENV_PATH:-$ROOT/.env}"

load_dotenv() {
  if [[ ! -f "$ENV_FILE" ]]; then
    return 0
  fi
  eval "$(
    DOTENV_FILE="$ENV_FILE" node <<'NODE'
const fs = require("node:fs");
const text = fs.readFileSync(process.env.DOTENV_FILE, "utf8");
const quote = (value) => `'${value.replace(/'/g, "'\\''")}'`;
for (const rawLine of text.split(/\r?\n/)) {
  const line = rawLine.trim();
  if (line === "" || line.startsWith("#")) { continue; }
  const normalized = line.startsWith("export ") ? line.slice("export ".length).trimStart() : line;
  const index = normalized.indexOf("=");
  if (index <= 0) { continue; }
  const name = normalized.slice(0, index).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) { continue; }
  if (process.env[name] && process.env[name].trim() !== "") { continue; }
  const value = normalized.slice(index + 1).trim();
  const unquoted = value.length >= 2 && (
    (value.startsWith("\"") && value.endsWith("\"")) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) ? value.slice(1, -1) : value;
  console.log(`export ${name}=${quote(unquoted)}`);
}
NODE
  )"
}

required_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required env: $name" >&2
    exit 1
  fi
}

require_evm_address() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "$name must be a 0x-prefixed 20-byte EVM address" >&2
    exit 1
  fi
}

require_nonzero_evm_address() {
  local name="$1"
  local value="$2"
  require_evm_address "$name" "$value"
  if [[ "$value" == "0x0000000000000000000000000000000000000000" ]]; then
    echo "$name must be a non-zero EVM address" >&2
    exit 1
  fi
}

require_official_batch_settlement_contract() {
  local value="$1"
  local actual
  local expected
  actual="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  expected="$(printf '%s' "$CANONICAL_BATCH_SETTLEMENT_CONTRACT" | tr '[:upper:]' '[:lower:]')"
  if [[ "$actual" != "$expected" ]]; then
    echo "BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS $CANONICAL_BATCH_SETTLEMENT_CONTRACT" >&2
    exit 1
  fi
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "$name must be a positive integer" >&2
    exit 1
  fi
}

require_uint128_integer() {
  local name="$1"
  local value="$2"
  require_positive_integer "$name" "$value"
  if ! UINT_VALUE="$value" UINT_MAX="$UINT128_MAX" node <<'NODE'
const value = BigInt(process.env.UINT_VALUE || "0");
const max = BigInt(process.env.UINT_MAX || "0");
process.exit(value <= max ? 0 : 1);
NODE
  then
    echo "$name must fit uint128" >&2
    exit 1
  fi
}

require_integer_range() {
  local name="$1"
  local value="$2"
  local min="$3"
  local max="$4"
  require_positive_integer "$name" "$value"
  if (( value < min || value > max )); then
    echo "$name must be between $min and $max" >&2
    exit 1
  fi
}

require_private_key() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo "$name must be a 0x-prefixed 32-byte private key" >&2
    exit 1
  fi
}

private_key_address() {
  local name="$1"
  local value="$2"
  PRIVATE_KEY_NAME="$name" PRIVATE_KEY_VALUE="$value" node --input-type=module <<'NODE'
import { privateKeyToAccount } from "viem/accounts";

try {
  console.log(privateKeyToAccount(process.env.PRIVATE_KEY_VALUE).address.toLowerCase());
} catch {
  console.error(`${process.env.PRIVATE_KEY_NAME} must be a valid secp256k1 private key`);
  process.exit(1);
}
NODE
}

require_batch_key_separation() {
  local facilitator
  local receiver_authorizer
  facilitator="$(private_key_address FACILITATOR_EVM_PRIVATE_KEY "$FACILITATOR_EVM_PRIVATE_KEY")"
  receiver_authorizer="$(private_key_address BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY "$BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")"
  if [[ "$facilitator" == "$receiver_authorizer" ]]; then
    echo "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address" >&2
    exit 1
  fi
}

require_single_https_rpc_url() {
  local name="$1"
  local value="$2"
  if [[ "$value" == *","* ]]; then
    echo "$name must contain exactly one HTTPS RPC origin" >&2
    exit 1
  fi
  if [[ ! "$value" =~ ^https://[^/:@?#[:space:]]+(:[0-9]+)?$ ]]; then
    echo "$name must be a single https://host[:port] RPC origin" >&2
    exit 1
  fi
}

require_https_origin() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^https://[^/:@?#[:space:]]+(:[0-9]+)?$ ]]; then
    echo "$name must be an HTTPS origin" >&2
    exit 1
  fi
}

require_ic_principal() {
  local name="$1"
  local value="$2"
  if ! PRINCIPAL_VALUE="$value" node <<'NODE'
const alphabet = "abcdefghijklmnopqrstuvwxyz234567";

function group(compact) {
  const groups = [];
  for (let index = 0; index < compact.length; index += 5) {
    groups.push(compact.slice(index, index + 5));
  }
  return groups.join("-");
}

function encode(bytes) {
  let buffer = 0;
  let bits = 0;
  let compact = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      compact += alphabet.charAt((buffer >> bits) & 0x1f);
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    compact += alphabet.charAt((buffer << (5 - bits)) & 0x1f);
  }
  return group(compact);
}

function decode(value) {
  if (value !== value.toLowerCase()) {
    return undefined;
  }
  const compact = value.replaceAll("-", "");
  if (compact.length === 0) {
    return undefined;
  }
  let buffer = 0;
  let bits = 0;
  const bytes = [];
  for (const char of compact) {
    const index = alphabet.indexOf(char);
    if (index < 0) {
      return undefined;
    }
    buffer = (buffer << 5) | index;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  if (bytes.length < 4 || encode(bytes) !== value) {
    return undefined;
  }
  return bytes;
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      const mask = -(crc & 1);
      crc = (crc >>> 1) ^ (0xedb88320 & mask);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function valid(value) {
  const bytes = decode(value);
  if (!bytes) {
    return false;
  }
  const checksum = crc32(bytes.slice(4));
  return (
    bytes[0] === ((checksum >>> 24) & 0xff) &&
    bytes[1] === ((checksum >>> 16) & 0xff) &&
    bytes[2] === ((checksum >>> 8) & 0xff) &&
    bytes[3] === (checksum & 0xff)
  );
}

process.exit(valid(process.env.PRINCIPAL_VALUE || "") ? 0 : 1);
NODE
  then
    echo "$name must be an IC principal" >&2
    exit 1
  fi
  if [[ "$value" == "2vxsx-fae" || "$value" == "aaaaa-aa" ]]; then
    echo "$name must be a non-system IC principal" >&2
    exit 1
  fi
}

candid_text() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

set_env() {
  local name="$1"
  local value="$2"
  local escaped_name
  local escaped_value
  escaped_name="$(candid_text "$name")"
  escaped_value="$(candid_text "$value")"
  icp canister call --environment "$ENVIRONMENT" "$CANISTER" set_env "(\"$escaped_name\", \"$escaped_value\")"
}

cd "$ROOT"
load_dotenv

required_env FACILITATOR_EVM_PRIVATE_KEY
required_env JPYC_EIP712_VERSION
required_env POLYGON_RPC_SERVICES
required_env FACILITATOR_PUBLIC_ORIGIN
required_env SELLER_CREDIT_PAY_TO
required_env SELLER_CREDIT_TOPUP_AMOUNT
required_env SELLER_SETTLEMENT_FEE_AMOUNT
require_private_key FACILITATOR_EVM_PRIVATE_KEY "$FACILITATOR_EVM_PRIVATE_KEY"
require_single_https_rpc_url POLYGON_RPC_SERVICES "$POLYGON_RPC_SERVICES"
require_https_origin FACILITATOR_PUBLIC_ORIGIN "$FACILITATOR_PUBLIC_ORIGIN"
require_nonzero_evm_address SELLER_CREDIT_PAY_TO "$SELLER_CREDIT_PAY_TO"
require_positive_integer SELLER_CREDIT_TOPUP_AMOUNT "$SELLER_CREDIT_TOPUP_AMOUNT"
require_positive_integer SELLER_SETTLEMENT_FEE_AMOUNT "$SELLER_SETTLEMENT_FEE_AMOUNT"
readonly RESOLVED_FACILITATOR_MAX_GAS="${FACILITATOR_MAX_GAS:-$DEFAULT_FACILITATOR_MAX_GAS}"
readonly RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI="${FACILITATOR_MAX_SETTLEMENT_FEE_WEI:-$DEFAULT_FACILITATOR_MAX_SETTLEMENT_FEE_WEI}"
readonly RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS="${SETTLE_CONFIRMATION_TIMEOUT_SECONDS:-$DEFAULT_SETTLE_CONFIRMATION_TIMEOUT_SECONDS}"
readonly RESOLVED_SETTLE_MIN_CONFIRMATIONS="${SETTLE_MIN_CONFIRMATIONS:-$DEFAULT_SETTLE_MIN_CONFIRMATIONS}"
readonly RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS="${SETTLEMENT_CACHE_TTL_SECONDS:-$DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS}"
readonly RESOLVED_BATCH_WITHDRAW_DELAY_SECONDS="${BATCH_WITHDRAW_DELAY_SECONDS:-$DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS}"
require_positive_integer FACILITATOR_MAX_GAS "$RESOLVED_FACILITATOR_MAX_GAS"
require_positive_integer FACILITATOR_MAX_SETTLEMENT_FEE_WEI "$RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI"
require_positive_integer SETTLE_CONFIRMATION_TIMEOUT_SECONDS "$RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS"
require_positive_integer SETTLE_MIN_CONFIRMATIONS "$RESOLVED_SETTLE_MIN_CONFIRMATIONS"
require_positive_integer SETTLEMENT_CACHE_TTL_SECONDS "$RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS"
if [[ -n "${BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY:-}" ]]; then
  required_env BATCH_SETTLEMENT_CONTRACT
  required_env BATCH_SETTLEMENT_FEE_AMOUNT
  require_private_key BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY "$BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"
  require_batch_key_separation
  require_nonzero_evm_address BATCH_SETTLEMENT_CONTRACT "$BATCH_SETTLEMENT_CONTRACT"
  require_official_batch_settlement_contract "$BATCH_SETTLEMENT_CONTRACT"
  require_integer_range BATCH_WITHDRAW_DELAY_SECONDS "$RESOLVED_BATCH_WITHDRAW_DELAY_SECONDS" "$MIN_BATCH_WITHDRAW_DELAY_SECONDS" "$MAX_BATCH_WITHDRAW_DELAY_SECONDS"
  require_uint128_integer BATCH_SETTLEMENT_FEE_AMOUNT "$BATCH_SETTLEMENT_FEE_AMOUNT"
fi

set_env FACILITATOR_EVM_PRIVATE_KEY "$FACILITATOR_EVM_PRIVATE_KEY"
set_env JPYC_EIP712_VERSION "$JPYC_EIP712_VERSION"
set_env POLYGON_RPC_SERVICES "$POLYGON_RPC_SERVICES"
set_env FACILITATOR_PUBLIC_ORIGIN "$FACILITATOR_PUBLIC_ORIGIN"
set_env SELLER_CREDIT_PAY_TO "$SELLER_CREDIT_PAY_TO"
set_env SELLER_CREDIT_TOPUP_AMOUNT "$SELLER_CREDIT_TOPUP_AMOUNT"
set_env SELLER_SETTLEMENT_FEE_AMOUNT "$SELLER_SETTLEMENT_FEE_AMOUNT"
set_env FACILITATOR_MAX_GAS "$RESOLVED_FACILITATOR_MAX_GAS"
set_env FACILITATOR_MAX_SETTLEMENT_FEE_WEI "$RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI"
set_env SETTLE_CONFIRMATION_TIMEOUT_SECONDS "$RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS"
set_env SETTLE_MIN_CONFIRMATIONS "$RESOLVED_SETTLE_MIN_CONFIRMATIONS"
set_env SETTLEMENT_CACHE_TTL_SECONDS "$RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS"
if [[ -n "${BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY:-}" ]]; then
  set_env BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY "$BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"
  set_env BATCH_SETTLEMENT_CONTRACT "$BATCH_SETTLEMENT_CONTRACT"
  set_env BATCH_WITHDRAW_DELAY_SECONDS "$RESOLVED_BATCH_WITHDRAW_DELAY_SECONDS"
  set_env BATCH_SETTLEMENT_FEE_AMOUNT "$BATCH_SETTLEMENT_FEE_AMOUNT"
else
  set_env BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY ""
  set_env BATCH_SETTLEMENT_CONTRACT ""
  set_env BATCH_WITHDRAW_DELAY_SECONDS ""
  set_env BATCH_SETTLEMENT_FEE_AMOUNT ""
fi
