#!/usr/bin/env bash
# scripts/set_canister_env.sh: Rust facilitator canister に runtime env を注入する。
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ENVIRONMENT="${1:-local}"
readonly CANISTER="${2:-edge}"
readonly MODE="${3:---sync}"
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

require_uint_minimum() {
  local name="$1"
  local value="$2"
  local minimum="$3"
  require_uint128_integer "$name" "$value"
  if ! UINT_VALUE="$value" UINT_MIN="$minimum" node <<'NODE'
const value = BigInt(process.env.UINT_VALUE || "0");
const minimum = BigInt(process.env.UINT_MIN || "0");
process.exit(value >= minimum ? 0 : 1);
NODE
  then
    echo "$name must be at least $minimum" >&2
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

require_polygon_rpc_url() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^https://[^/@?#[:space:]]+(/[^#[:space:]]*)?(\?[^#[:space:]]*)?$ ]] || [[ "$value" == *"@"* ]]; then
    echo "$name must be a HTTPS RPC URL without userinfo or fragment" >&2
    exit 1
  fi
}

require_contract_bytecode() {
  local rpc_url="$1"
  local contract="$2"
  RPC_URL="$rpc_url" CONTRACT_ADDRESS="$contract" node --input-type=module <<'NODE'
const response = await fetch(process.env.RPC_URL, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getCode",
    params: [process.env.CONTRACT_ADDRESS, "latest"],
  }),
});
if (!response.ok) {
  console.error(`Amoy batch contract bytecode check returned HTTP ${response.status}`);
  process.exit(1);
}
const body = await response.json();
if (body?.jsonrpc !== "2.0" || body?.id !== 1 || body?.error || typeof body?.result !== "string") {
  console.error("Amoy batch contract bytecode check returned an invalid JSON-RPC response");
  process.exit(1);
}
if (/^0x0*$/i.test(body.result)) {
  console.error("canonical Amoy batch contract has no bytecode; batch support remains disabled");
  process.exit(1);
}
NODE
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

require_candid_ok() {
  local output="$1"
  if [[ "$output" != *"variant { ok"* && "$output" != *"variant { Ok"* ]]; then
    echo "canister update returned a Candid error: $output" >&2
    return 1
  fi
}

set_runtime_configuration() {
  local profile="$1"
  local token="$2"
  local contract="$3"
  local seller_fee="$4"
  local deposit_fee="$5"
  local claim_fee="$6"
  local settle_fee="$7"
  local refund_fee="$8"
  local schedule="$9"
  local terms="${10}"
  local privacy="${11}"
  local asset_boundary="${12}"
  local escaped_profile escaped_token escaped_contract escaped_seller_fee
  local escaped_deposit escaped_claim escaped_settle escaped_refund
  local escaped_terms escaped_privacy escaped_asset_boundary
  local output
  escaped_profile="$(candid_text "$profile")"
  escaped_token="$(candid_text "$token")"
  escaped_contract="$(candid_text "$contract")"
  escaped_seller_fee="$(candid_text "$seller_fee")"
  escaped_deposit="$(candid_text "$deposit_fee")"
  escaped_claim="$(candid_text "$claim_fee")"
  escaped_settle="$(candid_text "$settle_fee")"
  escaped_refund="$(candid_text "$refund_fee")"
  escaped_terms="$(candid_text "$terms")"
  escaped_privacy="$(candid_text "$privacy")"
  escaped_asset_boundary="$(candid_text "$asset_boundary")"
  output="$(icp canister call --environment "$ENVIRONMENT" "$CANISTER" set_runtime_configuration "(record {
    profile = \"$escaped_profile\";
    token = \"$escaped_token\";
    batch_contract = \"$escaped_contract\";
    seller_settlement_fee_amount = \"$escaped_seller_fee\";
    deposit_fee_amount = \"$escaped_deposit\";
    claim_fee_amount = \"$escaped_claim\";
    settle_fee_amount = \"$escaped_settle\";
    refund_fee_amount = \"$escaped_refund\";
    claim_fee_schedule = $schedule;
    terms_version = \"$escaped_terms\";
    privacy_version = \"$escaped_privacy\";
    asset_boundary_version = \"$escaped_asset_boundary\";
  })")"
  printf '%s\n' "$output"
  require_candid_ok "$output"
}

cd "$ROOT"
load_dotenv

required_env FACILITATOR_EVM_PRIVATE_KEY
required_env JPYC_EIP712_VERSION
required_env POLYGON_RPC_URL
required_env FACILITATOR_PUBLIC_ORIGIN
required_env SELLER_CREDIT_PAY_TO
required_env SELLER_SETTLEMENT_FEE_AMOUNT
readonly RESOLVED_NETWORK_PROFILE="${NETWORK_PROFILE:-polygon}"
case "$RESOLVED_NETWORK_PROFILE" in
  polygon)
    readonly RESOLVED_NETWORK_TOKEN="0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB"
    ;;
  amoy)
    required_env AMOY_JPYC_ADDRESS
    require_nonzero_evm_address AMOY_JPYC_ADDRESS "$AMOY_JPYC_ADDRESS"
    readonly RESOLVED_NETWORK_TOKEN="$AMOY_JPYC_ADDRESS"
    BATCH_SETTLEMENT_CONTRACT="${AMOY_BATCH_SETTLEMENT_CONTRACT:-$CANONICAL_BATCH_SETTLEMENT_CONTRACT}"
    require_official_batch_settlement_contract "$BATCH_SETTLEMENT_CONTRACT"
    ;;
  *)
    echo "NETWORK_PROFILE must be polygon or amoy" >&2
    exit 1
    ;;
esac
require_private_key FACILITATOR_EVM_PRIVATE_KEY "$FACILITATOR_EVM_PRIVATE_KEY"
require_polygon_rpc_url POLYGON_RPC_URL "$POLYGON_RPC_URL"
require_https_origin FACILITATOR_PUBLIC_ORIGIN "$FACILITATOR_PUBLIC_ORIGIN"
require_nonzero_evm_address SELLER_CREDIT_PAY_TO "$SELLER_CREDIT_PAY_TO"
require_uint128_integer SELLER_SETTLEMENT_FEE_AMOUNT "$SELLER_SETTLEMENT_FEE_AMOUNT"
readonly RESOLVED_FACILITATOR_MAX_GAS="${FACILITATOR_MAX_GAS:-$DEFAULT_FACILITATOR_MAX_GAS}"
readonly RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI="${FACILITATOR_MAX_SETTLEMENT_FEE_WEI:-$DEFAULT_FACILITATOR_MAX_SETTLEMENT_FEE_WEI}"
readonly RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS="${SETTLE_CONFIRMATION_TIMEOUT_SECONDS:-$DEFAULT_SETTLE_CONFIRMATION_TIMEOUT_SECONDS}"
readonly RESOLVED_SETTLE_MIN_CONFIRMATIONS="${SETTLE_MIN_CONFIRMATIONS:-$DEFAULT_SETTLE_MIN_CONFIRMATIONS}"
readonly RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS="${SETTLEMENT_CACHE_TTL_SECONDS:-$DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS}"
readonly RESOLVED_BATCH_WITHDRAW_DELAY_SECONDS="${BATCH_WITHDRAW_DELAY_SECONDS:-$DEFAULT_BATCH_WITHDRAW_DELAY_SECONDS}"
readonly LEGACY_BATCH_FEE_INPUT="${BATCH_SETTLEMENT_FEE_AMOUNT:-10000000000000000000}"
readonly RESOLVED_BATCH_DEPOSIT_FEE_AMOUNT="${BATCH_DEPOSIT_FEE_AMOUNT:-$LEGACY_BATCH_FEE_INPUT}"
readonly RESOLVED_BATCH_CLAIM_FEE_AMOUNT="${BATCH_CLAIM_FEE_AMOUNT:-$LEGACY_BATCH_FEE_INPUT}"
readonly RESOLVED_BATCH_SETTLE_FEE_AMOUNT="${BATCH_SETTLE_FEE_AMOUNT:-$LEGACY_BATCH_FEE_INPUT}"
readonly RESOLVED_BATCH_REFUND_FEE_AMOUNT="${BATCH_REFUND_FEE_AMOUNT:-$LEGACY_BATCH_FEE_INPUT}"
readonly BATCH_CLAIM_SCHEDULE_ENV_NAMES=(
  BATCH_CLAIM_1_FEE_AMOUNT
  BATCH_CLAIM_10_FEE_AMOUNT
  BATCH_CLAIM_50_FEE_AMOUNT
  BATCH_CLAIM_100_FEE_AMOUNT
  BATCH_REFUND_WITH_CLAIM_1_FEE_AMOUNT
  BATCH_REFUND_WITH_CLAIM_10_FEE_AMOUNT
  BATCH_REFUND_WITH_CLAIM_50_FEE_AMOUNT
  BATCH_REFUND_WITH_CLAIM_100_FEE_AMOUNT
)
batch_claim_schedule_count=0
for schedule_name in "${BATCH_CLAIM_SCHEDULE_ENV_NAMES[@]}"; do
  if [[ -n "${!schedule_name:-}" ]]; then
    batch_claim_schedule_count=$((batch_claim_schedule_count + 1))
  fi
done
if [[ "$batch_claim_schedule_count" != "0" && "$batch_claim_schedule_count" != "8" ]]; then
  echo "all eight batch claim fee schedule envs must be set together" >&2
  exit 1
fi
if [[ "$batch_claim_schedule_count" == "8" ]]; then
  readonly RESOLVED_BATCH_SETTLEMENT_FEE_AMOUNT="$BATCH_CLAIM_100_FEE_AMOUNT"
else
  readonly RESOLVED_BATCH_SETTLEMENT_FEE_AMOUNT="$RESOLVED_BATCH_CLAIM_FEE_AMOUNT"
fi
if [[ -n "${BATCH_SETTLEMENT_FEE_AMOUNT:-}" && "$BATCH_SETTLEMENT_FEE_AMOUNT" != "$RESOLVED_BATCH_SETTLEMENT_FEE_AMOUNT" ]]; then
  echo "BATCH_SETTLEMENT_FEE_AMOUNT must equal the effective claim-100 fee $RESOLVED_BATCH_SETTLEMENT_FEE_AMOUNT" >&2
  exit 1
fi
require_positive_integer FACILITATOR_MAX_GAS "$RESOLVED_FACILITATOR_MAX_GAS"
require_positive_integer FACILITATOR_MAX_SETTLEMENT_FEE_WEI "$RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI"
require_positive_integer SETTLE_CONFIRMATION_TIMEOUT_SECONDS "$RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS"
require_positive_integer SETTLE_MIN_CONFIRMATIONS "$RESOLVED_SETTLE_MIN_CONFIRMATIONS"
require_positive_integer SETTLEMENT_CACHE_TTL_SECONDS "$RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS"
require_uint128_integer BATCH_SETTLEMENT_FEE_AMOUNT "$RESOLVED_BATCH_SETTLEMENT_FEE_AMOUNT"
require_uint128_integer BATCH_DEPOSIT_FEE_AMOUNT "$RESOLVED_BATCH_DEPOSIT_FEE_AMOUNT"
require_uint128_integer BATCH_CLAIM_FEE_AMOUNT "$RESOLVED_BATCH_CLAIM_FEE_AMOUNT"
require_uint128_integer BATCH_SETTLE_FEE_AMOUNT "$RESOLVED_BATCH_SETTLE_FEE_AMOUNT"
require_uint128_integer BATCH_REFUND_FEE_AMOUNT "$RESOLVED_BATCH_REFUND_FEE_AMOUNT"
if [[ "$batch_claim_schedule_count" == "8" ]]; then
  for schedule_name in "${BATCH_CLAIM_SCHEDULE_ENV_NAMES[@]}"; do
    require_uint128_integer "$schedule_name" "${!schedule_name}"
  done
fi
if [[ -n "${BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY:-}" ]]; then
  required_env BATCH_SETTLEMENT_CONTRACT
  required_env BATCH_SETTLEMENT_FEE_AMOUNT
  require_private_key BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY "$BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"
  require_batch_key_separation
  require_nonzero_evm_address BATCH_SETTLEMENT_CONTRACT "$BATCH_SETTLEMENT_CONTRACT"
  if [[ "$RESOLVED_NETWORK_PROFILE" == "polygon" ]]; then
    require_official_batch_settlement_contract "$BATCH_SETTLEMENT_CONTRACT"
  else
    require_contract_bytecode "$POLYGON_RPC_URL" "$BATCH_SETTLEMENT_CONTRACT"
  fi
  require_integer_range BATCH_WITHDRAW_DELAY_SECONDS "$RESOLVED_BATCH_WITHDRAW_DELAY_SECONDS" "$MIN_BATCH_WITHDRAW_DELAY_SECONDS" "$MAX_BATCH_WITHDRAW_DELAY_SECONDS"
  require_uint128_integer BATCH_SETTLEMENT_FEE_AMOUNT "$BATCH_SETTLEMENT_FEE_AMOUNT"
  if [[ "${REQUIRE_PRODUCTION_FEES:-0}" == "1" ]]; then
    require_uint_minimum BATCH_SETTLEMENT_FEE_AMOUNT "$BATCH_SETTLEMENT_FEE_AMOUNT" "500000000000000000"
  fi
fi
if [[ "$RESOLVED_NETWORK_PROFILE" == "polygon" || "${REQUIRE_PRODUCTION_FEES:-0}" == "1" ]]; then
  require_uint_minimum SELLER_SETTLEMENT_FEE_AMOUNT "$SELLER_SETTLEMENT_FEE_AMOUNT" "500000000000000000"
  require_uint_minimum BATCH_SETTLEMENT_FEE_AMOUNT "$RESOLVED_BATCH_SETTLEMENT_FEE_AMOUNT" "500000000000000000"
  for action_fee_name in BATCH_DEPOSIT_FEE_AMOUNT BATCH_CLAIM_FEE_AMOUNT BATCH_SETTLE_FEE_AMOUNT BATCH_REFUND_FEE_AMOUNT; do
    action_fee_value="${!action_fee_name:-}"
    if [[ -z "$action_fee_value" ]]; then
      case "$action_fee_name" in
        BATCH_DEPOSIT_FEE_AMOUNT) action_fee_value="$RESOLVED_BATCH_DEPOSIT_FEE_AMOUNT" ;;
        BATCH_CLAIM_FEE_AMOUNT) action_fee_value="$RESOLVED_BATCH_CLAIM_FEE_AMOUNT" ;;
        BATCH_SETTLE_FEE_AMOUNT) action_fee_value="$RESOLVED_BATCH_SETTLE_FEE_AMOUNT" ;;
        BATCH_REFUND_FEE_AMOUNT) action_fee_value="$RESOLVED_BATCH_REFUND_FEE_AMOUNT" ;;
      esac
    fi
    require_uint_minimum "$action_fee_name" "$action_fee_value" "500000000000000000"
  done
  if [[ "$batch_claim_schedule_count" == "8" ]]; then
    for schedule_name in "${BATCH_CLAIM_SCHEDULE_ENV_NAMES[@]}"; do
      require_uint_minimum "$schedule_name" "${!schedule_name}" "500000000000000000"
    done
  fi
  for version_name in SELLER_TERMS_VERSION PRIVACY_VERSION ASSET_BOUNDARY_VERSION; do
    version_value="${!version_name:-}"
    if [[ -z "$version_value" || "$version_value" == *-draft ]]; then
      echo "$version_name must be an approved, non-draft version for production" >&2
      exit 1
    fi
  done
fi

case "$MODE" in
  --validate-only)
    echo "validated canister environment for $CANISTER@$ENVIRONMENT"
    exit 0
    ;;
  --sync|--disable-batch)
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 1
    ;;
esac

set_env FACILITATOR_EVM_PRIVATE_KEY "$FACILITATOR_EVM_PRIVATE_KEY"
if [[ "$batch_claim_schedule_count" == "8" ]]; then
  runtime_schedule="opt record {
    claim_1_fee_amount = \"$(candid_text "$BATCH_CLAIM_1_FEE_AMOUNT")\";
    claim_10_fee_amount = \"$(candid_text "$BATCH_CLAIM_10_FEE_AMOUNT")\";
    claim_50_fee_amount = \"$(candid_text "$BATCH_CLAIM_50_FEE_AMOUNT")\";
    claim_100_fee_amount = \"$(candid_text "$BATCH_CLAIM_100_FEE_AMOUNT")\";
    refund_with_claim_1_fee_amount = \"$(candid_text "$BATCH_REFUND_WITH_CLAIM_1_FEE_AMOUNT")\";
    refund_with_claim_10_fee_amount = \"$(candid_text "$BATCH_REFUND_WITH_CLAIM_10_FEE_AMOUNT")\";
    refund_with_claim_50_fee_amount = \"$(candid_text "$BATCH_REFUND_WITH_CLAIM_50_FEE_AMOUNT")\";
    refund_with_claim_100_fee_amount = \"$(candid_text "$BATCH_REFUND_WITH_CLAIM_100_FEE_AMOUNT")\";
  }"
else
  runtime_schedule="null"
fi
set_runtime_configuration \
  "$RESOLVED_NETWORK_PROFILE" \
  "$RESOLVED_NETWORK_TOKEN" \
  "${BATCH_SETTLEMENT_CONTRACT:-$CANONICAL_BATCH_SETTLEMENT_CONTRACT}" \
  "$SELLER_SETTLEMENT_FEE_AMOUNT" \
  "$RESOLVED_BATCH_DEPOSIT_FEE_AMOUNT" \
  "$RESOLVED_BATCH_CLAIM_FEE_AMOUNT" \
  "$RESOLVED_BATCH_SETTLE_FEE_AMOUNT" \
  "$RESOLVED_BATCH_REFUND_FEE_AMOUNT" \
  "$runtime_schedule" \
  "${SELLER_TERMS_VERSION:-2026-07-13-draft}" \
  "${PRIVACY_VERSION:-2026-07-13-draft}" \
  "${ASSET_BOUNDARY_VERSION:-2026-07-13-draft}"
if [[ "$RESOLVED_NETWORK_PROFILE" == "amoy" && -n "${BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY:-}" ]]; then
  set_env AMOY_BATCH_CONTRACT_CODE_VERIFIED "1"
elif [[ "$MODE" == "--disable-batch" ]]; then
  set_env AMOY_BATCH_CONTRACT_CODE_VERIFIED ""
fi
set_env JPYC_EIP712_VERSION "$JPYC_EIP712_VERSION"
set_env POLYGON_RPC_URL "$POLYGON_RPC_URL"
set_env FACILITATOR_PUBLIC_ORIGIN "$FACILITATOR_PUBLIC_ORIGIN"
set_env SELLER_CREDIT_PAY_TO "$SELLER_CREDIT_PAY_TO"
set_env FACILITATOR_MAX_GAS "$RESOLVED_FACILITATOR_MAX_GAS"
set_env FACILITATOR_MAX_SETTLEMENT_FEE_WEI "$RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI"
set_env SETTLE_CONFIRMATION_TIMEOUT_SECONDS "$RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS"
set_env SETTLE_MIN_CONFIRMATIONS "$RESOLVED_SETTLE_MIN_CONFIRMATIONS"
set_env SETTLEMENT_CACHE_TTL_SECONDS "$RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS"
if [[ -n "${BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY:-}" ]]; then
  set_env BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY "$BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"
  set_env BATCH_WITHDRAW_DELAY_SECONDS "$RESOLVED_BATCH_WITHDRAW_DELAY_SECONDS"
elif [[ "$MODE" == "--disable-batch" ]]; then
  set_env BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY ""
fi
echo "synchronized canister environment for $CANISTER@$ENVIRONMENT"
