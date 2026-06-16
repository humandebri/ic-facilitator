#!/usr/bin/env bash
# scripts/set_canister_env.sh: Rust facilitator canister に runtime env を注入する。
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ENVIRONMENT="${1:-local}"
readonly CANISTER="${2:-edge}"
readonly DEFAULT_FACILITATOR_MAX_GAS="500000"
readonly DEFAULT_FACILITATOR_MAX_SETTLEMENT_FEE_WEI="30000000000000000"
readonly DEFAULT_SETTLE_CONFIRMATION_TIMEOUT_SECONDS="60"
readonly DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS="86400"
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

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "$name must be a positive integer" >&2
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

require_single_https_rpc_url() {
  local name="$1"
  local value="$2"
  if [[ "$value" == *","* ]]; then
    echo "$name must contain exactly one HTTPS RPC URL" >&2
    exit 1
  fi
  if [[ ! "$value" =~ ^https://[^[:space:]]+$ ]]; then
    echo "$name must be an HTTPS RPC URL" >&2
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
required_env SELLER_CREDIT_PAY_TO
required_env SELLER_CREDIT_TOPUP_AMOUNT
required_env SELLER_SETTLEMENT_FEE_AMOUNT
require_private_key FACILITATOR_EVM_PRIVATE_KEY "$FACILITATOR_EVM_PRIVATE_KEY"
require_single_https_rpc_url POLYGON_RPC_SERVICES "$POLYGON_RPC_SERVICES"
require_nonzero_evm_address SELLER_CREDIT_PAY_TO "$SELLER_CREDIT_PAY_TO"
require_positive_integer SELLER_CREDIT_TOPUP_AMOUNT "$SELLER_CREDIT_TOPUP_AMOUNT"
require_positive_integer SELLER_SETTLEMENT_FEE_AMOUNT "$SELLER_SETTLEMENT_FEE_AMOUNT"
readonly RESOLVED_FACILITATOR_MAX_GAS="${FACILITATOR_MAX_GAS:-$DEFAULT_FACILITATOR_MAX_GAS}"
readonly RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI="${FACILITATOR_MAX_SETTLEMENT_FEE_WEI:-$DEFAULT_FACILITATOR_MAX_SETTLEMENT_FEE_WEI}"
readonly RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS="${SETTLE_CONFIRMATION_TIMEOUT_SECONDS:-$DEFAULT_SETTLE_CONFIRMATION_TIMEOUT_SECONDS}"
readonly RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS="${SETTLEMENT_CACHE_TTL_SECONDS:-$DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS}"
require_positive_integer FACILITATOR_MAX_GAS "$RESOLVED_FACILITATOR_MAX_GAS"
require_positive_integer FACILITATOR_MAX_SETTLEMENT_FEE_WEI "$RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI"
require_positive_integer SETTLE_CONFIRMATION_TIMEOUT_SECONDS "$RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS"
require_positive_integer SETTLEMENT_CACHE_TTL_SECONDS "$RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS"

set_env FACILITATOR_EVM_PRIVATE_KEY "$FACILITATOR_EVM_PRIVATE_KEY"
set_env JPYC_EIP712_VERSION "$JPYC_EIP712_VERSION"
set_env POLYGON_RPC_SERVICES "$POLYGON_RPC_SERVICES"
set_env SELLER_CREDIT_PAY_TO "$SELLER_CREDIT_PAY_TO"
set_env SELLER_CREDIT_TOPUP_AMOUNT "$SELLER_CREDIT_TOPUP_AMOUNT"
set_env SELLER_SETTLEMENT_FEE_AMOUNT "$SELLER_SETTLEMENT_FEE_AMOUNT"
set_env FACILITATOR_MAX_GAS "$RESOLVED_FACILITATOR_MAX_GAS"
set_env FACILITATOR_MAX_SETTLEMENT_FEE_WEI "$RESOLVED_FACILITATOR_MAX_SETTLEMENT_FEE_WEI"
set_env SETTLE_CONFIRMATION_TIMEOUT_SECONDS "$RESOLVED_SETTLE_CONFIRMATION_TIMEOUT_SECONDS"
set_env SETTLEMENT_CACHE_TTL_SECONDS "$RESOLVED_SETTLEMENT_CACHE_TTL_SECONDS"
