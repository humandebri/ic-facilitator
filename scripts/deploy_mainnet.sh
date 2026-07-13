#!/usr/bin/env bash
# Production deployment remains disabled until a separately reviewed transition release exists.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"
REQUIRE_PRODUCTION_FEES=1 scripts/set_canister_env.sh ic edge --validate-only
echo "mainnet deployment is intentionally disabled for this MVP; existing canisters require a transition release and fresh production launch is out of scope" >&2
exit 1
