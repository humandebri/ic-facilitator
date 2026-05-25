#!/usr/bin/env bash
# scripts/build_facilitator_canister.sh: Rust facilitator canister wasm を生成する。
set -euo pipefail

OUTPUT="${1:?usage: scripts/build_facilitator_canister.sh <output-wasm>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"
scripts/require_canister_disk.sh "$ROOT"
mkdir -p "$(dirname "$OUTPUT")" dist
cargo build -p jpyc_x402_facilitator --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/jpyc_x402_facilitator.wasm "$OUTPUT"

