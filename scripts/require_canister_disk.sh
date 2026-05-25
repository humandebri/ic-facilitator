#!/usr/bin/env bash
# scripts/require_canister_disk.sh: canister build/upload 前に最低限の空き容量を確認する。
set -euo pipefail

readonly TARGET_PATH="${1:-.}"
readonly MIN_KIB="${MIN_CANISTER_DISK_KIB:-2097152}"

available_kib() {
  df -Pk "$TARGET_PATH" | awk 'NR == 2 { print $4 }'
}

readonly AVAILABLE="$(available_kib)"

if [[ ! "$AVAILABLE" =~ ^[0-9]+$ ]]; then
  echo "disk-space check failed: df output could not be parsed" >&2
  exit 1
fi

if (( AVAILABLE < MIN_KIB )); then
  echo "disk-space check failed: $((AVAILABLE / 1024)) MiB available; need at least $((MIN_KIB / 1024)) MiB" >&2
  exit 1
fi
