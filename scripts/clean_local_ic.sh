#!/usr/bin/env bash
# scripts/clean_local_ic.sh: local IC の再検証を阻害する生成 cache だけを削除する。
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CONFIRM="${1:-}"
readonly TARGETS=(
  ".icp/cache/networks/local"
)

cd "$ROOT"

if [[ "$CONFIRM" != "--yes" ]]; then
  printf 'dry-run: would stop local network and remove:\n'
  printf '  %s\n' "${TARGETS[@]}"
  printf 'run scripts/clean_local_ic.sh --yes to apply\n'
  exit 1
fi

icp network stop >/dev/null 2>&1 || true

for target in "${TARGETS[@]}"; do
  case "$target" in
    .icp/cache/*) rm -rf -- "$target" ;;
    *) echo "refusing unsafe target: $target" >&2; exit 1 ;;
  esac
done
