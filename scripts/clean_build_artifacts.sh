#!/usr/bin/env bash
# scripts/clean_build_artifacts.sh: local IC を止めずに巨大な生成 build artifact だけを削除する。
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CONFIRM="${1:-}"
readonly TARGETS=(
  "target"
  "dist"
)

cd "$ROOT"

if [[ "$CONFIRM" != "--yes" ]]; then
  printf 'dry-run: would remove generated build artifacts:\n'
  printf '  %s\n' "${TARGETS[@]}"
  printf 'run scripts/clean_build_artifacts.sh --yes to apply\n'
  exit 1
fi

for target in "${TARGETS[@]}"; do
  case "$target" in
    target|dist) rm -rf -- "$target" ;;
    *) echo "refusing unsafe target: $target" >&2; exit 1 ;;
  esac
done
