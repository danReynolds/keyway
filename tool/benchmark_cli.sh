#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${KEYWAY_BENCHMARK:-}" != "1" ]]; then
  echo "Set KEYWAY_BENCHMARK=1 and run on a disposable release test account." >&2
  exit 2
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/keyway-cli-bench.XXXXXX")"
app_id="${KEYWAY_BENCHMARK_APP_ID:-keyway-cli-benchmark-${GITHUB_RUN_ID:-$$}}"
cleanup() {
  rm -rf "$tmp"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    rm -rf "$HOME/Library/Application Support/$app_id"
    security delete-generic-password -s "$app_id" -a store-key \
      >/dev/null 2>&1 || true
  else
    rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/$app_id"
    secret-tool clear -- service "$app_id" account store-key \
      >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

dart compile exe packages/keyway_cli/tool/integration_harness.dart \
  -o "$tmp/keyway-benchmark"

iterations="${KEYWAY_BENCHMARK_ITERATIONS:-50}"
one="$tmp/one.env"
ten="$tmp/ten.env"
python="python3"
if [[ "$(uname -s)" == "Darwin" ]]; then
  python="/usr/bin/python3"
fi

for index in $(seq 1 10); do
  key="benchmark/key-$index"
  printf 'benchmark-value-%s' "$index" | \
    "$tmp/keyway-benchmark" "$app_id" set --stdin "$key"
  printf 'KEY_%s=kw://%s\n' "$index" "$key" >>"$ten"
  if [[ $index -eq 1 ]]; then
    printf 'KEY_1=kw://%s\n' "$key" >"$one"
  fi
done

one_result="$("$python" tool/benchmark_cli.py \
  "$tmp/keyway-benchmark" "$app_id" "$one" "$iterations")"
ten_result="$("$python" tool/benchmark_cli.py \
  "$tmp/keyway-benchmark" "$app_id" "$ten" "$iterations")"
printf 'one reference: %s\n' "$one_result"
printf 'ten references: %s\n' "$ten_result"

if [[ -n "${KEYWAY_BENCHMARK_OUTPUT:-}" ]]; then
  mkdir -p "$(dirname "$KEYWAY_BENCHMARK_OUTPUT")"
  printf '{"one_reference":%s,"ten_references":%s}\n' \
    "$one_result" \
    "$ten_result" > "$KEYWAY_BENCHMARK_OUTPUT"
fi

for index in $(seq 1 10); do
  "$tmp/keyway-benchmark" "$app_id" rm "benchmark/key-$index"
done
