#!/usr/bin/env bash
# Verify the frozen code-identity contract. Strict mode is the release gate;
# KEYWAY_ALLOW_ADHOC=1 exists only so the structural checks can run locally.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 KEYWAY_BINARY" >&2
  exit 2
fi

binary="$1"
details="$(codesign -dvvv "$binary" 2>&1)"

codesign --verify --strict --verbose=2 "$binary"
[[ "$details" == *$'\nIdentifier=dev.keyway.cli\n'* ]]
[[ "$details" == *"runtime"* ]]

entitlements="$(mktemp "${TMPDIR:-/tmp}/keyway-entitlements.XXXXXX")"
trap 'rm -f "$entitlements"' EXIT
codesign -d --entitlements - "$binary" >"$entitlements" 2>/dev/null
if [[ -s "$entitlements" ]]; then
  echo "release binary unexpectedly carries entitlements" >&2
  cat "$entitlements" >&2
  exit 1
fi

if [[ "${KEYWAY_ALLOW_ADHOC:-}" != "1" ]]; then
  [[ "$details" == *$'\nAuthority=Developer ID Application:'* ]]
  [[ "$details" == *$'\nTimestamp='* ]]
  team="$(printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p')"
  [[ -n "$team" && "$team" != "not set" ]]

  requirement="$(codesign -d -r- "$binary" 2>&1)"
  [[ "$requirement" == *'identifier "dev.keyway.cli"'* ]]
  [[ "$requirement" == *"anchor apple generic"* ]]
  [[ "$requirement" == *"certificate leaf[subject.OU] = \"$team\""* ]]
fi

echo "macOS release identity passed"
