#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 ARCHIVE.tar.gz EXPECTED_VERSION" >&2
  exit 2
fi

archive="$1"
version="$2"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/keyway-cli-verify.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

tar -xzf "$archive" -C "$tmp"
expected=$'LICENSE\nREADME.md\nkeyway'
actual="$(find "$tmp" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | sort)"
if [[ "$actual" != "$expected" ]]; then
  echo "unexpected release archive contents:" >&2
  printf '%s\n' "$actual" >&2
  exit 1
fi

[[ -x "$tmp/keyway" ]]
[[ "$("$tmp/keyway" --version)" == "keyway $version" ]]

help="$("$tmp/keyway" --help)"
for command in run set rm list doctor; do
  [[ "$help" == *"  $command"* ]]
done
[[ "$(printf '%s\n' "$help" | wc -l | tr -d ' ')" -le 24 ]]

echo "CLI release archive passed"
