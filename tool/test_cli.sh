#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

tmp="$(mktemp -d "${TMPDIR:-/tmp}/keyway-cli-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

dart compile exe packages/keyway_cli/bin/keyway.dart -o "$tmp/keyway"
dart compile exe packages/keyway_cli/tool/prompt_harness.dart \
  -o "$tmp/prompt_harness"
python3 tool/test_cli_exec.py "$tmp/keyway"
python3 tool/test_cli_pty.py "$tmp/prompt_harness"
python3 tool/test_homebrew_formula.py
./tool/test_cli_dart_install.sh
