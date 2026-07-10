#!/usr/bin/env bash
# Run the Linux integration tier locally on ANY machine with Docker (e.g. a
# macOS dev box) — the same tier CI runs: the Secret Service backend against a
# real gnome-keyring under a throwaway D-Bus session. Verified in-repo.
#
#   ./tool/test_linux.sh
#
# The repo is mounted read-only and copied inside the container, so the host's
# .dart_tool is never rewritten with container paths.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec docker run --rm -i -v "$REPO":/src:ro dart:stable bash -s <<'INNER'
set -euo pipefail
apt-get update -qq
apt-get install -y -qq libsecret-tools gnome-keyring dbus >/dev/null
cp -r /src /build && cd /build
dart pub get >/dev/null

# Secret Service via secret-tool, under a throwaway D-Bus session + keyring.
# ~/.local/share exists on any real desktop session (the only place a keyring
# is unlocked); a bare container lacks it, so create the fixture the desktop
# guarantees — the library itself deliberately refuses to create intermediate
# parent dirs with unknown modes.
mkdir -p "$HOME/.local/share"
dbus-run-session -- bash -c '
  eval "$(printf itest | gnome-keyring-daemon --daemonize --unlock --components=secrets)"
  export GNOME_KEYRING_CONTROL
  SECRET_STORE_INTEGRATION=1 dart test test/secret_service_integration_test.dart
'
INNER
