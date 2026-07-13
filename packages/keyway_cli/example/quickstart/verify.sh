#!/bin/sh
set -eu

if [ "${API_URL:-}" != "https://staging.example.com" ]; then
  echo "unexpected API_URL" >&2
  exit 1
fi

if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "OPENAI_API_KEY was not injected" >&2
  exit 1
fi

echo "Keyway quickstart passed."
