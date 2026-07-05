# secret_store

Platform-keystore secret storage for Dart **without Flutter**. macOS Keychain and
Linux Secret Service backends, plus an authenticated encrypted-file container,
behind one small async API.

> Status: pre-1.0, in active development. Not yet published. Design and full
> threat-model derivation live in the RFC (`dune_cli/doc/rfcs/0005`).

## Why

The community answer to "secure storage in Dart" is `flutter_secure_storage` — a
Flutter plugin, unusable from a CLI or server. Python/Go/Rust all have a `keyring`
library; Dart did not. `secret_store` fills that gap: pure Dart + FFI, no platform
channels, so it runs in CLIs, servers, and Flutter apps alike.

## Threat model

**Protects against:** plaintext key material on disk (backup / Time-Machine /
dotfile-sync leaks); offline disk theft without full-disk encryption; other local
users; casual disclosure (scrollback, `ps` argv).

**Does not protect against:** same-user malware while the keystore is unlocked;
process-memory disclosure, including swap and crash/core dumps (Dart cannot zero
buffers); rollback to an older genuine container; timing side-channels in pure-Dart
crypto (there is no remote oracle); root. There is **no key escrow** — losing the
keystore item loses the store; recovery, if needed, belongs a layer up.

The bar is ssh-agent / aws-vault, not an HSM.

## Cryptography

XChaCha20-Poly1305 (AEAD) container, HKDF-SHA256 key derivation, `Random.secure()`
only — all via `package:cryptography`, exercised against RFC 8439 / RFC 5869 /
Wycheproof vectors in this package's own test suite so a buggy or compromised
dependency update cannot pass silently.

## License

MIT.
