# Changelog

## 0.1.0 (unreleased)

Initial implementation (RFC 0005). Not yet published.

- **Front API** — `SecretStorage`: bytes-first async key/value with String
  conveniences, identifier/label validation, capability-guarded enumeration.
  Default `SecretStorage(service:)` resolves the platform keystore (fail-closed
  off macOS/Linux).
- **Backends** (`SecretBackend` seam, honest `capabilities`):
  - `KeystoreBackend` — direct OS-keystore items (model A). macOS via
    `MacKeychainApi` (direct `SecItem` FFI, validated against the real login
    Keychain); Linux via `SecretToolApi` (`secret-tool`, stdin transport, hard
    timeout, output scrubbing).
  - `EncryptedFileBackend` — XChaCha20-Poly1305 authenticated container with
    HKDF-SHA256 key derivation, binary TLV payload, profile-bound AAD, atomic
    0600-from-birth writes; the full §7 failure matrix as distinct typed errors.
- **Key sources**: `KeystoreKeySource` (model B — key in the OS keystore,
  container encrypted on disk; dune's default), `FileKeySource` (explicit
  insecure fallback), `InMemoryKeySource`.
- **Security**: `Random.secure()` only; RFC 8439 / RFC 5869 / vendored vectors
  run against the pinned `cryptography`; one third-party runtime dependency,
  enforced by a dependency-closure test.
