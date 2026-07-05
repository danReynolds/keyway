# Changelog

## 0.1.0 (unreleased)

Initial implementation (RFC 0005). Not yet published.

- Core API: `SecretStorage` (bytes-first async KV) + `SecretBackend` seam with
  honest `capabilities`.
- `EncryptedFileBackend`: XChaCha20-Poly1305 authenticated container, HKDF-SHA256
  key derivation, binary TLV payload, atomic 0600-from-birth writes.
- macOS `KeychainBackend` (direct `SecItem` FFI) and Linux `SecretServiceBackend`
  (`secret-tool`). *(in progress)*
