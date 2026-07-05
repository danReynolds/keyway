/// Typed error taxonomy (RFC 0005 §5, §7 failure matrix).
///
/// Every error carries a stable [code] and, where relevant, the *name* of the
/// secret involved — **never a secret value**, and never raw subprocess output.
/// Names are non-secret (they appear in keystore UIs); values never leave the
/// container, the OS keystore, or process memory.
library;

/// Base type for every error this library throws deliberately.
///
/// Sealed so a consumer can exhaustively `switch` on the failure kinds that
/// feed a diagnostics UI (e.g. dune's `doctor`).
sealed class SecretStoreException implements Exception {
  const SecretStoreException(this.code, this.message);

  /// Stable, machine-branchable identifier. Never localized.
  final String code;

  /// Human-readable detail. Contains no secret values.
  final String message;

  @override
  String toString() => '$runtimeType($code): $message';
}

/// The store key exists but the container file is gone (e.g. deleted, or the
/// store dir was partially restored). Recoverable if the file is restored.
final class ContainerMissing extends SecretStoreException {
  const ContainerMissing(this.path)
      : super('container_missing', 'Container file is absent: $path');
  final String path;
}

/// The container file exists but its store key is gone from the keystore
/// (keychain item deleted, keyring reset). **Unrecoverable without a backup of
/// the key** — the ciphertext can no longer be opened.
final class StoreKeyMissing extends SecretStoreException {
  const StoreKeyMissing()
      : super(
            'store_key_missing',
            'Container exists but its store key is absent from the keystore; '
                'the data cannot be decrypted without a backup of the key.');
}

/// Decryption failed authentication: wrong key, tampering, or a container from
/// a different profile (the AAD binds profile identity). The data is not
/// returned — a failed tag never yields partial or empty plaintext.
final class AuthenticationFailed extends SecretStoreException {
  const AuthenticationFailed()
      : super(
            'authentication_failed',
            'Container failed authentication (wrong key, tamper, or a '
                'container from a different profile).');
}

/// The container bytes are structurally malformed (bad magic/version, or a
/// length field that overruns the buffer). Distinct from
/// [AuthenticationFailed]: this is caught *before* or independent of the AEAD
/// tag, on obviously-not-our-format input.
final class ContainerCorrupt extends SecretStoreException {
  const ContainerCorrupt(String detail)
      : super('container_corrupt', 'Container is malformed: $detail');
}

/// The OS keystore is present but locked / requires user interaction that
/// cannot be satisfied (e.g. a headless SSH session). Retryable once unlocked.
final class KeystoreLocked extends SecretStoreException {
  const KeystoreLocked([String? detail])
      : super('keystore_locked',
            detail ?? 'The OS keystore is locked or requires interaction.');
}

/// No usable keystore provider (no Secret Service, tool missing, or a call
/// timed out). Distinct from [KeystoreLocked]: the store isn't reachable at all.
final class KeystoreUnreachable extends SecretStoreException {
  const KeystoreUnreachable([String? detail])
      : super('keystore_unreachable',
            detail ?? 'No usable OS keystore provider is available.');
}

/// A low-level keystore operation failed in a way that isn't one of the
/// modeled states. Carries a backend-specific [status] (e.g. an `OSStatus`)
/// for diagnostics — never any secret material.
final class KeystoreOperationFailed extends SecretStoreException {
  const KeystoreOperationFailed(String detail, {this.status})
      : super('keystore_operation_failed', detail);
  final int? status;
}

/// The backend does not support the requested capability (e.g. enumeration on
/// the macOS direct-items backend). Guard with `backend.capabilities` first.
final class UnsupportedCapability extends SecretStoreException {
  const UnsupportedCapability(String capability)
      : super('unsupported_capability', 'This backend does not support: $capability');
}
