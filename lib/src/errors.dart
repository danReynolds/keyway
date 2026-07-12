/// Typed error taxonomy (see doc/design.md).
///
/// Every error carries a stable [code] and, where relevant, the *name* of the
/// secret involved — **never a secret value**, and never raw subprocess output.
/// Names are non-secret (they appear in keystore UIs); values never leave the
/// container, the OS keystore, or process memory.
library;

import 'backend.dart' show StorageScheme;

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

/// The container file exists but the keystore did not return its store key.
///
/// If the keystore is unlocked and reachable, this is the deleted-key state
/// (keychain item removed, keyring reset) and is **unrecoverable without a
/// backup of the key** — the ciphertext can no longer be opened. But some
/// backends cannot tell a *locked or unreachable* keyring apart from a deleted
/// item: the Linux Secret Service in particular reports "not found" for a
/// locked collection that fails without a prompter, so a merely-locked keyring
/// surfaces here too. Before treating the key as lost, confirm the keystore is
/// unlocked and reachable and retry.
final class StoreKeyMissing extends SecretStoreException {
  const StoreKeyMissing()
      : super(
            'store_key_missing',
            'Container exists but its store key was not returned by the '
                'keystore. If the keystore is unlocked and reachable, the key '
                'is gone and the data cannot be decrypted without a backup; '
                'otherwise unlock the keystore and retry (a locked or '
                'unreachable keyring can present the same way on some '
                'backends).');
}

/// The store key does not match this container: the header's key-commitment
/// value disagrees with the one derived from the supplied key. The key is
/// wrong, or the container was sealed under a different key (or, on a store
/// configured with a caller context, a different context). Detected in
/// constant time *before* decryption, so it is reliably distinguishable from
/// tampering ([AuthenticationFailed]). One caveat: a tampered or corrupted
/// commitment field in the container header also surfaces here — by
/// construction it is indistinguishable from a wrong key.
final class WrongStoreKey extends SecretStoreException {
  const WrongStoreKey()
      : super(
            'wrong_store_key',
            'The store key or context does not match this container (key '
                'commitment check failed).');
}

/// Decryption failed authentication under a key that passed the commitment
/// check: the ciphertext or authenticated header was modified after sealing —
/// tamper or corruption. (A wrong key or context surfaces as [WrongStoreKey]
/// before decryption is attempted.) The data is not returned — a failed tag
/// never yields partial or empty plaintext.
final class AuthenticationFailed extends SecretStoreException {
  const AuthenticationFailed()
      : super(
            'authentication_failed',
            'Container failed AEAD authentication under a matching key: the '
                'ciphertext or header was modified after sealing.');
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

/// A filesystem operation on the store failed, or refused to proceed because a
/// path did not meet the security invariants (e.g. a group/other-accessible
/// container or store directory — the OpenSSH stance). Part of the typed
/// taxonomy so a diagnostics UI classifies it rather than seeing an untyped
/// crash. Carries the [operation], the non-secret [path], and the OS [errno]
/// (0 when the failure is a policy rejection rather than a syscall error).
final class SecureFileError extends SecretStoreException {
  SecureFileError(this.operation, this.path, this.errno)
      : super('file_error', '$operation "$path": errno $errno');
  final String operation;
  final String path;
  final int errno;
}

/// The hardware-held key that wraps the store key exists on record but can no
/// longer be used: the wrapped-key blob is present while the keystore key is
/// gone or fails to unwrap it (Android Keystore key evicted by the OS/OEM,
/// data restored onto a different device — hardware keys never leave the
/// original — or a corrupted blob). The store cannot be decrypted; this is
/// surfaced loudly rather than silently starting an empty store. Recovery is
/// re-provisioning: delete the store's data directory and write the secrets
/// again.
final class KeyInvalidated extends SecretStoreException {
  const KeyInvalidated([String? detail])
      : super(
            'key_invalidated',
            detail ??
                'The hardware key wrapping this store\'s key is no longer '
                    'usable; the store cannot be decrypted.');
}

/// The backend does not support the requested capability (e.g. enumeration on
/// a backend that cannot list its items). Guard with `backend.capabilities`
/// first.
final class UnsupportedCapability extends SecretStoreException {
  const UnsupportedCapability(String capability)
      : super('unsupported_capability',
            'This backend does not support: $capability');
}

/// The store for this `appId` was provisioned under a **different scheme** than
/// the one that now resolves, so silently using the current scheme would hide
/// the existing secrets (an empty-looking store) or, worse, resurface stale
/// values from an abandoned store. On macOS this happens when an app *gains*
/// the Keychain Sharing entitlement between versions (encrypted file → Data
/// Protection keychain). Only that direction can throw: a *lost* entitlement
/// is undetectable from the now-unentitled process, which cannot see the
/// abandoned keychain items (see doc/platforms/macos.md). Rather than switch
/// stores silently, the library throws this so the transition is a
/// deliberate decision. Resolve it by migrating the secrets across and then
/// removing the abandoned store — for a gained entitlement, the old encrypted
/// file (`~/Library/Application Support/<appId>/secrets.enc`) — to proceed
/// under the new scheme.
final class MigrationRequired extends SecretStoreException {
  MigrationRequired({required this.appId, required this.from, required this.to})
      : super(
            'migration_required',
            'store for "$appId" holds data under the ${from.name} scheme but '
                '${to.name} now resolves; refusing to switch stores silently');

  /// The app id whose store scheme changed.
  final String appId;

  /// The scheme the existing data was written under.
  final StorageScheme from;

  /// The scheme that resolves now.
  final StorageScheme to;
}

/// A write was rejected because the whole sealed store would exceed the
/// container size cap. Raised **before** the existing container is touched, so
/// the prior contents remain intact and readable — an oversized value can
/// never brick the store. Split large blobs, or store a reference instead of
/// the payload.
final class StoreTooLarge extends SecretStoreException {
  StoreTooLarge(this.sealedBytes, this.maxBytes)
      : super('store_too_large',
            'sealed store is $sealedBytes bytes, over the $maxBytes-byte cap');
  final int sealedBytes;
  final int maxBytes;
}
