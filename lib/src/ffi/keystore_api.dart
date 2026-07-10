/// The OS-keystore seam (see doc/design.md): a narrow (service, account) → bytes
/// interface implemented by `AppleKeychainApi` (macOS, SecItem FFI) and
/// `SecretToolApi` (Linux, Secret Service), and by fakes in tests.
library;

import 'dart:typed_data';

/// Result of a keystore reachability probe.
final class KeystoreProbe {
  const KeystoreProbe({
    required this.available,
    required this.locked,
    this.detail,
  });

  /// Whether the keystore can be reached at all.
  final bool available;

  /// Whether it is locked / needs interaction that can't be satisfied.
  final bool locked;

  final String? detail;
}

/// Storage of named byte secrets keyed by (service, account).
///
/// Async because a keystore is an IO boundary: the macOS binding resolves
/// immediately (synchronous FFI wrapped in a future), while the Linux binding
/// spawns `secret-tool` (real IO, with a timeout).
abstract interface class KeystoreApi {
  /// The value for (service, account), or null if not found.
  Future<Uint8List?> get(String service, String account);

  /// Adds or replaces (service, account) = value, with an optional label.
  Future<void> set(String service, String account, Uint8List value,
      {String? label});

  /// Deletes (service, account). Idempotent (missing is not an error).
  Future<void> delete(String service, String account);

  /// Every (account → value) under [service].
  Future<Map<String, Uint8List>> getAll(String service);

  /// Whether [service] is reachable and unlocked (best effort).
  Future<KeystoreProbe> probe(String service);
}
