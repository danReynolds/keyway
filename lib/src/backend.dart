/// The backend seam (RFC 0005 §5).
///
/// A [SecretBackend] is bound to a single service at construction; its methods
/// take only a key. Adding a platform is one implementation + one line of
/// default resolution. Capabilities are reported honestly — the macOS
/// direct-items backend genuinely cannot enumerate, and says so.
library;

import 'dart:typed_data';

/// What a backend can and cannot do. Guard optional operations on these rather
/// than catching an [UnsupportedCapability] after the fact.
final class BackendCapabilities {
  const BackendCapabilities({
    required this.enumeration,
    required this.persistent,
  });

  /// Whether [SecretBackend.readAll] is supported.
  final bool enumeration;

  /// Whether secrets survive process exit (false only for in-memory backends).
  final bool persistent;
}

/// A point-in-time health snapshot for diagnostics UIs.
final class BackendInfo {
  const BackendInfo({
    required this.name,
    required this.available,
    required this.locked,
    required this.capabilities,
    this.detail,
  });

  /// Backing mechanism, e.g. `keychain`, `secret-service`, `encrypted-file`.
  final String name;

  /// Whether the backend can be reached at all.
  final bool available;

  /// Whether it is locked / needs interaction that can't be satisfied.
  final bool locked;

  final BackendCapabilities capabilities;

  /// Free-form extra detail (e.g. a path or provider name). Never a secret.
  final String? detail;
}

/// Storage of named byte secrets for one service.
abstract interface class SecretBackend {
  /// Static description of what this backend supports.
  BackendCapabilities get capabilities;

  /// The value for [key], or null if absent.
  Future<Uint8List?> read(String key);

  /// Whether [key] exists, without materializing its value where the backend
  /// can avoid it.
  Future<bool> contains(String key);

  /// Stores [value] under [key], replacing any existing value. [label] is
  /// optional non-secret metadata for keystore UIs.
  Future<void> write(String key, Uint8List value, {String? label});

  /// Removes [key]. Idempotent.
  Future<void> delete(String key);

  /// All entries. Throws [UnsupportedCapability] when
  /// [BackendCapabilities.enumeration] is false.
  Future<Map<String, Uint8List>> readAll();

  /// Health snapshot for diagnostics.
  Future<BackendInfo> describe();
}
