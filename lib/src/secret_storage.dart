/// The front API (RFC 0005 §4): a bytes-first async key-value store over a
/// [SecretBackend]. Platform options live on backend constructors; these verbs
/// take only key/value.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'backend.dart';
import 'backends/keystore_backend.dart';
import 'errors.dart';
import 'ffi/keychain.dart';
import 'ffi/keystore_api.dart';
import 'ffi/secret_service.dart';
import 'identifiers.dart';

/// Returns the platform's OS keystore binding — `MacKeychainApi` on macOS,
/// `SecretToolApi` on Linux. Throws [KeystoreUnreachable] elsewhere (fail-closed
/// — no silent fallback to weaker storage). Used to build a keystore-wrapped
/// container (model B) as well as by [SecretStorage.new].
KeystoreApi platformKeystore() {
  if (Platform.isMacOS) return MacKeychainApi();
  if (Platform.isLinux) return SecretToolApi();
  throw KeystoreUnreachable(
      'no OS keystore backend for ${Platform.operatingSystem}');
}

/// Stores named byte secrets in a [SecretBackend].
///
/// The default constructor resolves the platform keystore and stores each
/// secret as its own item (model A — the `flutter_secure_storage` shape). For
/// the wrapped-key container (model B), compose explicitly with
/// [SecretStorage.withBackend].
final class SecretStorage {
  SecretStorage.withBackend(this.backend);

  /// Resolves the platform OS keystore (fail-closed off macOS/Linux) and stores
  /// each secret as its own item under [service].
  factory SecretStorage({required String service}) {
    validateIdentifier(service, 'service');
    return SecretStorage.withBackend(
        KeystoreBackend(service: service, api: platformKeystore()));
  }

  /// The underlying backend. Read [SecretBackend.capabilities] to branch on
  /// optional operations, or `await backend.describe()` for a health snapshot.
  final SecretBackend backend;

  /// Reads the raw bytes for [key], or null if absent.
  Future<Uint8List?> read(String key) {
    validateIdentifier(key, 'key');
    return backend.read(key);
  }

  /// Reads [key] as a UTF-8 string, or null if absent.
  Future<String?> readString(String key) async {
    final bytes = await read(key);
    return bytes == null ? null : utf8.decode(bytes);
  }

  /// Whether [key] exists.
  Future<bool> containsKey(String key) {
    validateIdentifier(key, 'key');
    return backend.contains(key);
  }

  /// Stores [value] under [key], replacing any existing value. [label] is
  /// optional non-secret metadata shown in keystore UIs.
  Future<void> write(String key, Uint8List value, {String? label}) {
    validateIdentifier(key, 'key');
    validateLabel(label);
    return backend.write(key, value, label: label);
  }

  /// Stores [value] (encoded UTF-8) under [key].
  Future<void> writeString(String key, String value, {String? label}) =>
      write(key, Uint8List.fromList(utf8.encode(value)), label: label);

  /// Removes [key]. Idempotent.
  Future<void> delete(String key) {
    validateIdentifier(key, 'key');
    return backend.delete(key);
  }

  /// All entries. Throws [UnsupportedCapability] when the backend cannot
  /// enumerate (guard with `backend.capabilities.enumeration`). `async` so the
  /// capability failure surfaces as a rejected future, not a synchronous throw.
  Future<Map<String, Uint8List>> readAll() async {
    if (!backend.capabilities.enumeration) {
      throw const UnsupportedCapability('enumeration');
    }
    return backend.readAll();
  }

  /// Removes every entry. Requires enumeration.
  Future<void> deleteAll() async {
    final all = await readAll();
    for (final key in all.keys) {
      await backend.delete(key);
    }
  }
}
