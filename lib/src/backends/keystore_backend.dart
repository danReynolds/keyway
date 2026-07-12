/// Direct OS-keystore backend (see doc/design.md): each secret is its own
/// keystore item. Thin over the [KeystoreApi] seam. The resolver selects it
/// where a hardware store holds arbitrary secrets per item — the Apple Data
/// Protection keychain (`AppleKeychainApi.dataProtection()`), on iOS
/// unconditionally and on entitled macOS apps.
library;

import 'dart:typed_data';

import '../ffi/keystore_api.dart';
import '../backend.dart';

final class KeystoreBackend implements SecretBackend {
  KeystoreBackend({
    required this.service,
    required KeystoreApi api,
    this.level = SecurityLevel.loginBound,
  }) : _api = api;

  /// The service all this backend's items share.
  final String service;
  final KeystoreApi _api;

  /// Offline-protection level of the underlying keystore, set by the resolver
  /// (login keychain → [SecurityLevel.loginBound]; Data Protection keychain →
  /// [SecurityLevel.hardwareBacked]).
  final SecurityLevel level;

  @override
  BackendCapabilities get capabilities =>
      const BackendCapabilities(enumeration: true, persistent: true);

  @override
  Future<Uint8List?> read(String key) => _api.get(service, key);

  @override
  Future<bool> contains(String key) => _api.exists(service, key);

  @override
  Future<void> write(String key, Uint8List value, {String? label}) =>
      _api.set(service, key, value, label: label);

  @override
  Future<void> delete(String key) => _api.delete(service, key);

  @override
  Future<Map<String, Uint8List>> readAll() => _api.getAll(service);

  @override
  Future<BackendInfo> describe() async {
    final p = await _api.probe(service);
    return BackendInfo(
      scheme: StorageScheme.nativeItems,
      available: p.available,
      locked: p.locked,
      capabilities: capabilities,
      level: level,
      detail: p.detail,
    );
  }
}
