/// Direct OS-keystore backend (RFC 0005 §5/§6 model A): each secret is its own
/// keystore item. Thin over the [KeystoreApi] seam — `MacKeychainApi` on macOS,
/// `SecretToolApi` on Linux. The platform-resolving `SecretStorage({service})`
/// constructor wires the right one; pass [api] explicitly (or a fake) otherwise.
library;

import 'dart:typed_data';

import '../ffi/keystore_api.dart';
import '../backend.dart';

final class KeystoreBackend implements SecretBackend {
  KeystoreBackend({required this.service, required KeystoreApi api})
      : _api = api;

  /// The service all this backend's items share.
  final String service;
  final KeystoreApi _api;

  @override
  BackendCapabilities get capabilities =>
      const BackendCapabilities(enumeration: true, persistent: true);

  @override
  Future<Uint8List?> read(String key) => _api.get(service, key);

  @override
  Future<bool> contains(String key) async =>
      await _api.get(service, key) != null;

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
      name: 'keystore',
      available: p.available,
      locked: p.locked,
      capabilities: capabilities,
      detail: p.detail,
    );
  }
}
