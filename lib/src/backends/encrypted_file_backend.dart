/// Encrypted-file backend: an authenticated container sealed by a store key
/// from a [KeySource] (RFC 0005 §6 model B, §7).
///
/// Implements the §7 failure matrix precisely, so a diagnostics UI can tell a
/// fresh install from a lost container, a lost key, or tampering.
library;

import 'dart:typed_data';

import '../backend.dart';
import '../container/container.dart';
import '../container/tlv.dart';
import '../errors.dart';
import '../ffi/posix_file.dart';
import '../key_source.dart';

/// On-disk cap for the container file, checked before the bytes are read. Three
/// orders of magnitude above any realistic store.
const int maxContainerBytes = 16 * 1024 * 1024;

final class EncryptedFileBackend implements SecretBackend {
  EncryptedFileBackend({
    required this.path,
    required KeySource keySource,
    List<int> contextSalt = const [],
    SecureFileSystem fs = const SecureFileSystem(),
  })  : _keySource = keySource,
        _fs = fs,
        _container = Container(contextSalt: contextSalt);

  /// Path to the container file. Its parent directory is ensured `0700`.
  final String path;

  final KeySource _keySource;
  final SecureFileSystem _fs;
  final Container _container;

  @override
  BackendCapabilities get capabilities =>
      const BackendCapabilities(enumeration: true, persistent: true);

  String get _parentDir {
    final i = path.lastIndexOf('/');
    return i <= 0 ? '.' : path.substring(0, i);
  }

  /// Loads and decrypts the whole store, applying the §7 failure matrix.
  Future<Map<String, ContainerEntry>> _load() async {
    final bytes = _fs.readCappedSync(path, maxBytes: maxContainerBytes);
    final key = await _keySource.read();
    if (bytes == null) {
      if (key == null) return {}; // fresh install
      throw ContainerMissing(path); // key orphaned by a lost container
    }
    if (key == null) {
      throw const StoreKeyMissing(); // ciphertext exists but key is gone
    }
    return _container.open(
        bytes, key); // AuthenticationFailed / ContainerCorrupt
  }

  /// Encrypts and atomically writes [entries], creating the store key on first
  /// write. If the write fails right after a *fresh* key was created, the key
  /// is rolled back so the store returns to a clean uninitialized state rather
  /// than a key-without-container orphan.
  Future<void> _save(Map<String, ContainerEntry> entries) async {
    var key = await _keySource.read();
    final createdFreshKey = key == null;
    key ??= await _keySource.create();
    try {
      final sealed = await _container.seal(entries, key);
      _fs.ensurePrivateDirSync(_parentDir);
      _fs.writeAtomicSync(path, sealed);
    } catch (_) {
      if (createdFreshKey) {
        try {
          await _keySource.delete();
        } catch (_) {
          // best effort — surface the original write error
        }
      }
      rethrow;
    }
  }

  @override
  Future<Uint8List?> read(String key) async => (await _load())[key]?.value;

  @override
  Future<bool> contains(String key) async => (await _load()).containsKey(key);

  @override
  Future<void> write(String key, Uint8List value, {String? label}) async {
    final entries = await _load();
    entries[key] = ContainerEntry(Uint8List.fromList(value), label: label);
    await _save(entries);
  }

  @override
  Future<void> delete(String key) async {
    final entries = await _load();
    if (entries.remove(key) != null) {
      await _save(entries);
    }
  }

  @override
  Future<Map<String, Uint8List>> readAll() async {
    final entries = await _load();
    return {for (final e in entries.entries) e.key: e.value.value};
  }

  @override
  Future<BackendInfo> describe() async {
    final keyStatus = await _keySource.describe();
    final containerPresent =
        _fs.readCappedSync(path, maxBytes: maxContainerBytes) != null;
    return BackendInfo(
      name: 'encrypted-file',
      available: keyStatus.available,
      locked: keyStatus.locked,
      capabilities: capabilities,
      detail: 'container=${containerPresent ? 'present' : 'absent'} '
          'key=${keyStatus.present ? 'present' : 'absent'} '
          'via ${keyStatus.name}',
    );
  }
}
