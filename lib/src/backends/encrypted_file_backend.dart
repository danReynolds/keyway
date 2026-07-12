/// Encrypted-file backend: an authenticated container sealed by a store key
/// from a [KeySource] (see doc/design.md).
///
/// Implements the §7 failure matrix precisely, so a diagnostics UI can tell a
/// fresh install from a lost container, a lost key, a wrong key, or tampering.
///
/// **Concurrency.** Whole-file read-modify-write operations are serialized by
/// a FIFO mutex keyed on the **container path**, so concurrent calls within one
/// isolate — even from two separate backend instances (e.g. two
/// `SecretStorage(appId:)` objects) targeting the same store — never interleave
/// and drop updates. The mutex is an isolate-local static, so coordination
/// *across isolates* (a Flutter background isolate, a spawned `Isolate`) and
/// *across processes* is out of scope: a container has a **single writer**.
/// Two writers on one container concurrently can lose an update or, on first
/// write, both create a store key and leave the container sealed under a
/// discarded one — keep a container to a single isolate, bring your own lock,
/// or don't share it between writers. (An advisory `flock` was prototyped and
/// cut as surface the common single-writer deployment doesn't need; locking a
/// fresh file description per operation, it would have covered cross-isolate
/// and cross-process writers alike, and it remains the natural follow-up if
/// multi-writer support is ever wanted.)
library;

import 'dart:async';
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

  /// Serialization is keyed by container path and shared across backend
  /// instances **within an isolate**: two backends for the same store in the
  /// same isolate must take the same lock or they can drop each other's
  /// whole-file updates. Statics are isolate-local, so this does not coordinate
  /// across isolates or processes (see the class doc). (Isolate-lifetime; one
  /// small entry per distinct store path.)
  static final Map<String, _TurnLock> _locks = {};
  _TurnLock get _mutex => _locks.putIfAbsent(path, _TurnLock.new);

  @override
  BackendCapabilities get capabilities =>
      const BackendCapabilities(enumeration: true, persistent: true);

  String get _parentDir {
    final i = path.lastIndexOf('/');
    return i <= 0 ? '.' : path.substring(0, i);
  }

  /// Serializes [body] against same-isolate siblings (FIFO mutex). Mutations
  /// create + verify the private store directory first; reads only verify it.
  Future<T> _serialized<T>(
      {required bool exclusive, required Future<T> Function() body}) {
    return _mutex.run(() async {
      if (exclusive) {
        _fs.ensurePrivateDirSync(_parentDir);
      } else {
        _fs.verifyPrivateDirSync(_parentDir);
      }
      return body();
    });
  }

  /// Loads and decrypts the whole store, applying the §7 failure matrix.
  /// Call only under [_serialized].
  ///
  /// [healOrphanedKey] is set by the mutating paths (write/delete): if a store
  /// key exists but the container is absent — the wedge left by a process
  /// crash between key creation and the first container write — they treat the
  /// store as empty and re-seal under the existing key, rather than throwing
  /// [ContainerMissing] forever. On the read paths it stays false so a lost
  /// container is reported loudly instead of silently looking empty.
  Future<Map<String, ContainerEntry>> _load(
      {bool healOrphanedKey = false}) async {
    final bytes = _fs.readCappedSync(path,
        maxBytes: maxContainerBytes, requirePrivate: true);
    final key = await _keySource.read();
    if (bytes == null) {
      if (key == null || healOrphanedKey) {
        return {}; // fresh install, or an orphaned key we're about to re-seal
      }
      throw ContainerMissing(path); // key orphaned by a lost container
    }
    if (key == null) {
      throw const StoreKeyMissing(); // ciphertext exists but key is gone
    }
    // WrongStoreKey / AuthenticationFailed / ContainerCorrupt from here.
    return _container.open(bytes, key);
  }

  /// Encrypts and atomically writes [entries], creating the store key on first
  /// write. If the write fails right after a *fresh* key was created, the key
  /// is rolled back so the store returns to a clean uninitialized state rather
  /// than a key-without-container orphan. Call only under an exclusive
  /// [_serialized].
  Future<void> _save(Map<String, ContainerEntry> entries) async {
    var key = await _keySource.read();
    final createdFreshKey = key == null;
    key ??= await _keySource.create();
    try {
      final sealed = await _container.seal(entries, key);
      // Reject before the atomic replace: the read side caps the container at
      // maxContainerBytes, so a larger file would make *every* subsequent read
      // fail closed. Checking here leaves the existing container untouched.
      if (sealed.length > maxContainerBytes) {
        throw StoreTooLarge(sealed.length, maxContainerBytes);
      }
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
  Future<Uint8List?> read(String key) => _serialized(
      exclusive: false, body: () async => (await _load())[key]?.value);

  @override
  Future<bool> contains(String key) => _serialized(
      exclusive: false, body: () async => (await _load()).containsKey(key));

  @override
  Future<void> write(String key, Uint8List value, {String? label}) =>
      _serialized(
          exclusive: true,
          body: () async {
            final entries = await _load(healOrphanedKey: true);
            entries[key] =
                ContainerEntry(Uint8List.fromList(value), label: label);
            await _save(entries);
          });

  @override
  Future<void> delete(String key) => _serialized(
      exclusive: true,
      body: () async {
        final entries = await _load(healOrphanedKey: true);
        if (entries.remove(key) != null) {
          await _save(entries);
        }
      });

  @override
  Future<Map<String, Uint8List>> readAll() => _serialized(
      exclusive: false,
      body: () async {
        final entries = await _load();
        return {for (final e in entries.entries) e.key: e.value.value};
      });

  @override
  Future<BackendInfo> describe() async {
    final keyStatus = await _keySource.describe();
    final containerPresent = _fs.existsSync(path);
    return BackendInfo(
      scheme: StorageScheme.encryptedFile,
      available: keyStatus.available,
      locked: keyStatus.locked,
      capabilities: capabilities,
      // The level is whatever the key's home actually reports (measured, e.g.
      // Android inspects KeyInfo) — not a value the backend assumes.
      level: keyStatus.securityLevel,
      detail: 'container=${containerPresent ? 'present' : 'absent'} '
          'key=${keyStatus.present ? 'present' : 'absent'} '
          'via ${keyStatus.name}',
    );
  }
}

/// A minimal FIFO async mutex: bodies run one at a time, in call order.
class _TurnLock {
  Future<void> _tail = Future<void>.value();

  Future<T> run<T>(Future<T> Function() body) {
    final prev = _tail;
    final gate = Completer<void>();
    _tail = gate.future;
    return prev.then((_) => body()).whenComplete(gate.complete);
  }
}
