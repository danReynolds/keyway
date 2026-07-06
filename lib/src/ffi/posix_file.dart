/// A minimal POSIX file shim (RFC 0005 §7).
///
/// `dart:io` cannot create a file with restrictive permissions from birth (no
/// umask/chmod/fchmod), cannot `fsync`, and cannot exclusive-create — verified:
/// `File.writeAsBytes` yields mode 0644. For key material that is unacceptable,
/// so writes go through libc directly: `open(O_CREAT|O_EXCL|O_WRONLY, 0600)` →
/// write → `fsync` → `close` → atomic `rename`. This is a second, deliberately
/// tiny FFI locus (the first being the macOS Keychain binding); it is the
/// safest category of FFI — fixed-arity libc calls over ints and byte buffers.
///
/// POSIX-only. macOS and Linux share these libc symbols; the open() flag values
/// differ by platform and are selected below.
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// --- libc bindings -----------------------------------------------------------

final DynamicLibrary _libc = DynamicLibrary.process();

// open() is variadic in C (`int open(const char*, int, ...)`). The mode MUST be
// bound as a vararg: on Apple arm64 variadic arguments are passed on the stack,
// not in registers, so a fixed 3-argument binding silently passes mode where
// open never reads it — yielding a mode-000 file. `VarArgs` marshals it
// correctly. (Verified: the fixed binding produced 0o000; VarArgs produces
// 0o600. The perms test guards this permanently.)
final int Function(Pointer<Utf8>, int, int) _open = _libc.lookupFunction<
    Int32 Function(Pointer<Utf8>, Int32, VarArgs<(Int32,)>),
    int Function(Pointer<Utf8>, int, int)>('open');

final int Function(int, Pointer<Uint8>, int) _write = _libc.lookupFunction<
    IntPtr Function(Int32, Pointer<Uint8>, IntPtr),
    int Function(int, Pointer<Uint8>, int)>('write');

final int Function(int) _fsync =
    _libc.lookupFunction<Int32 Function(Int32), int Function(int)>('fsync');

final int Function(int) _close =
    _libc.lookupFunction<Int32 Function(Int32), int Function(int)>('close');

// mkdir(const char*, mode_t). mode_t is uint16 (macOS) / uint32 (Linux); a
// Uint32 binding is correct on both (macOS reads the low 16 bits).
final int Function(Pointer<Utf8>, int) _mkdir = _libc.lookupFunction<
    Int32 Function(Pointer<Utf8>, Uint32),
    int Function(Pointer<Utf8>, int)>('mkdir');

// errno location: __error() on macOS/BSD, __errno_location() on Linux/glibc.
final Pointer<Int32> Function() _errnoLocation =
    _libc.lookupFunction<Pointer<Int32> Function(), Pointer<Int32> Function()>(
        Platform.isMacOS ? '__error' : '__errno_location');

int get _errno => _errnoLocation().value;

// open() flags — values differ between Linux and macOS/BSD.
final int _oWrOnly = 0x0001;
final int _oCreat = Platform.isMacOS ? 0x0200 : 0x40;
final int _oExcl = Platform.isMacOS ? 0x0800 : 0x80;

/// Thrown when a low-level file operation fails. Carries the operation and the
/// path — never file contents.
final class SecureFileError implements Exception {
  SecureFileError(this.operation, this.path, this.errno);
  final String operation;
  final String path;
  final int errno;
  @override
  String toString() => 'SecureFileError($operation "$path"): errno $errno';
}

/// Secure file primitives for the encrypted-file backend and file key source.
class SecureFileSystem {
  const SecureFileSystem();

  /// Writes [bytes] to [path] atomically and privately: an exclusive-created
  /// `0600` temp file in the same directory, fsync'd, then renamed over [path].
  /// A crash leaves either the previous file or the new one — never a torn
  /// mix. The temp file is unlinked on any failure.
  void writeAtomicSync(String path, Uint8List bytes) {
    final dir = File(path).parent.path;
    // Random suffix so a stale/pre-placed temp can't collide, and O_EXCL means
    // creation fails rather than following a planted file/symlink.
    final tmp = '$dir/.${_baseName(path)}.tmp.${_randomSuffix()}';
    final tmpPtr = tmp.toNativeUtf8();
    final fd = _open(tmpPtr, _oWrOnly | _oCreat | _oExcl, 0x180 /* 0600 */);
    if (fd < 0) {
      final e = _errno;
      malloc.free(tmpPtr);
      throw SecureFileError('open', tmp, e);
    }
    final buf = malloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
    try {
      if (bytes.isNotEmpty) buf.asTypedList(bytes.length).setAll(0, bytes);
      var written = 0;
      while (written < bytes.length) {
        final n = _write(fd, buf + written, bytes.length - written);
        if (n < 0) {
          final e = _errno;
          if (e == 4 /* EINTR */) continue;
          throw SecureFileError('write', tmp, e);
        }
        written += n;
      }
      if (_fsync(fd) < 0) {
        throw SecureFileError('fsync', tmp, _errno);
      }
    } catch (_) {
      _close(fd);
      _tryUnlink(tmp);
      rethrow;
    } finally {
      malloc.free(buf);
      malloc.free(tmpPtr);
    }
    if (_close(fd) < 0) {
      final e = _errno;
      _tryUnlink(tmp);
      throw SecureFileError('close', tmp, e);
    }
    // Atomic same-directory rename (POSIX guarantees it). Dart's rename maps to
    // rename(2). On failure, drop the temp so we don't litter.
    try {
      File(tmp).renameSync(path);
    } catch (_) {
      _tryUnlink(tmp);
      rethrow;
    }
  }

  /// Reads [path], rejecting anything larger than [maxBytes] *before* reading
  /// the contents. Returns null if the file does not exist.
  Uint8List? readCappedSync(String path, {required int maxBytes}) {
    final f = File(path);
    if (!f.existsSync()) return null;
    final len = f.lengthSync();
    if (len > maxBytes) {
      throw SecureFileError('read(too-large:$len>$maxBytes)', path, 0);
    }
    return f.readAsBytesSync();
  }

  /// Deletes [path] if present. Idempotent.
  void deleteSync(String path) {
    final f = File(path);
    if (f.existsSync()) f.deleteSync();
  }

  /// Ensures [dirPath] exists as a directory that grants no group/other access
  /// (`mode & 0o077 == 0`). Creates it `0700` via `mkdir(2)` if absent (unlike
  /// `Directory.createSync`, which respects umask and can yield 0755), then
  /// verifies — so a *pre-existing* world/group-accessible dir is rejected, not
  /// silently trusted. The dir's privacy is the property the file backend's
  /// security rests on, so it is enforced, not assumed.
  ///
  /// Note (v1): the strict "owned by the current euid" check is deferred — it
  /// needs per-platform `struct stat` offsets. A 0700 directory owned by
  /// another user is unusable to us anyway (operations fail with EACCES), so
  /// the mode check carries the load. Tracked as a hardening follow-up.
  void ensurePrivateDirSync(String dirPath) {
    final dir = Directory(dirPath);
    if (!dir.existsSync()) {
      final parent = dir.parent;
      if (!parent.existsSync()) {
        // Only create the leaf privately; a missing parent is the caller's
        // responsibility (we won't create intermediate dirs with unknown modes).
        throw SecureFileError('parent-missing', dirPath, 0);
      }
      final ptr = dirPath.toNativeUtf8();
      try {
        if (_mkdir(ptr, 0x1C0 /* 0700 */) < 0) {
          final e = _errno;
          if (e != 17 /* EEXIST: lost a race, fall through to verify */) {
            throw SecureFileError('mkdir', dirPath, e);
          }
        }
      } finally {
        malloc.free(ptr);
      }
    }
    final stat = dir.statSync();
    if (stat.type != FileSystemEntityType.directory) {
      throw SecureFileError('not-a-directory', dirPath, 0);
    }
    if ((stat.mode & 0x3F) != 0) {
      // 0x3F = 0o77 (group+other bits). Refuse a world/group-accessible dir.
      throw SecureFileError(
          'insecure-dir-mode(${(stat.mode & 0x1FF).toRadixString(8)})',
          dirPath,
          0);
    }
  }

  void _tryUnlink(String path) {
    try {
      final f = File(path);
      if (f.existsSync()) f.deleteSync();
    } catch (_) {
      // best effort
    }
  }

  String _baseName(String path) {
    final i = path.lastIndexOf('/');
    return i < 0 ? path : path.substring(i + 1);
  }
}

// Non-crypto uniqueness for the temp name (O_EXCL provides the real safety).
int _tmpCounter = 0;
String _randomSuffix() =>
    '${pid}_${DateTime.now().microsecondsSinceEpoch}_${_tmpCounter++}';
