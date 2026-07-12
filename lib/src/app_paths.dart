/// Derived per-app storage locations (see doc/implementation-plan.md §3).
///
/// The container path is a pure function of the validated `appId` — no path
/// knob exists on the public API. `appId` is a single traversal-proof path
/// segment (enforced by `validateAppId`), so these joins cannot escape the
/// platform data directory.
library;

import 'dart:io';

import 'errors.dart';

/// The container file name inside the app's data directory.
const String containerFileName = 'secrets.enc';

/// Derives the container file path for [appId] on this platform:
///
/// - macOS: `~/Library/Application Support/<appId>/secrets.enc`
/// - Linux: `${XDG_DATA_HOME:-~/.local/share}/<appId>/secrets.enc`
///   (a relative `XDG_DATA_HOME` is ignored, per the XDG Base Directory spec)
///
/// [appId] must already have passed `validateAppId`. [environment] is an
/// internal test seam; production callers use the process environment.
/// Throws [KeystoreUnreachable] when no data directory can be derived.
String containerPathFor(String appId, {Map<String, String>? environment}) {
  final env = environment ?? Platform.environment;
  final home = env['HOME'];
  if (Platform.isMacOS) {
    if (home == null || home.isEmpty) {
      throw const KeystoreUnreachable(
          'HOME is not set; cannot derive the application data directory');
    }
    return '$home/Library/Application Support/$appId/$containerFileName';
  }
  if (Platform.isLinux) {
    final xdg = env['XDG_DATA_HOME'];
    if (xdg != null && xdg.startsWith('/')) {
      return '$xdg/$appId/$containerFileName';
    }
    if (home == null || home.isEmpty) {
      throw const KeystoreUnreachable(
          'neither XDG_DATA_HOME nor HOME is set; cannot derive the '
          'application data directory');
    }
    return '$home/.local/share/$appId/$containerFileName';
  }
  throw KeystoreUnreachable(
      'no secret storage scheme for ${Platform.operatingSystem}');
}

/// Derives the Android app data directory from
/// `System.getProperty("java.io.tmpdir")` — which the framework sets to the
/// app's **cache** dir (`<dataDir>/cache`) — giving `<dataDir>` without
/// needing an `android.content.Context` (no hidden APIs; `files` and `cache`
/// are sibling children of `dataDir` per the stable `ApplicationInfo` layout).
///
/// Pure and strict: anything other than an absolute path ending in `/cache`
/// throws [KeystoreUnreachable] rather than guessing at a location that will
/// hold key material.
String androidDataDirFromTmpdir(String tmpdir) {
  // Tolerate a single trailing slash; reject anything else surprising.
  final normalized = tmpdir.endsWith('/') && tmpdir.length > 1
      ? tmpdir.substring(0, tmpdir.length - 1)
      : tmpdir;
  final dataDir = normalized.startsWith('/') && normalized.endsWith('/cache')
      ? normalized.substring(0, normalized.length - '/cache'.length)
      : '';
  if (dataDir.isEmpty) {
    throw const KeystoreUnreachable(
        'unexpected java.io.tmpdir layout on Android; cannot derive the '
        'app data directory');
  }
  return dataDir;
}

/// The Android container path: `<dataDir>/files/<appId>/secrets.enc`.
/// [appId] must already have passed `validateAppId`; [tmpdir] is the value of
/// `System.getProperty("java.io.tmpdir")` (see [androidDataDirFromTmpdir]).
String androidContainerPathFor(String appId, {required String tmpdir}) =>
    '${androidDataDirFromTmpdir(tmpdir)}/files/$appId/$containerFileName';
