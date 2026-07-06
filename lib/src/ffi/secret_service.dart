/// Linux Secret Service via `secret-tool` (RFC 0005 §5).
///
/// libsecret's own CLI, so no D-Bus protocol of our own (that's a recorded
/// follow-up). The secret always crosses on **stdin** (never argv — argv is
/// `ps`-visible), base64-encoded so binary/newlines survive the pipe. Every
/// call has a **hard timeout**: `secret-tool` has no no-prompt flag and a
/// locked collection spawns a GUI prompter, which over SSH would hang forever;
/// on timeout we kill it and surface a typed [KeystoreLocked]. Subprocess
/// stdout/stderr is parsed into the taxonomy and then discarded — it is never
/// attached to a surfaced error (a failed `store` echoes its stdin, i.e. the
/// base64 value).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../errors.dart';
import 'keystore_api.dart';

/// Outcome of a subprocess run. Output is captured as bytes; callers parse what
/// they need and must not surface it in errors.
final class ProcessRunResult {
  const ProcessRunResult({
    required this.exitCode,
    required this.stdout,
    required this.stderr,
    required this.timedOut,
    required this.launchFailed,
  });
  final int exitCode;
  final String stdout;
  final String stderr;
  final bool timedOut;

  /// The executable could not be launched (e.g. not installed).
  final bool launchFailed;
}

/// Runs a subprocess with optional stdin and a hard timeout. Injectable so the
/// backend logic is testable without a real `secret-tool`.
abstract interface class ProcessRunner {
  Future<ProcessRunResult> run(
    String executable,
    List<String> args, {
    String? stdin,
    required Duration timeout,
  });
}

/// The real runner over `dart:io`.
final class SystemProcessRunner implements ProcessRunner {
  const SystemProcessRunner();

  @override
  Future<ProcessRunResult> run(
    String executable,
    List<String> args, {
    String? stdin,
    required Duration timeout,
  }) async {
    Process proc;
    try {
      proc = await Process.start(executable, args);
    } on ProcessException {
      return const ProcessRunResult(
          exitCode: -1,
          stdout: '',
          stderr: '',
          timedOut: false,
          launchFailed: true);
    }
    if (stdin != null) {
      proc.stdin.write(stdin);
    }
    await proc.stdin.close();

    final outF = proc.stdout.transform(utf8.decoder).join();
    final errF = proc.stderr.transform(utf8.decoder).join();

    var timedOut = false;
    final timer = Timer(timeout, () {
      timedOut = true;
      proc.kill(ProcessSignal.sigkill);
    });
    final code = await proc.exitCode;
    timer.cancel();
    final out = await outF;
    final err = await errF;
    return ProcessRunResult(
        exitCode: code,
        stdout: out,
        stderr: err,
        timedOut: timedOut,
        launchFailed: false);
  }
}

/// Secret Service backing via `secret-tool`.
final class SecretToolApi implements KeystoreApi {
  SecretToolApi({
    ProcessRunner runner = const SystemProcessRunner(),
    this.executable = 'secret-tool',
    this.timeout = const Duration(seconds: 15),
  }) : _runner = runner;

  final ProcessRunner _runner;

  /// `secret-tool` resolved via PATH by default; override to pin an absolute
  /// path (a same-user PATH hijack is outside the threat model, but the knob
  /// costs nothing).
  final String executable;

  /// Hard per-call timeout; a locked collection would otherwise hang on a GUI
  /// prompt.
  final Duration timeout;

  List<String> _attrs(String service, String account) =>
      ['service', service, 'account', account];

  Future<ProcessRunResult> _run(List<String> args, {String? stdin}) =>
      _runner.run(executable, args, stdin: stdin, timeout: timeout);

  Never _translate(ProcessRunResult r, String op) {
    if (r.launchFailed) {
      throw KeystoreUnreachable('$op: `$executable` not found');
    }
    if (r.timedOut) {
      throw KeystoreLocked('$op: `$executable` timed out (locked collection?)');
    }
    // Never include r.stdout/r.stderr — a failed store echoes the base64 value.
    throw KeystoreOperationFailed('$op failed', status: r.exitCode);
  }

  @override
  Future<Uint8List?> get(String service, String account) async {
    final r = await _run(['lookup', ..._attrs(service, account)]);
    if (r.launchFailed || r.timedOut) _translate(r, 'get');
    if (r.exitCode == 1) return null; // not found
    if (r.exitCode != 0) _translate(r, 'get');
    return _decode(r.stdout);
  }

  @override
  Future<void> set(String service, String account, Uint8List value,
      {String? label}) async {
    final r = await _run(
      [
        'store',
        '--label',
        label ?? 'secret_store',
        ..._attrs(service, account),
      ],
      stdin: base64.encode(value),
    );
    if (r.exitCode != 0) _translate(r, 'set');
  }

  @override
  Future<void> delete(String service, String account) async {
    final r = await _run(['clear', ..._attrs(service, account)]);
    // clear on a missing item still exits 0; any nonzero is a real failure.
    if (r.exitCode != 0) _translate(r, 'delete');
  }

  @override
  Future<Map<String, Uint8List>> getAll(String service) async {
    final r = await _run(['search', '--all', 'service', service]);
    if (r.launchFailed || r.timedOut) _translate(r, 'getAll');
    // `search` exits 1 when nothing matches.
    if (r.exitCode == 1) return {};
    if (r.exitCode != 0) _translate(r, 'getAll');
    final accounts = _parseAccounts(r.stdout);
    final result = <String, Uint8List>{};
    for (final account in accounts) {
      final v = await get(service, account);
      if (v != null) result[account] = v;
    }
    return result;
  }

  @override
  Future<KeystoreProbe> probe(String service) async {
    final r =
        await _run(['lookup', ..._attrs(service, '__secret_store_probe__')]);
    if (r.launchFailed) {
      return KeystoreProbe(
          available: false, locked: false, detail: '`$executable` not found');
    }
    if (r.timedOut) {
      return const KeystoreProbe(
          available: true, locked: true, detail: 'timed out (locked?)');
    }
    // exit 0 (found, unlikely) or 1 (not found) both mean reachable+unlocked.
    return const KeystoreProbe(available: true, locked: false);
  }

  Uint8List? _decode(String stdout) {
    final trimmed = stdout.trim();
    if (trimmed.isEmpty) return Uint8List(0);
    try {
      return Uint8List.fromList(base64.decode(trimmed));
    } on FormatException {
      throw const KeystoreOperationFailed('stored value was not valid base64');
    }
  }

  /// `secret-tool search --all` prints each item's attributes; account lines
  /// read `attribute.account = NAME`.
  List<String> _parseAccounts(String stdout) {
    final accounts = <String>[];
    for (final line in const LineSplitter().convert(stdout)) {
      final m =
          RegExp(r'^\s*attribute\.account\s*=\s*(.+?)\s*$').firstMatch(line);
      if (m != null) accounts.add(m.group(1)!);
    }
    return accounts;
  }
}
