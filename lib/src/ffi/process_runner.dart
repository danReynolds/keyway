/// A minimal, injectable subprocess runner for the CLI-backed seam
/// (`secret-tool` on Linux).
///
/// Injectable so backend logic is testable without the real binary. Output is
/// captured as raw bytes because it can echo secret material; callers parse
/// what they need, zero the buffers, and must never attach them to an error.
library;

import 'dart:async';
import 'dart:typed_data';
import 'dart:io';

/// Outcome of a subprocess run.
final class ProcessRunResult {
  ProcessRunResult({
    required this.exitCode,
    required this.stdout,
    required this.stderr,
    required this.timedOut,
    required this.launchFailed,
  });

  final int exitCode;

  /// Raw stdout bytes. May carry secret material.
  final Uint8List stdout;

  /// Raw stderr bytes. Same handling rule as [stdout].
  final Uint8List stderr;

  final bool timedOut;

  /// The executable could not be launched (e.g. not installed).
  final bool launchFailed;
}

/// Runs a subprocess with optional stdin and a hard timeout.
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
      return ProcessRunResult(
          exitCode: -1,
          stdout: Uint8List(0),
          stderr: Uint8List(0),
          timedOut: false,
          launchFailed: true);
    }
    // Start draining stdout/stderr before touching stdin so a chatty child
    // can't deadlock on a full pipe.
    final outF = _drain(proc.stdout);
    final errF = _drain(proc.stderr);

    // Arm the hard timeout *before* touching stdin: a child that never drains
    // its stdin can block flush() past the OS pipe buffer, so the timer must
    // already be able to fire (and SIGKILL it) during the write, not only
    // while awaiting exit.
    var timedOut = false;
    final timer = Timer(timeout, () {
      timedOut = true;
      proc.kill(ProcessSignal.sigkill);
    });
    try {
      if (stdin != null) {
        proc.stdin.write(stdin);
      }
      await proc.stdin.flush();
      await proc.stdin.close();
    } on Object {
      // Broken pipe (child exited or was killed without reading stdin). The
      // exit code / timedOut flag tell the story; don't let it escape untyped.
    }

    final code = await proc.exitCode;
    timer.cancel();
    return ProcessRunResult(
        exitCode: code,
        stdout: await outF,
        stderr: await errF,
        timedOut: timedOut,
        launchFailed: false);
  }

  static Future<Uint8List> _drain(Stream<List<int>> stream) async {
    final builder = BytesBuilder(copy: false);
    await for (final chunk in stream) {
      builder.add(chunk);
    }
    return builder.takeBytes();
  }
}
