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
    // can't deadlock on a full pipe. The builders live out here so the
    // bounded wait below can return whatever bytes arrived even when EOF
    // never comes.
    final outB = BytesBuilder(copy: false);
    final errB = BytesBuilder(copy: false);
    final outDone = proc.stdout.forEach(outB.add);
    final errDone = proc.stderr.forEach(errB.add);

    // Arm the hard timeout *before* touching stdin: a child that never drains
    // its stdin can block flush() past the OS pipe buffer, so the timer must
    // already be able to fire (and SIGKILL it) during the write, not only
    // while awaiting exit.
    var timedOut = false;
    final timer = Timer(timeout, () {
      // kill() returns false when the child already exited — a run that
      // finished just before the deadline must not be reported as timed out.
      timedOut = proc.kill(ProcessSignal.sigkill);
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
    // Bounded drain: the pipes hit EOF the instant the child dies — unless a
    // grandchild inherited the write ends (a forked helper), which our
    // SIGKILL of the direct child cannot reach. Waiting only a grace period
    // past exit preserves the no-hang contract; the builders still hold every
    // byte that actually arrived.
    Future<void> bounded(Future<void> done) =>
        done.timeout(_drainGrace, onTimeout: () {});
    await bounded(outDone);
    await bounded(errDone);
    return ProcessRunResult(
        exitCode: code,
        stdout: outB.takeBytes(),
        stderr: errB.takeBytes(),
        timedOut: timedOut,
        launchFailed: false);
  }

  /// How long to wait for stdout/stderr EOF after the child has exited.
  static const _drainGrace = Duration(seconds: 2);
}
