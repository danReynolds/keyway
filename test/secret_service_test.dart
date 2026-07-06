@Tags(['unit'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:secret_store/secret_store.dart';
import 'package:test/test.dart';

/// Scripted [ProcessRunner]: records calls and returns canned outcomes, so the
/// secret-tool command construction, base64 transport, exit-code mapping, and
/// no-hang behavior are tested on any OS (no real secret-tool needed). The real
/// binary is covered by a Linux-only integration test in CI.
class ScriptedRunner implements ProcessRunner {
  ScriptedRunner(this._respond);
  final ProcessRunResult Function(List<String> args, String? stdin) _respond;
  final List<List<String>> calls = [];
  final List<String?> stdins = [];

  @override
  Future<ProcessRunResult> run(String executable, List<String> args,
      {String? stdin, required Duration timeout}) async {
    calls.add(args);
    stdins.add(stdin);
    return _respond(args, stdin);
  }
}

ProcessRunResult ok(String stdout) => ProcessRunResult(
    exitCode: 0,
    stdout: stdout,
    stderr: '',
    timedOut: false,
    launchFailed: false);
ProcessRunResult exit(int code) => ProcessRunResult(
    exitCode: code,
    stdout: '',
    stderr: '',
    timedOut: false,
    launchFailed: false);
const _timedOut = ProcessRunResult(
    exitCode: -1, stdout: '', stderr: '', timedOut: true, launchFailed: false);
const _launchFailed = ProcessRunResult(
    exitCode: -1, stdout: '', stderr: '', timedOut: false, launchFailed: true);

void main() {
  Uint8List b(List<int> v) => Uint8List.fromList(v);

  test('set writes base64 on stdin (never argv) and builds store args',
      () async {
    late List<String> args;
    final runner = ScriptedRunner((a, s) {
      args = a;
      return ok('');
    });
    final api = SecretToolApi(runner: runner);
    await api.set('svc', 'acct', b([1, 2, 3, 250]), label: 'My Label');

    expect(args,
        ['store', '--label', 'My Label', 'service', 'svc', 'account', 'acct']);
    expect(runner.stdins.single, base64.encode([1, 2, 3, 250]));
    // The raw value bytes must never appear in argv.
    expect(args.join(' '), isNot(contains(String.fromCharCodes([250]))));
  });

  test('get decodes base64 stdout; exit 1 is null', () async {
    final found = SecretToolApi(
        runner: ScriptedRunner((a, s) => ok(base64.encode([9, 8, 7]))));
    expect(await found.get('s', 'a'), [9, 8, 7]);

    final missing = SecretToolApi(runner: ScriptedRunner((a, s) => exit(1)));
    expect(await missing.get('s', 'a'), isNull);
  });

  test('lookup/clear build the right args', () async {
    final getRunner = ScriptedRunner((a, s) => exit(1));
    await SecretToolApi(runner: getRunner).get('svc', 'k');
    expect(
        getRunner.calls.single, ['lookup', 'service', 'svc', 'account', 'k']);

    final delRunner = ScriptedRunner((a, s) => ok(''));
    await SecretToolApi(runner: delRunner).delete('svc', 'k');
    expect(delRunner.calls.single, ['clear', 'service', 'svc', 'account', 'k']);
  });

  test('timeout -> KeystoreLocked (never hangs)', () async {
    final api = SecretToolApi(runner: ScriptedRunner((a, s) => _timedOut));
    await expectLater(api.get('s', 'a'), throwsA(isA<KeystoreLocked>()));
    await expectLater(
        api.set('s', 'a', b([1])), throwsA(isA<KeystoreLocked>()));
  });

  test('missing secret-tool -> KeystoreUnreachable', () async {
    final api = SecretToolApi(runner: ScriptedRunner((a, s) => _launchFailed));
    await expectLater(api.get('s', 'a'), throwsA(isA<KeystoreUnreachable>()));
    final probe = await api.probe('s');
    expect(probe.available, isFalse);
  });

  test('a store failure never leaks the value into the error', () async {
    // secret-tool would echo the offending stdin (the base64 value) on stderr;
    // our error must carry only the exit code.
    final value = b([42, 42, 42]);
    final api = SecretToolApi(
        runner: ScriptedRunner((a, s) => ProcessRunResult(
            exitCode: 2,
            stdout: base64.encode(value),
            stderr: 'bad input: ${base64.encode(value)}',
            timedOut: false,
            launchFailed: false)));
    try {
      await api.set('s', 'a', value);
      fail('should have thrown');
    } on KeystoreOperationFailed catch (e) {
      expect(e.toString(), isNot(contains(base64.encode(value))));
    }
  });

  test('getAll parses accounts from search output then fetches each', () async {
    final api = SecretToolApi(runner: ScriptedRunner((a, s) {
      if (a.first == 'search') {
        return ok('[/org/.../1]\n'
            'label = x\n'
            'attribute.service = svc\n'
            'attribute.account = alpha\n'
            '[/org/.../2]\n'
            'attribute.account = beta\n');
      }
      // lookup for a specific account
      final account = a[a.indexOf('account') + 1];
      return ok(base64.encode(account.codeUnits));
    }));
    final all = await api.getAll('svc');
    expect(all.keys.toSet(), {'alpha', 'beta'});
    expect(all['alpha'], 'alpha'.codeUnits);
  });

  test('empty search -> empty map', () async {
    final api = SecretToolApi(runner: ScriptedRunner((a, s) => exit(1)));
    expect(await api.getAll('svc'), isEmpty);
  });
}
