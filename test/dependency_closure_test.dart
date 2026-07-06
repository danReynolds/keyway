@Tags(['unit'])
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

/// Supply-chain firewall (RFC 0005 §4a): the *runtime* dependency closure must
/// stay exactly one third-party package (`cryptography`) whose own closure is
/// entirely dart-lang official. This test fails CI the moment a dependency is
/// added or the tree shifts — a deliberate speed bump on that decision.
void main() {
  test('runtime dependency closure is the vetted set', () {
    final result = Process.runSync('dart', ['pub', 'deps', '--json']);
    if (result.exitCode != 0) {
      fail('`dart pub deps --json` failed: ${result.stderr}');
    }
    final data = jsonDecode(result.stdout as String) as Map<String, dynamic>;
    final packages = (data['packages'] as List).cast<Map<String, dynamic>>();
    final byName = {for (final p in packages) p['name'] as String: p};

    // `directDependencies` is the main deps only (dev deps are listed
    // separately under `devDependencies`), so the BFS covers the runtime
    // closure and excludes the test/lints toolchain.
    final root = packages.firstWhere((p) => p['kind'] == 'root');
    final seeds = (root['directDependencies'] as List).cast<String>();

    // BFS the main closure.
    final closure = <String>{};
    final queue = [...seeds];
    while (queue.isNotEmpty) {
      final name = queue.removeLast();
      if (!closure.add(name)) continue;
      final pkg = byName[name];
      if (pkg == null) continue;
      queue.addAll((pkg['dependencies'] as List).cast<String>());
    }

    expect(
      closure,
      unorderedEquals(<String>{
        'cryptography', // the one third-party runtime dep
        'ffi', // dart-lang official (POSIX shim)
        'collection', 'crypto', 'meta', 'typed_data', // dart-lang official
      }),
      reason: 'runtime dependency closure changed — review the supply chain '
          'before updating this expectation (RFC 0005 §4a).',
    );
  });

  test('exact version pins on the third-party dep', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    // Not a range: an exact "cryptography: 2.9.0" line.
    expect(pubspec, contains(RegExp(r'cryptography:\s*2\.9\.0\b')));
    expect(pubspec, isNot(contains('dependency_overrides')));
  });
}
