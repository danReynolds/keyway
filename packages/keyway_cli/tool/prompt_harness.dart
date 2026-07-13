import 'dart:io';

import 'package:keyway_cli/src/secret_input.dart';

Future<void> main() async {
  final reader = SecretInputReader.system(stdin: stdin, stderr: stderr);
  try {
    final value = await reader.read(key: 'test/prompt', fromStdin: false);
    stdout.writeln('read:${value.length}');
    await Future<void>.delayed(const Duration(milliseconds: 250));
  } on SecretInputException catch (error) {
    stderr.writeln('error: $error');
    exitCode = 2;
  }
}
