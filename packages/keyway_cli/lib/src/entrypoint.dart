import 'dart:io';

import 'package:keyway/keyway.dart';

import 'application.dart';
import 'command.dart';
import 'manifest.dart';
import 'process_executor.dart';
import 'secret_input.dart';

Future<int> runKeyway(
  List<String> arguments, {
  String appId = 'keyway-cli',
}) async {
  try {
    final command = parseCommand(arguments);
    final input = SecretInputReader.system(stdin: stdin, stderr: stderr);
    final application = CliApplication(
      loadManifest: (path) => readManifest(File(path)),
      createStorage: () => SecretStorage(appId: appId),
      readSecretValue: input.read,
      commandExecutor: SystemCommandExecutor(stderr: stderr),
      parentEnvironment: Platform.environment,
      stdout: stdout,
      stderr: stderr,
      isCompiled: isCompiledExecutable(),
    );
    return await application.execute(command);
  } on CliUsageException catch (error) {
    stderr.writeln('keyway: $error');
    stderr.writeln('Try keyway --help.');
    return exitUsage;
  } on SecretInputException catch (error) {
    stderr.writeln('error: $error.');
    return exitUsage;
  } on UnsupportedError {
    stderr.writeln('error: keyway supports macOS and Linux desktop only.');
    stderr.writeln('In CI, use the CI platform secret store.');
    return exitUnavailable;
  } on Object {
    stderr.writeln('error: an internal Keyway CLI invariant failed.');
    stderr.writeln('Report this bug upstream.');
    return exitSoftware;
  }
}

bool isCompiledExecutable() {
  final executable = Platform.resolvedExecutable
      .replaceAll('\\', '/')
      .split('/')
      .last
      .toLowerCase();
  return executable != 'dart' &&
      executable != 'dart.exe' &&
      executable != 'dartaotruntime' &&
      executable != 'dartaotruntime.exe';
}
