import 'dart:io';

import 'package:keyway_cli/src/entrypoint.dart';

Future<void> main(List<String> arguments) async {
  if (arguments.isEmpty) {
    stderr.writeln('usage: integration_harness APP_ID KEYWAY_ARGS...');
    exitCode = 2;
    return;
  }
  exitCode = await runKeyway(arguments.sublist(1), appId: arguments.first);
}
