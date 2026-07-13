import 'dart:io';

import 'package:keyway_cli/src/entrypoint.dart';

Future<void> main(List<String> arguments) async {
  exitCode = await runKeyway(arguments);
}
