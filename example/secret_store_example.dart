// A tiny CLI demonstrating both composition models.
//
//   dart run example/secret_store_example.dart
//
// Model A (each secret is its own OS-keystore item) is the default. Model B
// (one keystore-wrapped key + an encrypted container file) is what a
// multi-secret app like dune uses.
import 'dart:convert';
import 'dart:io';

import 'package:secret_store/secret_store.dart';

Future<void> main() async {
  // --- Model A: direct keystore items (flutter_secure_storage shape) --------
  final store = SecretStorage(service: 'com.example.secret_store_demo');

  await store.writeString('api_token', 's3cr3t-value', label: 'Demo API token');
  stdout.writeln('read back: ${await store.readString('api_token')}');
  stdout.writeln('present?   ${await store.containsKey('api_token')}');
  await store.delete('api_token');
  stdout.writeln('after delete: ${await store.readString('api_token')}');

  // --- Model B: one wrapped key + an encrypted container --------------------
  final dir = Directory.systemTemp.createTempSync('secret_store_demo_');
  try {
    final modelB = SecretStorage.withBackend(
      EncryptedFileBackend(
        path: '${dir.path}/secrets.enc',
        keySource: KeystoreKeySource(
          service: 'com.example.secret_store_demo/container',
          api: platformKeystore(),
        ),
        contextSalt: utf8.encode('demo-profile-uuid'),
      ),
    );
    await modelB.writeString('db_key', 'the spice must flow');
    stdout.writeln('container read: ${await modelB.readString('db_key')}');
    stdout.writeln('container file is ciphertext on disk at ${dir.path}');
  } finally {
    dir.deleteSync(recursive: true);
  }
}
