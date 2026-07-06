/// The authenticated encrypted container (RFC 0005 §7).
///
/// On-disk layout:
/// ```
/// magic "DSS1" (4) | version u8 | cipher u8 | nonce(24) | ciphertext | tag(16)
/// ```
/// - AEAD key = HKDF-SHA256(storeKey, salt: contextSalt,
///                          info: "secret_store:v1:container" ‖ cipherId)
/// - AAD      = magic ‖ version ‖ cipher ‖ contextSalt   (binds profile identity)
/// - cipher   = XChaCha20-Poly1305
///
/// The raw store key is never used directly as the AEAD key — HKDF gives domain
/// separation so the same keystore key could later serve other purposes without
/// cross-protocol reuse.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../errors.dart';
import 'tlv.dart';

const List<int> _magic = [0x44, 0x53, 0x53, 0x31]; // "DSS1"
const int _version = 1;
const int _cipherXChaCha20Poly1305 = 1;
const int _nonceLength = 24;
const int _tagLength = 16;
const int _headerLength = 6; // magic(4) + version(1) + cipher(1)

/// Seals/opens the whole-store TLV payload under a 32-byte store key.
///
/// [contextSalt] binds the container to a caller identity (dune passes its
/// profile UUID): it is both the HKDF salt and part of the AEAD AAD, so a
/// container moved between profiles fails authentication even under a shared
/// key. Pass an empty list for a context-free container.
final class Container {
  Container({required List<int> contextSalt})
      : _contextSalt = Uint8List.fromList(contextSalt);

  final Uint8List _contextSalt;
  final _aead = Xchacha20.poly1305Aead();
  final Random _rng = Random.secure();

  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _hkdfInfo = Uint8List.fromList([
    ...utf8.encode('secret_store:v1:container'),
    _cipherXChaCha20Poly1305,
  ]);

  Future<SecretKey> _deriveKey(List<int> storeKey) async {
    return _hkdf.deriveKey(
      secretKey: SecretKey(storeKey),
      nonce: _contextSalt, // HKDF salt (verified against RFC 5869 in tests)
      info: _hkdfInfo,
    );
  }

  Uint8List _aad() => Uint8List.fromList(
      [..._magic, _version, _cipherXChaCha20Poly1305, ..._contextSalt]);

  /// Encrypts [entries] into container bytes ready to write to disk.
  Future<Uint8List> seal(
    Map<String, ContainerEntry> entries,
    List<int> storeKey,
  ) async {
    final plaintext = encodeTlv(entries);
    final key = await _deriveKey(storeKey);
    final nonce = Uint8List(_nonceLength);
    for (var i = 0; i < _nonceLength; i++) {
      nonce[i] = _rng.nextInt(256);
    }
    final box = await _aead.encrypt(
      plaintext,
      secretKey: key,
      nonce: nonce,
      aad: _aad(),
    );
    // magic|version|cipher | nonce | ciphertext | tag
    final out = BytesBuilder(copy: false)
      ..add(_magic)
      ..addByte(_version)
      ..addByte(_cipherXChaCha20Poly1305)
      ..add(nonce)
      ..add(box.cipherText)
      ..add(box.mac.bytes);
    return out.toBytes();
  }

  /// Decrypts container [bytes]. Throws [ContainerCorrupt] on a structurally
  /// invalid envelope and [AuthenticationFailed] on a bad key / tamper / wrong
  /// profile. Never returns partial or empty data on failure.
  Future<Map<String, ContainerEntry>> open(
    Uint8List bytes,
    List<int> storeKey,
  ) async {
    if (bytes.length < _headerLength + _nonceLength + _tagLength) {
      throw const ContainerCorrupt('too short to be a container');
    }
    for (var i = 0; i < _magic.length; i++) {
      if (bytes[i] != _magic[i]) {
        throw const ContainerCorrupt('bad magic');
      }
    }
    final version = bytes[4];
    final cipher = bytes[5];
    if (version != _version) {
      throw ContainerCorrupt('unsupported version $version');
    }
    if (cipher != _cipherXChaCha20Poly1305) {
      throw ContainerCorrupt('unsupported cipher $cipher');
    }

    final nonce = Uint8List.sublistView(
        bytes, _headerLength, _headerLength + _nonceLength);
    final cipherStart = _headerLength + _nonceLength;
    final tagStart = bytes.length - _tagLength;
    final cipherText = Uint8List.sublistView(bytes, cipherStart, tagStart);
    final tag = Uint8List.sublistView(bytes, tagStart);

    final key = await _deriveKey(storeKey);
    final List<int> plaintext;
    try {
      plaintext = await _aead.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
        secretKey: key,
        aad: _aad(),
      );
    } on SecretBoxAuthenticationError {
      throw const AuthenticationFailed();
    }
    return decodeTlv(Uint8List.fromList(plaintext));
  }
}
