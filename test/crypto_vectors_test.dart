@Tags(['unit'])
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

/// Vector firewall (RFC 0005 §4a): the pinned `cryptography` implementation is
/// checked against published standard test vectors *in our own suite*, so a
/// silently-buggy or compromised dependency update cannot pass unnoticed. These
/// also confirm the primitives run in a pure-Dart CLI (no Flutter, no native
/// accelerator) and pin the library's parameter semantics (e.g. that HKDF's
/// `nonce` argument is the salt — verified against the vector, not trusted from
/// a doc comment).
void main() {
  group('XChaCha20-Poly1305 AEAD (draft-arciszewski-xchacha-03 §A.3.1)', () {
    // The canonical "sunscreen" test vector.
    final key = _hex(
      '808182838485868788898a8b8c8d8e8f'
      '909192939495969798999a9b9c9d9e9f',
    );
    final nonce = _hex('404142434445464748494a4b4c4d4e4f5051525354555657');
    final aad = _hex('50515253c0c1c2c3c4c5c6c7');
    final plaintext = _hex(
      '4c616469657320616e642047656e746c656d656e206f662074686520636c6173'
      '73206f66202739393a204966204920636f756c64206f6666657220796f75206f'
      '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73'
      '637265656e20776f756c642062652069742e',
    );
    final expectedCipher = _hex(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb'
      '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452'
      '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9'
      '21f9664c97637da9768812f615c68b13b52e',
    );
    final expectedTag = _hex('c0875924c1c7987947deafd8780acf49');

    final algo = Xchacha20.poly1305Aead();

    test('encrypt reproduces the published ciphertext + tag', () async {
      final box = await algo.encrypt(
        plaintext,
        secretKey: SecretKey(key),
        nonce: nonce,
        aad: aad,
      );
      expect(box.cipherText, expectedCipher);
      expect(box.mac.bytes, expectedTag);
    });

    test('decrypt recovers the plaintext', () async {
      final clear = await algo.decrypt(
        SecretBox(expectedCipher, nonce: nonce, mac: Mac(expectedTag)),
        secretKey: SecretKey(key),
        aad: aad,
      );
      expect(clear, plaintext);
    });

    test('a one-bit ciphertext flip fails authentication', () async {
      final tampered = Uint8List.fromList(expectedCipher)..[0] ^= 0x01;
      expect(
        () => algo.decrypt(
          SecretBox(tampered, nonce: nonce, mac: Mac(expectedTag)),
          secretKey: SecretKey(key),
          aad: aad,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });

    test('wrong AAD fails authentication (AAD is bound)', () async {
      final wrongAad = Uint8List.fromList(aad)..[0] ^= 0x01;
      expect(
        () => algo.decrypt(
          SecretBox(expectedCipher, nonce: nonce, mac: Mac(expectedTag)),
          secretKey: SecretKey(key),
          aad: wrongAad,
        ),
        throwsA(isA<SecretBoxAuthenticationError>()),
      );
    });
  });

  group('HKDF-SHA256 (RFC 5869 Test Case 1)', () {
    test('deriveKey reproduces the published OKM; nonce==salt confirmed', () async {
      final ikm = _hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = _hex('000102030405060708090a0b0c');
      final info = _hex('f0f1f2f3f4f5f6f7f8f9');
      final expectedOkm = _hex(
        '3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );

      final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 42);
      final derived = await hkdf.deriveKey(
        secretKey: SecretKey(ikm),
        nonce: salt, // library's `nonce` == HKDF salt — asserted by the vector
        info: info,
      );
      expect(await derived.extractBytes(), expectedOkm);
    });
  });
}

Uint8List _hex(String s) {
  assert(s.length.isEven);
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
