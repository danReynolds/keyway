/// Binary TLV payload codec for the encrypted container (RFC 0005 §7).
///
/// This replaces JSON specifically so secret *values* never become Dart
/// `String`s (which are interned and cannot be overwritten) and so no
/// general-purpose parser runs on decrypted bytes. The layout is fixed and
/// every length is bounds-checked against the remaining buffer before use — a
/// truncated or malformed payload yields [ContainerCorrupt], never an
/// out-of-range read or a crash. It is the direct target of the fuzz test.
///
/// ```
/// entryCount : u32 (big-endian)
/// per entry (sorted by key, ascending, for canonical output):
///   keyLen   : u16   keyBytes   (UTF-8, non-secret)
///   labelLen : u16   labelBytes (UTF-8, non-secret; 0 = no label)
///   valueLen : u32   valueBytes (the secret — raw bytes)
/// ```
library;

import 'dart:convert';
import 'dart:typed_data';

import '../errors.dart';

/// One decoded container entry: the secret [value] plus its optional [label].
final class ContainerEntry {
  ContainerEntry(this.value, {this.label});

  /// Raw secret bytes. Kept as [Uint8List] end-to-end — never a `String`.
  final Uint8List value;

  /// Optional human-readable label (non-secret); shown in keystore UIs.
  final String? label;
}

/// Largest payload the decoder will accept, as a guard against a hostile or
/// corrupt length field claiming a huge allocation. Three orders of magnitude
/// above any realistic store. The container file backend applies its own
/// on-disk cap before this ever runs.
const int maxTlvBytes = 16 * 1024 * 1024;

/// Encodes [entries] into the canonical TLV byte layout. Keys are emitted in
/// ascending code-unit order so the output is deterministic.
Uint8List encodeTlv(Map<String, ContainerEntry> entries) {
  final keys = entries.keys.toList()..sort();
  final out = BytesBuilder(copy: false);
  final header = ByteData(4)..setUint32(0, keys.length);
  out.add(header.buffer.asUint8List());

  for (final key in keys) {
    final entry = entries[key]!;
    final keyBytes = utf8.encode(key);
    final labelBytes = entry.label == null ? const <int>[] : utf8.encode(entry.label!);

    if (keyBytes.length > 0xFFFF) {
      throw ArgumentError('key too long to encode: ${keyBytes.length} bytes');
    }
    if (labelBytes.length > 0xFFFF) {
      throw ArgumentError('label too long to encode: ${labelBytes.length} bytes');
    }

    final head = ByteData(2 + 2)
      ..setUint16(0, keyBytes.length)
      ..setUint16(2, labelBytes.length);
    out.add(head.buffer.asUint8List());
    out.add(keyBytes);
    out.add(labelBytes);

    final valueHead = ByteData(4)..setUint32(0, entry.value.length);
    out.add(valueHead.buffer.asUint8List());
    out.add(entry.value);
  }
  return out.toBytes();
}

/// Decodes a TLV payload produced by [encodeTlv]. Throws [ContainerCorrupt] on
/// any structural problem (short buffer, overrunning length, trailing bytes,
/// invalid UTF-8 in a key/label).
Map<String, ContainerEntry> decodeTlv(Uint8List bytes) {
  if (bytes.length > maxTlvBytes) {
    throw ContainerCorrupt('payload exceeds $maxTlvBytes bytes');
  }
  final reader = _Reader(bytes);
  final count = reader.u32();
  // A count can't imply more entries than there are bytes for; each entry is
  // at least 8 header bytes. This rejects a huge count up front.
  if (count > bytes.length ~/ 8) {
    throw ContainerCorrupt('entry count $count exceeds what the buffer can hold');
  }

  final entries = <String, ContainerEntry>{};
  for (var i = 0; i < count; i++) {
    final keyLen = reader.u16();
    final labelLen = reader.u16();
    final key = reader.utf8String(keyLen, 'key');
    final label = labelLen == 0 ? null : reader.utf8String(labelLen, 'label');
    final valueLen = reader.u32();
    final value = reader.bytes(valueLen);
    if (entries.containsKey(key)) {
      throw ContainerCorrupt('duplicate key in payload');
    }
    entries[key] = ContainerEntry(value, label: label);
  }
  if (!reader.atEnd) {
    throw ContainerCorrupt('${reader.remaining} trailing bytes after $count entries');
  }
  return entries;
}

/// A forward-only reader that bounds-checks every access.
class _Reader {
  _Reader(this._data) : _view = ByteData.sublistView(_data);

  final Uint8List _data;
  final ByteData _view;
  int _pos = 0;

  bool get atEnd => _pos == _data.length;
  int get remaining => _data.length - _pos;

  void _need(int n) {
    if (n < 0 || _pos + n > _data.length) {
      throw ContainerCorrupt(
          'read of $n bytes at offset $_pos overruns ${_data.length}-byte buffer');
    }
  }

  int u16() {
    _need(2);
    final v = _view.getUint16(_pos);
    _pos += 2;
    return v;
  }

  int u32() {
    _need(4);
    final v = _view.getUint32(_pos);
    _pos += 4;
    return v;
  }

  Uint8List bytes(int n) {
    _need(n);
    final out = Uint8List.sublistView(_data, _pos, _pos + n);
    _pos += n;
    // Copy so callers own an independent buffer they can zero, and so the
    // large plaintext buffer can be released/zeroed independently.
    return Uint8List.fromList(out);
  }

  String utf8String(int n, String field) {
    final raw = bytes(n);
    try {
      return utf8.decode(raw, allowMalformed: false);
    } on FormatException {
      throw ContainerCorrupt('invalid UTF-8 in $field');
    }
  }
}
