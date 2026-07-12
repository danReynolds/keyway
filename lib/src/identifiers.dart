/// Identifier and label validation (see doc/design.md).
///
/// A single grammar across every backend beats per-backend escaping rules.
/// Service and key names are constrained to a conservative charset (they become
/// keystore attributes and, on Linux, `secret-tool` argv); labels are
/// human-readable metadata (shown in Keychain Access / Seahorse) so they allow
/// spaces and printable text but reject control characters (C0, DEL, and C1)
/// and are length-capped.
///
/// Validation errors deliberately do **not** echo the offending value: a
/// caller that transposes `(key, secret)` arguments must not find the secret
/// reproduced in an exception message or a log line.
library;

final RegExp _identifier = RegExp(r'^[A-Za-z0-9._/-]{1,120}$');

// Unlike key names, an appId names a *directory* (and the keystore service),
// so its grammar excludes `/` entirely and requires at least one alphanumeric
// — which rejects `.` and `..`. A valid appId is therefore a single,
// traversal-proof path segment by construction, not by filtering.
final RegExp _appId = RegExp(r'^[A-Za-z0-9._-]{1,120}$');
final RegExp _hasAlnum = RegExp(r'[A-Za-z0-9]');

/// Validates a service or key name. Throws [ArgumentError] on violation
/// (without echoing the value).
void validateIdentifier(String value, String field) {
  if (!_identifier.hasMatch(value)) {
    throw ArgumentError('$field must be 1..120 characters from [A-Za-z0-9._/-] '
        '(got ${value.length} character${value.length == 1 ? '' : 's'})');
  }
}

/// Validates an application id (e.g. `com.example.myapp`). Stricter than
/// [validateIdentifier]: no `/`, and at least one letter or digit, so the id
/// can never traverse out of the data directory it names. Throws
/// [ArgumentError] on violation (without echoing the value).
void validateAppId(String value) {
  if (!_appId.hasMatch(value) || !_hasAlnum.hasMatch(value)) {
    throw ArgumentError(
        'appId must be 1..120 characters from [A-Za-z0-9._-] and contain at '
        'least one letter or digit '
        '(got ${value.length} character${value.length == 1 ? '' : 's'})');
  }
}

/// Validates an optional label: printable text with spaces, no control
/// characters (C0, DEL, or C1 — guards terminal/log/keystore-UI injection;
/// C1 includes escape introducers such as U+009B CSI), at most 256 code
/// units. Throws [ArgumentError] on violation (without echoing the value).
void validateLabel(String? label) {
  if (label == null) return;
  if (label.length > 256) {
    throw ArgumentError(
        'label must be at most 256 characters (got ${label.length})');
  }
  for (final unit in label.codeUnits) {
    // Code units are UTF-16, so 0x80..0x9f only ever matches genuine C1
    // controls: every other non-ASCII character encodes as code units
    // >= 0xa0 or as surrogates (>= 0xd800).
    if (unit < 0x20 || unit == 0x7f || (unit >= 0x80 && unit <= 0x9f)) {
      throw ArgumentError('label must not contain control characters');
    }
  }
}
