/// Identifier and label validation (RFC 0005 §4).
///
/// A single grammar across every backend beats per-backend escaping rules.
/// Service and key names are constrained to a conservative charset (they become
/// keystore attributes and, on Linux, `secret-tool` argv); labels are
/// human-readable metadata (shown in Keychain Access / Seahorse) so they allow
/// spaces and printable text but reject control characters and are length-capped.
library;

final RegExp _identifier = RegExp(r'^[A-Za-z0-9._/-]{1,120}$');

/// Validates a service or key name. Throws [ArgumentError] on violation.
void validateIdentifier(String value, String field) {
  if (!_identifier.hasMatch(value)) {
    throw ArgumentError.value(
      value,
      field,
      'must match [A-Za-z0-9._/-] and be 1..120 chars',
    );
  }
}

/// Validates an optional label: no control characters (guards against terminal
/// / log / keystore-UI injection), at most 256 code units. Spaces and general
/// printable text are allowed. Throws [ArgumentError] on violation.
void validateLabel(String? label) {
  if (label == null) return;
  if (label.length > 256) {
    throw ArgumentError.value(label, 'label', 'must be at most 256 characters');
  }
  for (final unit in label.codeUnits) {
    if (unit < 0x20 || unit == 0x7f) {
      throw ArgumentError.value(
          label, 'label', 'must not contain control characters');
    }
  }
}
