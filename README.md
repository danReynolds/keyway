# secret_store

Secret storage for Dart **without Flutter**, behind one small async API with a
single input: your app id. The library gives each platform its strongest
scheme — secrets live *directly* in secure hardware where the platform offers
it (Apple's Secure Enclave), and everywhere else in one authenticated encrypted
file (XChaCha20-Poly1305) whose key is sealed in the platform's best store:
hardware-backed on Android (Keystore, TEE/StrongBox), login-bound in the OS
keychain on macOS and Linux desktops. macOS, Linux, iOS, and Android ship
today, each validated end-to-end against the real platform keystore; Windows is
the next milestone.

`flutter_secure_storage` is a Flutter plugin, so a CLI or server can't use it.
Python, Go, and Rust each have a `keyring` library; this is Dart's. Pure Dart +
FFI, no platform channels — it runs in CLIs, servers, and Flutter apps alike,
and (uniquely, as far as we know) reaches Android's hardware Keystore without
pulling in a Flutter-SDK dependency, so a headless server can still depend on
it (see [doc/design.md](doc/design.md) §12).

```dart
import 'package:secret_store/secret_store.dart';

final store = SecretStorage(appId: 'com.example.myapp');

await store.writeString('api_token', 's3cr3t', label: 'API token');
final token = await store.readString('api_token');   // 's3cr3t'
await store.delete('api_token');
```

`read`/`write` are bytes-first (`Uint8List`); `readString`/`writeString` are the
convenience tier. The core keeps values as `Uint8List` rather than routing them
through interned `String`s — though note Dart's GC can't zero heap memory, so
this is copy-minimisation, not a zeroing guarantee (see the threat model).

## How your secrets are protected

secret_store seals your data with authenticated encryption and anchors the key
in the strongest store each platform offers. `SecretStorage(appId:)` selects the
scheme for you and is **fail-closed** — with no secure home for the key, it
throws rather than silently downgrade. Every supported platform below is
validated end-to-end against the real platform keystore (simulator/emulator
for mobile) by the test suite:

| Platform (context) | Data stored in | Data encryption at rest | Key stored in | Hardware / key protection | Level |
|---|---|---|---|---|---|
| **iOS** | Data Protection Keychain (native items) | AES-256-GCM *(OS keychain)* | — *(none; data is the keychain item)* | Secure Enclave; per-item access control; device-bound | **S1**\*\* |
| **macOS** — signed + entitled | Data Protection Keychain (native items) | AES-256-GCM *(OS keychain)* | — *(none; data is the keychain item)* | Secure Enclave; device-bound | **S1**\* |
| **macOS** — CLI / unentitled | encrypted file (`0600`, atomic) | XChaCha20-Poly1305 + key commitment | login Keychain (`SecItem`) | key wrapped by the login Keychain — 3DES-CBC under a login-password key | **S3** |
| **Android** (12 / API 31+) | encrypted file (app-private) | XChaCha20-Poly1305 + key commitment | wrapped by an Android Keystore key | key sealed in hardware — TEE / StrongBox | **S1**\*\*\* |
| **Linux** — desktop | encrypted file (`0600`, atomic) | XChaCha20-Poly1305 + key commitment | Secret Service (`secret-tool`) | key wrapped by GNOME Keyring (AES-128-CBC) / KWallet (Blowfish), login-derived | **S3** |

### Not supported yet (upcoming milestones)

| Platform | Planned scheme | Today |
|---|---|---|
| **Windows** | encrypted file; key in DPAPI / Credential Manager (**S3**) | throws a typed `KeystoreUnreachable` |
| **Linux / servers — headless** | encrypted file; key TPM-sealed via `systemd-creds` (**S1**) — full design in [doc/headless-implementation-plan.md](doc/headless-implementation-plan.md); a prototype was validated against real `systemd-creds` and is kept in git history | throws a typed `KeystoreUnreachable` (headless [can't be safely auto-detected](doc/headless-implementation-plan.md), so it will be its own explicit entry point) |

**Security level** (full scale in [doc/design.md](doc/design.md)):

- **S1 — hardware-bound.** The key (or the data itself) is sealed in secure
  hardware — Secure Enclave, StrongBox, or TPM. A stolen disk, laptop, or backup
  is useless offline: the attacker needs that exact device.
- **S3 — login-bound.** The key sits in the OS keychain under a
  login-password-derived key: safe from other local users and casual theft;
  against a stolen disk, only as strong as the login password. Note the *data* is
  still XChaCha20-Poly1305 — modern AEAD, and *stronger* than the legacy cipher
  the OS keychain would apply to the secret itself.

S1 assumes the platform's secure hardware is present **and** a device lock is set
— a passcode (iOS), a Secure Enclave (Apple-silicon or T2 Macs), or a
hardware-backed Keystore (most, not all, Android devices). Where it isn't, the
same code runs but the key falls to that platform's software protection;
`describe()` reports the level actually in effect.

\* Both macOS branches are validated: the refusal path (−34018 → the file
scheme, never a silent fallback) in CI on every push, and the entitled-app
**success** path — which needs a signed, provisioned bundle CI can't produce —
end-to-end via the `example_flutter/` host app (Keychain Sharing + a
development team; the resolver picks native items and reports
`hardwareBacked`). That leg is local-only (signing identity required); the
repeatable recipe is
[tool/dp_keychain_verification.md](tool/dp_keychain_verification.md).
\*\* No probe on iOS — the DP keychain is the only keychain there, and every
app can use it. Full round-trip validated on the iOS simulator (in the
pure-Dart-FFI design it needs zero CocoaPods plugins). The simulator has no
real Secure Enclave, so the **hardware** property itself (S1) is pending a
one-time on-device run.
\*\*\* Requires **Android 12 (API 31)+** — the floor at which Android exports
JNI VM discovery to apps, which is what lets this stay pure `dart:ffi` with
**no plugin, no platform channels, and no Flutter-SDK-requiring dependency**
(decision record: [doc/design.md](doc/design.md) §12). Older Android throws a
typed error rather than degrading. The key-encryption key is generated
`setUserAuthenticationRequired(false)` (the reliability-first profile),
StrongBox when present (TEE otherwise), and every store creation runs a
**wrap→unwrap self-test** before anything is persisted. Validated end-to-end
on an API 33 emulator (real AndroidKeyStore; StrongBox-fallback branch
included); as with iOS, the S1 hardware property itself is pending a one-time
physical-device run. See **Android notes** below for backup exclusion.

Every row is **authenticated**: a wrong or mismatched key, or any tampering,
fails closed *before* decryption (the key-commitment header). The two macOS rows
are chosen automatically — the library tries the Data Protection keychain, and
`errSecMissingEntitlement` (−34018) → the file path; success → the Secure
Enclave; **any other error → a loud failure**, never a silent downgrade.

### Android notes

**Exclude the store from backups.** The wrapping key lives in your device's
hardware and **never migrates** — data restored onto another device (cloud
backup or device-to-device transfer) cannot be decrypted, and the library
reports that loudly as a typed `KeyInvalidated` rather than silently starting
an empty store. Excluding the store's directory from backup avoids both that
confusing restore experience and shipping your ciphertext around. Security does
**not** depend on this step — restored blobs are useless without the original
device — and since this is a plain Dart package (not a plugin), it cannot
inject manifest rules for you; add them to your app (API 31+ mechanism):

```xml
<!-- AndroidManifest.xml -->
<application android:dataExtractionRules="@xml/data_extraction_rules" …>
```

```xml
<!-- res/xml/data_extraction_rules.xml — <appId> is the id you pass to
     SecretStorage(appId:) -->
<data-extraction-rules>
  <cloud-backup><exclude domain="file" path="<appId>/" /></cloud-backup>
  <device-transfer><exclude domain="file" path="<appId>/" /></device-transfer>
</data-extraction-rules>
```

The `example_flutter/` harness app carries these rules as a living example.
**Key loss is loud, not silent:** `KeyInvalidated` also covers OS/OEM key
eviction and blob corruption; recovery is deleting the store's data directory
and re-provisioning the secrets.

## Threat model

**Protects against** plaintext key material on disk (backup / Time-Machine /
dotfile-sync leaks), offline disk theft without full-disk encryption, other local
users, casual disclosure (scrollback, `ps` argv), and a wrong or swapped store key
(key-committing container — fails closed before decryption).

**Does not protect against** same-user malware while the keystore is unlocked;
process-memory disclosure, including swap and core dumps (Dart-heap buffers
cannot be zeroed; the package's own native staging buffers *are* zeroed, but
decrypted copies in the GC heap remain); rollback to an older genuine container
(out of scope — AEAD is not anti-rollback; closing it would need a
keystore-anchored counter, a possible v2); concurrent writes from multiple
*processes* (in-process handles serialize on a per-file lock; across processes a
container is single-writer — don't run two writers); timing side-channels in
pure-Dart crypto; root. There is **no key escrow** — losing the key store item
loses the store.

**macOS: know your trust unit.** Keychain ACLs bind to the *acting binary*.
Under `dart run` that binary is the shared Dart VM, so one "Always Allow"
authorizes every Dart script you ever run to read the item silently. For
production, `dart compile exe` and sign with a stable Developer ID — the ACL
then binds to your app and survives upgrades. A locked keychain in a headless/CI
context surfaces as a typed error rather than hanging on a GUI unlock prompt.

The bar is ssh-agent / aws-vault, not an HSM. Full derivation and the crypto/FFI
engineering practices are in [doc/design.md](doc/design.md).

## Requirements

- Dart SDK ≥ 3.6.
- **Desktop/server:** macOS or Linux (Windows planned). Linux needs
  `secret-tool` (Debian/Ubuntu: `libsecret-tools`) and a Secret Service
  provider (GNOME Keyring or KWallet ≥ 5.97).
- **Mobile (inside a Flutter app):** iOS, or Android 12 (API 31)+.
- One third-party runtime dependency, exact-pinned: `cryptography`. The full
  runtime closure is `{cryptography, ffi, collection, crypto, meta, typed_data}`
  — everything but `cryptography` is dart-lang official, and a test fails CI if
  the tree changes.

## Cryptography

XChaCha20-Poly1305 (AEAD) container with an HKDF-derived **key-commitment**
header (wrong key ≠ tamper, and multi-key ciphertext games fail closed);
HKDF-SHA256 key derivation; `Random.secure()`
only. All via `package:cryptography` (exact-pinned, concrete `Dart*`
implementations constructed directly so the global `Cryptography.instance`
locator cannot swap them), exercised against RFC 8439 / RFC 5869 /
draft-arciszewski vectors plus empty-AAD and block-boundary edge cases in this
package's own suite, so a buggy or compromised dependency update cannot pass
silently. A CI canary fails when a newer `cryptography` release appears, so
the pin moves only by reviewed decision.

## Testing

The testing bar is **every supported platform exercised against its real
keystore** (simulator/emulator count for mobile), repeatably, from the suite —
not mocks. Three commands:

```sh
./tool/test.sh          # format + analyze + unit + this-machine keystore integration
./tool/test_linux.sh    # Linux Secret Service tier, against real gnome-keyring in Docker
./tool/test_e2e.sh      # the FULL real-platform matrix (add --entitled for the DP path)
```

- **Unit tier** (crypto vectors against RFC 8439 / 5869, container fuzzing,
  POSIX permissions on the real filesystem, backend logic over fakes, the
  dependency-closure firewall) — hermetic, needs no keystore.
- **Desktop keystore integration** — the real macOS login Keychain and the
  real Linux Secret Service (opt-in `SECRET_STORE_INTEGRATION=1`,
  platform-gated `@TestOn`; the Linux tier runs against a real gnome-keyring in
  a container so you can regression-test it from a Mac).
- **Real-platform e2e matrix** (`tool/test_e2e.sh`) — the public
  `SecretStorage(appId:)` from inside a real app bundle on macOS, an iOS
  simulator (native DP items), and an Android emulator (Keystore-wrapped),
  booting/tearing down devices automatically; `--entitled` adds the signed
  macOS DP-success leg (applies and restores a signing overlay).

**In CI on every push:** the unit tier + desktop keystore integration (macOS
and Linux). The mobile/entitled legs need device toolchains and a signing
identity, so they run **locally on demand** via `tool/test_e2e.sh` (CI runners
for the emulators are a planned addition); the entitled macOS leg stays local
by nature. The manual fallback for the DP-success path is
[tool/dp_keychain_verification.md](tool/dp_keychain_verification.md).

One honest boundary: on a simulator/emulator the secure hardware is
*software-emulated*, so these prove the real keystore **code path** executes
end-to-end, not that physical silicon mediated it — the S1 hardware claim on
mobile still wants a one-time on-device run.

## Status

Pre-1.0 and not yet published to pub.dev; the API and on-disk container format
may still change before 1.0. **Shipping today** (each validated end-to-end
against its real keystore): macOS — both CLI and signed/entitled — Linux, iOS,
and Android 12+. **Not supported yet:** Windows (next) and headless servers,
both of which fail closed with a typed error until they land. Report
vulnerabilities per [SECURITY.md](SECURITY.md); the design rationale is in
[doc/design.md](doc/design.md) and [doc/architecture.md](doc/architecture.md),
and a benchmark against best-in-class secret storage across ecosystems (native
iOS/Android, `flutter_secure_storage`, React Native, and the Rust/Python/Go
keyring peers) is in [doc/ecosystem-comparison.md](doc/ecosystem-comparison.md).

## License

MIT.
