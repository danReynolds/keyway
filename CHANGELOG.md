# Changelog

## 0.1.0 (unreleased)

Initial implementation (see [doc/design.md](doc/design.md)). Not yet published.

### Fixes from a second review pass (pre-release)

Correctness / fail-closed:
- **Linux `delete()` no longer fails open on a locked collection.** The
  confirm-read that guards `secret-tool clear`'s ambiguous exit 1 used
  `lookup`, which is blind on a locked collection (exits 1 empty, identical to
  a miss) — so on a locked headless keyring, `delete()` reported success while
  the secret survived. The confirm now uses `search`, which still lists a
  matching item's attributes when its collection is locked and prints the
  `secret =` line only when unlocked (verified against real gnome-keyring):
  item still listed without its secret → typed `KeystoreLocked`; listed with
  it → `KeystoreOperationFailed`; clean no-match → idempotent success; the
  confirm itself failing → fail closed, never silent success. Pinned by
  scripted unit tests and by the locked-collection integration test against a
  real locked keyring.
- **Container header version bumped to 2.** The key-commitment field changed
  the layout without bumping the version byte, so a pre-commitment (v1)
  container surfaced as a misleading `WrongStoreKey` instead of a format
  error. v1 is now rejected as `ContainerCorrupt("unsupported version 1")` —
  the version byte doing exactly the job it exists for. (Pre-release format
  break, as before: dev containers must be recreated.)
- **Android KEK self-test cleanup no longer deletes the Keystore alias.** On a
  wrap/unwrap self-test failure, `create()` deleted the alias and blob
  "best-effort" — but that call has persisted nothing at that point, so the
  only state the cleanup could remove was a *concurrent* provisioner's healthy
  KEK and blob, escalating a documented lose-an-update race into permanent key
  loss. It now cleans up nothing and throws; a broken KEK is inert and every
  future `create()` fails just as loudly.
- **Labels now reject C1 controls** (U+0080–U+009F) alongside C0/DEL — they
  surface in keystore UIs and logs, where C1 bytes are escape introducers
  (U+009B CSI); the "rejects C0/C1" test now actually tests C1.
- **`describe()` on the file scheme can no longer throw.** `SystemKeySource`'s
  presence read is guarded: a failing get (a mangled stored value, or the
  keystore locking between probe and get) degrades into `detail` instead of
  escaping a diagnostics call — completing the contract whose macOS-probe half
  was fixed a pass earlier.
- **Apple enumeration skips foreign undecodable accounts.** One >1 KiB or
  non-UTF-8-convertible account written by another tool under the service no
  longer aborts the whole `readAll()` (parity with the Linux account parser,
  which already skipped).
- **JNI OOM hygiene.** The `PushLocalFrame`-failure and
  `GetStringUTFChars`-null paths now clear the pending `OutOfMemoryError`
  before throwing (a pending exception makes the next JNI call undefined
  behavior), and `withFrame` rejects a `Future`-returning body loudly — an
  async body would resume on dead local references.
- **Subprocess runner robustness.** Post-exit pipe drains are bounded, so a
  grandchild that inherited the pipes (outside our SIGKILL's reach) can no
  longer hang `run()` — output that arrived is still returned; and a child
  that exits just before the deadline is no longer misreported as timed out
  (`kill()`'s return value now decides).

Docs / examples / tooling:
- Honesty batch: the container and `WrongStoreKey` docs state that a tampered
  commitment *field* also reports `WrongStoreKey` (the distinction is
  one-directional) and that the deterministic commit discloses key *equality*
  across containers (never material); `MigrationRequired` documents that only
  the *gained*-entitlement direction can throw; stale wording fixed
  (`contextSalt` consumer claim, design.md's dart:io scoping, the "Android
  notes" pointers, README's "on every push"); `implementation-plan.md` carries
  a point-in-time banner; two shipped follow-ups are marked in design.md §13.
- CI: the weekly cron now runs only the canary tier (the test matrix skips
  scheduled runs — the cron exists for the crypto-pin canary, not to re-test
  unchanged code); `tool/test_e2e.sh` bails out before mutating any real
  config when its backup copy fails, and removes its backup dir on a clean
  restore.
- The README and design-doc concurrency wording now matches the implemented
  contract (the mutex is **isolate**-local, not process-wide), and the
  recorded flock-removal rationale is corrected: per-operation `flock` *would*
  have covered cross-isolate and cross-process writers alike (locks belong to
  the open file description); it was cut as unneeded surface for the
  single-writer deployment, and remains the natural follow-up.
- The locked-collection integration test requires a second opt-in
  (`SECRET_STORE_LOCKED_TEST=1`, set by CI and `tool/test_linux.sh`) so
  `tool/test.sh` on a real Linux desktop can no longer lock the developer's
  actual login keyring; `tool/test_linux.sh` now runs the locked tier too (in
  its own throwaway session), matching CI.
- The dependency-closure firewall also rejects a committed
  `pubspec_overrides.yaml` and asserts every closure package resolves from
  `hosted` — closing the silent local-override bypass.
- The raw NUL byte in `test/secret_storage_test.dart` is now the `\u0000`
  escape, so git stops treating the file as binary and its diffs are
  reviewable again.
- `example_flutter` pins `minSdk = 31` (the library's floor) instead of
  Flutter's default, so the living example can't install on devices where the
  store then fails closed.

### Fixes from a PR review pass (pre-release)

Correctness / honesty:
- **Linux locked-keyring diagnosis is honest.** `secret-tool lookup` cannot tell
  a genuinely-absent key from a collection that is locked/unreachable without a
  prompter; a present container then surfaced as `StoreKeyMissing` claiming the
  data was unrecoverable. The `StoreKeyMissing` message (and the get-path
  comment) now say to confirm the keystore is unlocked and retry before treating
  the key as lost.
- **`describe()` can no longer throw on macOS.** An unexpected `OSStatus` from
  the Apple keychain probe was propagated as `KeystoreOperationFailed`; the probe
  now reports it in `detail` instead, honoring the diagnostics-never-throw
  contract.
- **The concatenated-plaintext buffer is scrubbed** after seal/open (best-effort
  Dart-heap zeroing; native-buffer zeroing remains the load-bearing guarantee).

Docs / tests / CI:
- Concurrency contract corrected: the serialization mutex is **isolate**-local,
  not process-wide (a background isolate is a second uncoordinated writer).
- Test coverage: real-subprocess tests for `SystemProcessRunner` (timeout SIGKILL
  incl. the stdin-blocked path, launch-failure, exit codes); TLV golden wire
  vector, duplicate-key/trailing-byte rejection, empty-value round-trips; the
  fresh-key-rollback test now actually exercises the rollback (was passing
  vacuously); a vacuous "ciphertext" assertion fixed.
- CI: least-privilege `permissions`, a weekly `schedule` so the crypto-pin canary
  fires on an idle repo, `push` scoped to main to avoid double-runs; stale
  comments corrected.
- The manual DP-keychain verification procedure and the ecosystem/design docs
  were brought back in line with the shipped code (removed `service:` API,
  cut `flock`/rollback-field/`TpmKeySource`, iOS-simulator Secure Enclave); the
  committed personal iOS `DEVELOPMENT_TEAM` was scrubbed.

### Hardening from a self-review pass (pre-release)

Correctness / lifecycle:
- **A first-write crash no longer wedges the store.** If a process died between
  creating the store key and writing the first container, every later
  operation threw `ContainerMissing` with no way to recover; the mutating paths
  now heal the orphaned key by re-sealing a container under it.
- **Android JNI: attached threads are now detached.** Work run on a spawned
  isolate attached that thread to the JVM and never detached it — a thread
  exiting still-attached aborts the app (ART). We now detach any thread we
  attached (the main thread was already attached, so it's unaffected).
- **`secret-tool` delete verifies removal.** `clear`'s exit 1 is ambiguous
  (no-match *and* real failure), so a delete now confirms the item is gone
  rather than trusting the code — no silent fail-open on a locked collection.
- Android: the wrapped-key blob read cap now covers the largest valid blob, so
  a corrupt oversized blob is reported as `KeyInvalidated`, not a file error;
  the KEK self-test's cleanup can no longer mask its own diagnostic; the
  StrongBox→TEE fallback runs with ample JNI local-frame headroom.
- `describe()` never throws (a missing framework symbol on an OEM ROM yields a
  degraded status, not an exception); a value-only keychain update preserves an
  existing custom label; the subprocess hard-timeout is armed before the stdin
  write that could block.

Honest reporting & API:
- **Apple security level is now measured, not assumed** — the library probes
  for a usable Secure Enclave and reports `hardwareBacked` only when one
  exists, so an entitled app on a pre-T2 Intel Mac honestly reports
  `softwareBacked`.
- **`BackendInfo.name` (a `String`) → `BackendInfo.scheme` (`StorageScheme`
  enum)**, unifying the backend name and the migration discriminator into one
  typed value; `MigrationRequired.from`/`to` are now `StorageScheme`. The macOS
  scheme-migration guard dropped its plaintext `.scheme` marker (it could
  false-fire on a never-written store, or throw untyped on a corrupt marker) —
  a gained entitlement is detected by the existing container's presence
  instead. `SecureFileError` joined the typed `SecretStoreException` taxonomy.
- `SecurityLevel.softwareBacked` and `StorageScheme` are exported; `level` may
  now be null before an Android store's first write (documented).

### Hardening from code review (pre-release)

Correctness and honesty fixes from an external review; all now covered by
tests (unit + the real-platform e2e matrix). The cryptographic core was
unchanged — these are lifecycle/ownership and truthful-reporting fixes.

- **`describe().level` is now measured, not asserted.** Added
  `SecurityLevel.softwareBacked`. Android inspects the KEK's
  `KeyInfo.getSecurityLevel()` and reports `hardwareBacked` only for
  `TRUSTED_ENVIRONMENT`/`STRONGBOX` (emulators and software Keystores report
  `softwareBacked`). Apple native items report `hardwareBacked` as the
  platform-mechanism claim — the DP keychain has no per-item residency query
  and the simulator/pre-T2-Intel exceptions aren't detectable from pure Dart
  FFI, so they're documented with the silicon check pending an on-device run.
  The level is now owned by the key source (where the key lives), not a backend
  constant.
- **macOS entitlement changes no longer switch stores silently.** A `.scheme`
  marker records how a store was provisioned; if a later run resolves to a
  different scheme (entitlement gained/lost), the resolver throws the new typed
  **`MigrationRequired`** rather than showing an empty store or resurfacing
  stale values.
- **Oversized writes can't brick a store.** `write` now rejects a value whose
  sealed container would exceed the read cap with the new typed
  **`StoreTooLarge`**, *before* replacing the existing container (which stays
  intact and readable).
- **Same-store serialization is per container path**, not per backend object —
  two `SecretStorage(appId:)` instances in one process no longer drop each
  other's updates.
- **The macOS DP probe can no longer touch a caller's item**: it uses a
  dedicated internal service outside the public `appId` grammar and only
  removes its own probe item.
- **Linux fixes:** the `appId` reaches `secret-tool` after a `--` option
  terminator (a leading-dash id can't be parsed as a flag); and a clean account
  with no `~/.local/share` now has the XDG data hierarchy created `0700`
  instead of failing the first write.
- **Android filesystem errors are typed**: the POSIX shim resolves the errno
  symbol across libcs (`__errno_location` on glibc/musl, `__errno` on bionic)
  instead of a fixed guess.

### Android backend (pre-release)

- **Android (12 / API 31+) now resolves to the encrypted file with its key
  wrapped by an AndroidKeyStore hardware key** (AES-256-GCM KEK; StrongBox
  when present, TEE otherwise; `setUserAuthenticationRequired(false)` — the
  reliability-first profile), reported as `hardwareBacked`. Below API 31 the
  resolver throws typed guidance.
- **Pure `dart:ffi` — no plugin, no platform channels, no `package:jni`, zero
  new dependencies.** VM discovery via `libnativehelper`'s
  `JNI_GetCreatedJavaVMs` (officially app-visible at API 31+); a ~24-function
  hand-rolled JNI shim drives boot-classpath framework classes only. Decision
  record with the full alternatives analysis: doc/design.md §12. This keeps
  the package resolvable by Flutter-less CLIs/servers — the constraint every
  jni-based route breaks.
- **Write-time self-test**: every store creation wrap→unwrap→compares through
  the real Keystore before anything is persisted (fail closed on the
  broken-Keystore device tail; no silent software fallback).
- New typed error **`KeyInvalidated`**: a present wrapped-key blob whose
  Keystore key is gone or fails to unwrap (backup restored onto a different
  device — hardware keys never migrate — OS/OEM key eviction, or blob
  corruption) is reported loudly instead of silently starting an empty store.
- Container path is derived **without an Android Context** (no hidden APIs):
  `System.getProperty("java.io.tmpdir")` → `<dataDir>/files/<appId>/`.
- README "Android notes" documents **backup exclusion**
  (`dataExtractionRules`) with snippets; `example_flutter/` carries them as a
  living example. Validated end-to-end on an API 33 emulator (real
  AndroidKeyStore, StrongBox-fallback branch included).

### iOS backend (pre-release)

- **iOS now resolves to native Data Protection keychain items** — Secure
  Enclave, `hardwareBacked`. No probe (the DP keychain is the only keychain on
  iOS; every app can use it via the implicit default access group). Items are
  created `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (device-bound,
  never restored to another device, readable by background work after first
  unlock) with `synchronizable=false`.
- The macOS keychain binding was generalized to `AppleKeychainApi` (was
  `MacKeychainApi`) and loads Security.framework symbols from the process image
  on iOS (`DynamicLibrary.process()`) vs absolute-path `dlopen` on macOS — same
  SecItem code otherwise. Internal rename; the type is not exported.
- Added `example_flutter/`, a Flutter host app carrying the mobile + desktop
  integration tiers (also the living proof the package runs inside Flutter with
  **zero** CocoaPods plugins). Round-trip validated on the iOS simulator; the
  Secure-Enclave hardware property is pending a one-time on-device run.

### One-input API + per-platform resolver (pre-release; supersedes the earlier constructor surface)

- **The production surface is now exactly `SecretStorage(appId:)`.** The
  resolver derives everything from the validated `appId` and picks the
  strongest scheme per platform: on macOS a once-per-process **Data Protection
  probe** selects native Secure-Enclave keychain items for entitled apps, or
  (on `errSecMissingEntitlement` −34018 — the normal CLI result) the encrypted
  file with its key in the login Keychain; any *other* DP failure throws loud.
  Linux composes the encrypted file + Secret Service key. Anything else throws
  `KeystoreUnreachable` with guidance. `describe()` now reports a
  **`SecurityLevel`** (`hardwareBacked` / `loginBound`).
- **appId is traversal-proof by grammar** (`[A-Za-z0-9._-]{1,120}`, must
  contain an alphanumeric — no `/`, and `.`/`..` are unrepresentable), because
  it names the derived data directory
  (`~/Library/Application Support/<appId>/` on macOS,
  `${XDG_DATA_HOME:-~/.local/share}/<appId>/` on Linux) and the keystore
  service.
- **Removed** (breaking, pre-release): the `service:`/`api:` parameters,
  `SecretStorage.encryptedFile(...)`, `contextSalt`, the
  `MacKeychainApi(nonInteractive:)` knob (the fail-fast non-interactive
  behavior is now unconditional), `platformKeystore()`, and the exported
  key-source/binding/shim surface (`SystemKeySource`, `TpmKeySource`,
  `KeySource`, `MacKeychainApi`, `SecretToolApi`, `KeystoreApi`,
  `SecureFileSystem`, `ProcessRunner`, …). Public API =
  `SecretStorage` + verbs, the error taxonomy, and the
  `SecretBackend`/`BackendInfo`/`BackendCapabilities`/`SecurityLevel`
  describe/test surface.

### Headless / TPM: out of scope (pre-release)

- A `TpmKeySource` (store key wrapped by `systemd-creds`, TPM-sealed) was
  built and validated against real `systemd-creds`, then **removed from the
  tree** before release — headless is out of scope for now, and unreachable
  code in a security package is unjustified surface. The design survives in
  doc/headless-implementation-plan.md (and the implementation in git history)
  should demand appear. Headless boxes fail closed with a typed error.
- **`ProcessRunner` extracted** to `src/ffi/process_runner.dart` (was in the
  `secret-tool` file), injectable for tests.

### Key-source surface: secure-only (pre-release)

- **`KeystoreKeySource` renamed to `SystemKeySource`** (dropped the `Key…Key`
  stutter).
- **`FileKeySource` and `InMemoryKeySource` un-exported.** The insecure
  plaintext-key-on-disk source and the non-persistent test double stay in
  `src/` (reference impl + test double). Bring-your-own-key or an on-disk key is
  served by implementing the public `KeySource` interface (with the exported
  `SecureFileSystem` for 0600 hygiene) — so an insecure choice is one you write
  deliberately, never grab from autocomplete. README now documents at-rest
  protection per platform.

### Security hardening pass (pre-release; container format changed while unshipped)

- **Key commitment in the container format.** XChaCha20-Poly1305 is not
  key-committing, so the header now carries a 32-byte HKDF-derived
  key-commitment value, checked in constant time before decryption. New typed
  error `WrongStoreKey` makes "wrong key/context" reliably distinct from
  "tampered" (`AuthenticationFailed`). **Pre-release format break**: existing
  dev containers must be recreated.
- **In-process write serialization.** `EncryptedFileBackend` operations run
  under a FIFO mutex, so concurrent calls within a process never interleave
  their whole-file read-modify-write. Cross-process coordination is out of
  scope — a container is single-writer.
- **Native staging buffers zeroed** before free in the POSIX write path and
  the Keychain `CFData` path (Dart-heap memory still can't be scrubbed; FFI
  memory can, so it is).
- **Read-side permission enforcement.** Container, key file, and store
  directory are refused on *read* when group/other-accessible (OpenSSH
  stance); non-regular files (FIFO) refused; container writes now end with a
  best-effort directory fsync so the rename survives a power cut.
- **Pinned crypto implementations.** The container constructs
  `DartXchacha20`/`DartHkdf` directly instead of the `Cryptography.instance`
  factories, so a host app swapping the global instance (e.g.
  `flutter_cryptography`) cannot substitute an un-vector-tested
  implementation. Added RFC 8439 §2.8.2 vector and empty-AAD/empty-plaintext/
  block-boundary AEAD edge tests.
- **Validation hardening.** Labels reject control characters (C0/DEL) and are
  length-capped; validation errors no longer echo the offending value (a
  transposed `(key, secret)` argument pair must not leak into logs).
- **macOS.** `MacKeychainApi(nonInteractive: true)` adds per-call
  `kSecUseAuthenticationUIFail` so a locked keychain fails fast as
  `KeystoreLocked` instead of raising a GUI prompt (headless/CI). Default
  item label now matches Linux (`secret_store`).
- **CI.** Actions pinned by commit SHA; the OSV job now uses the reusable
  workflow correctly (the old `osv-scanner-action@v1` reference was dangling);
  a canary job fails when pub.dev publishes a `cryptography` release newer
  than the pin, forcing a reviewed bump.

### Austerity pass (pre-release; first-principles removal of speculative surface)

- **Cut the generation counter.** It provided no rollback protection on its own
  (a counter bound in the AAD is only tamper-evident); rollback resistance, if
  built, is a versioned v2 with a keystore-anchored counter. Removes a header
  field and the `ContainerData` wrapper — `Container.open` returns the entry
  map directly again. **Format break** (folds into the pre-release change
  above).
- **Cut the cross-process `flock`.** Removed `SecureFileSystem.tryFlockSync`,
  `AdvisoryFileLock`, the `StoreContended` error, and the `lockTimeout` option
  — surface for a race the single-writer contract avoids. The in-process mutex
  stays.
- **Cut the hand-rolled base64 codec** in favour of `dart:convert` — it was a
  maintained crypto-adjacent artifact to avoid one `String` copy the GC can't
  zero anyway. `ProcessRunner.stdin` is a `String` again (breaking for custom
  runners); subprocess *output* stays bytes for scrubbing.
- **Simplified label validation** to control-char + length (dropped the Unicode
  format/bidi-category machinery — heavier than the keystore-UI-spoof threat).

### Linux backend fixes (found by the real integration test)

- **`delete` is now idempotent against real gnome-keyring.** `secret-tool clear`
  exits 1 (not 0) when nothing matched; `delete` no longer treats that as a
  failure. The mocked unit test had encoded the wrong exit code.
- **`getAll` now enumerates correctly.** `secret-tool search` prints account
  attributes to **stderr** (secrets go to stdout); `getAll` parses stderr (and
  stdout defensively), then scrubs both. It previously scanned only stdout and
  found nothing.
- **New Linux integration test** (`test/secret_service_integration_test.dart`)
  runs under `dbus-run-session` against a real gnome-keyring in CI — verified
  locally in a Docker ubuntu container. This is what caught the two bugs above.
