# Verifying the macOS Data Protection keychain (entitled success path)

On macOS the resolver picks native Data Protection keychain items (AES-256-GCM +
Secure Enclave, `hardwareBacked`) **only** for a signed app carrying a
`keychain-access-groups` entitlement authorized by a provisioning profile. Its
two other outcomes are covered automatically:

- **Refusal path** (`errSecMissingEntitlement` −34018 → the file scheme) — CI,
  every push (`keychain_integration_test.dart`, plus the resolver end-to-end).
- **Unentitled file scheme inside a real `.app`** — the `example_flutter/`
  harness, `flutter test integration_test -d macos` (no signing needed).

The **entitled success path** can't run in CI (no signing identity) and needs a
one-time local run. This is that check.

## Prerequisite (this is what blocks it)

The account holder must have accepted the **current Apple Developer Program
License Agreement**. If not, automatic provisioning fails with:

> Unable to process request - PLA Update available: … your team's Account
> Holder … must agree to the latest Program License Agreement.

Accept it at <https://developer.apple.com/account> (or App Store Connect) →
then provisioning works. Nothing in this repo can bypass this; it is a legal
agreement tied to the Apple ID.

## Procedure (~5 min; needs Xcode + a signing identity)

The permanent harness is `example_flutter/` — no throwaway app. Apply the
entitled config overlay (kept out of the default build so the unentitled leg
stays runnable), provision once, run.

1. **Signing + identity** — in `example_flutter/macos/Runner/Configs/AppInfo.xcconfig`
   add (a target-level xcconfig outranks the project's ad-hoc `CODE_SIGN_IDENTITY = "-"`):

   ```
   DEVELOPMENT_TEAM = <YOUR_TEAM_ID>
   CODE_SIGN_IDENTITY = Apple Development
   ```

2. **Entitlement** — in `example_flutter/macos/Runner/Runner/DebugProfile.entitlements`
   add (the default access group is implicit; `$(AppIdentifierPrefix)` resolves
   at sign time):

   ```xml
   <key>keychain-access-groups</key>
   <array>
     <string>$(AppIdentifierPrefix)com.example.exampleFlutter</string>
   </array>
   ```

3. **Provision once** — Flutter's build does not pass `-allowProvisioningUpdates`,
   so create the managed profile directly (registers the App ID under your team):

   ```sh
   cd example_flutter/macos
   xcodebuild build -workspace Runner.xcworkspace -scheme Runner \
     -configuration Debug -destination 'platform=macOS' -allowProvisioningUpdates
   ```

   Expected: `** BUILD SUCCEEDED **`. If it fails on the PLA, do the
   prerequisite above. If it fails with "No profiles found" *after* accepting
   the PLA, open the workspace in Xcode once so it can sign in / 2FA, then retry.

4. **Run the entitled leg** — the profile now exists locally, so `flutter test`
   reuses it:

   ```sh
   cd example_flutter
   flutter test integration_test/secret_store_test.dart -d macos \
     --dart-define=EXPECT_HARDWARE=true
   ```

   Expected: **All tests passed!** The first test (`resolver picked the scheme
   this build config must get`) asserts `backend.name == 'keystore'` and
   `level == SecurityLevel.hardwareBacked` — i.e. the DP **success** branch is
   live. A build error about "entitlements that require signing with a
   development certificate" means step 1's identity didn't take; a runtime
   `keystore_unreachable` means the entitlement/profile isn't in effect
   (recheck steps 2–3).

5. **Revert the overlay** (optional) — remove the two edits to restore the
   default ad-hoc build so the unentitled leg (`-d macos`, no dart-define) runs
   again.
