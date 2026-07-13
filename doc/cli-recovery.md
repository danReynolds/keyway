# Keyway CLI store recovery

This procedure is for an unreadable `keyway-cli` store. It is intentionally
manual: Keyway never deletes or replaces ciphertext it cannot authenticate.

## Before changing anything

1. Stop other Keyway processes.
2. Unlock the login Keychain (macOS) or Secret Service collection (Linux), run
   `keyway doctor`, and retry. A locked Linux collection can look like a
   missing store key.
3. If a backup exists, restore the encrypted container and its matching
   keystore item as a pair. Either half alone is insufficient.

Do not run `keyway set` against an unreadable existing container. It cannot
recover lost key material, and Keyway deliberately fails closed.

## Preserve an abandoned container

If recovery is impossible and you deliberately choose to re-provision, move
the entire application-data directory aside first. Do not delete it:

### macOS

```sh
mv "$HOME/Library/Application Support/keyway-cli" \
  "$HOME/Library/Application Support/keyway-cli.unreadable.$(date +%Y%m%d%H%M%S)"
```

Only after preserving the directory, remove the unmatched login-Keychain item
if it still exists:

```sh
security delete-generic-password -s keyway-cli -a store-key
```

### Linux

```sh
data_home="${XDG_DATA_HOME:-$HOME/.local/share}"
mv "$data_home/keyway-cli" \
  "$data_home/keyway-cli.unreadable.$(date +%Y%m%d%H%M%S)"
```

Only after preserving the directory, remove the unmatched Secret Service item
if it still exists:

```sh
secret-tool clear -- service keyway-cli account store-key
```

These commands are destructive to the active store identity. Re-read the
paths and service name before running them. Afterward, `keyway set` provisions
a new store; old ciphertext remains preserved but is unreadable without its
original key.

## Permission failures

Keyway accepts no group/other access on its store:

- directories: `chmod 700 PATH`
- container and lock files: `chmod 600 PATH`

Use the exact path printed by Keyway. Do not weaken the check or move the store
to network storage; atomic replacement and advisory locking require local
application-data storage.

## Scheme migration

`MigrationRequired` means the same app ID now resolves to a different physical
storage scheme. Keep both stores intact. Use the last known working binary to
read each required value only into a deliberately scoped process, write it
through the new binary, verify the application, and only then preserve and
retire the old store. Keyway does not automate this because a wrong migration
decision can strand the only readable copy.
