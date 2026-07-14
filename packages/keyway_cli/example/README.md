# Keyway CLI examples

These are all examples of the CLI process boundary:

- [`quickstart`](quickstart): the packaged language-neutral acceptance path
- [`flutter`](flutter): inject a test credential into a Flutter widget test
- [`rails`](rails): boot a Rails application and run application code
- [`node`](node): start a Node HTTP service

Each example contains a manifest template with public configuration and
`kw://` references only. Copy it to `.secrets.env` as instructed; every
developer supplies their own values through the local Keyway store. The
examples use different qualified namespaces, so their disposable values do
not bleed into one another.

## Choose the executable first

For an installed release, install the native executable and follow Dart's
`PATH` notice if it prints one:

```sh
dart install keyway_cli
keyway --version
```

For the current source checkout, do not install a stale snapshot. Resolve the
workspace and define the source runner once from the repository root:

```sh
dart pub get
alias keyway="$PWD/tool/keyway-dev"
```

Then enter any example directory and use the same command name:

```sh
cd packages/keyway_cli/example/flutter
keyway --version
```

`keyway-dev` runs the current source with the root package configuration while
preserving the example directory as the manifest directory. On macOS, the
shared Dart VM is the Keychain trust unit for this source mode; the signed
installed binary has its own stable identity. The runner is contributor
tooling, not a sixth CLI command and not part of a release archive.

Dart also supports global activation from the local package path:

```sh
dart pub global activate --source path packages/keyway_cli
```

That is convenient when global state and Pub's dependency-resolution output on
each invocation are acceptable. It can shadow an installed release; remove it
with `dart pub global deactivate keyway_cli`. The repository-local runner above
is the quieter default for source development.

Now follow the selected README. Run every command from that example directory;
Keyway deliberately reads only its manifest and never searches parents.
Remove the disposable value with the documented `keyway rm` command when
finished.
