# Quickstart example

This language-neutral example proves both halves of a mixed Keyway manifest:
the literal `API_URL` and the referenced `OPENAI_API_KEY` reach exactly one
child process.

From this directory:

```sh
cp secrets.env.example .secrets.env
keyway run -- ./verify.sh
keyway set acme-example/openai-api-key
keyway run -- ./verify.sh
```

The first `run` fails closed and prints the `set` command without launching the
script. Enter any disposable value at the hidden prompt. The second `run`
prints `Keyway quickstart passed.` without revealing the value.
