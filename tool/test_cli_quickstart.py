#!/usr/bin/env python3
"""Execute the README quickstart against the compiled product and a real store."""

from __future__ import annotations

import errno
import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import termios
import time


KEY = "acme-example/openai-api-key"
PROMPT = f"Value for {KEY} (input hidden): ".encode()
TIMEOUT = 10.0


def wait_for(fd: int, needle: bytes) -> bytes:
    deadline = time.monotonic() + TIMEOUT
    output = bytearray()
    while needle not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"timed out waiting for {needle!r}: {bytes(output)!r}")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        output.extend(chunk)
    if needle not in output:
        raise AssertionError(f"process ended before {needle!r}: {bytes(output)!r}")
    return bytes(output)


def read_remaining(fd: int) -> bytes:
    deadline = time.monotonic() + 1.0
    output = bytearray()
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.05)
        if not readable:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def interactive_set(executable: str, cwd: str, secret: bytes) -> bytes:
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execl(executable, executable, "set", KEY)

    output = wait_for(master, PROMPT)
    if termios.tcgetattr(master)[3] & termios.ECHO:
        raise AssertionError("terminal echo remained enabled at the real set prompt")
    os.write(master, secret + b"\n")
    output += wait_for(master, b"Stored.")
    _, status = os.waitpid(pid, 0)
    output += read_remaining(master)
    os.close(master)
    exit_code = os.waitstatus_to_exitcode(status)
    if exit_code != 0:
        raise AssertionError(f"interactive set exited {exit_code}: {output!r}")
    if secret in output:
        raise AssertionError("the quickstart secret appeared in prompt output")
    return output


def run_checked(arguments: list[str], cwd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} KEYWAY QUICKSTART_DIR", file=sys.stderr)
        return 2

    executable = os.path.abspath(sys.argv[1])
    source = os.path.abspath(sys.argv[2])
    secret = f"keyway-quickstart-secret-{os.getpid()}".encode()

    with tempfile.TemporaryDirectory(prefix="keyway-quickstart-example.") as tmp:
        repo = os.path.join(tmp, "quickstart")
        shutil.copytree(source, repo)
        shutil.copyfile(
            os.path.join(repo, "secrets.env.example"),
            os.path.join(repo, ".secrets.env"),
        )

        missing = run_checked([executable, "run", "--", "./verify.sh"], repo)
        if missing.returncode != 78:
            raise AssertionError(f"initial run exited {missing.returncode}: {missing.stderr}")
        if f"keyway set {KEY}" not in missing.stderr:
            raise AssertionError(f"initial run omitted remediation: {missing.stderr!r}")
        if missing.stdout:
            raise AssertionError(f"failed run launched or wrote data: {missing.stdout!r}")

        interactive_set(executable, repo, secret)

        success = run_checked([executable, "run", "--", "./verify.sh"], repo)
        if success.returncode != 0:
            raise AssertionError(f"second run exited {success.returncode}: {success.stderr}")
        if success.stdout != "Keyway quickstart passed.\n" or success.stderr:
            raise AssertionError(
                f"unexpected quickstart output: {success.stdout!r} {success.stderr!r}"
            )

        listed = run_checked([executable, "list"], repo)
        if listed.returncode != 0 or KEY not in listed.stdout.splitlines():
            raise AssertionError(f"stored key not listed: {listed.stdout!r} {listed.stderr!r}")

        removed = run_checked([executable, "rm", KEY], repo)
        if removed.returncode != 0 or removed.stdout or removed.stderr:
            raise AssertionError(f"rm was not silent/idempotent: {removed!r}")
        removed_again = run_checked([executable, "rm", KEY], repo)
        if removed_again.returncode != 0 or removed_again.stdout or removed_again.stderr:
            raise AssertionError(f"second rm was not silent/idempotent: {removed_again!r}")

    print("CLI README quickstart passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
