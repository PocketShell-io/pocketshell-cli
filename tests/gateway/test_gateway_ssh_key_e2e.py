"""End to end: vault key → `gateway ssh --key` → private ssh-agent → real sshd.

Reuses the real-sshd / fake-gateway / fake-broker fixtures of
test_gateway_connect_e2e.py. Every pocketshell step runs as a subprocess on
a real pseudo-terminal that is its controlling TTY, so the device password
travels exactly as a user's would: typed at the `/dev/tty` prompt, never in
argv or the environment. Covered:

- a generated vault key (no own passphrase) logs in;
- an imported key WITH its own OpenSSH passphrase: ssh-add asks on the
  terminal (answered through the pty) — and, separately, through
  SSH_ASKPASS + SSH_ASKPASS_REQUIRE=force (test-only plumbing);
- a wrong device password fails before ssh, sshd never sees a login;
- after every run no agent process and no socket directory remain, and no
  private key bytes were written anywhere under the test's TMPDIR/HOME/XDG.
"""

from __future__ import annotations

import fcntl
import getpass
import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

import pytest

import test_gateway_connect_e2e as base

# The real-sshd / fake-gateway / logged-in fixtures, re-exported for pytest.
sshd = base.sshd
gateway = base.gateway
logged_in = base.logged_in
DEVICE = base.DEVICE
_env = base._env
_pin = base._pin

pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("ssh", "ssh-keygen", "ssh-agent", "ssh-add")),
    reason="OpenSSH client tools unavailable",
)

DEVICE_PW = "e2e-device-password"
KEY_PP = "e2e-key-passphrase"


class PtyRun:
    """A pocketshell subprocess whose controlling terminal is a fresh pty."""

    def __init__(self, argv, env, cwd):
        self.master, slave = pty.openpty()

        def make_ctty():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen(
            argv, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=cwd, preexec_fn=make_ctty,
        )
        os.close(slave)
        self.screen = b""

    def _pump(self, timeout):
        r, _, _ = select.select([self.master], [], [], timeout)
        if r:
            try:
                data = os.read(self.master, 4096)
            except OSError:  # EIO: every slave fd closed
                return False
            self.screen += data
            return bool(data)
        return True

    def answer(self, prompt: bytes, reply: str, timeout=30):
        """Wait until ``prompt`` is on the terminal, then type ``reply``."""
        deadline = time.monotonic() + timeout
        while prompt not in self.screen:
            if time.monotonic() > deadline or not self._pump(0.1):
                raise AssertionError(f"no {prompt!r} on the terminal; got {self.screen!r}")
        # The prompt is written before echo is turned off and input flushed;
        # give the reader a moment to reach its read().
        time.sleep(0.2)
        os.write(self.master, reply.encode() + b"\n")
        self.screen = self.screen.replace(prompt, b"<answered>", 1)

    def finish(self, timeout=60):
        deadline = time.monotonic() + timeout
        while self.proc.poll() is None and time.monotonic() < deadline:
            self._pump(0.1)
        if self.proc.poll() is None:
            self.proc.kill()
            raise AssertionError(f"timed out; terminal: {self.screen!r}")
        out, err = self.proc.communicate()
        while self._pump(0):
            pass
        os.close(self.master)
        return self.proc.returncode, out, err


@pytest.fixture
def short_tmp():
    base = tempfile.mkdtemp(prefix="pke", dir="/tmp")
    yield Path(base)
    shutil.rmtree(base, ignore_errors=True)


def _user_env(tmp_path, short_tmp, **extra) -> dict:
    env = _env(tmp_path)
    env["TMPDIR"] = str(short_tmp)
    env.update(extra)
    return env


def _run(tmp_path, short_tmp, *args, answers=(), **extra_env):
    run = PtyRun(
        [sys.executable, "-m", "pocketshell", *args],
        _user_env(tmp_path, short_tmp, **extra_env), tmp_path,
    )
    for prompt, reply in answers:
        run.answer(prompt, reply)
    return run.finish()


def _authorize(sshd_fixture, pub_line: str) -> None:
    path = Path(sshd_fixture["client_key"]).parent / "sshd" / "authorized_keys"
    with open(path, "a") as fh:
        fh.write(pub_line.strip() + "\n")


def _ssh_key(tmp_path, short_tmp, gateway, name, *command, answers=(), **env):
    return _run(
        tmp_path, short_tmp,
        "gateway", "ssh", DEVICE, "-l", getpass.getuser(), "--key", name,
        "--server", f"ws://127.0.0.1:{gateway['port']}", "--insecure-dev",
        "--trust-gateway", "127.0.0.1", "--", *command,
        answers=answers, **env,
    )


def _no_leftovers(short_tmp):
    assert list(short_tmp.iterdir()) == []  # socket dir removed
    agents = subprocess.run(["pgrep", "-f", str(short_tmp)], capture_output=True)
    assert agents.stdout == b"", "an ssh-agent outlived the session"


def _scan_for(roots, needles):
    hits = []
    for root in roots:
        for dirpath, _d, files in os.walk(root):
            for f in files:
                p = os.path.join(dirpath, f)
                try:
                    data = open(p, "rb").read()
                except OSError:
                    continue
                if any(n in data for n in needles):
                    hits.append(p)
    return hits


def test_generated_vault_key_logs_in_through_the_gateway(
    tmp_path, short_tmp, sshd, gateway, logged_in
):
    _pin(tmp_path, sshd["host_pub"])
    rc, out, err = _run(
        tmp_path, short_tmp, "keys", "generate", "lab",
        answers=[(b"New device password", DEVICE_PW), (b"Repeat", DEVICE_PW)],
    )
    assert rc == 0, err
    pub_line = out.decode().strip()
    _authorize(sshd, pub_line)

    rc, out, err = _ssh_key(
        tmp_path, short_tmp, gateway, "lab", "echo", "vault-key-ok",
        answers=[(b"Device password for key 'lab'", DEVICE_PW)],
    )
    assert rc == 0, err
    assert out == b"vault-key-ok\n"
    _no_leftovers(short_tmp)
    # The default ~/.ssh identities were never offered: the only key that
    # can work is the vault one (-i absent, IdentitiesOnly=yes).
    assert not any((tmp_path / "home" / ".ssh").glob("id_*"))

    # Wrong device password: refused before ssh, gateway never contacted again.
    before = gateway["seen"]["connections"]
    rc, out, err = _ssh_key(
        tmp_path, short_tmp, gateway, "lab", "echo", "must-not-run",
        answers=[(b"Device password for key 'lab'", "wrong-password")],
    )
    assert rc == 1
    assert b"wrong device password" in err
    assert b"must-not-run" not in out
    assert gateway["seen"]["connections"] == before
    _no_leftovers(short_tmp)


def _imported_passphrase_key(tmp_path, short_tmp, sshd):
    src = tmp_path / "src" / "id_pp"
    src.parent.mkdir()
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", KEY_PP, "-C", "pp", "-f", str(src)],
        check=True,
    )
    _authorize(sshd, (src.parent / "id_pp.pub").read_text())
    rc, out, err = _run(
        tmp_path, short_tmp, "keys", "add", "pp", "--from", str(src),
        answers=[(b"New device password", DEVICE_PW), (b"Repeat", DEVICE_PW)],
    )
    assert rc == 0, err
    assert b"has its own passphrase" in out
    secret = src.read_bytes()
    body = b"".join(secret.split(b"\n")[1:-2])
    # Remove the source so a later scan only finds copies WE might have made.
    src.unlink()
    return [body[:64], body[-64:]]


def test_key_with_own_passphrase_is_prompted_on_the_terminal(
    tmp_path, short_tmp, sshd, gateway, logged_in
):
    _pin(tmp_path, sshd["host_pub"])
    needles = _imported_passphrase_key(tmp_path, short_tmp, sshd)
    rc, out, err = _ssh_key(
        tmp_path, short_tmp, gateway, "pp", "echo", "both-secrets-ok",
        answers=[
            (b"Device password for key 'pp'", DEVICE_PW),
            (b"Enter passphrase", KEY_PP),  # ssh-add, on the same terminal
        ],
    )
    assert rc == 0, err
    assert out == b"both-secrets-ok\n"
    assert b"also has its own passphrase" in err
    _no_leftovers(short_tmp)
    # The vault file holds the key only as ciphertext; nothing else on disk has it.
    roots = [tmp_path, short_tmp]
    assert _scan_for(roots, needles) == []


def test_key_with_own_passphrase_via_askpass(tmp_path, short_tmp, sshd, gateway, logged_in):
    _pin(tmp_path, sshd["host_pub"])
    _imported_passphrase_key(tmp_path, short_tmp, sshd)
    askpass = tmp_path / "askpass"
    askpass.write_text(f"#!/bin/sh\necho '{KEY_PP}'\n")
    askpass.chmod(0o700)
    rc, out, err = _ssh_key(
        tmp_path, short_tmp, gateway, "pp", "echo", "askpass-ok",
        answers=[(b"Device password for key 'pp'", DEVICE_PW)],
        SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force",
    )
    assert rc == 0, err
    assert out == b"askpass-ok\n"
    _no_leftovers(short_tmp)

    # A wrong key passphrase: ssh-add says "Bad passphrase, try again" and
    # asks until it gets an empty answer (a user presses Enter) — then fails;
    # ssh never runs, cleanup still happens.
    state = tmp_path / "askpass-called"
    askpass.write_text(
        f"#!/bin/sh\nif [ -e {state} ]; then echo; else touch {state}; echo wrong; fi\n"
    )
    rc, out, err = _ssh_key(
        tmp_path, short_tmp, gateway, "pp", "echo", "must-not-run",
        answers=[(b"Device password for key 'pp'", DEVICE_PW)],
        SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE="force",
    )
    assert rc == 1, err
    assert b"ssh-add could not load the key" in err
    assert b"must-not-run" not in out
    _no_leftovers(short_tmp)


def test_plain_identity_file_still_works(tmp_path, short_tmp, sshd, gateway, logged_in):
    """-i keeps its old exec path (OpenSSH reads the file itself)."""
    _pin(tmp_path, sshd["host_pub"])
    rc, out, err = _run(
        tmp_path, short_tmp,
        "gateway", "ssh", DEVICE, "-l", getpass.getuser(), "-i", str(sshd["client_key"]),
        "--server", f"ws://127.0.0.1:{gateway['port']}", "--insecure-dev",
        "--trust-gateway", "127.0.0.1", "--", "echo", "identity-ok",
    )
    assert rc == 0, err
    assert out == b"identity-ok\n"
