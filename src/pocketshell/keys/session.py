"""``gateway ssh --key NAME``: one ssh session signed by a private, throwaway agent.

1. the vault entry is looked up (no password needed) before anything is
   asked or started;
2. the device password is read from the terminal and the key is decrypted
   into a ``bytearray`` in memory;
3. a fresh 0700 directory (``mkdtemp``) gets the agent socket and the
   key's ``.pub`` — never the private key;
4. ``ssh-agent -D -a SOCK -t LIFETIME`` starts in its own session (a
   terminal Ctrl-C does not reach it);
5. the key goes to ``ssh-add`` through an anonymous pipe passed as
   ``/dev/fd/N``, so ssh-add's stdin stays the terminal: if the key has its
   own OpenSSH passphrase, ssh-add asks for it there (``ssh-add -`` would
   make the pipe its stdin and could not prompt). The buffer is wiped as
   soon as the pipe has it;
6. ssh runs as a child with ``IdentityAgent=SOCK``, ``IdentityFile=<.pub>``
   and the hardened options (``IdentitiesOnly=yes``, ``ForwardAgent=no``);
7. when ssh exits — or on Ctrl-C, SIGTERM, SIGHUP or any error — the agent
   is killed and the directory removed. The agent's key lifetime is the
   backstop if this process is SIGKILLed.

Nothing here reaches the network except ssh itself; the gateway only
carries the encrypted SSH stream and never sees the key.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from typing import Callable, Optional, Sequence

from pocketshell.keys import crypto, prompt, store

# Seconds the key stays usable in the private agent. User authentication
# happens once, at connect (ConnectTimeout=30 bounds the setup), and the
# agent is killed when ssh exits anyway; this bounds the window in which
# another process of the same user could use the agent socket, and is the
# cleanup backstop if this process is SIGKILLed.
KEY_LIFETIME_SECONDS = 120
AGENT_START_TIMEOUT = 10.0


class KeySessionError(Exception):
    """Could not set up the key session. Message is safe to print."""


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise KeySessionError(f"OpenSSH `{name}` was not found on PATH (needed for --key)")
    return os.path.abspath(found)


def _start_agent(agent: str, sock: str, lifetime: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [agent, "-D", "-a", sock, "-t", str(lifetime)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + AGENT_START_TIMEOUT
    while not os.path.exists(sock):
        if proc.poll() is not None:
            err = proc.stderr.read().decode("utf-8", "replace").strip() if proc.stderr else ""
            raise KeySessionError(f"ssh-agent failed to start: {err[-300:] or 'no output'}")
        if time.monotonic() > deadline:
            raise KeySessionError("ssh-agent did not create its socket in time")
        time.sleep(0.02)
    return proc


def _stop_agent(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        proc.wait()
    if proc.stderr is not None:
        proc.stderr.close()


def _add_key(ssh_add: str, sock: str, key: bytearray, env: dict) -> None:
    rfd, wfd = os.pipe()

    def feed() -> None:
        try:
            view = memoryview(key)
            while view:
                view = view[os.write(wfd, view) :]
        except OSError:
            pass  # ssh-add died early; its exit status says why
        finally:
            os.close(wfd)

    writer = threading.Thread(target=feed, daemon=True)
    add_env = dict(env)
    add_env["SSH_AUTH_SOCK"] = sock
    try:
        writer.start()
        try:
            rc = subprocess.call(
                [ssh_add, "-q", f"/dev/fd/{rfd}"],
                env=add_env,
                pass_fds=(rfd,),
                stdout=subprocess.DEVNULL,
            )
        finally:
            os.close(rfd)
            writer.join(10)
    finally:
        crypto.wipe(key)
    if rc != 0:
        raise KeySessionError(
            "ssh-add could not load the key into the session agent "
            "(wrong key passphrase, or a key type this OpenSSH does not support)"
        )


class _Signals:
    """SIGTERM/SIGHUP handling for the whole key session.

    Before ssh runs, either signal unwinds this process through its
    ``finally`` (agent killed, directory removed) instead of dying on the
    spot. While ssh runs they are forwarded to ssh, and SIGINT/SIGQUIT are
    ignored here like system(3) does: the terminal delivers them to ssh,
    which owns them.
    """

    def __init__(self) -> None:
        self.child: Optional[subprocess.Popen] = None
        self._previous: dict = {}

    def _handle(self, signum, _frame):
        if self.child is not None and self.child.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.child.send_signal(signum)
            return
        raise SystemExit(128 + signum)

    def __enter__(self) -> "_Signals":
        for sig in (signal.SIGTERM, signal.SIGHUP):
            self._previous[sig] = signal.signal(sig, self._handle)
        return self

    def __exit__(self, *exc) -> None:
        for sig, handler in self._previous.items():
            signal.signal(sig, handler)

    def run(self, argv: Sequence[str], env: dict) -> int:
        """Run ssh in the foreground; its exit status (128+N for signal N)."""
        # Ignore only AFTER the spawn: ignored dispositions survive exec, and
        # ssh must keep the default SIGINT (Ctrl-C while connecting).
        self.child = subprocess.Popen(list(argv), env=env)
        quiet = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGQUIT)}
        try:
            rc = self.child.wait()
        finally:
            for sig, handler in quiet.items():
                signal.signal(sig, handler)
        return 128 - rc if rc < 0 else rc


def run_ssh_with_vault_key(
    name: str,
    build_argv: Callable[[str, str], list[str]],
    env: dict,
    *,
    lifetime: int = KEY_LIFETIME_SECONDS,
    notice: Callable[[str], None] = lambda _msg: None,
) -> int:
    """Decrypt vault key ``name``, run ssh via a private agent, clean up.

    ``build_argv(agent_socket, public_key_file)`` returns the full ssh argv.
    """
    if os.name != "posix":
        raise KeySessionError("--key is not supported on this platform yet; use -i KEYFILE")
    entry = store.load().get(name)
    agent_bin = _tool("ssh-agent")
    add_bin = _tool("ssh-add")
    password = prompt.read_password(f"Device password for key {name!r}: ")
    key = crypto.decrypt_into(entry.envelope, password, entry.aad)
    del password
    workdir: Optional[str] = None
    agent: Optional[subprocess.Popen] = None
    signals = _Signals().__enter__()
    try:
        workdir = tempfile.mkdtemp(prefix="pocketshell-key-")
        os.chmod(workdir, 0o700)
        sock = os.path.join(workdir, "agent.sock")
        pub = os.path.join(workdir, "key.pub")
        fd = os.open(pub, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(entry.public.line + "\n")
        argv = build_argv(sock, pub)
        agent = _start_agent(agent_bin, sock, lifetime)
        if entry.passphrase_protected:
            notice(f"Key {name!r} also has its own passphrase; ssh-add will ask for it.")
        _add_key(add_bin, sock, key, env)
        return signals.run(argv, env)
    finally:
        crypto.wipe(key)
        _stop_agent(agent)
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
        signals.__exit__()


def run_vault_key_ssh(name: str, argv: list[str], env: dict) -> int:
    """`gateway ssh --key NAME`: the CLI boundary around :func:`run_ssh_with_vault_key`.

    ``argv`` is the hardened ssh argv built without ``-i``; it is narrowed
    to the vault key with :func:`pocketshell.gateway.sshcmd.with_identity_agent`.
    """
    import click

    from pocketshell.gateway import sshcmd

    try:
        return run_ssh_with_vault_key(
            name,
            lambda sock, pub: sshcmd.with_identity_agent(argv, sock, pub),
            env,
            notice=lambda msg: click.echo(msg, err=True),
        )
    except (
        KeySessionError,
        store.VaultError,
        crypto.VaultCryptoError,
        prompt.PromptError,
        sshcmd.SshArgsError,
    ) as exc:
        raise click.ClickException(str(exc)) from None
