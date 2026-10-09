"""Read the device password from the controlling terminal — and only there.

Never from argv, the environment, or a redirected stdin: :func:`getpass`
silently falls back to stdin (with echo!) when there is no ``/dev/tty``;
this module refuses instead. Tests replace :func:`read_password`.
"""

from __future__ import annotations

import os

MAX_PASSWORD_BYTES = 1024
MIN_NEW_PASSWORD_CHARS = 8


class PromptError(Exception):
    """No terminal, or unreadable input. Message is safe to print."""


def read_password(prompt: str) -> str:
    """One line from ``/dev/tty`` with echo off (the trailing newline stripped)."""
    if os.name != "posix":  # pragma: no cover - the vault itself is POSIX-only today
        import getpass

        return getpass.getpass(prompt)
    import termios

    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError:
        raise PromptError(
            "the device password must be typed on a terminal, and this process has none"
        ) from None
    try:
        try:
            old = termios.tcgetattr(fd)
        except termios.error:
            raise PromptError("cannot turn off echo on the terminal") from None
        new = list(old)
        new[3] &= ~(termios.ECHO | termios.ECHONL)
        new[3] |= termios.ICANON
        os.write(fd, prompt.encode("utf-8", "replace"))
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)
        buf = bytearray()
        try:
            while b"\n" not in buf:
                chunk = os.read(fd, 256)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_PASSWORD_BYTES:
                    raise PromptError("password is too long")
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
            os.write(fd, b"\n")
        line = bytes(buf).split(b"\n", 1)[0].rstrip(b"\r")
        buf[:] = bytes(len(buf))
        try:
            return line.decode("utf-8")
        except UnicodeDecodeError:
            raise PromptError("password is not valid UTF-8") from None
    finally:
        os.close(fd)


def read_new_password() -> str:
    """Ask for a new device password twice; enforce a minimum length."""
    first = read_password("New device password for the PocketShell key vault: ")
    if len(first) < MIN_NEW_PASSWORD_CHARS:
        raise PromptError(
            f"the device password must be at least {MIN_NEW_PASSWORD_CHARS} characters"
        )
    second = read_password("Repeat the device password: ")
    if first != second:
        raise PromptError("the passwords do not match; nothing was changed")
    return first
