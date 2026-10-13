"""``pocketshell keys …``: the device-password-protected SSH key vault.

See docs/keys.md. Every command that writes a private key into the vault,
or reads one out of it, asks for the device password on the terminal;
``list`` / ``public`` / ``remove`` need no password (they only touch the
public metadata, and anyone who can write the file can delete it anyway).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional

import click

from pocketshell.keys import crypto, prompt, sshkeys, store


def _fail(exc: Exception) -> click.ClickException:
    return click.ClickException(str(exc))


_ERRORS = (
    store.VaultError,
    crypto.VaultCryptoError,
    prompt.PromptError,
    sshkeys.KeyFormatError,
)


def _password_for(vault: store.Vault, *, verb: str) -> str:
    """The existing device password (verified), or a new one for an empty vault."""
    if not vault.entries:
        click.echo(
            "The key vault is empty: choose a device password. It never leaves this "
            "device and cannot be recovered; without it the vault's keys are lost.",
            err=True,
        )
        return prompt.read_new_password()
    password = prompt.read_password(f"Device password (to {verb}): ")
    store.verify_password(vault, password)
    return password


def _read_key_source(source: str) -> bytearray:
    limit = sshkeys.MAX_KEY_FILE_BYTES
    buf = bytearray(limit + 1)
    if source == "-":
        stream = click.get_binary_stream("stdin")
        n = 0
        while n <= limit:
            got = stream.readinto(memoryview(buf)[n:])
            if not got:
                break
            n += got
    else:
        try:
            with open(source, "rb", buffering=0) as fh:
                n = 0
                while n <= limit:
                    got = fh.readinto(memoryview(buf)[n:])
                    if not got:
                        break
                    n += got
        except OSError as exc:
            crypto.wipe(buf)
            raise sshkeys.KeyFormatError(
                f"cannot read {source} ({os.strerror(exc.errno or 0)})"
            ) from None
    if n > limit:
        crypto.wipe(buf)
        raise sshkeys.KeyFormatError("file is too large to be an SSH private key")
    out = bytearray(memoryview(buf)[:n])
    crypto.wipe(buf)
    return out


def _companion_pub(source: str) -> Optional[str]:
    if source == "-":
        return None
    try:
        with open(source + ".pub", encoding="ascii") as fh:
            return fh.read(16 * 1024)
    except (OSError, UnicodeDecodeError):
        return None


@click.group("keys")
def keys_group() -> None:
    """SSH keys kept on this device, encrypted with a device password.

    The private keys never leave this device and PocketShell's servers
    never hold them. `pocketshell gateway ssh DEVICE --key NAME` uses one
    through a private, short-lived ssh-agent. See docs/keys.md.
    """


@keys_group.command("add")
@click.argument("name")
@click.option(
    "--from", "source", required=True, metavar="FILE",
    help="OpenSSH/PEM private key to import ('-' reads stdin). A key with its own "
    "passphrase stays encrypted with it.",
)
def add(name: str, source: str) -> None:
    """Import a private key into the vault under NAME."""
    try:
        store.validate_name(name)
        if store.load().entries.get(name) is not None:
            raise store.VaultError(f"a key named {name!r} already exists; remove it first")
        key = _read_key_source(source)
        try:
            pub_line = _companion_pub(source)
            try:
                info = sshkeys.inspect_private_key(key, pub_line)
            except sshkeys.KeyFormatError:
                if pub_line is None:
                    raise
                # A stale or unrelated .pub next to the file: ignore it.
                info = sshkeys.inspect_private_key(key)
            public = info.public
            if not public.comment:
                public = sshkeys.PublicKey(public.key_type, public.blob, name)
            with store.locked() as txn:
                if name in txn.vault.entries:
                    raise store.VaultError(f"a key named {name!r} already exists; remove it first")
                password = _password_for(txn.vault, verb="add a key")
                txn.vault.entries[name] = store.new_entry(
                    name, public, info.passphrase_protected, key, password
                )
                path = txn.commit()
        finally:
            crypto.wipe(key)
    except _ERRORS as exc:
        raise _fail(exc) from None
    click.echo(f"added {name}: {public.fingerprint} ({public.key_type})"
               + (", has its own passphrase" if info.passphrase_protected else ""))
    click.echo(f"vault: {path}", err=True)
    if source != "-":
        click.echo(
            f"{source} was not modified. Delete it if the vault should hold the only copy.",
            err=True,
        )


@keys_group.command("generate")
@click.argument("name")
@click.option(
    "--type", "key_type", type=click.Choice(sorted(sshkeys.GENERATE_TYPES)), default="ed25519",
    show_default=True, help="Key type (ecdsa is P-256, rsa is 4096 bits).",
)
@click.option("--comment", default=None, help="Comment on the public key (default: NAME).")
def generate(name: str, key_type: str, comment: Optional[str]) -> None:
    """Generate a new key in memory and store it in the vault under NAME.

    Prints the public key line for the server's authorized_keys.
    """
    try:
        store.validate_name(name)
        if store.load().entries.get(name) is not None:
            raise store.VaultError(f"a key named {name!r} already exists; remove it first")
        with store.locked() as txn:
            if name in txn.vault.entries:
                raise store.VaultError(f"a key named {name!r} already exists; remove it first")
            password = _password_for(txn.vault, verb="add a key")
            private, public = sshkeys.generate(key_type, name if comment is None else comment)
            txn.vault.entries[name] = store.new_entry(name, public, False, private, password)
            del private
            txn.commit()
    except _ERRORS as exc:
        raise _fail(exc) from None
    click.echo(f"generated {name}: {public.fingerprint} ({public.key_type})", err=True)
    click.echo(public.line)


@keys_group.command("list")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def list_keys(as_json: bool) -> None:
    """List the vault's keys (public metadata only; no password needed)."""
    try:
        vault = store.load()
    except _ERRORS as exc:
        raise _fail(exc) from None
    entries = sorted(vault.entries.values(), key=lambda e: e.name)
    if as_json:
        click.echo(json.dumps({"keys": [
            {
                "name": e.name,
                "type": e.public.key_type,
                "fingerprint": e.public.fingerprint,
                "passphrase_protected": e.passphrase_protected,
                "public_key": e.public.line,
            }
            for e in entries
        ]}, indent=2, sort_keys=True))
        return
    if not entries:
        click.echo("the key vault is empty (add one with `pocketshell keys generate NAME`)")
        return
    rows = [("NAME", "TYPE", "FINGERPRINT", "OWN PASSPHRASE")]
    rows += [
        (e.name, e.public.key_type, e.public.fingerprint, "yes" if e.passphrase_protected else "no")
        for e in entries
    ]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    for r in rows:
        click.echo("  ".join(r[i].ljust(widths[i]) for i in range(3)) + "  " + r[3])


@keys_group.command("public")
@click.argument("name")
def public(name: str) -> None:
    """Print NAME's public key line (for the server's authorized_keys)."""
    try:
        entry = store.load().get(name)
    except _ERRORS as exc:
        raise _fail(exc) from None
    click.echo(entry.public.line)


@keys_group.command("remove")
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Do not ask for confirmation.")
def remove(name: str, yes: bool) -> None:
    """Delete NAME from the vault. There is no undo."""
    try:
        entry = store.load().get(name)
        if not yes:
            if not sys.stdin.isatty():
                raise store.VaultError("refusing to remove a key without --yes (no terminal)")
            click.confirm(
                f"Permanently delete key {name!r} ({entry.public.fingerprint})?", abort=True
            )
        with store.locked() as txn:
            txn.vault.get(name)
            del txn.vault.entries[name]
            txn.commit()
    except _ERRORS as exc:
        raise _fail(exc) from None
    click.echo(f"removed {name}: {entry.public.fingerprint}")


@keys_group.command("passwd")
def passwd() -> None:
    """Change the device password (re-encrypts every key in the vault)."""
    try:
        with store.locked() as txn:
            if not txn.vault.entries:
                raise store.VaultError(
                    "the key vault is empty; the password is chosen when the first key is added"
                )
            old = prompt.read_password("Current device password: ")
            store.verify_password(txn.vault, old)
            new = prompt.read_new_password()
            txn.vault.entries = {
                n: store.rewrap(e, old, new) for n, e in txn.vault.entries.items()
            }
            txn.commit()
            count = len(txn.vault.entries)
    except _ERRORS as exc:
        raise _fail(exc) from None
    click.echo(f"device password changed; re-encrypted {count} key(s)")
