"""Trusted enrollment: local host facts + account-unlocked vault only.

The relay cannot authorize a key or supply trusted fingerprints. Publishing
ciphertext precedes local authorization, so an interrupted registration can
leave an unavailable entry but cannot silently grant new server access.
"""
from __future__ import annotations

import getpass
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pocketshell.account import credentials
from pocketshell.account.errors import AccountError, CredentialsUnsafe, NotLoggedIn
from pocketshell.account.shared_vault import SharedVault, VaultError, b64, parse, unb64, wire
from pocketshell.gateway import endpoint, pins


def default_config_dir() -> Path:
    root = os.environ.get("XDG_CONFIG_HOME")
    return (Path(root) if root and os.path.isabs(root) else Path.home() / ".config") / "pocketshell-link"


def read_private(path: Path, limit=65536) -> bytes:
    """No symlinks, unsafe owner/mode, reparse points, or oversized records."""
    if sys.platform == "win32":
        from pocketshell.windows_security import read_private as read_windows_private
        return read_windows_private(path, limit)
    for parent in (path.parent,):
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise VaultError("The local enrollment directory is not protected by its owner.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() \
                or st.st_mode & 0o077 or st.st_nlink != 1:
            raise VaultError("The local enrollment file is not owner-private.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise VaultError("The local enrollment file is too large.")
        return data
    finally:
        os.close(fd)


def read_enrollment_config(path: Path) -> bytes:
    """The public helper config uses the gateway's native authority contract.

    Windows helper-created config files may also grant SYSTEM/Administrators
    access. The private device PEM and vault trust records retain read_private's
    stricter owner-only storage contract.
    """
    if sys.platform != "win32":
        return read_private(path)
    from pocketshell.gateway.service_common import ServiceError
    from pocketshell.gateway.service_windows import WindowsApi
    api = WindowsApi()
    sid = api.current_sid()
    try:
        api.path_authority(str(path), sid, role="private", protected=True)
        data = api.read_private_file(str(path), sid, 65536)
    except ServiceError:
        raise VaultError("The local gateway config is not protected by its owner.") from None
    if data is None:
        raise VaultError("The local gateway config is missing.")
    return data


def local_identity(config_dir: Path) -> dict:
    config = parse(read_enrollment_config(config_dir / "config.json").decode("utf-8"))
    server, device = config.get("server"), config.get("device_id")
    if server != endpoint.DEFAULT_SERVER or not isinstance(device, str) \
            or not endpoint.DEVICE_ID_RE.fullmatch(device):
        raise VaultError("Trusted vault registration requires the PocketShell production gateway and a valid local enrollment.")
    host = pins.parse_host_key(config.get("ssh_host_key", ""))
    private = serialization.load_pem_private_key(read_private(config_dir / "device_ed25519.pem"), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise VaultError("The local device identity is not Ed25519.")
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"serverUrl": server, "deviceId": device, "sshHostKey": host.line,
            "devicePublicKey": b64(public), "config": config}


def local_user() -> str:
    if sys.platform == "win32":
        value = getpass.getuser()
    else:
        import pwd
        value = pwd.getpwuid(os.getuid()).pw_name
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value):
        raise VaultError("The local SSH account name is unsupported.")
    return value


def same_local_identity(config_dir: Path, expected: dict):
    current = local_identity(config_dir)
    if any(current[k] != expected[k] for k in ("serverUrl", "deviceId", "sshHostKey", "devicePublicKey")):
        raise VaultError("The local server identity changed. Registration was stopped.")


def write_intent(config_dir: Path, record: dict):
    """Public-only retry proof, written BEFORE the encrypted index CAS."""
    write_private_record(config_dir, "vault-enrollment-intent.json", record)


def write_private_record(config_dir: Path, filename: str, record: dict):
    if sys.platform != "win32":
        directory = config_dir.lstat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or directory.st_mode & 0o022:
            raise VaultError("The local registration directory is not protected by its owner.")
    path = config_dir / filename
    data = wire(record).encode("utf-8")
    if len(data) > 65536:
        raise VaultError("The protected local registration record is full.")
    if os.path.lexists(path):
        # Never erase unsafe, symlinked or unsupported local trust metadata.
        read_private(path)
    if sys.platform == "win32":
        from pocketshell.windows_security import write_private
        write_private(path, data)
        return
    fd, name = tempfile.mkstemp(prefix=".vault-intent-", dir=config_dir)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory_fd = os.open(config_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_intent(config_dir: Path):
    try:
        return parse(read_private(config_dir / "vault-enrollment-intent.json").decode("utf-8"))
    except FileNotFoundError:
        return None


def read_trust(config_dir: Path):
    try:
        record = parse(read_private(config_dir / "vault-enrollment-trust.json").decode("utf-8"))
    except FileNotFoundError:
        return {"v": 1, "records": {}}
    if set(record) != {"v", "records"} or type(record["v"]) is not int or record["v"] != 1 \
            or not isinstance(record["records"], dict) or len(record["records"]) > 32:
        raise VaultError("The protected local trust history is unsupported. It was not reset.")
    return record


def write_trust(config_dir: Path, record: dict):
    write_private_record(config_dir, "vault-enrollment-trust.json", record)


def trust_scope(identity: dict):
    fields = [identity[k] for k in ("accountId", "vaultId", "epoch", "serverUrl", "deviceId")]
    return hashlib.sha256(wire(fields).encode("utf-8")).hexdigest()


def descriptor_digest(envelope: dict):
    fields = [envelope[k] for k in ("v", "accountId", "vaultId", "epoch", "serverUrl", "deviceId", "revision", "n", "ct")]
    return hashlib.sha256(wire(fields).encode("utf-8")).hexdigest()


def accepted_trust(config_dir: Path, identity: dict):
    history = read_trust(config_dir)
    floor = history["records"].get(trust_scope(identity))
    if floor is None:
        return history, None
    if not isinstance(floor, dict) or set(floor) != set(identity) | {"keyId", "revision", "state", "digest"} \
            or any(type(floor.get(k)) is not type(v) or floor[k] != v for k, v in identity.items()) \
            or type(floor["revision"]) is not int or not 1 <= floor["revision"] < 2**53 \
            or floor["state"] not in ("active", "revoking", "revoked") \
            or not isinstance(floor["digest"], str) or not re.fullmatch(r"[a-f0-9]{64}", floor["digest"]) \
            or not isinstance(floor["keyId"], str):
        raise VaultError("The protected server trust identity or name changed, or its format is unsupported.")
    unb64(floor["keyId"], 16)
    return history, floor


def remember_trust(config_dir: Path, history: dict, identity: dict, *, key_id: str,
                   envelope: dict, state: str):
    scope = trust_scope(identity)
    if scope not in history["records"] and len(history["records"]) >= 32:
        raise VaultError("The protected server trust history is full; no local key was changed.")
    previous = history["records"].get(scope)
    revision, digest = envelope["revision"], descriptor_digest(envelope)
    if previous is not None:
        if revision < previous["revision"] or (revision == previous["revision"] and digest != previous["digest"]) \
                or (previous["state"] in ("revoking", "revoked") and state == "active"):
            raise VaultError("The local server trust history refuses rollback or revival of a revoked key.")
        if previous["state"] == "revoked" and state == "revoking":
            state = "revoked"
    history["records"][scope] = {**identity, "keyId": key_id, "revision": revision, "state": state, "digest": digest}
    write_trust(config_dir, history)


@contextmanager
def registration_lock(config_dir: Path):
    """Serialize this endpoint's registration and local key-set updates."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateMutexW
        create.argtypes, create.restype = [ctypes.c_void_p, w.BOOL, w.LPCWSTR], w.HANDLE
        wait = kernel.WaitForSingleObject
        wait.argtypes, wait.restype = [w.HANDLE, w.DWORD], w.DWORD
        release, close = kernel.ReleaseMutex, kernel.CloseHandle
        release.argtypes, release.restype = [w.HANDLE], w.BOOL
        close.argtypes, close.restype = [w.HANDLE], w.BOOL
        digest = hashlib.sha256(os.path.normcase(os.path.abspath(config_dir)).encode()).hexdigest()
        handle = create(None, False, "Global\\PocketShell.VaultRegistration." + digest)
        if not handle:
            raise VaultError("The server registration lock could not be acquired.")
        acquired = False
        try:
            # An abandoned owner may have left an intent journal. Its complete
            # identity is validated by the ordinary retry path before reuse.
            acquired = wait(handle, 0) in (0, 0x80)
            if not acquired:
                raise VaultError("Another registration is already changing this server. Try again when it finishes.")
            yield
        finally:
            if acquired:
                release(handle)
            close(handle)
    else:
        import fcntl
        path = config_dir / ".vault-registration.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077 or st.st_nlink != 1:
                raise VaultError("The local registration lock is not owner-private.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise VaultError("Another registration is already changing this server. Try again when it finishes.") from None
            yield
        finally:
            os.close(fd)


def _run(binary: str, args: list[str], data: bytes | None = None):
    from pocketshell.gateway import cli
    cli._reverify_windows_helper(binary)
    flags = 0x08000000 if sys.platform == "win32" else 0
    proc = subprocess.run([binary, *args], input=data, stdin=None if data is not None else subprocess.DEVNULL,
                          capture_output=True, timeout=180, creationflags=flags)
    if proc.returncode != 0:
        raise VaultError("The local PocketShell endpoint operation was refused; no cloud command was executed.")
    return proc.stdout


def authorize_public_key(binary: str, config_dir: Path, public: str, *, revoke=False):
    """Only a locally unlocked key can reach this local authorization path."""
    from pocketshell.gateway import cli
    if sys.platform == "win32":
        api, runner = cli._api_runner()
        agent = cli._agent
        binding, _manifest, host_key = agent.load_binding(api=api, runner=runner, revalidate=True)
        if os.path.normcase(os.path.abspath(binding["configDir"])) != os.path.normcase(os.path.abspath(config_dir)) \
                or host_key.line != local_identity(config_dir)["sshHostKey"]:
            raise VaultError("The Windows endpoint binding does not match this server registration.")
        operation = "vault-" + os.urandom(12).hex()
        fn = agent.revoke_key_command if revoke else agent.authorize_key_command
        document, code = fn(public, api=api, runner=runner, operation_id=operation, confirmed=True)
        if code or not document.get("ok"):
            raise VaultError("The owner-private Windows endpoint refused the vault public key change.")
        return
    from pocketshell.gateway.cli import build_gateway_auth_argv
    identity = local_identity(config_dir)
    if not identity["config"].get("ssh_exec") or identity["config"].get("ssh_host"):
        raise VaultError("Vault registration requires the private SSH endpoint, never system SSH.")
    target = config_dir / "managed_authorized_keys"
    try:
        current = read_private(target).decode("utf-8")
    except FileNotFoundError:
        current = ""
    lines = []
    for line in current.splitlines():
        if line.strip():
            lines.append(pins.parse_host_key(line).line)
    if revoke:
        lines = [line for line in lines if line != public]
    elif public not in lines:
        lines.append(public)
    args = build_gateway_auth_argv("set", config_dir=str(config_dir), policy="managed",
                                   keys_stdin=True, as_json=True)
    _run(binary, args, ("\n".join(lines) + "\n").encode("utf-8"))


def unlock_for_registration(*, prompt, vault_factory=SharedVault) -> SharedVault:
    vault = vault_factory(credentials.load())
    try:
        status = vault.status()
        new = status.get("kdf") is None and not status.get("hasVerifier")
        passphrase = prompt("Create a strong vault passphrase" if new else "Vault passphrase")
        if passphrase is None:
            raise VaultError("Registration cancelled; no SSH key was authorized.")
        if new:
            confirm = prompt("Confirm vault passphrase")
            if confirm is None or confirm != passphrase:
                raise VaultError("The vault passphrases did not match; no SSH key was authorized.")
            vault.create(passphrase, status)
        else:
            vault.unlock(passphrase, status)
        return vault
    except BaseException:
        vault.close()
        raise


def ensure_login():
    """The registration command continues the normal device flow itself."""
    try:
        return credentials.require_session()
    except CredentialsUnsafe:
        raise
    except NotLoggedIn:
        from pocketshell.account.config import resolve_broker_url
        from pocketshell.account.device import default_label, login
        return login(resolve_broker_url(), label=default_label())


def publish(vault: SharedVault, *, binary: str, config_dir: Path, name: str | None = None, revoke=False):
    """Shared CLI/tray implementation. Authenticated vault descriptor is authoritative."""
    with registration_lock(config_dir):
        return _publish(vault, binary=binary, config_dir=config_dir, name=name, revoke=revoke)


def _publish(vault: SharedVault, *, binary: str, config_dir: Path, name: str | None, revoke: bool):
    identity = local_identity(config_dir)
    server, device = identity["serverUrl"], identity["deviceId"]
    alias = name or device
    user = local_user()
    _slot, version, old, old_envelope = vault.read_descriptor_record(server=server, device=device)
    expected_intent = {"v": 1, "accountId": vault.account_id, "vaultId": vault.header["vaultId"],
                       "epoch": vault.header["epoch"], "serverUrl": server, "deviceId": device,
                       "hostAlias": alias, "username": user, "sshHostKey": identity["sshHostKey"],
                       "devicePublicKey": identity["devicePublicKey"]}
    history, floor = accepted_trust(config_dir, expected_intent)
    intent = read_intent(config_dir) if floor is None else None
    if intent is not None:
        expected_fields = set(expected_intent) | {"keyId", "phase"}
        if set(intent) != expected_fields or type(intent.get("v")) is not int or intent["v"] != 2 \
                or intent.get("phase") != "pending" \
                or any(type(intent.get(k)) is not type(v) or intent[k] != v
                       for k, v in expected_intent.items() if k != "v"):
            raise VaultError("The pending enrollment identity changed or uses legacy metadata without a trust floor. Explicit migration is required.")
        unb64(intent["keyId"], 16)
    if floor is not None:
        if floor["state"] in ("revoking", "revoked") and not revoke:
            raise VaultError("This server was revoked locally. Ordinary registration cannot revive its key.")
        if old is None:
            raise VaultError("A previously accepted server trust record is missing. Local history was preserved.")
        if version < floor["revision"] or (version == floor["revision"]
                and descriptor_digest(old_envelope) != floor["digest"]) or old["keyId"] != floor["keyId"]:
            raise VaultError("The cloud server record rolled back or changed previously accepted trust.")
    if old is not None:
        if any(old[k] != expected_intent[k] for k in ("hostAlias", "username", "sshHostKey", "devicePublicKey")):
            raise VaultError("The server's trusted identity or name changed. Explicit rotation is required.")
        if old["status"] == "revoked" and not revoke:
            remember_trust(config_dir, history, expected_intent, key_id=old["keyId"],
                           envelope=old_envelope, state="revoked")
            raise VaultError("This server was revoked. Explicit re-registration is required.")
    if old is None and alias in vault.index["hosts"]:
        expected = {**expected_intent, "v": 2, "phase": "pending", "keyId": vault.index["hosts"][alias]["keyId"]}
        if intent != expected:
            raise VaultError("This name already has a vault key without trusted enrollment. Choose a different server name.")
    if revoke and old is None:
        raise VaultError("This server has no authenticated vault registration to revoke.")
    if revoke and alias not in vault.index["hosts"]:
        raise VaultError("The revoked server's original vault binding is missing; no new key was created.")
    kid, public = vault.ensure_key(alias, before_bind=lambda key_id:
                                   write_intent(config_dir, {**expected_intent, "v": 2,
                                                             "phase": "pending", "keyId": key_id}))
    values = {"hostAlias": alias, "username": user, "keyId": kid, "sshHostKey": identity["sshHostKey"],
              "devicePublicKey": identity["devicePublicKey"], "status": "revoked" if revoke else "active"}
    vault.check_identity()
    vault.confirm_binding(alias, kid)
    same_local_identity(config_dir, identity)
    if revoke:
        # Durable intent FIRST. A conflict, crash, lost response or replay after
        # removal must never make ordinary registration re-authorize this key.
        remember_trust(config_dir, history, expected_intent, key_id=kid,
                       envelope=old_envelope, state="revoking")
        # Actual authorization goes first: stale cloud records cannot keep this key usable.
        authorize_public_key(binary, config_dir, public, revoke=True)
    envelope = vault.descriptor(server=server, device=device, values=values)
    # This survives process restart and is independent of replayable storage.
    # It is persisted before authorization, including first acceptance.
    remember_trust(config_dir, history, expected_intent, key_id=kid,
                   envelope=envelope, state="revoked" if revoke else "active")
    vault.check_identity()
    vault.confirm_binding(alias, kid)
    same_local_identity(config_dir, identity)
    if not revoke:
        authorize_public_key(binary, config_dir, public)
    return {"server": alias, "deviceId": device, "status": values["status"]}


def bound_windows_endpoint():
    """Use measured, owner-bound paths; never infer a tray's config from HOME."""
    from pocketshell.gateway import cli
    api, runner = cli._api_runner()
    binding, _manifest, _host_key = cli._agent.load_binding(api=api, runner=runner, revalidate=True)
    if binding.get("enrolled") is False or not binding.get("helper") or not binding.get("configDir"):
        raise VaultError("Finish installing the PocketShell tray endpoint before vault registration.")
    return binding["helper"], Path(binding["configDir"])


def register_from_tray(prompt, *, revoke=False):
    """The tray and CLI share one crypto/publication/authorization implementation."""
    ensure_login()
    binary, directory = bound_windows_endpoint()
    vault = unlock_for_registration(prompt=prompt)
    try:
        return publish(vault, binary=binary, config_dir=directory, revoke=revoke)
    finally:
        vault.close()


def start_registered_daemon(binary: str, directory: Path):
    """Supported user service, with no rewrite/restart of an existing unit."""
    if not sys.platform.startswith("linux"):
        return
    from pocketshell.gateway import service_linux as service
    from pocketshell.gateway.service_common import ServiceError
    try:
        current = service.status()
        if current.installed:
            if not current.managed or not current.config_dir \
                    or os.path.realpath(current.config_dir) != os.path.realpath(directory) or not current.helper:
                raise VaultError("The existing gateway service belongs to a different enrollment; it was left unchanged.")
            service.resolve_helper(current.helper)
            # start is idempotent and preserves live streams of an active unit.
            for args in (service.systemctl_argv("enable", service.UNIT_NAME),
                         service.systemctl_argv("start", service.UNIT_NAME)):
                service._check(service.run_child(args), args)
        else:
            plan = service.plan_install(binary, str(directory), force=False, start=True)
            service.apply_install(plan)
        if not service.status().running:
            raise VaultError("The encrypted server registration is saved, but its background agent did not become running.")
    except ServiceError:
        raise VaultError("The encrypted server registration is saved, but the supported user service could not start. No online status was claimed.") from None


@click.command("register")
@click.option("--config-dir", type=click.Path(path_type=Path), default=None)
@click.option("--name", default=None, help="Server name shown on your phone; defaults to this device's ID.")
@click.option("--device-id", default=None, help="Name for a new server enrollment.")
@click.option("--revoke", is_flag=True, help="Remove this server's actual vault public key and publish its revocation.")
@click.option("--foreground", is_flag=True, help="Run the registered agent in the foreground, for containers without systemd.")
@click.pass_context
def register(ctx, config_dir, name, device_id, revoke, foreground):
    """Register this server for one-tap access with your encrypted account vault.

    Google device sign-in starts automatically when needed. Your strong
    vault passphrase is entered locally and never sent to PocketShell.
    Only encrypted SSH keys are synced; their public halves stay authorized
    locally on this server.
    """
    from pocketshell.gateway import cli, helper
    vault = None
    try:
        if foreground and (revoke or sys.platform == "win32"):
            raise VaultError("Foreground registration is for non-Windows server agents, not revocation.")
        ensure_login()
        if sys.platform == "win32":
            binary, directory = bound_windows_endpoint()
            if config_dir is not None and os.path.normcase(os.path.abspath(config_dir)) \
                    != os.path.normcase(os.path.abspath(directory)):
                raise VaultError("The supplied configuration differs from the owner-bound Windows endpoint.")
        else:
            binary = cli._verified_helper(ctx)
            directory = config_dir or default_config_dir()
        vault = unlock_for_registration(prompt=lambda text: click.prompt(text, hide_input=True))
        if not (directory / "config.json").exists():
            if revoke:
                raise VaultError("This server is not registered.")
            if sys.platform == "win32":
                raise VaultError("Install the owner-private PocketShell tray endpoint before registering it.")
            from pocketshell.gateway.private_endpoint import init
            args = helper.build_helper_argv("enroll", server=endpoint.DEFAULT_SERVER,
                                           config_dir=str(directory), token_stdin=True,
                                           device_id=device_id, ssh_exec=init())
            token = cli.gateway_tokens.obtain_token(cli._enroll_token_provider)
            _run(binary, args, token.encode("ascii") + b"\n")
        result = publish(vault, binary=binary, config_dir=directory, name=name, revoke=revoke)
        # Do not keep an unlocked DEK alive in the long-running daemon.
        vault.close()
        vault = None
        if not revoke:
            if foreground:
                click.echo(f"Server registered: {result['server']}; starting foreground agent.")
                args = helper.build_helper_argv("run", config_dir=str(directory))
                helper.exec_helper(binary, args)
                return
            start_registered_daemon(binary, directory)
        click.echo("Server revoked." if revoke else f"Server registered: {result['server']}. Unlock PocketShell on your phone to connect.")
    except (AccountError, ValueError, OSError, subprocess.SubprocessError) as exc:
        if isinstance(exc, AccountError):
            raise click.ClickException(str(exc)) from None
        raise click.ClickException("Registration could not complete safely; no remote command was authorized.") from None
    finally:
        if vault is not None:
            vault.close()
