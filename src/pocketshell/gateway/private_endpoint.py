"""Per-user OpenSSH inetd endpoint. No TCP listener or system service."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


class EndpointError(ValueError):
    pass


def default_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/PocketShell/endpoint"
    return Path.home() / ".local/state/pocketshell/endpoint"


def _quoted(path: Path) -> str:
    value = str(path)
    if any(c in value for c in '\n\r\x00"\\'):
        raise EndpointError("unsupported character in endpoint path")
    return '"' + value + '"'


def _private(path: Path, mode: int) -> None:
    st = path.lstat()
    if st.st_uid != os.getuid() or stat.S_ISLNK(st.st_mode) or stat.S_IMODE(st.st_mode) != mode:
        raise EndpointError(f"{path} must be owned by you with mode {mode:o}")


def init() -> list[str]:
    if sys.platform == "win32":
        raise EndpointError("Windows uses gateway agent install's private loopback endpoint")
    sshd = next((p for p in ("/usr/sbin/sshd", "/usr/local/sbin/sshd") if Path(p).is_file()), None)
    if sshd is None:
        raise EndpointError("No OpenSSH sshd binary found at /usr/sbin/sshd or /usr/local/sbin/sshd. "
                            "A portable bundled OpenSSH runtime is planned; no system service is used.")
    directory = default_dir()
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    _private(directory, 0o700)
    key = directory / "ssh_host_ed25519_key"
    if not key.exists():
        if key.with_suffix(".pub").exists():
            raise EndpointError("host public key exists without its private key; refusing replacement")
        try:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           check=True, capture_output=True, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as exc:
            raise EndpointError("Unable to generate private endpoint host key with ssh-keygen") from exc
    _private(key, 0o600)
    # Only read the public file. Never inspect/log private key material.
    public = Path(str(key) + ".pub")
    if not public.is_file() or public.is_symlink():
        raise EndpointError("private host key public file is missing or unsafe")
    authorized = directory / "authorized_keys"
    if not authorized.exists():
        fd = os.open(authorized, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    _private(authorized, 0o600)
    import pwd
    user = pwd.getpwuid(os.getuid()).pw_name
    if not user or any(c.isspace() or c in '*?![]@#\\"\r\n' for c in user):
        raise EndpointError("unsupported account name")
    config = directory / "sshd_config"
    content = "\n".join([
        f"HostKey {_quoted(key)}",
        f"AuthorizedKeysFile {_quoted(Path.home() / '.ssh/authorized_keys')} {_quoted(authorized)}",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
        "PermitRootLogin no", "UsePAM no", "StrictModes yes", "PidFile none",
        "Subsystem sftp internal-sftp", "LogLevel ERROR", f"AllowUsers {user}",
        "AllowTcpForwarding local", "GatewayPorts no", "X11Forwarding no",
        "AllowAgentForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no", "",
    ])
    # Upgrade only the byte-identical former generated policy. User edits stay intact.
    legacy = content.replace(
        "AllowTcpForwarding local\nGatewayPorts no\nX11Forwarding no\n"
        "AllowAgentForwarding no\nAllowStreamLocalForwarding no\nPermitTunnel no\n",
        "DisableForwarding yes\n",
    )
    if not config.exists():
        fd = os.open(config, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(content)
    _private(config, 0o600)
    if config.read_bytes() == legacy.encode("utf-8"):
        # Atomic replacement retains the owner-private mode and never leaves a
        # partially rewritten config visible to a new sshd process.
        name = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory,
                                             prefix=".sshd_config-", delete=False) as f:
                name = f.name
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, config)
        finally:
            if name is not None and os.path.exists(name):
                os.unlink(name)
    return [sshd, "-i", "-f", str(config)]
