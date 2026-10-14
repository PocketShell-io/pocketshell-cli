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


def _openssh_version() -> tuple[int, int]:
    """(major, minor) of the installed OpenSSH, (0, 0) when unknown."""
    import re
    try:
        out = subprocess.run(["ssh", "-V"], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return (0, 0)
    match = re.search(r"OpenSSH_(\d+)\.(\d+)", out.stderr + out.stdout)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def session_env_lines(runtime_root: Path = Path("/run/user"), version: tuple[int, int] | None = None) -> list[str]:
    """The login-session variables the system sshd gets from PAM (pam_systemd).

    The private endpoint runs with UsePAM no, so without these a session has
    no XDG_RUNTIME_DIR and user services (aplexer's daemon sockets under
    /run/user/<uid>, the user D-Bus, `systemctl --user`) are unreachable.
    Server-side SetEnv needs OpenSSH 8.7+; older daemons would reject it.
    """
    if not sys.platform.startswith("linux"):
        return []
    runtime = runtime_root / str(os.getuid())
    if not runtime.is_dir():
        return []
    if (version or _openssh_version()) < (8, 7):
        return []
    values = [f"XDG_RUNTIME_DIR={runtime}"]
    if (runtime / "bus").exists():
        values.append(f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus")
    return ["SetEnv " + " ".join(values)]


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
    policy = [
        f"HostKey {_quoted(key)}",
        f"AuthorizedKeysFile {_quoted(Path.home() / '.ssh/authorized_keys')} {_quoted(authorized)}",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
        "PermitRootLogin no", "UsePAM no", "StrictModes yes", "PidFile none",
        "Subsystem sftp internal-sftp", "LogLevel ERROR", f"AllowUsers {user}",
        "AllowTcpForwarding local", "GatewayPorts no", "X11Forwarding no",
        "AllowAgentForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no",
    ]
    content = "\n".join(policy + session_env_lines() + [""])
    # Upgrade only byte-identical former generated policies. User edits stay intact.
    without_env = "\n".join(policy + [""])
    previous = {
        without_env,
        without_env.replace(
            "AllowTcpForwarding local\nGatewayPorts no\nX11Forwarding no\n"
            "AllowAgentForwarding no\nAllowStreamLocalForwarding no\nPermitTunnel no\n",
            "DisableForwarding yes\n",
        ),
    } - {content}
    if not config.exists():
        fd = os.open(config, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(content)
    _private(config, 0o600)
    if config.read_bytes() in {p.encode("utf-8") for p in previous}:
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
