"""Status and lifecycle for the gateway host agent and system tray.

Implements the status contract (schema v1) defined in windows-tray.md:
- agent: local service/process check + broker presence (authoritative for connected)
- sshd: loopback reachability
- clients: established loopback TCP connections to sshd, joined with auth log + authorized_keys
- sessions: in-process aplexer session list
- state derivation: not_installed | offline | degraded | online | error
- start / stop / restart lifecycle commands
"""

from __future__ import annotations

import base64
import binascii
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Optional, Sequence, Set
import urllib.error
import urllib.request

from pocketshell.gateway import endpoint as gateway_endpoint
from pocketshell.gateway import pins as gateway_pins
from pocketshell.gateway import service_common as common
from pocketshell.gateway import tokens as gateway_tokens
from pocketshell.runtime import sessions as runtime_sessions
from pocketshell.tokentls import token_opener

CONTRACT_VERSION = 1
DEFAULT_SSHD_PORT = 22
PRESENCE_CACHE_TTL_SECONDS = 10.0
SSHD_CONNECT_TIMEOUT_SECONDS = 1.0
BROKER_TIMEOUT_SECONDS = 2.0

# RFC 3339 regex for log timestamp validation
_RFC3339_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})\Z"
)

# OpenSSH accepted authentication log regex (matches syslog, ISO, and Windows timestamps)
_AUTH_LOG_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?:127\.0\.0\.1|::1)\s+port\s+(?P<port>\d+)"
    r"(?:\s+ssh2(?::\s+(?P<keytype>\S+)\s+(?P<fingerprint>SHA256:\S+))?)?",
    re.IGNORECASE,
)
_TS_ISO_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b")
_TS_SYSLOG_RE = re.compile(r"\b([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\b")

_MONTH_NAMES = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(frozen=True)
class Presence:
    """Gateway-observed liveness of a device's host agent (advisory)."""

    online: bool
    observed_at: Optional[str] = None
    connected_since: Optional[str] = None
    session_generation: Optional[int] = None


@dataclass(frozen=True)
class SshdProcessSession:
    """Active SSHD session process discovered on the host."""

    pid: Optional[int]
    user: str
    since: Optional[str]  # UTC ISO timestamp e.g. "2026-10-13T19:25:52Z"
    cmdline: Optional[str] = None


def parse_presence(raw: object, *, revoked: bool = False) -> Optional[Presence]:
    """Lenient parse of one device's ``presence`` object; None = unknown."""
    if not isinstance(raw, dict) or not isinstance(raw.get("online"), bool):
        return None
    online = raw["online"] and not revoked
    generation = raw.get("session_generation")
    if not (
        isinstance(generation, int)
        and not isinstance(generation, bool)
        and 0 < generation <= (1 << 64) - 1
    ):
        generation = None

    def _ts(val: object) -> Optional[str]:
        if isinstance(val, str) and len(val) <= 40 and _RFC3339_RE.match(val):
            return val
        return None

    return Presence(
        online=online,
        observed_at=_ts(raw.get("observed_at")),
        connected_since=_ts(raw.get("connected_since")) if online else None,
        session_generation=generation if online else None,
    )


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_syslog_timestamp(raw: str, ref_year: Optional[int] = None) -> Optional[str]:
    parts = raw.split()
    if len(parts) != 3:
        return None
    month_str, day_str, time_str = parts
    month = _MONTH_NAMES.get(month_str)
    if month is None:
        return None
    try:
        day = int(day_str)
        t_parts = [int(p) for p in time_str.split(":")]
        if len(t_parts) != 3:
            return None
        hour, minute, second = t_parts
        year = ref_year or datetime.now(timezone.utc).year
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return None


def _parse_addr_port(endpoint_str: str) -> Optional[tuple[str, int]]:
    endpoint_str = endpoint_str.strip()
    if not endpoint_str:
        return None
    if endpoint_str.startswith("["):
        bracket_end = endpoint_str.find("]")
        if bracket_end == -1 or bracket_end + 1 >= len(endpoint_str) or endpoint_str[bracket_end + 1] != ":":
            return None
        host = endpoint_str[1:bracket_end]
        port_str = endpoint_str[bracket_end + 2:]
    else:
        host, sep, port_str = endpoint_str.rpartition(":")
        if not sep:
            return None
    host = host.split("%")[0]
    try:
        port = int(port_str)
    except ValueError:
        return None
    return host, port


def _is_loopback(host: str) -> bool:
    h = host.lower()
    return h in ("127.0.0.1", "::1", "localhost") or h.startswith("127.")


def match_loopback_pair(local: str, peer: str, sshd_port: int) -> Optional[int]:
    """If local and peer form an established loopback connection to sshd_port, return client port."""
    p1 = _parse_addr_port(local)
    p2 = _parse_addr_port(peer)
    if not p1 or not p2:
        return None
    host1, port1 = p1
    host2, port2 = p2
    if not (_is_loopback(host1) and _is_loopback(host2)):
        return None
    if port1 == sshd_port and port2 != sshd_port:
        return port2
    if port2 == sshd_port and port1 != sshd_port:
        return port1
    return None


def parse_ss_established_connections(output: str, sshd_port: int) -> tuple[Set[int], dict[int, int]]:
    """Parse output of `ss -tn` or `ss -tnp` and return (client_ports, port_to_pid)."""
    ports: Set[int] = set()
    port_to_pid: dict[int, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        local = parts[3]
        peer = parts[4]
        source_port = match_loopback_pair(local, peer, sshd_port)
        if source_port is not None:
            ports.add(source_port)
            p1 = _parse_addr_port(local)
            if p1 and p1[1] == sshd_port:
                m_pid = re.search(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)', line)
                if m_pid and m_pid.group("name") in ("sshd", "sshd-session", "sshd.exe"):
                    port_to_pid[source_port] = int(m_pid.group("pid"))
    return ports, port_to_pid


def parse_ss_established_ports(output: str, sshd_port: int) -> Set[int]:
    """Parse output of `ss -tn` and return client source ports connected to sshd_port."""
    ports, _ = parse_ss_established_connections(output, sshd_port)
    return ports


def parse_netstat_established_connections(output: str, sshd_port: int) -> tuple[Set[int], dict[int, int]]:
    """Parse output of Windows `netstat -ano -p tcp` and return (client_ports, port_to_pid)."""
    ports: Set[int] = set()
    port_to_pid: dict[int, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() != "TCP":
            continue
        if parts[3].upper() != "ESTABLISHED":
            continue
        local = parts[1]
        peer = parts[2]
        source_port = match_loopback_pair(local, peer, sshd_port)
        if source_port is not None:
            ports.add(source_port)
            p1 = _parse_addr_port(local)
            if p1 and p1[1] == sshd_port and len(parts) >= 5 and parts[4].isdigit():
                port_to_pid[source_port] = int(parts[4])
    return ports, port_to_pid


def parse_netstat_established_ports(output: str, sshd_port: int) -> Set[int]:
    """Parse output of Windows `netstat -ano -p tcp` or `netstat -ano`."""
    ports, _ = parse_netstat_established_connections(output, sshd_port)
    return ports


def parse_proc_net_tcp(content: str, sshd_port: int) -> Set[int]:
    """Parse Linux /proc/net/tcp or /proc/net/tcp6 hex connection tables."""
    ports: Set[int] = set()
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].startswith("sl"):
            continue
        # State 01 is TCP_ESTABLISHED
        if parts[3] != "01":
            continue
        local_raw = parts[1]
        peer_raw = parts[2]
        _, sep1, lport_hex = local_raw.partition(":")
        _, sep2, rport_hex = peer_raw.partition(":")
        if not sep1 or not sep2:
            continue
        try:
            lport = int(lport_hex, 16)
            rport = int(rport_hex, 16)
        except ValueError:
            continue
        # 127.0.0.1 in little-endian hex is 0100007F
        lip_hex = local_raw.partition(":")[0]
        rip_hex = peer_raw.partition(":")[0]
        is_loop = (
            (lip_hex.endswith("00007F") or lip_hex == "00000000000000000000000001000000")
            and (rip_hex.endswith("00007F") or rip_hex == "00000000000000000000000001000000")
        )
        if not is_loop:
            continue
        if lport == sshd_port and rport != sshd_port:
            ports.add(rport)
        elif rport == sshd_port and lport != sshd_port:
            ports.add(lport)
    return ports


def parse_sshd_auth_log(log_text: str) -> dict[int, dict[str, Any]]:
    """Parse sshd authentication log entries into {port: {user, key_fingerprint, since}}."""
    entries: dict[int, dict[str, Any]] = {}
    for line in log_text.splitlines():
        m = _AUTH_LOG_RE.search(line)
        if not m:
            continue
        port = int(m.group("port"))
        user = m.group("user")
        key_fp = m.group("fingerprint")

        ts: Optional[str] = None
        prefix = line[:m.start()]
        m_iso = _TS_ISO_RE.search(prefix)
        if m_iso:
            ts = m_iso.group(1).replace(" ", "T")
        else:
            m_syslog = _TS_SYSLOG_RE.search(prefix)
            if m_syslog:
                ts = _normalize_syslog_timestamp(m_syslog.group(1))

        entries[port] = {
            "user": user,
            "key_fingerprint": key_fp,
            "since": ts,
        }
    return entries


def parse_authorized_keys_line(line: str) -> Optional[tuple[str, Optional[str]]]:
    """Parse one authorized_keys line, returning (fingerprint, comment)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    tokens = line.split()
    # Find token starting with a known keytype prefix
    key_idx = -1
    for i, token in enumerate(tokens):
        if token.startswith(("ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-")):
            key_idx = i
            break
    if key_idx == -1 or key_idx + 1 >= len(tokens):
        return None

    blob_b64 = tokens[key_idx + 1]
    comment = " ".join(tokens[key_idx + 2:]).strip() or None

    try:
        blob = base64.b64decode(blob_b64, validate=True)
    except (binascii.Error, ValueError):
        return None

    fp = gateway_pins.fingerprint_of_blob(blob)
    return fp, comment


def parse_authorized_keys(content: str) -> dict[str, str]:
    """Parse authorized_keys file text into a dict of {fingerprint: comment}."""
    mapping: dict[str, str] = {}
    for line in content.splitlines():
        parsed = parse_authorized_keys_line(line)
        if parsed is not None:
            fp, comment = parsed
            if comment:
                mapping[fp] = comment
    return mapping


def load_authorized_keys_comments(extra_paths: Sequence[str] = ()) -> dict[str, str]:
    """Scan standard user and system authorized_keys files and return {fingerprint: comment}."""
    paths: list[str] = []
    home = os.path.expanduser("~")
    paths.append(os.path.join(home, ".ssh", "authorized_keys"))
    paths.append(os.path.join(home, ".ssh", "authorized_keys2"))

    if sys.platform == "win32":
        prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
        paths.append(os.path.join(prog_data, "ssh", "administrators_authorized_keys"))
    else:
        paths.append("/etc/ssh/authorized_keys")

    paths.extend(extra_paths)

    comments: dict[str, str] = {}
    for p in paths:
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                comments.update(parse_authorized_keys(f.read()))
        except (OSError, PermissionError):
            continue
    return comments


def read_enrolled_config(config_dir: Optional[str] = None) -> tuple[Optional[str], int, Optional[str]]:
    """Read device_id, sshd_port, and server from enrolled config.json or agent binding.

    Returns (device_id, sshd_port, server).
    """
    config_dir = config_dir or common.default_config_dir()
    cfg_path = os.path.join(config_dir, common.CONFIG_FILE)
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            device_id = data.get("device_id")
            ssh_host = data.get("ssh_host") or f"127.0.0.1:{DEFAULT_SSHD_PORT}"
            server = data.get("server")
            _, port = _parse_addr_port(ssh_host) or ("127.0.0.1", DEFAULT_SSHD_PORT)
            return device_id, port, server
        except (OSError, ValueError, TypeError):
            pass

    # Windows ordinary-user agent fallback (binding.json)
    agent_dir = os.path.join(
        os.environ.get("XDG_CONFIG_HOME")
        or os.path.join(os.environ.get("USERPROFILE") or os.path.expanduser("~"), ".config"),
        "pocketshell",
        "agent",
    )
    binding_path = os.path.join(agent_dir, "binding.json")
    if os.path.isfile(binding_path):
        try:
            with open(binding_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            device_id = data.get("deviceId")
            port = data.get("port") or DEFAULT_SSHD_PORT
            cfg_dir = data.get("configDir")
            server = None
            if cfg_dir and os.path.isfile(os.path.join(cfg_dir, common.CONFIG_FILE)):
                with open(os.path.join(cfg_dir, common.CONFIG_FILE), "r", encoding="utf-8") as f:
                    server = json.load(f).get("server")
            return device_id, port, server
        except (OSError, ValueError, TypeError):
            pass

    return None, DEFAULT_SSHD_PORT, None


def _presence_cache_path(device_id: str) -> str:
    uid = getattr(os, "getuid", lambda: "u")()
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", device_id)
    return os.path.join(tempfile.gettempdir(), f".pocketshell-presence-{uid}-{safe_id}.json")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would re-send the Authorization header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def fetch_broker_presence(
    endpoint: gateway_endpoint.GatewayEndpoint,
    token_provider: gateway_tokens.TokenProvider,
    device_id: str,
    *,
    opener: Optional[urllib.request.OpenerDirector] = None,
    timeout: float = BROKER_TIMEOUT_SECONDS,
) -> Optional[Presence]:
    """Query GET /identity/v1/devices from broker and extract presence for device_id."""
    token = gateway_tokens.obtain_token(token_provider)
    request = urllib.request.Request(
        endpoint.devices_url(),
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "pocketshell-cli",
        },
    )
    try:
        with (opener or token_opener(_NoRedirect())).open(request, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            body = resp.read(1 << 20)
            doc = json.loads(body.decode("utf-8"))
            devices = doc.get("devices") if isinstance(doc, dict) else None
            if isinstance(devices, list):
                for item in devices:
                    if isinstance(item, dict) and item.get("id") == device_id:
                        return parse_presence(item.get("presence"), revoked=bool(item.get("revoked", False)))
    except Exception:
        pass
    return None


def _read_cached_presence(device_id: str) -> Optional[Presence]:
    path = _presence_cache_path(device_id)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cached_at = float(data.get("cached_at", 0))
        if time.time() - cached_at > PRESENCE_CACHE_TTL_SECONDS:
            return None
        raw_presence = data.get("presence")
        if raw_presence is None:
            return None
        return Presence(
            online=bool(raw_presence.get("online")),
            observed_at=raw_presence.get("observed_at"),
            connected_since=raw_presence.get("connected_since"),
            session_generation=raw_presence.get("session_generation"),
        )
    except (OSError, ValueError, TypeError):
        return None


def _write_cached_presence(device_id: str, presence: Optional[Presence]) -> None:
    path = _presence_cache_path(device_id)
    data: dict[str, Any] = {
        "device_id": device_id,
        "cached_at": time.time(),
        "presence": None,
    }
    if presence is not None:
        data["presence"] = {
            "online": presence.online,
            "observed_at": presence.observed_at,
            "connected_since": presence.connected_since,
            "session_generation": presence.session_generation,
        }
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=".ps-pres-", dir=os.path.dirname(path))
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp_path, path)
    except OSError:
        pass


def check_sshd_reachable(
    port: int,
    *,
    timeout: float = SSHD_CONNECT_TIMEOUT_SECONDS,
    connect_fn: Optional[Callable[..., Any]] = None,
) -> bool:
    """Check if 127.0.0.1:port accepts TCP connections."""
    if connect_fn is not None:
        return bool(connect_fn(port, timeout=timeout))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def collect_agent_status(
    device_id: Optional[str],
    config_dir: Optional[str] = None,
    server_url: Optional[str] = None,
    *,
    runner: Optional[common.Runner] = None,
    presence_fetcher: Optional[Callable[..., Any]] = None,
) -> tuple[dict[str, Any], list[str]]:
    """Collect agent installation, process running state, and broker presence."""
    errors: list[str] = []
    installed = False
    running = False
    pid: Optional[int] = None

    # 1. Local service / process check
    if sys.platform.startswith("linux"):
        from pocketshell.gateway import service_linux
        try:
            st = service_linux.status(runner=runner)
            installed = st.installed
            running = st.running
            if st.processes:
                pid = st.processes[0].get("pid")
        except Exception as exc:
            errors.append(f"local agent check failed: {exc}")

        # Fallback process check if not running as systemd unit
        if not running:
            try:
                ps_res = (runner or common.run_child)(["pgrep", "-f", "pocketshell-link run"])
                if ps_res.returncode == 0 and ps_res.stdout.strip():
                    first_pid = ps_res.stdout.split()[0].decode("ascii", "replace")
                    if first_pid.isdigit():
                        running = True
                        installed = True
                        pid = int(first_pid)
            except Exception:
                pass
    elif sys.platform == "win32":
        try:
            from pocketshell.gateway import service_windows
            st = service_windows.status()
            installed = st.installed
            running = st.running
            if st.processes:
                pid = st.processes[0].get("pid")
        except Exception as exc:
            errors.append(f"Windows service status check failed: {exc}")
    else:
        installed = False
        running = False

    # 2. Broker presence check
    connected = False
    connected_since: Optional[str] = None
    source = "unknown"
    last_error: Optional[str] = None

    if not device_id:
        source = "local"
        connected = running
    else:
        cached = _read_cached_presence(device_id)
        if cached is not None:
            source = "presence"
            connected = cached.online
            connected_since = cached.connected_since
        else:
            try:
                ep = gateway_endpoint.resolve_endpoint(server_url, insecure_dev=False)
                fetch = presence_fetcher or (
                    lambda ep, tp: fetch_broker_presence(
                        ep, tp, device_id, timeout=BROKER_TIMEOUT_SECONDS
                    )
                )
                res = fetch(ep, gateway_tokens.default_token_provider)
                if isinstance(res, Presence):
                    pres = res
                elif isinstance(res, list):
                    found = next((d for d in res if getattr(d, "id", None) == device_id), None)
                    pres = getattr(found, "presence", None)
                elif res is None:
                    pres = None
                else:
                    pres = getattr(res, "presence", None)

                if pres:
                    _write_cached_presence(device_id, pres)
                    source = "presence"
                    connected = pres.online
                    connected_since = pres.connected_since
                elif res is not None:
                    source = "presence"
                    connected = False
                    _write_cached_presence(device_id, Presence(
                        online=False, observed_at=_utcnow_iso(), connected_since=None, session_generation=None
                    ))
                else:
                    source = "local"
                    connected = running
            except gateway_tokens.NotLoggedInError:
                source = "local"
                connected = running
            except Exception as exc:
                last_error = f"broker presence unavailable: {exc}"
                errors.append(last_error)
                source = "local"
                connected = running

    agent_dict = {
        "installed": installed,
        "running": running,
        "pid": pid,
        "connected": connected,
        "connected_since": connected_since,
        "source": source,
        "last_error": last_error,
    }
    return agent_dict, errors


def parse_wmic_cim_timestamp(val: str) -> Optional[str]:
    """Parse WMI CIM datetime string 'YYYYMMDDHHMMSS.uuuuuu+UUU' into UTC ISO 8601."""
    m = re.match(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.\d+([+-]\d+)$", val.strip())
    if not m:
        return None
    year, month, day, hour, minute, second, offset_mins = m.groups()
    try:
        tz = timezone(timedelta(minutes=int(offset_mins)))
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), tzinfo=tz)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        return None


def discover_sshd_session_processes(
    runner: Optional[common.Runner] = None,
    *,
    platform: Optional[str] = None,
) -> list[SshdProcessSession]:
    """Discover active sshd user session processes on the host.

    Linux: inspects /proc for 'sshd: USER@...' processes (or runs 'ps -eo pid,user,etimes,args').
    Windows: inspects sshd.exe child processes with owner via psutil, or tasklist /V + wmic.
    """
    sessions: list[SshdProcessSession] = []
    plat = platform or sys.platform

    if plat == "win32":
        # 1. Try psutil if available
        try:
            import psutil
            for p in psutil.process_iter(["pid", "name", "username", "create_time"]):
                pname = (p.info.get("name") or "").lower()
                if pname == "sshd.exe":
                    raw_user = p.info.get("username") or ""
                    user = raw_user.split("\\")[-1] if "\\" in raw_user else raw_user
                    if user and user.upper() not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "N/A", ""):
                        ctime = p.info.get("create_time")
                        since = (
                            datetime.fromtimestamp(ctime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            if ctime
                            else None
                        )
                        sessions.append(SshdProcessSession(pid=p.info.get("pid"), user=user, since=since))
            if sessions:
                return sessions
        except Exception:
            pass

        # 2. Try tasklist /V /FO CSV + wmic
        run_fn = runner or common.run_child
        wmic_dates: dict[int, str] = {}
        try:
            wmic_res = run_fn(["wmic", "process", "where", "name='sshd.exe'", "get", "ProcessId,CreationDate", "/format:csv"])
            if wmic_res.returncode == 0 and wmic_res.stdout:
                wmic_text = wmic_res.stdout.decode("ascii", "replace")
                reader = csv.reader(wmic_text.splitlines())
                for row in reader:
                    if len(row) >= 3 and row[2].strip().isdigit():
                        pid = int(row[2].strip())
                        ts = parse_wmic_cim_timestamp(row[1].strip())
                        if ts:
                            wmic_dates[pid] = ts
        except Exception:
            pass

        try:
            res = run_fn(["tasklist", "/V", "/FO", "CSV", "/FI", "IMAGENAME eq sshd.exe"])
            if res.returncode == 0 and res.stdout:
                reader = csv.reader(res.stdout.decode("ascii", "replace").splitlines())
                for row in reader:
                    if len(row) >= 7 and row[0].lower() == "sshd.exe" and row[1].isdigit():
                        pid = int(row[1])
                        raw_user = row[6].strip()
                        user = raw_user.split("\\")[-1] if "\\" in raw_user else raw_user
                        if user and user.upper() not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "N/A", ""):
                            since = wmic_dates.get(pid)
                            sessions.append(SshdProcessSession(pid=pid, user=user, since=since))
        except Exception:
            pass

        return sessions

    # Linux / POSIX
    # 1. When runner is None and /proc is readable, scan /proc directly (fast, no subprocess)
    if runner is None and os.path.isdir("/proc"):
        import pwd
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            cmd_path = os.path.join("/proc", entry, "cmdline")
            try:
                with open(cmd_path, "rb") as f:
                    cmd_raw = f.read().decode("utf-8", "replace")
            except OSError:
                continue

            if not cmd_raw.startswith("sshd:") or any(
                marker in cmd_raw for marker in ("[listener]", "[accepted]", "[net]", "[priv]")
            ):
                continue

            m = re.match(r"^sshd:\s*([a-zA-Z0-9._-]+)(?:@|\s|$)", cmd_raw)
            if not m:
                continue
            user_candidate = m.group(1)
            if user_candidate in ("sshd", "root") and "@" not in cmd_raw:
                continue

            try:
                st = os.stat(os.path.join("/proc", entry))
                try:
                    pw = pwd.getpwuid(st.st_uid)
                    user = pw.pw_name if pw.pw_name != "root" else user_candidate
                except (KeyError, ValueError):
                    user = user_candidate

                since = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                sessions.append(SshdProcessSession(pid=pid, user=user, since=since, cmdline=cmd_raw.strip("\x00")))
            except OSError:
                continue

        if sessions:
            return sorted(sessions, key=lambda s: (s.since or "", s.pid or 0))

    # 2. Try 'ps -eo pid,user,etimes,args'
    run_fn = runner or common.run_child
    try:
        res = run_fn(["ps", "-eo", "pid,user,etimes,args"])
        if res.returncode == 0 and res.stdout:
            now_utc = datetime.now(timezone.utc)
            for line in res.stdout.decode("utf-8", "replace").splitlines():
                parts = line.split(None, 3)
                if len(parts) < 4 or not parts[0].isdigit() or not parts[2].isdigit():
                    continue
                pid = int(parts[0])
                user_col = parts[1]
                etimes = int(parts[2])
                args = parts[3]

                if not args.startswith("sshd:") or any(
                    marker in args for marker in ("[listener]", "[accepted]", "[net]", "[priv]")
                ):
                    continue

                m = re.search(r"sshd:\s*([a-zA-Z0-9._-]+)(?:@|\s|$)", args)
                if not m:
                    continue
                extracted_user = m.group(1)
                user = extracted_user if user_col == "root" else user_col

                start_dt = now_utc - timedelta(seconds=etimes)
                since = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                sessions.append(SshdProcessSession(pid=pid, user=user, since=since, cmdline=args))
    except Exception:
        pass

    return sorted(sessions, key=lambda s: (s.since or "", s.pid or 0))


def find_loopback_connections(
    sshd_port: int,
    *,
    runner: Optional[common.Runner] = None,
    platform: Optional[str] = None,
) -> tuple[Set[int], dict[int, int], list[str]]:
    """Discover established TCP loopback connections to sshd_port.

    Returns (ports, port_to_pid, errors).
    """
    errors: list[str] = []
    run_fn = runner or common.run_child
    plat = platform or sys.platform

    # On Windows, try netstat -ano
    if plat == "win32":
        try:
            res = run_fn(["netstat", "-ano", "-p", "tcp"])
            if res.returncode == 0:
                output = res.stdout.decode("ascii", "replace")
                ports, port_to_pid = parse_netstat_established_connections(output, sshd_port)
                return ports, port_to_pid, errors
            errors.append(f"netstat failed (exit {res.returncode})")
        except Exception as exc:
            errors.append(f"netstat error: {exc}")
        return set(), {}, errors

    # On Linux, try ss -tnp or ss -tn first
    try:
        res = run_fn(["ss", "-tnp"])
        if res.returncode == 0:
            output = res.stdout.decode("utf-8", "replace")
            ports, port_to_pid = parse_ss_established_connections(output, sshd_port)
            return ports, port_to_pid, errors
    except Exception:
        pass

    try:
        res = run_fn(["ss", "-tn"])
        if res.returncode == 0:
            output = res.stdout.decode("utf-8", "replace")
            ports, port_to_pid = parse_ss_established_connections(output, sshd_port)
            return ports, port_to_pid, errors
    except Exception:
        pass

    # Fallback to /proc/net/tcp
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="ascii") as f:
                    ports = parse_proc_net_tcp(f.read(), sshd_port)
                    if ports:
                        return ports, {}, errors
            except OSError as exc:
                errors.append(f"could not read {path}: {exc}")

    return set(), {}, errors


def read_auth_log_text(runner: Optional[common.Runner] = None) -> str:
    """Read recent auth log text from journalctl, /var/log/auth.log, or Windows sshd.log."""
    run_fn = runner or common.run_child

    if sys.platform == "win32":
        prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
        candidates = [
            os.path.join(prog_data, "ssh", "logs", "sshd.log"),
        ]
        for p in candidates:
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        return f.read()
                except OSError:
                    pass
        return ""

    # Linux: try journalctl -u ssh -u sshd
    try:
        res = run_fn(["journalctl", "-u", "ssh", "-u", "sshd", "-n", "300", "-o", "short-iso", "--no-pager"])
        if res.returncode == 0 and res.stdout:
            text = res.stdout.decode("utf-8", "replace")
            if "Accepted " in text:
                return text
    except Exception:
        pass

    # Fallback to auth.log
    for p in ("/var/log/auth.log", "/var/log/secure"):
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except OSError:
                pass

    return ""


def collect_clients_status(
    sshd_port: int,
    *,
    runner: Optional[common.Runner] = None,
    established_ports: Optional[Set[int]] = None,
    port_to_pid: Optional[dict[int, int]] = None,
    auth_log_text: Optional[str] = None,
    auth_keys_comments: Optional[dict[str, str]] = None,
    discovered_sessions: Optional[list[SshdProcessSession]] = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Find who is connected right now by correlating TCP sockets with auth logs.

    When the auth log has no entry for a connection (e.g. log unreadable as non-root),
    falls back to discovered sshd session processes to populate user and since.
    """
    errors: list[str] = []

    if established_ports is None:
        ports, p_to_pid, conn_errors = find_loopback_connections(sshd_port, runner=runner)
        errors.extend(conn_errors)
    else:
        ports = established_ports
        p_to_pid = port_to_pid or {}

    if not ports:
        return [], errors

    if auth_log_text is None:
        log_text = read_auth_log_text(runner=runner)
    else:
        log_text = auth_log_text

    auth_by_port = parse_sshd_auth_log(log_text) if log_text else {}
    comments = auth_keys_comments if auth_keys_comments is not None else load_authorized_keys_comments()

    clients_by_port: dict[int, dict[str, Any]] = {}
    unmapped_ports: list[int] = []

    for port in sorted(ports):
        auth = auth_by_port.get(port)
        if auth and auth.get("user"):
            user = auth.get("user")
            fp = auth.get("key_fingerprint")
            since = auth.get("since")
            comment = comments.get(fp) if fp else None
            clients_by_port[port] = {
                "user": user,
                "key_fingerprint": fp,
                "key_comment": comment,
                "since": since,
                "via": "gateway",
            }
        else:
            unmapped_ports.append(port)

    # Process fallback when auth log has no entry
    if unmapped_ports:
        sessions = (
            discovered_sessions
            if discovered_sessions is not None
            else discover_sshd_session_processes(runner=runner)
        )
        sessions_by_pid = {s.pid: s for s in sessions if s.pid is not None}
        used_sessions: Set[SshdProcessSession] = set()

        # 1. Match by PID if socket connection PID is known
        still_unmapped: list[int] = []
        for port in unmapped_ports:
            pid = p_to_pid.get(port)
            if pid and pid in sessions_by_pid:
                sess = sessions_by_pid[pid]
                used_sessions.add(sess)
                clients_by_port[port] = {
                    "user": sess.user,
                    "key_fingerprint": None,
                    "key_comment": None,
                    "since": sess.since,
                    "via": "gateway",
                }
            else:
                still_unmapped.append(port)

        # 2. Match remaining ports 1:1 with remaining sessions
        available_sessions = [s for s in sessions if s not in used_sessions]
        for port, sess in zip(still_unmapped, available_sessions):
            used_sessions.add(sess)
            clients_by_port[port] = {
                "user": sess.user,
                "key_fingerprint": None,
                "key_comment": None,
                "since": sess.since,
                "via": "gateway",
            }

        # 3. Any ports without matching session get null fields
        for port in still_unmapped[len(available_sessions):]:
            clients_by_port[port] = {
                "user": None,
                "key_fingerprint": None,
                "key_comment": None,
                "since": None,
                "via": "gateway",
            }

    clients = [clients_by_port[p] for p in sorted(ports)]
    return clients, errors


def collect_sessions_status(
    *,
    enumerate_fn: Optional[Callable[..., tuple[list[runtime_sessions.LiveSession], list[dict[str, str]]]]] = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """List active aplexer sessions."""
    errors: list[str] = []
    enum = enumerate_fn or runtime_sessions.enumerate_live_sessions
    try:
        live, errs = enum()
        for err in errs:
            errors.append(str(err.get("message") or "session probe failed"))
        sessions_list = [
            {
                "name": s.name,
                "id": s.aplexer_id,
                "engine": s.engine,
                "state": s.phase or "running",
                "agent_state": s.agent_state,
            }
            for s in live
        ]
        return sessions_list, errors
    except Exception as exc:
        errors.append(f"failed to query sessions: {exc}")
        return [], errors


def derive_state(
    agent: Mapping[str, Any],
    sshd: Mapping[str, Any],
    device_id: Optional[str],
) -> tuple[str, str]:
    """Derive overall state and summary sentence per spec contract."""
    if not device_id:
        return "not_installed", "Gateway agent is not enrolled"

    if not agent.get("installed", False):
        return "not_installed", "Gateway agent is not installed"

    if not agent.get("running", False):
        return "offline", "Gateway agent is not running"

    if not agent.get("connected", False):
        return "offline", "Gateway agent is offline"

    if not sshd.get("reachable", False):
        return "degraded", "Connected to gateway, but local SSH server is not running — nobody can connect"

    return "online", "Connected to gateway, local SSH server reachable"


def collect_gateway_status(
    *,
    config_dir: Optional[str] = None,
    runner: Optional[common.Runner] = None,
    connect_fn: Optional[Callable[..., Any]] = None,
    presence_fetcher: Optional[Callable[..., Any]] = None,
    established_ports: Optional[Set[int]] = None,
    port_to_pid: Optional[dict[int, int]] = None,
    auth_log_text: Optional[str] = None,
    auth_keys_comments: Optional[dict[str, str]] = None,
    discovered_sessions: Optional[list[SshdProcessSession]] = None,
    enumerate_sessions_fn: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Build the complete status contract dictionary."""
    checked_at = _utcnow_iso()
    all_errors: list[str] = []

    # 1. Config & Enrollment
    device_id, sshd_port, server_url = read_enrolled_config(config_dir)

    # 2. Agent Status
    agent_dict, agent_errors = collect_agent_status(
        device_id,
        config_dir=config_dir,
        server_url=server_url,
        runner=runner,
        presence_fetcher=presence_fetcher,
    )
    all_errors.extend(agent_errors)

    # 3. SSHD Reachability
    reachable = check_sshd_reachable(sshd_port, connect_fn=connect_fn)
    sshd_dict = {
        "running": reachable,
        "port": sshd_port,
        "reachable": reachable,
    }

    # 4. Clients
    clients_list, client_errors = collect_clients_status(
        sshd_port,
        runner=runner,
        established_ports=established_ports,
        port_to_pid=port_to_pid,
        auth_log_text=auth_log_text,
        auth_keys_comments=auth_keys_comments,
        discovered_sessions=discovered_sessions,
    )
    all_errors.extend(client_errors)

    # 5. Sessions
    sessions_list, session_errors = collect_sessions_status(enumerate_fn=enumerate_sessions_fn)
    all_errors.extend(session_errors)

    # 6. State Derivation
    state, summary = derive_state(agent_dict, sshd_dict, device_id)

    return {
        "v": CONTRACT_VERSION,
        "checked_at": checked_at,
        "device_id": device_id,
        "state": state,
        "summary": summary,
        "agent": agent_dict,
        "sshd": sshd_dict,
        "clients": clients_list,
        "sessions": sessions_list,
        "errors": all_errors,
    }


def format_human_status(doc: Mapping[str, Any]) -> str:
    """Format readable status summary for terminal output."""
    state_upper = str(doc.get("state", "UNKNOWN")).upper()
    lines = [
        f"Gateway status: {state_upper}",
        f"Summary:        {doc.get('summary', '')}",
        f"Device ID:      {doc.get('device_id') or 'not enrolled'}",
    ]
    agent = doc.get("agent", {})
    agent_parts = []
    if agent.get("installed"):
        agent_parts.append("installed")
    else:
        agent_parts.append("not installed")
    if agent.get("running"):
        pid = agent.get("pid")
        agent_parts.append(f"running (PID {pid})" if pid else "running")
    else:
        agent_parts.append("not running")
    if agent.get("connected"):
        src = agent.get("source", "unknown")
        since = f", since {agent['connected_since']}" if agent.get("connected_since") else ""
        agent_parts.append(f"connected ({src}{since})")
    else:
        agent_parts.append("disconnected")
    lines.append(f"Agent:          {', '.join(agent_parts)}")

    sshd = doc.get("sshd", {})
    sshd_status = "reachable" if sshd.get("reachable") else "not reachable"
    lines.append(f"SSHD:           {sshd_status} on 127.0.0.1:{sshd.get('port', DEFAULT_SSHD_PORT)}")

    clients = doc.get("clients", [])
    lines.append(f"Clients:        {len(clients)} connected")
    for c in clients:
        user = c.get("user") or "unknown-user"
        comment = f" ({c['key_comment']})" if c.get("key_comment") else ""
        fp = f" [{c['key_fingerprint']}]" if c.get("key_fingerprint") else ""
        since = f" since {c['since']}" if c.get("since") else ""
        via = f" via {c['via']}" if c.get("via") else ""
        lines.append(f"  - {user}{comment}{fp}{since}{via}")

    sessions = doc.get("sessions", [])
    lines.append(f"Sessions:       {len(sessions)} active")
    for s in sessions:
        name = s.get("name", "unknown")
        engine = f" [{s.get('engine')}]" if s.get("engine") else ""
        agent_st = f" ({s.get('agent_state')})" if s.get("agent_state") else ""
        lines.append(f"  - {name}{engine}{agent_st}")

    errors = doc.get("errors", [])
    if errors:
        lines.append("Errors:")
        for err in errors:
            lines.append(f"  ! {err}")

    return "\n".join(lines)


# --- Lifecycle commands (start / stop / restart) --------------------------------------

def find_running_gateway_pids(runner: Optional[common.Runner] = None) -> list[int]:
    """Find process IDs of running pocketshell-link run or pocketshell gateway run processes."""
    pids: list[int] = []
    if sys.platform.startswith("linux"):
        try:
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                if pid == os.getpid():
                    continue
                cmdline_path = os.path.join(entry.path, "cmdline")
                try:
                    with open(cmdline_path, "rb") as f:
                        raw = f.read(1024)
                    cmd = raw.replace(b"\x00", b" ").decode("utf-8", "replace")
                    if ("pocketshell-link" in cmd and " run" in cmd) or (
                        "pocketshell" in cmd and "gateway" in cmd and "run" in cmd
                    ):
                        pids.append(pid)
                except OSError:
                    continue
        except OSError:
            pass
        if not pids:
            run_fn = runner or common.run_child
            try:
                res = run_fn(["pgrep", "-f", "pocketshell-link run"])
                if res.returncode == 0:
                    for line in res.stdout.split():
                        if line.isdigit() and int(line) != os.getpid():
                            pids.append(int(line))
            except Exception:
                pass
    elif sys.platform == "win32":
        run_fn = runner or common.run_child
        try:
            res = run_fn(["tasklist", "/FI", "IMAGENAME eq pocketshell-link.exe", "/FO", "CSV", "/NH"])
            if res.returncode == 0:
                for line in res.stdout.decode("ascii", "replace").splitlines():
                    parts = [p.strip(' "') for p in line.split(",")]
                    if len(parts) >= 2 and parts[1].isdigit():
                        pids.append(int(parts[1]))
        except Exception:
            pass
    return pids


def spawn_detached_run(
    spawn_fn: Optional[Callable[..., Any]] = None,
) -> int:
    """Spawn a detached `pocketshell gateway run` process and return its PID."""
    argv = [sys.executable, "-m", "pocketshell", "gateway", "run"]
    if spawn_fn is not None:
        proc = spawn_fn(argv)
        return getattr(proc, "pid", 12345)

    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        flags = 0x08000000 | 0x00000008  # CREATE_NO_WINDOW | DETACHED_PROCESS
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(argv, **kwargs)
    return proc.pid


def start_gateway(
    runner: Optional[common.Runner] = None,
    spawn_fn: Optional[Callable[..., Any]] = None,
) -> str:
    """Start the host gateway agent.

    Wraps existing service mechanisms (systemd user unit on Linux, Task Scheduler on Windows).
    If the service is not installed, falls back to spawning detached `pocketshell gateway run`.
    """
    run_fn = runner or common.run_child

    if sys.platform.startswith("linux"):
        from pocketshell.gateway import service_linux
        path = service_linux.unit_path()
        if os.path.lexists(path):
            res = run_fn(service_linux.systemctl_argv("start", service_linux.UNIT_NAME))
            if res.returncode != 0:
                err = common.decode(res.stderr or res.stdout).strip()
                raise common.ServiceError(f"failed to start pocketshell-gateway.service: {err}")
            return "started pocketshell-gateway.service"

        pid = spawn_detached_run(spawn_fn=spawn_fn)
        return f"pocketshell-gateway.service is not installed; spawned detached 'pocketshell gateway run' (PID {pid})"

    elif sys.platform == "win32":
        task_installed = False
        try:
            res = run_fn(["schtasks.exe", "/Query", "/TN", r"\PocketShell\GatewayLink", "/FO", "CSV"])
            task_installed = (res.returncode == 0)
        except Exception:
            task_installed = False

        if task_installed:
            res = run_fn(["schtasks.exe", "/Run", "/TN", r"\PocketShell\GatewayLink"])
            if res.returncode != 0:
                err = common.decode(res.stderr or res.stdout).strip()
                raise common.ServiceError(f"failed to start GatewayLink task: {err}")
            return r"started \PocketShell\GatewayLink task"

        pid = spawn_detached_run(spawn_fn=spawn_fn)
        return f"Task Scheduler task is not installed; spawned detached 'pocketshell gateway run' (PID {pid})"

    raise common.ServiceError(f"unsupported platform: {sys.platform}")


def stop_gateway(
    runner: Optional[common.Runner] = None,
    kill_fn: Optional[Callable[[int], Any]] = None,
) -> str:
    """Stop the host gateway agent.

    Wraps existing service mechanisms and also stops any detached gateway processes.
    """
    run_fn = runner or common.run_child

    if sys.platform.startswith("linux"):
        from pocketshell.gateway import service_linux
        path = service_linux.unit_path()
        stopped_unit = False
        if os.path.lexists(path):
            res = run_fn(service_linux.systemctl_argv("stop", service_linux.UNIT_NAME))
            if res.returncode != 0:
                err = common.decode(res.stderr or res.stdout).strip()
                raise common.ServiceError(f"failed to stop pocketshell-gateway.service: {err}")
            stopped_unit = True

        pids = find_running_gateway_pids(runner=run_fn)
        for pid in pids:
            if kill_fn is not None:
                kill_fn(pid)
            else:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass

        if stopped_unit:
            return "stopped pocketshell-gateway.service"
        elif pids:
            return f"stopped detached gateway agent (PID {', '.join(map(str, pids))})"
        else:
            return "gateway agent is not running"

    elif sys.platform == "win32":
        task_installed = False
        try:
            res = run_fn(["schtasks.exe", "/Query", "/TN", r"\PocketShell\GatewayLink", "/FO", "CSV"])
            task_installed = (res.returncode == 0)
        except Exception:
            task_installed = False

        stopped_task = False
        if task_installed:
            res = run_fn(["schtasks.exe", "/End", "/TN", r"\PocketShell\GatewayLink"])
            if res.returncode != 0:
                err = common.decode(res.stderr or res.stdout).strip()
                raise common.ServiceError(f"failed to stop GatewayLink task: {err}")
            stopped_task = True

        pids = find_running_gateway_pids(runner=run_fn)
        for pid in pids:
            if kill_fn is not None:
                kill_fn(pid)
            else:
                run_fn(["taskkill", "/PID", str(pid), "/F"])

        if stopped_task:
            return r"stopped \PocketShell\GatewayLink task"
        elif pids:
            return f"stopped detached gateway agent (PID {', '.join(map(str, pids))})"
        else:
            return "gateway agent is not running"

    raise common.ServiceError(f"unsupported platform: {sys.platform}")


def restart_gateway(
    runner: Optional[common.Runner] = None,
    spawn_fn: Optional[Callable[..., Any]] = None,
    kill_fn: Optional[Callable[[int], Any]] = None,
) -> str:
    """Restart the host gateway agent.

    Wraps existing service mechanisms or restarts detached gateway process.
    """
    run_fn = runner or common.run_child

    if sys.platform.startswith("linux"):
        from pocketshell.gateway import service_linux
        path = service_linux.unit_path()
        if os.path.lexists(path):
            res = run_fn(service_linux.systemctl_argv("restart", service_linux.UNIT_NAME))
            if res.returncode != 0:
                err = common.decode(res.stderr or res.stdout).strip()
                raise common.ServiceError(f"failed to restart pocketshell-gateway.service: {err}")
            return "restarted pocketshell-gateway.service"

        stop_gateway(runner=run_fn, kill_fn=kill_fn)
        pid = spawn_detached_run(spawn_fn=spawn_fn)
        return f"pocketshell-gateway.service is not installed; restarted detached 'pocketshell gateway run' (PID {pid})"

    elif sys.platform == "win32":
        task_installed = False
        try:
            res = run_fn(["schtasks.exe", "/Query", "/TN", r"\PocketShell\GatewayLink", "/FO", "CSV"])
            task_installed = (res.returncode == 0)
        except Exception:
            task_installed = False

        if task_installed:
            stop_gateway(runner=run_fn, kill_fn=kill_fn)
            return start_gateway(runner=run_fn, spawn_fn=spawn_fn)

        stop_gateway(runner=run_fn, kill_fn=kill_fn)
        pid = spawn_detached_run(spawn_fn=spawn_fn)
        return f"Task Scheduler task is not installed; restarted detached 'pocketshell gateway run' (PID {pid})"

    raise common.ServiceError(f"unsupported platform: {sys.platform}")
