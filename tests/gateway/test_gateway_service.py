"""`pocketshell gateway service install|uninstall|status` — unit tests.

Linux: the systemd --user backend against a temporary XDG_CONFIG_HOME
(conftest isolates it) with EVERY ``systemctl`` call recorded by a fake
runner — the real user manager of the machine running the tests is never
touched (a guard fails the test if a real ``systemctl`` is spawned).

Windows logic (task XML, quoting, digest allow-list, principal SID, the
schtasks command sequence) is tested here on any OS with fake runners and a
fake native API; tests/gateway/test_windows_gateway_service_native.py
registers a real task on the windows-latest CI runner.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from click.testing import CliRunner

from pocketshell.cli import cli
from pocketshell.gateway import service_common as common
from pocketshell.gateway import service_linux as linux
from pocketshell.gateway import service_windows as win
from pocketshell.gateway.service_common import ChildResult, ServiceError

POSIX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="systemd backend + sh test doubles")
LINUX = POSIX

QUALIFIED = "f9582de6a3f635ec70e4daaf755479788f788d8d493c3ed1fd58812f555dabe1"
HISTORICAL_8CB = "57f3a86e2166b079e99479a985fd8cbc56a91260cf3d8dee76c446e60189ac63"
HISTORICAL_771 = "f6e357d8b43369b9f9de222fa9603ce523b37959b38cc4ca8bb04d68fa7c1c37"
USER_SID = "S-1-5-21-1846869698-1433458354-420588588-1001"
OTHER_SID = "S-1-5-21-1846869698-1433458354-420588588-1002"
WIN_HELPER = r"C:\Users\alexey\PocketShellFleet\quiet-sshd-v26a\gateway-helper-cd7\pocketshell-link.exe"
WIN_CONFIG = r"C:\Users\alexey\PocketShellFleet\quiet-sshd-v26a\gateway-helper-cd7\keys"

SHOW_OUT = (
    "server:          wss://gateway.pocketshell.io\n"
    "device id:       home-lab\n"
    "local ssh:       127.0.0.1:22 (loopback only)\n"
    "device key:      SHA256:abc\n"
    "pinned ssh host key: ssh-ed25519 AAAA\n"
)

# A fake helper whose `show` only checks that the two enrollment files
# exist (never reads them), like the real helper's refusal surface.
_SHOW_HELPER = """#!/bin/sh
if [ "$1" = show ]; then
  if [ "$2" = --config-dir ] && [ -f "$3/config.json" ] && [ -f "$3/device_ed25519.pem" ]; then
    cat <<'OUT'
""" + SHOW_OUT + """OUT
    exit 0
  fi
  echo "not enrolled: open config: no such file" >&2
  exit 1
fi
echo "unexpected: $*" >&2
exit 9
"""


@pytest.fixture(autouse=True)
def _no_real_systemctl(monkeypatch):
    """Belt and braces: spawning a real systemctl fails the test."""
    real = subprocess.run

    def guarded(argv, *args, **kwargs):
        if argv and os.path.basename(str(argv[0])) in {"systemctl", "loginctl", "schtasks.exe"}:
            raise AssertionError(f"real {argv[0]} spawned by a unit test")
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded)


class Systemctl:
    """Records systemctl argv; delegates everything else to the real runner."""

    def __init__(self, show_props: str = "", fail: tuple = ()):
        self.calls: list[list[str]] = []
        self.show_props = show_props
        self.fail = fail

    def __call__(self, argv, **kwargs):
        if argv[0] == "systemctl":
            self.calls.append(list(argv))
            if argv[2] in self.fail:
                return ChildResult(1, b"", b"Failed to connect to bus\x1b[31m")
            if argv[2] == "show":
                return ChildResult(0, self.show_props.encode(), b"")
            return ChildResult(0, b"", b"")
        return common.run_child(argv, **kwargs)


@pytest.fixture
def systemctl(monkeypatch):
    fake = Systemctl()
    monkeypatch.setattr(linux, "run_child", fake)
    monkeypatch.setattr(linux.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(linux, "linger_enabled", lambda user=None: True)
    return fake


@pytest.fixture
def enrolled(tmp_path):
    config = tmp_path / "state dir" / "pocketshell-link"
    config.mkdir(parents=True)
    (config / "config.json").write_text('{"device_id":"home-lab"}')
    (config / "device_ed25519.pem").write_text("NOT A REAL KEY")
    return config


def _snapshot(directory: Path) -> dict:
    return {
        p.name: (p.stat().st_mtime_ns, p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in sorted(directory.iterdir())
    }


def _unit_file() -> Path:
    return Path(linux.unit_path())


# --- RED -> GREEN control -------------------------------------------------------


def test_service_group_is_registered():
    """GREEN control. On the base branch (ece39ec) the same invocation exits 2
    with "No such command 'service'" — see the PR description."""
    result = CliRunner().invoke(cli, ["gateway", "service", "--help"])
    assert result.exit_code == 0, result.output
    for sub in ("install", "uninstall", "status"):
        assert sub in result.output


# --- systemd unit content ---------------------------------------------------------


def test_unit_runs_the_absolute_helper_directly():
    text = linux.render_unit("/opt/ps/pocketshell-link", "/home/u/.config/pocketshell-link")
    lines = text.splitlines()
    assert 'ExecStart="/opt/ps/pocketshell-link" run --config-dir "/home/u/.config/pocketshell-link"' in lines
    assert "Restart=on-failure" in lines
    assert "RestartSec=5" in lines
    assert "After=network-online.target" in lines
    assert "Wants=network-online.target" in lines
    assert "WantedBy=default.target" in lines
    assert linux.MANAGED_MARKER in text
    assert "/bin/sh" not in text and "bash" not in text and "pocketshell gateway run" not in text
    assert "Environment=" not in text
    assert linux.parse_unit(text) == ("/opt/ps/pocketshell-link", "/home/u/.config/pocketshell-link")


def test_unit_escapes_systemd_specifiers_and_refuses_unquotable():
    text = linux.render_unit("/opt/a%b$c/pocketshell-link", "/srv/x y")
    assert 'ExecStart="/opt/a%%b$$c/pocketshell-link" run --config-dir "/srv/x y"' in text
    assert linux.parse_unit(text) == ("/opt/a%b$c/pocketshell-link", "/srv/x y")
    for bad in ('/srv/a"b', "/srv/a\\b", "/srv/a\nExecStartPre=/bin/evil", "relative/dir"):
        with pytest.raises(ServiceError):
            linux.render_unit("/opt/pocketshell-link", bad)


# --- Linux install ---------------------------------------------------------------


@POSIX
def test_install_writes_unit_and_enables(pin_helper, enrolled, systemctl):
    helper = pin_helper(_SHOW_HELPER)
    before = _snapshot(enrolled)
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--config-dir", str(enrolled)])
    assert result.exit_code == 0, result.output
    assert "home-lab" in result.stdout
    unit = _unit_file()
    assert unit.read_text() == linux.render_unit(helper, str(enrolled))
    assert unit.stat().st_mode & 0o777 == 0o644
    assert not [p for p in unit.parent.iterdir() if p.name.startswith(".pocketshell")]
    assert systemctl.calls == [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", linux.UNIT_NAME],
    ]
    assert _snapshot(enrolled) == before


@POSIX
def test_install_refuses_when_not_enrolled(pin_helper, tmp_path, systemctl):
    pin_helper(_SHOW_HELPER)
    empty = tmp_path / "nothing"
    empty.mkdir()
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--config-dir", str(empty)])
    assert result.exit_code == 1
    assert "run `pocketshell gateway enroll` first" in result.stderr
    assert "Traceback" not in result.output
    assert not _unit_file().exists()
    assert systemctl.calls == []
    assert list(empty.iterdir()) == []


@POSIX
def test_install_refuses_when_helper_show_refuses(pin_helper, enrolled, systemctl):
    pin_helper("#!/bin/sh\necho 'bad key permissions \x1b[2J' >&2\nexit 1\n")
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--config-dir", str(enrolled)])
    assert result.exit_code == 1
    assert "pocketshell gateway enroll" in result.stderr
    assert "\x1b" not in result.output
    assert not _unit_file().exists()
    assert systemctl.calls == []


@POSIX
def test_install_refuses_incompatible_helper(pin_helper, enrolled, systemctl):
    pin_helper(_SHOW_HELPER, version_json='{"version":"x","protocol":"pocketshell-tunnel-v0","commit":"y"}')
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--config-dir", str(enrolled)])
    assert result.exit_code == 1
    assert "protocol" in result.stderr
    assert not _unit_file().exists()


@POSIX
def test_dry_run_writes_nothing(pin_helper, enrolled, systemctl):
    helper = pin_helper(_SHOW_HELPER)
    before = _snapshot(enrolled)
    result = CliRunner().invoke(
        cli, ["gateway", "service", "install", "--config-dir", str(enrolled), "--dry-run"]
    )
    assert result.exit_code == 0, result.output
    assert linux.render_unit(helper, str(enrolled)) in result.stdout
    assert "systemctl --user enable --now pocketshell-gateway.service" in result.stdout
    assert json.dumps([helper, "run", "--config-dir", str(enrolled)]) in result.stdout
    assert not Path(linux.unit_dir()).exists()
    assert systemctl.calls == []
    assert _snapshot(enrolled) == before


@POSIX
def test_existing_unit_needs_force(pin_helper, enrolled, systemctl):
    pin_helper(_SHOW_HELPER)
    unit = _unit_file()
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\nExecStart=/usr/bin/pocketshell gateway run\n")
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--config-dir", str(enrolled)])
    assert result.exit_code == 1
    assert "--force" in result.stderr
    assert "gateway run" in unit.read_text()
    assert systemctl.calls == []
    result = CliRunner().invoke(
        cli, ["gateway", "service", "install", "--config-dir", str(enrolled), "--force"]
    )
    assert result.exit_code == 0, result.output
    assert linux.MANAGED_MARKER in unit.read_text()
    assert systemctl.calls[-1] == ["systemctl", "--user", "restart", linux.UNIT_NAME]


@POSIX
def test_no_start_only_enables(pin_helper, enrolled, systemctl):
    pin_helper(_SHOW_HELPER)
    result = CliRunner().invoke(
        cli, ["gateway", "service", "install", "--config-dir", str(enrolled), "--no-start"]
    )
    assert result.exit_code == 0, result.output
    assert systemctl.calls[-1] == ["systemctl", "--user", "enable", linux.UNIT_NAME]


@POSIX
def test_install_warns_when_linger_off(pin_helper, enrolled, systemctl, monkeypatch):
    pin_helper(_SHOW_HELPER)
    monkeypatch.setattr(linux, "linger_enabled", lambda user=None: False)
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--config-dir", str(enrolled)])
    assert result.exit_code == 0, result.output
    assert "enable-linger" in result.stderr


@POSIX
def test_systemctl_failure_is_reported_without_traceback(pin_helper, enrolled, monkeypatch):
    pin_helper(_SHOW_HELPER)
    fake = Systemctl(fail=("enable",))
    monkeypatch.setattr(linux, "run_child", fake)
    monkeypatch.setattr(linux, "linger_enabled", lambda user=None: True)
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--config-dir", str(enrolled)])
    assert result.exit_code == 1
    assert "failed (exit 1)" in result.stderr
    assert "\x1b" not in result.output and "Traceback" not in result.output


# --- Linux uninstall / status -----------------------------------------------------


@POSIX
def test_uninstall_removes_only_the_unit_and_is_idempotent(pin_helper, enrolled, systemctl):
    pin_helper(_SHOW_HELPER)
    assert CliRunner().invoke(
        cli, ["gateway", "service", "install", "--config-dir", str(enrolled)]
    ).exit_code == 0
    before = _snapshot(enrolled)
    systemctl.calls.clear()
    result = CliRunner().invoke(cli, ["gateway", "service", "uninstall"])
    assert result.exit_code == 0, result.output
    assert not _unit_file().exists()
    assert systemctl.calls[0] == ["systemctl", "--user", "disable", "--now", linux.UNIT_NAME]
    assert ["systemctl", "--user", "daemon-reload"] in systemctl.calls
    assert all(str(enrolled) not in " ".join(c) for c in systemctl.calls)
    assert _snapshot(enrolled) == before
    again = CliRunner().invoke(cli, ["gateway", "service", "uninstall"])
    assert again.exit_code == 0
    assert "nothing to do" in again.stdout
    assert _snapshot(enrolled) == before


@LINUX
def test_uninstall_refuses_a_hand_written_unit(systemctl):
    unit = _unit_file()
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\nExecStart=%h/.local/bin/pocketshell gateway run\n")
    result = CliRunner().invoke(cli, ["gateway", "service", "uninstall"])
    assert result.exit_code == 1
    assert "hand-written" in result.stderr
    assert unit.exists()
    assert systemctl.calls == []


@LINUX
def test_status_not_installed(systemctl):
    result = CliRunner().invoke(cli, ["gateway", "service", "status"])
    assert result.exit_code == common.EXIT_NOT_INSTALLED == 4
    assert "not installed" in result.stdout


@POSIX
@pytest.mark.parametrize(
    "props, code, running",
    [
        ("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\n", 0, True),
        ("LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\n", 3, False),
    ],
)
def test_status_reports_state_and_show(pin_helper, enrolled, systemctl, props, code, running):
    helper = pin_helper(_SHOW_HELPER)
    assert CliRunner().invoke(
        cli, ["gateway", "service", "install", "--config-dir", str(enrolled)]
    ).exit_code == 0
    systemctl.show_props = props
    result = CliRunner().invoke(cli, ["gateway", "service", "status", "--json"])
    assert result.exit_code == code, result.output
    data = json.loads(result.stdout)
    assert data["installed"] is True and data["running"] is running and data["managed"] is True
    assert data["helper"] == helper and data["config_dir"] == str(enrolled)
    assert data["helper_sha256"] == hashlib.sha256(Path(helper).read_bytes()).hexdigest()
    assert "device id:       home-lab" in data["show"]
    assert data["exit_code"] == code
    if running:
        assert data["processes"] == [{"pid": 4242}]
    text = CliRunner().invoke(cli, ["gateway", "service", "status"])
    assert text.exit_code == code
    assert "home-lab" in text.stdout


# --- Windows: task XML --------------------------------------------------------------

NS = {"t": win.TASK_NS}


def _xml(helper=WIN_HELPER, config=WIN_CONFIG, sid=USER_SID, **kw):
    return win.build_task_xml(helper, config, sid, **kw)


def test_task_xml_schema_fields():
    text = _xml()
    root = ET.fromstring(win._strip_declaration(text))
    assert text.startswith('<?xml version="1.0" encoding="UTF-16"?>')
    get = lambda path: root.find(path, NS).text  # noqa: E731
    assert get("t:RegistrationInfo/t:URI") == "\\PocketShell\\GatewayLink"
    assert get("t:Principals/t:Principal/t:UserId") == USER_SID
    assert get("t:Principals/t:Principal/t:LogonType") == "S4U"
    assert get("t:Principals/t:Principal/t:RunLevel") == "LeastPrivilege"
    assert get("t:Triggers/t:BootTrigger/t:Delay") == "PT30S"
    assert get("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval") == "PT5M"
    assert get("t:Triggers/t:TimeTrigger/t:Repetition/t:StopAtDurationEnd") == "false"
    assert get("t:Settings/t:MultipleInstancesPolicy") == "IgnoreNew"
    assert get("t:Settings/t:ExecutionTimeLimit") == "PT0S"
    assert get("t:Settings/t:DisallowStartIfOnBatteries") == "false"
    assert get("t:Settings/t:StopIfGoingOnBatteries") == "false"
    assert get("t:Settings/t:RunOnlyIfNetworkAvailable") == "false"
    assert get("t:Settings/t:RestartOnFailure/t:Interval") == "PT1M"
    assert get("t:Settings/t:RestartOnFailure/t:Count") == "999"
    assert root.find("t:Actions", NS).get("Context") == "Author"
    assert root.find("t:Principals/t:Principal", NS).get("id") == "Author"


def test_task_action_is_the_direct_helper_argv():
    """Revision 5: the exe itself, no cmd.exe / shell / redirection."""
    text = _xml()
    root = ET.fromstring(win._strip_declaration(text))
    actions = list(root.find("t:Actions", NS))
    assert len(actions) == 1 and actions[0].tag == f"{{{win.TASK_NS}}}Exec"
    exe = actions[0]
    assert exe.find("t:Command", NS).text == WIN_HELPER
    arguments = exe.find("t:Arguments", NS).text
    assert arguments == f'run --config-dir "{WIN_CONFIG}"'
    assert exe.find("t:WorkingDirectory", NS).text == WIN_HELPER.rsplit("\\", 1)[0]
    assert win.parse_arguments(arguments) == ["run", "--config-dir", WIN_CONFIG]
    assert win.action_argv(WIN_HELPER, WIN_CONFIG) == [WIN_HELPER, "run", "--config-dir", WIN_CONFIG]
    low = text.lower()
    for forbidden in ("cmd.exe", "cmd /", "/c ", "powershell", "2>", "&gt;", "conhost"):
        assert forbidden not in low


def test_task_xml_laptop_revision5_action():
    fields = win.parse_task_xml(_xml())
    assert fields["command"] == WIN_HELPER
    assert fields["arguments"] == (
        'run --config-dir "C:\\Users\\alexey\\PocketShellFleet\\quiet-sshd-v26a\\gateway-helper-cd7\\keys"'
    )
    assert fields["working_directory"] == (
        "C:\\Users\\alexey\\PocketShellFleet\\quiet-sshd-v26a\\gateway-helper-cd7"
    )
    assert fields["user_id"] == USER_SID


def test_no_start_registers_the_task_disabled():
    root = ET.fromstring(win._strip_declaration(_xml(enabled=False)))
    assert root.find("t:Settings/t:Enabled", NS).text == "false"
    root = ET.fromstring(win._strip_declaration(_xml()))
    assert root.find("t:Settings/t:Enabled", NS).text == "true"


def test_parse_applies_schema_defaults_omitted_by_export():
    """Task Scheduler's export drops default values (seen on windows-latest:
    no <RunLevel> for LeastPrivilege)."""
    text = _xml().replace("<RunLevel>LeastPrivilege</RunLevel>", "")
    text = text.replace("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", "")
    fields = win.parse_task_xml(text)
    assert fields["run_level"] == "LeastPrivilege"
    assert fields["execution_time_limit"] == "PT72H"
    high = win.parse_task_xml(_xml().replace("LeastPrivilege", "HighestAvailable"))
    assert high["run_level"] == "HighestAvailable"


def test_task_xml_escapes_values():
    config = r"C:\Users\a b\keys & <stuff> 'x'"
    text = _xml(config=config)
    assert "&amp;" in text and "&lt;stuff&gt;" in text
    fields = win.parse_task_xml(text)
    assert win.parse_arguments(fields["arguments"]) == ["run", "--config-dir", config]


def test_task_xml_bytes_are_utf16_with_bom_and_crlf():
    data = win.task_xml_bytes(_xml(config="C:\\Users\\Jürgen\\keys"))
    assert data[:2] in (b"\xff\xfe", b"\xfe\xff")
    text = data.decode("utf-16")
    assert "\r\n" in text and "Jürgen" in text
    assert win.parse_task_xml(common.decode(data))["arguments"].endswith('Jürgen\\keys"')


def test_task_xml_refuses_bad_principal():
    for sid in ("", "Everyone", "S-1-1-0", USER_SID + "</UserId>"):
        with pytest.raises(ServiceError):
            _xml(sid=sid)


@pytest.mark.parametrize(
    "value",
    [
        'C:\\Users\\a"b\\keys',
        "C:\\Users\\%USERNAME%\\keys",
        "C:\\Users\\a\nb",
        "C:\\Users\\a\x00b",
        "keys",
        "\\\\server\\share\\keys",
        "\\\\?\\C:\\keys",
        "C:keys",
        "C:\\keys:stream",
    ],
)
def test_path_validation_refuses(value):
    with pytest.raises(ServiceError):
        win.validate_path(value, "config dir")


@pytest.mark.parametrize(
    "value",
    ["C:\\", "C:\\a b\\", "C:\\x\\\\", "D:\\Ünïcode dir\\keys", "C:\\a\\b c\\d"],
)
def test_quoting_round_trips_like_commandlinetoargvw(value):
    quoted = win.quote_arg(value)
    assert quoted.startswith('"') and quoted.endswith('"')
    assert win.parse_arguments("run --config-dir " + quoted) == ["run", "--config-dir", value]


def test_quote_arg_root_doubles_trailing_backslash():
    assert win.quote_arg("C:\\") == '"C:\\\\"'


# --- Windows: digest allow-list ------------------------------------------------------


def test_allow_list_is_exactly_the_qualified_cd7_build():
    assert win.ALLOWED_HELPER_SHA256 == frozenset({QUALIFIED})
    win.check_digest(QUALIFIED)


@pytest.mark.parametrize("digest, build", [(HISTORICAL_8CB, "8cbeb8f"), (HISTORICAL_771, "771c9e1")])
def test_historical_builds_are_refused(digest, build):
    with pytest.raises(ServiceError, match=f"historical {build}"):
        win.check_digest(digest)


def test_unknown_digest_is_refused():
    with pytest.raises(ServiceError, match="not a reviewed"):
        win.check_digest(hashlib.sha256(b"anything").hexdigest())


# --- Windows: install / uninstall flow with fakes -------------------------------------

VERSION_OK = b'{"version":"cd7c6f6","protocol":"pocketshell-tunnel-v1","commit":"cd7c6f6a"}\n'


class FakeApi:
    def __init__(self, sid=USER_SID, owners=None, procs=None):
        self.sid = sid
        self.owners = owners or {}
        self.procs = procs if procs is not None else []

    def current_sid(self):
        return self.sid

    def owner_sid(self, path):
        return self.owners.get(path, self.sid)

    def processes(self, image):
        return list(self.procs)


_STATE_CODES = {"Unknown": 0, "Disabled": 1, "Queued": 2, "Ready": 3, "Running": 4}


class FakeWindows:
    """Fake schtasks / Task Scheduler COM (via powershell) / helper.

    Keeps the 'registered' XML and a task state; knobs simulate query
    failures, a failing or non-starting /Run, and a registration whose
    readback differs from what was requested.
    """

    def __init__(self, *, registered=None, create_rc=0, version=VERSION_OK, show_rc=0):
        self.calls: list[list[str]] = []
        self.registered = registered
        self.create_rc = create_rc
        self.version = version
        self.show_rc = show_rc
        self.xml_seen = None
        self.xml_path = None
        self.state = "Ready"
        self.query_error = False          # access denied on every query
        self.query_error_after_delete = False
        self.run_rc = 0
        self.run_starts = True            # /Run success moves the task to Running
        self.mutate_on_create = None      # callable(xml) -> registered readback
        self.deleted = False

    def _query_failed(self):
        return self.query_error or (self.query_error_after_delete and self.deleted)

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        exe = argv[0].lower()
        if exe.endswith("schtasks.exe"):
            verb = argv[1]
            if verb == "/Query":
                if self._query_failed():
                    return ChildResult(1, b"", b"ERROR: Access is denied.\r\n")
                if self.registered is None:
                    return ChildResult(1, b"", b"ERROR: The system cannot find the file specified.\r\n")
                return ChildResult(0, self.registered.encode("utf-16"), b"")
            if verb == "/Create":
                self.xml_path = argv[argv.index("/XML") + 1]
                self.xml_seen = Path(self.xml_path).read_bytes()
                if self.create_rc:
                    return ChildResult(self.create_rc, b"", b"ERROR: Access is denied.\r\n")
                xml = self.xml_seen.decode("utf-16")
                self.registered = self.mutate_on_create(xml) if self.mutate_on_create else xml
                self.state = "Disabled" if "<Enabled>false</Enabled>" in xml else "Ready"
                return ChildResult(0, b"SUCCESS", b"")
            if verb == "/Run":
                if self.run_rc:
                    return ChildResult(self.run_rc, b"", b"ERROR: Access is denied.\r\n")
                if self.run_starts:
                    self.state = "Running"
                return ChildResult(0, b"SUCCESS", b"")
            if verb == "/End":
                if self.state == "Running":
                    self.state = "Ready"
            if verb == "/Delete":
                self.registered = None
                self.deleted = True
            return ChildResult(0, b"", b"")
        if exe.endswith("powershell.exe"):
            script = argv[-1]
            if "Schedule.Service" in script:  # COM query
                if self._query_failed():
                    out = {"found": False, "hresult": "0x80070005", "message": "Access is denied.\x1b[2J"}
                elif self.registered is None:
                    out = {"found": False, "hresult": "0x80070002", "message": "not found"}
                else:
                    out = {
                        "found": True,
                        "state": _STATE_CODES[self.state],
                        "last_result": 267009,
                        "xml": base64.b64encode(self.registered.encode("utf-8")).decode(),
                    }
                return ChildResult(0, json.dumps(out).encode(), b"")
            if self._query_failed():
                return ChildResult(1, b"", b"Access is denied.")
            return ChildResult(0, json.dumps({"State": self.state}).encode(), b"")
        if argv[1:] == ["version", "--json"]:
            return ChildResult(0, self.version, b"")
        if argv[1] == "show":
            return ChildResult(self.show_rc, SHOW_OUT.encode() if not self.show_rc else b"", b"denied")
        raise AssertionError(f"unexpected child {argv}")


@pytest.fixture
def fake_windows(monkeypatch):
    fake = FakeWindows()
    monkeypatch.setattr(win, "run_child", fake)
    monkeypatch.setattr(common, "run_child", fake)
    monkeypatch.setattr(win, "file_sha256", lambda path: QUALIFIED)
    monkeypatch.setattr(win, "WindowsApi", FakeApi)
    monkeypatch.setattr(win, "final_path", lambda p: p)
    # the enrolled files "exist" (paths are Windows paths on a POSIX box)
    real_isfile, real_isdir = os.path.isfile, os.path.isdir
    monkeypatch.setattr(common.os.path, "isfile", lambda p: True if str(p).startswith("C:\\") else real_isfile(p))
    monkeypatch.setattr(common.os.path, "isdir", lambda p: True if str(p).startswith("C:\\") else real_isdir(p))
    return fake


def _windows_cli(monkeypatch, *args):
    original = sys.platform
    monkeypatch.setattr(sys, "platform", "win32")
    try:
        return CliRunner().invoke(cli, ["gateway", "service", *args])
    finally:
        monkeypatch.setattr(sys, "platform", original)


def test_windows_resolve_helper_gates(fake_windows, monkeypatch):
    assert win.resolve_helper(WIN_HELPER) == WIN_HELPER
    monkeypatch.setattr(win, "file_sha256", lambda path: HISTORICAL_8CB)
    with pytest.raises(ServiceError, match="historical"):
        win.resolve_helper(WIN_HELPER)
    monkeypatch.setattr(win, "file_sha256", lambda path: QUALIFIED)
    fake_windows.version = b'{"version":"x","protocol":"pocketshell-tunnel-v2","commit":"y"}\n'
    with pytest.raises(ServiceError, match="protocol"):
        win.resolve_helper(WIN_HELPER)
    with pytest.raises(ServiceError, match="--helper"):
        win.resolve_helper(None)
    with pytest.raises(ServiceError, match=".exe"):
        win.resolve_helper("C:\\tools\\pocketshell-link.bat")


def test_windows_install_registers_one_direct_task(fake_windows):
    plan = win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=FakeApi())
    warnings = win.apply_install(plan)
    assert warnings == []
    verbs = [c[1] for c in fake_windows.calls if c[0].lower().endswith("schtasks.exe")]
    assert verbs == ["/Query", "/Create", "/Query", "/Run"]
    create = next(c for c in fake_windows.calls if c[1:2] == ["/Create"])
    assert create[1:5] == ["/Create", "/TN", "\\PocketShell\\GatewayLink", "/XML"]
    assert "/F" not in create and "/RU" not in create and "/RP" not in create
    assert fake_windows.xml_seen.startswith(b"\xff\xfe")
    assert not Path(fake_windows.xml_path).exists()  # temp definition removed
    assert not Path(fake_windows.xml_path).parent.exists()
    for argv in fake_windows.calls:
        assert "cmd.exe" not in " ".join(argv).lower()
    fields = win.parse_task_xml(fake_windows.registered)
    assert fields["command"] == WIN_HELPER and fields["logon_type"] == "S4U"


def test_windows_install_refuses_sid_mismatch(fake_windows):
    key = WIN_CONFIG + "\\device_ed25519.pem"
    api = FakeApi(owners={key: OTHER_SID})
    with pytest.raises(ServiceError, match="owned by .*not by you"):
        win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=api)
    api = FakeApi(owners={WIN_CONFIG: OTHER_SID})
    with pytest.raises(ServiceError, match="enrolling user"):
        win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=api)
    # the key itself must be the user's, even if Administrators own it
    api = FakeApi(owners={key: "S-1-5-32-544"})
    with pytest.raises(ServiceError, match="owned by S-1-5-32-544"):
        win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=api)
    assert not any(c[1:2] == ["/Create"] for c in fake_windows.calls)


def test_windows_install_accepts_elevated_created_config_dir(fake_windows):
    """An elevated mkdir by the same user stamps Administrators as owner;
    the helper accepts that, so does install (the key stays the user's)."""
    api = FakeApi(owners={WIN_CONFIG: "S-1-5-32-544"})
    plan = win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=api)
    assert plan.user_sid == USER_SID


def test_windows_install_refuses_when_not_enrolled(fake_windows):
    fake_windows.show_rc = 1
    with pytest.raises(common.NotEnrolledError, match="gateway enroll"):
        win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=FakeApi())
    assert not any(c[1:2] == ["/Create"] for c in fake_windows.calls)


def test_windows_install_refuses_existing_without_force(fake_windows):
    fake_windows.registered = _xml()
    with pytest.raises(ServiceError, match="--force"):
        win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=FakeApi())
    plan = win.plan_install(WIN_HELPER, WIN_CONFIG, force=True, start=False, api=FakeApi())
    assert "<Enabled>false</Enabled>" in plan.xml
    win.apply_install(plan)
    verbs = [c[1] for c in fake_windows.calls if c[0].lower().endswith("schtasks.exe")]
    assert verbs[-3:] == ["/End", "/Create", "/Query"]
    assert next(c for c in fake_windows.calls if c[1:2] == ["/Create"])[-1] == "/F"


def test_windows_registration_refusal_is_clear(fake_windows):
    fake_windows.create_rc = 1
    plan = win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=FakeApi())
    with pytest.raises(ServiceError) as info:
        win.apply_install(plan)
    message = str(info.value)
    assert "Access is denied" in message and "elevated" in message and "S4U" in message
    assert not Path(fake_windows.xml_path).exists()


def test_windows_dry_run_cli_writes_nothing(fake_windows, monkeypatch):
    result = _windows_cli(
        monkeypatch, "install", "--helper", WIN_HELPER, "--config-dir", WIN_CONFIG, "--dry-run"
    )
    assert result.exit_code == 0, result.output
    assert "<LogonType>S4U</LogonType>" in result.stdout
    assert f"<UserId>{USER_SID}</UserId>" in result.stdout
    assert json.dumps([WIN_HELPER, "run", "--config-dir", WIN_CONFIG]) in result.stdout
    assert fake_windows.xml_path is None
    assert [c[1] for c in fake_windows.calls if c[0].lower().endswith("schtasks.exe")] == ["/Query"]


def test_windows_uninstall_only_deletes_the_task(fake_windows):
    fake_windows.registered = _xml()
    message = win.uninstall(api=FakeApi())
    assert "removed" in message and "untouched" in message
    sch = [c for c in fake_windows.calls if c[0].lower().endswith("schtasks.exe")]
    assert [c[1] for c in sch] == ["/Query", "/End", "/Delete", "/Query"]
    for argv in fake_windows.calls:
        assert WIN_CONFIG not in argv
    assert "nothing to do" in win.uninstall(api=FakeApi())


def test_windows_status_reports_process_session_and_show(fake_windows):
    fake_windows.registered = _xml()
    fake_windows.state = "Running"
    api = FakeApi(procs=[
        {"pid": 11944, "session_id": 0, "path": WIN_HELPER},
        {"pid": 7, "session_id": 1, "path": "C:\\other\\pocketshell-link.exe"},
    ])
    st = win.status(api=api)
    assert st.installed and st.running and st.managed
    assert st.processes == [{"pid": 11944, "session_id": 0, "path": WIN_HELPER}]
    assert st.helper == WIN_HELPER and st.config_dir == WIN_CONFIG
    assert st.helper_allowed is True and st.details["direct_launch"] is True
    assert st.details["logon_type"] == "S4U" and st.state == "Running"
    assert "home-lab" in st.show
    assert st.exit_code == 0


def test_windows_status_does_not_run_an_unreviewed_helper(fake_windows, monkeypatch):
    fake_windows.registered = _xml()
    monkeypatch.setattr(win, "file_sha256", lambda path: HISTORICAL_771)
    st = win.status(api=FakeApi())
    assert st.helper_allowed is False and st.show is None
    assert not any(c[1:2] == ["show"] for c in fake_windows.calls)


def test_windows_status_exit_codes(fake_windows, monkeypatch):
    result = _windows_cli(monkeypatch, "status")
    assert result.exit_code == 4
    fake_windows.registered = _xml()
    fake_windows.state = "Ready"
    result = _windows_cli(monkeypatch, "status", "--json")
    assert result.exit_code == 3, result.output
    assert json.loads(result.stdout)["running"] is False


# --- shared ---------------------------------------------------------------------------------


def test_children_get_create_no_window_on_windows(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    original = sys.platform
    monkeypatch.setattr(sys, "platform", "win32")
    try:
        common.run_child(["C:\\Windows\\System32\\schtasks.exe", "/Query"])
    finally:
        monkeypatch.setattr(sys, "platform", original)
    assert seen["creationflags"] == 0x08000000
    assert seen["stdin"] is subprocess.DEVNULL
    assert "shell" not in seen


def test_sanitize_strips_escapes():
    assert common.sanitize("a\x1b[31mb\x07\r\nc") == "a?[31mb?\nc"


def test_decode_handles_schtasks_encodings():
    assert common.decode("<Task/>".encode("utf-16")) == "<Task/>"
    assert common.decode("<Task/>".encode("utf-16-le")) == "<Task/>"
    assert common.decode(b"<Task/>") == "<Task/>"
