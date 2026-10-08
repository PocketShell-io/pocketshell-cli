"""`gateway pin` / `gateway unpin` and the strict pin-file contract."""

from __future__ import annotations

import base64
import os
import shutil
import stat
import subprocess

import pytest
from click.testing import CliRunner

from gateway_keyblobs import (
    ED25519_LINE,
    ED25519_LINE_2,
    ecdsa_blob,
    ed25519_blob,
    line,
    mpint,
    rsa_blob,
    ssh_string,
)
from pocketshell.cli import cli
from pocketshell.gateway import pins
from pocketshell.gateway.pins import PinError, load_pins, parse_host_key


@pytest.fixture(autouse=True)
def _xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


def _pin_file(tmp_path):
    return tmp_path / "xdg" / "pocketshell" / "gateway_known_hosts"


# --- host-key line validation ----------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        ED25519_LINE,
        line("ecdsa-sha2-nistp256", ecdsa_blob("nistp256", 65)),
        line("ecdsa-sha2-nistp384", ecdsa_blob("nistp384", 97)),
        line("ecdsa-sha2-nistp521", ecdsa_blob("nistp521", 133)),
        line("ssh-rsa", rsa_blob(2048)),
        line("ssh-rsa", rsa_blob(4096, e=3)),
        "  " + ED25519_LINE + " ",
    ],
)
def test_wellformed_host_keys_parse(text):
    key = parse_host_key(text)
    assert key.line == text.strip()
    assert key.fingerprint.startswith("SHA256:")
    assert "=" not in key.fingerprint


def test_fingerprint_matches_ssh_keygen(tmp_path):
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen unavailable")
    keyfile = tmp_path / "hk"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(keyfile)],
        check=True,
    )
    pub = (tmp_path / "hk.pub").read_text().split()
    key = parse_host_key(f"{pub[0]} {pub[1]}")
    out = subprocess.run(
        ["ssh-keygen", "-lf", str(tmp_path / "hk.pub")],
        capture_output=True, text=True, check=True,
    ).stdout
    assert out.split()[1] == key.fingerprint


_B64_ED = base64.b64encode(ed25519_blob()).decode()
_B64_EC = base64.b64encode(ecdsa_blob()).decode()
assert _B64_EC.endswith("E=")  # one pad char: 104-byte blob


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        f"ssh-ed25519 {_B64_ED} root@host",  # trailing comment / extra field
        f"ssh-ed25519  {_B64_ED}",  # double space → empty field
        f"ssh-ed25519\t{_B64_ED}",
        f"ssh-ed25519 {_B64_ED}\n",
        f"ssh-ed25519 {_B64_ED}\n@cert-authority * ssh-ed25519 {_B64_ED}",
        f"ssh-ed25519 {_B64_ED}\r\n* ssh-ed25519 {_B64_ED}",
        f"@cert-authority ssh-ed25519 {_B64_ED}",
        f"@revoked ssh-ed25519 {_B64_ED}",
        f"* ssh-ed25519 {_B64_ED}",
        f"pocketshell-gateway.other ssh-ed25519 {_B64_ED}",
        f"ssh-dss {_B64_ED}",
        f"sk-ssh-ed25519@openssh.com {_B64_ED}",
        f"ssh-ed25519-cert-v01@openssh.com {_B64_ED}",
        "ssh-ed25519 not*base64",
        "ecdsa-sha2-nistp256 " + _B64_EC.rstrip("="),  # missing padding
        "ecdsa-sha2-nistp256 " + _B64_EC + "==",
        "ecdsa-sha2-nistp256 " + _B64_EC[:-2] + "F=",  # non-canonical trailing bits
        # stated type differs from the blob's own type
        f"ssh-rsa {_B64_ED}",
        line("ecdsa-sha2-nistp256", ecdsa_blob("nistp384", 97)),
        # malformed blobs of the right type
        line("ssh-ed25519", ssh_string(b"ssh-ed25519") + ssh_string(b"\x01" * 31)),
        line("ssh-ed25519", ed25519_blob() + b"\x00"),  # trailing bytes
        line("ssh-ed25519", ssh_string(b"ssh-ed25519")),  # truncated
        line("ssh-ed25519", b"\xff\xff\xff\xff"),
        line("ecdsa-sha2-nistp256",
             ssh_string(b"ecdsa-sha2-nistp256") + ssh_string(b"nistp256")
             + ssh_string(b"\x02" + b"\x11" * 64)),  # compressed point
        line("ssh-rsa", rsa_blob(1024)),  # too small
        line("ssh-rsa", rsa_blob(2048, e=65536)),  # even exponent
        line("ssh-rsa", ssh_string(b"ssh-rsa") + ssh_string(b"\x00\x01") + mpint(1 << 2047 | 1)),
        line("ssh-rsa", ssh_string(b"ssh-rsa") + ssh_string(b"\x81") + mpint(1 << 2047 | 1)),
        f"ssh-ed25519 {_B64_ED}\x1b[31m",
        f"ssh-ed25519 {_B64_ED}‮",
    ],
)
def test_malformed_or_injecting_host_keys_are_refused(text):
    with pytest.raises(PinError):
        parse_host_key(text)


# --- CLI ------------------------------------------------------------------------


def test_pin_writes_a_private_strict_known_hosts_line(tmp_path):
    result = CliRunner().invoke(cli, ["gateway", "pin", "home-lab", ED25519_LINE])
    assert result.exit_code == 0, result.output
    key = parse_host_key(ED25519_LINE)
    assert f"pinned home-lab: {key.fingerprint} (ED25519)" in result.output
    path = _pin_file(tmp_path)
    assert path.read_text() == f"pocketshell-gateway.home-lab {ED25519_LINE}\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert load_pins() == {"home-lab": key}


def test_pin_same_key_twice_is_idempotent(tmp_path):
    runner = CliRunner()
    runner.invoke(cli, ["gateway", "pin", "home-lab", ED25519_LINE])
    result = runner.invoke(cli, ["gateway", "pin", "home-lab", ED25519_LINE])
    assert result.exit_code == 0
    assert "already pinned" in result.output


def test_pin_refuses_to_silently_swap_a_key(tmp_path):
    runner = CliRunner()
    runner.invoke(cli, ["gateway", "pin", "home-lab", ED25519_LINE])
    result = runner.invoke(cli, ["gateway", "pin", "home-lab", ED25519_LINE_2])
    assert result.exit_code == 1
    assert "--replace" in result.output
    assert load_pins()["home-lab"] == parse_host_key(ED25519_LINE)
    result = runner.invoke(
        cli, ["gateway", "pin", "--replace", "home-lab", ED25519_LINE_2]
    )
    assert result.exit_code == 0, result.output
    assert load_pins()["home-lab"] == parse_host_key(ED25519_LINE_2)


def test_multiple_devices_and_unpin(tmp_path):
    runner = CliRunner()
    runner.invoke(cli, ["gateway", "pin", "bbb-host", ED25519_LINE])
    runner.invoke(cli, ["gateway", "pin", "aaa-host", ED25519_LINE_2])
    assert set(load_pins()) == {"aaa-host", "bbb-host"}
    result = runner.invoke(cli, ["gateway", "unpin", "bbb-host"])
    assert result.exit_code == 0, result.output
    assert "unpinned bbb-host" in result.output
    assert set(load_pins()) == {"aaa-host"}
    result = runner.invoke(cli, ["gateway", "unpin", "bbb-host"])
    assert result.exit_code == 1
    assert "no host key is pinned" in result.output


@pytest.mark.parametrize("device_id", ["x", "-oProxyCommand=id", "a b c", "a%hbc", "ab\ncd"])
def test_pin_refuses_hostile_device_ids(tmp_path, device_id):
    result = CliRunner().invoke(cli, ["gateway", "pin", device_id, ED25519_LINE])
    assert result.exit_code != 0
    assert not _pin_file(tmp_path).exists()


def test_pin_refuses_injection_in_the_key_argument(tmp_path):
    hostile = f"{ED25519_LINE}\n@cert-authority * {ED25519_LINE}"
    result = CliRunner().invoke(cli, ["gateway", "pin", "home-lab", hostile])
    assert result.exit_code == 1
    assert not _pin_file(tmp_path).exists()


# --- reading back: the file is untrusted until fully validated ------------------


def _write_raw(tmp_path, text, mode=0o600):
    path = _pin_file(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(text)
    os.chmod(path, mode)
    return path


@pytest.mark.parametrize(
    "extra",
    [
        f"@cert-authority * {ED25519_LINE}\n",
        f"@revoked pocketshell-gateway.home-lab {ED25519_LINE}\n",
        f"* {ED25519_LINE}\n",
        f"|1|abc=|def= {ED25519_LINE}\n",
        f"pocketshell-gateway.home-lab,* {ED25519_LINE}\n",
        "# a comment\n",
        "\n",
        f"pocketshell-gateway.home-lab {ED25519_LINE_2}\n",  # second key, same device
        f"pocketshell-gateway.other-host {ED25519_LINE} comment\n",
    ],
)
def test_foreign_lines_make_the_whole_file_untrusted(tmp_path, extra):
    _write_raw(tmp_path, f"pocketshell-gateway.home-lab {ED25519_LINE}\n" + extra)
    with pytest.raises(PinError):
        load_pins()
    # …and pin/unpin refuse to rewrite (and thereby launder) it.
    result = CliRunner().invoke(cli, ["gateway", "pin", "new-host", ED25519_LINE])
    assert result.exit_code == 1


def test_group_writable_pin_file_is_refused(tmp_path):
    _write_raw(tmp_path, f"pocketshell-gateway.home-lab {ED25519_LINE}\n", mode=0o620)
    with pytest.raises(PinError, match="writable"):
        load_pins()


def test_symlinked_pin_file_is_refused(tmp_path):
    real = tmp_path / "elsewhere"
    real.write_text(f"pocketshell-gateway.home-lab {ED25519_LINE}\n")
    path = _pin_file(tmp_path)
    path.parent.mkdir(parents=True, mode=0o700)
    path.symlink_to(real)
    with pytest.raises(PinError):
        load_pins()


def test_missing_final_newline_is_refused(tmp_path):
    _write_raw(tmp_path, f"pocketshell-gateway.home-lab {ED25519_LINE}")
    with pytest.raises(PinError, match="truncated"):
        load_pins()


def test_require_pin_explains_how_to_get_one(tmp_path):
    with pytest.raises(PinError) as exc:
        pins.require_pin("home-lab")
    assert "gateway show --pin-command" in str(exc.value)
    assert "never trusted" in str(exc.value)


def test_relative_xdg_config_home_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/dir")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert pins.pin_file_path() == tmp_path / "home" / ".config" / "pocketshell" / (
        "gateway_known_hosts"
    )
