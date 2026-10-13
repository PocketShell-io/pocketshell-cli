"""`pocketshell keys …` flows with a scripted password prompt (no real TTY)."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from keyhelpers import keygen
from pocketshell.cli import cli
from pocketshell.keys import crypto, store

PW = "device-password"


def run(*args, input=None):
    return CliRunner().invoke(cli, ["keys", *args], input=input)


def _plain(name: str, password: str = PW) -> bytes:
    entry = store.load().get(name)
    buf = crypto.decrypt_into(entry.envelope, password, entry.aad)
    try:
        return bytes(buf)
    finally:
        crypto.wipe(buf)


def _secret_markers(path) -> list[bytes]:
    """Byte strings that must never appear on disk for this private key file."""
    text = path.read_bytes()
    body = b"".join(text.split(b"\n")[1:-2])
    return [text, body[:64], body[-64:]]


def _scan(root, markers) -> list[str]:
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            if any(m in data for m in markers):
                hits.append(p)
    return hits


def test_generate_list_public_flow(passwords, xdg):
    passwords.push(PW, PW)
    result = run("generate", "laptop")
    assert result.exit_code == 0, result.output
    pub_line = result.stdout.strip().splitlines()[-1]
    assert pub_line.startswith("ssh-ed25519 ") and pub_line.endswith(" laptop")
    assert "New device password" in passwords.prompts[0]
    assert "Repeat" in passwords.prompts[1]

    result = run("public", "laptop")
    assert result.exit_code == 0 and result.stdout.strip() == pub_line
    assert passwords.prompts[2:] == []  # no password needed to read public data

    result = run("list")
    assert result.exit_code == 0
    assert "laptop" in result.stdout and "ssh-ed25519" in result.stdout
    doc = json.loads(run("list", "--json").stdout)
    assert doc["keys"][0]["name"] == "laptop"
    assert doc["keys"][0]["passphrase_protected"] is False
    assert _plain("laptop").startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")


@pytest.mark.parametrize("key_type, prefix", [("ecdsa", "ecdsa-sha2-nistp256"), ("rsa", "ssh-rsa")])
def test_generate_other_types(passwords, key_type, prefix):
    passwords.push(PW, PW)
    result = run("generate", "k", "--type", key_type, "--comment", "me@box")
    assert result.exit_code == 0, result.output
    assert result.stdout.strip().startswith(prefix) and result.stdout.strip().endswith(" me@box")


def test_second_key_needs_the_existing_password(passwords):
    passwords.push(PW, PW)
    assert run("generate", "a").exit_code == 0
    passwords.push("not-the-password")
    result = run("generate", "b")
    assert result.exit_code == 1
    assert "wrong device password" in result.output
    assert sorted(store.load().entries) == ["a"]
    passwords.push(PW)
    assert run("generate", "b").exit_code == 0
    assert sorted(store.load().entries) == ["a", "b"]


def test_new_password_rules(passwords):
    passwords.push("short", "short")
    result = run("generate", "a")
    assert result.exit_code == 1 and "at least 8" in result.output
    passwords.queue.clear()
    passwords.push("long-enough-1", "long-enough-2")
    result = run("generate", "a")
    assert result.exit_code == 1 and "do not match" in result.output
    assert store.load().entries == {}


def test_add_unprotected_openssh_key(passwords, tmp_path, xdg):
    src = keygen(tmp_path / "id_ed25519")
    passwords.push(PW, PW)
    result = run("add", "work", "--from", str(src))
    assert result.exit_code == 0, result.output
    assert "added work: SHA256:" in result.stdout
    assert "was not modified" in result.stderr
    entry = store.load().get("work")
    assert not entry.passphrase_protected
    # The public half is the .pub's (comment included), the private bytes are kept verbatim.
    assert entry.public.line == (tmp_path / "id_ed25519.pub").read_text().strip()
    assert _plain("work") == src.read_bytes()
    assert _scan(xdg, _secret_markers(src)) == []


def test_add_passphrase_key_keeps_its_own_encryption(passwords, tmp_path):
    src = keygen(tmp_path / "id_pp", passphrase="key-passphrase")
    os.remove(tmp_path / "id_pp.pub")  # public half must come from the openssh header
    passwords.push(PW, PW)
    result = run("add", "pp", "--from", str(src))
    assert result.exit_code == 0, result.output
    assert "has its own passphrase" in result.stdout
    entry = store.load().get("pp")
    assert entry.passphrase_protected
    assert _plain("pp") == src.read_bytes()  # still encrypted with key-passphrase
    pub = subprocess.run(
        ["ssh-keygen", "-y", "-P", "key-passphrase", "-f", str(src)],
        check=True, capture_output=True, text=True,
    ).stdout.split()[:2]
    assert entry.public.line.split()[:2] == pub
    assert "yes" in run("list").stdout


def test_add_from_stdin(passwords, tmp_path):
    src = keygen(tmp_path / "id_stdin")
    passwords.push(PW, PW)
    result = run("add", "piped", "--from", "-", input=src.read_bytes())
    assert result.exit_code == 0, result.output
    assert _plain("piped") == src.read_bytes()


def test_add_unencrypted_pem_rsa(passwords, tmp_path):
    src = keygen(tmp_path / "id_rsa_pem", "-m", "PEM", key_type="rsa")
    os.remove(tmp_path / "id_rsa_pem.pub")
    passwords.push(PW, PW)
    result = run("add", "pem", "--from", str(src))
    assert result.exit_code == 0, result.output
    expected = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(src)], check=True, capture_output=True, text=True
    ).stdout.split()[:2]
    assert store.load().get("pem").public.line.split()[:2] == expected


def test_encrypted_pem_needs_its_pub(passwords, tmp_path):
    src = keygen(tmp_path / "id_enc_pem", "-m", "PEM", passphrase="pp-12345", key_type="rsa")
    pub = (tmp_path / "id_enc_pem.pub").read_text()
    os.remove(tmp_path / "id_enc_pem.pub")
    result = run("add", "x", "--from", str(src))
    assert result.exit_code == 1 and "does not reveal its public key" in result.output
    (tmp_path / "id_enc_pem.pub").write_text(pub)
    passwords.push(PW, PW)
    result = run("add", "x", "--from", str(src))
    assert result.exit_code == 0, result.output
    assert store.load().get("x").passphrase_protected


@pytest.mark.parametrize(
    "content, message",
    [
        (b"hello", "not a PEM or OpenSSH private key"),
        (b"PuTTY-User-Key-File-3: ssh-ed25519\n", "PuTTY"),
        (b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", "not a private key"),
        (b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
         + base64.b64encode(b"garbage-not-magic") + b"\n-----END OPENSSH PRIVATE KEY-----\n",
         "not an openssh-key-v1"),
        (b"x" * (17 * 1024), "too large"),
    ],
)
def test_add_refuses_non_keys_without_prompting(passwords, tmp_path, content, message):
    src = tmp_path / "bad"
    src.write_bytes(content)
    result = run("add", "bad", "--from", str(src))
    assert result.exit_code == 1
    assert message in result.output
    assert passwords.prompts == []


def test_add_missing_file(passwords, tmp_path):
    result = run("add", "x", "--from", str(tmp_path / "nope"))
    assert result.exit_code == 1 and "cannot read" in result.output


def test_duplicate_and_invalid_names(passwords):
    passwords.push(PW, PW)
    assert run("generate", "a").exit_code == 0
    result = run("generate", "a")
    assert result.exit_code == 1 and "already exists" in result.output
    result = run("generate", "../evil")
    assert result.exit_code == 1 and "invalid key name" in result.output


def test_unknown_key(passwords):
    result = run("public", "ghost")
    assert result.exit_code == 1 and "no key named 'ghost'" in result.output


def test_remove(passwords):
    passwords.push(PW, PW)
    assert run("generate", "a").exit_code == 0
    result = run("remove", "a")  # CliRunner stdin is not a TTY
    assert result.exit_code == 1 and "--yes" in result.output
    result = run("remove", "a", "--yes")
    assert result.exit_code == 0 and "removed a" in result.output
    assert store.load().entries == {}


def test_passwd_rewraps_every_key(passwords):
    passwords.push(PW, PW)
    assert run("generate", "a").exit_code == 0
    passwords.push(PW)
    assert run("generate", "b").exit_code == 0
    before = {n: _plain(n) for n in ("a", "b")}

    passwords.push("wrong-password")
    result = run("passwd")
    assert result.exit_code == 1 and "wrong device password" in result.output

    passwords.push(PW, "brand-new-password", "brand-new-password")
    result = run("passwd")
    assert result.exit_code == 0, result.output
    assert "re-encrypted 2 key(s)" in result.output
    for n in ("a", "b"):
        with pytest.raises(crypto.WrongPassword):
            _plain(n, PW)
        assert _plain(n, "brand-new-password") == before[n]


def test_passwd_on_empty_vault(passwords):
    result = run("passwd")
    assert result.exit_code == 1 and "empty" in result.output


def test_vault_file_holds_no_plaintext_or_password(passwords, tmp_path, xdg):
    src = keygen(tmp_path / "id_scan")
    passwords.push(PW, PW)
    assert run("add", "scan", "--from", str(src)).exit_code == 0
    passwords.push(PW)
    gen = run("generate", "gen")
    assert gen.exit_code == 0
    raw = (xdg / "pocketshell" / store.FILE_NAME).read_bytes()
    assert PW.encode() not in raw
    assert _scan(xdg, _secret_markers(src) + [PW.encode()]) == []
    generated = _plain("gen")
    body = b"".join(generated.split(b"\n")[1:-2])
    assert _scan(xdg, [body[:64], body[-64:]]) == []


def test_real_prompt_refuses_without_a_terminal(tmp_path, xdg):
    """No controlling TTY: the real prompt refuses (never falls back to stdin)."""
    env = dict(os.environ, XDG_CONFIG_HOME=str(xdg))
    proc = subprocess.run(
        [sys.executable, "-m", "pocketshell", "keys", "generate", "x"],
        input=b"device-password\ndevice-password\n",
        capture_output=True, env=env, timeout=60, start_new_session=True,
    )
    assert proc.returncode == 1
    assert b"must be typed on a terminal" in proc.stderr
    assert store.load().entries == {}
