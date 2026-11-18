"""Mandatory normal-tray artifact gate: actual private SSH and native PTYs."""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import shlex
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows native terminal")


@pytest.fixture(scope="module")
def endpoint():
    sys.path[:0] = [str(Path(__file__).parents[1] / "gateway"), str(Path(__file__).parent)]
    from tray_terminal_fixture import Endpoint
    payload = os.environ["POCKETSHELL_TRAY_TERMINAL_PAYLOAD"]  # missing input is a failure, never a skip
    host = Endpoint(payload)
    host.proofs = []
    try:
        host.start()
        yield host
    finally:
        host.close()
        proof = {"qualification": host.qualification, "source": host.catalog["source"],
                 "provenance": getattr(host, "provenance", None), "proofs": host.proofs,
                 "killProofs": host.kill_proofs, "memoryObservations": host.memory_observations,
                 "oomPreservations": host.oom_preservations, "environmentProofs": host.environment_proofs}
        Path(os.environ["POCKETSHELL_TRAY_TERMINAL_PROOF"]).write_text(json.dumps(proof, indent=2))


def test_fresh_create_pty_reconnect_and_owned_kill(endpoint):
    host = endpoint
    control = host.create("control-" + host.nonce[:8])
    target = host.create("fresh-" + host.nonce[:8])
    assert target["id"] != control["id"] and target["created"] is True
    proof = host.kernel_oracle(target["id"])
    assert proof["bytes"] == 12 * 1024**3
    assert target["memory_enforcement"]["memory_limit_bytes"] == proof["bytes"]
    host.proofs += [host.attach_io(target["id"], "first", interrupt_probe=True), host.attach_io(target["id"], "reconnect")]
    host.kill(target["id"])
    assert control["id"] in {row["id"] for row in host.rows()}
    host.proofs.append(host.attach_io(control["id"], "unrelated-preserved"))
    host.kill(control["id"])


def test_project_cap_is_kernel_enforced_not_only_reported(endpoint):
    host = endpoint
    control = host.create("allocation-control-" + host.nonce[:8])
    host.proofs.append(host.attach_io(control["id"], "kernel-allows-128m", allocation_probe="allow"))
    config = host.workspace / "cgroups.toml"
    assert not config.exists()
    config.write_text('mem = "64M"\n')
    try:
        target = host.create("bounded-" + host.nonce[:8])
        proof = host.kernel_oracle(target["id"])
        assert proof["bytes"] == 64 * 1024**2
        host.proofs.append({"kernelBound": proof, **host.attach_io(
            target["id"], "kernel-refused-128m", allocation_probe="deny")})
        host.kill(target["id"], after_oom=True)
        assert control["id"] in {row["id"] for row in host.rows()}
        host.kill(control["id"])
    finally:
        config.unlink()


def test_invalid_caps_and_mutable_selectors_fail_closed(endpoint):
    host = endpoint
    control = host.create("preserved-" + host.nonce[:8])
    before = {row["id"] for row in host.rows()}
    cwd = shlex.quote(host.sftp_workspace())
    for cap in ("none", "invalid", "1M"):
        code, output = host.exec(f"pocketshell sessions create --json --cwd {cwd} --mem {cap} -- denied")
        assert code != 0 and "error" in json.loads(output)
        assert {row["id"] for row in host.rows()} == before
    config = host.workspace / "cgroups.toml"
    config.write_text('mem = "none"\n')
    try:
        code, output = host.exec(f"pocketshell sessions create --json --cwd {cwd} -- denied-project")
        assert code != 0 and "error" in json.loads(output)
    finally:
        config.unlink()
    for command in ("attach", "kill --json"):
        code, _ = host.exec(f"pocketshell sessions {command} -- " + shlex.quote(control["name"]))
        assert code != 0
    assert {row["id"] for row in host.rows()} == before
    host.proofs.append(host.attach_io(control["id"], "negative-preserved"))
    host.kill(control["id"])


def test_private_profile_preserves_complete_scripts_and_interactive_shell(endpoint):
    host = endpoint
    values = ["space arg", "single' and double\" quote", "C:\\tail dir\\", r"C:\\paired\\slashes", "Ω 日本 😀",
              "$(printf NOT_AN_EXPANSION)", "; printf ALSO_DATA", "line one\nline two"]
    oracle = host.workspace / "argv-boundary.json"
    code = "import json,pathlib,sys;pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]),encoding='utf8');print('ARGV44_OK')"
    command = host.python_command(code) + " " + shlex.quote(str(oracle)) + " " + " ".join(map(shlex.quote, values))
    for pty in (False, True):
        assert not oracle.exists()
        answer = host.exec_pty(command) if pty else host.exec(command)
        assert answer[0] == 0 and "ARGV44_OK" in answer[1], answer
        assert json.loads(oracle.read_text(encoding="utf8")) == values
        oracle.unlink()
        # Actual Python SOURCE, not encoded data: the Windows literals must
        # arrive unchanged through both Bash command-line boundaries.
        embedded = ("import json,pathlib\npathlib.Path(" + repr(str(oracle)) + ").write_text(json.dumps("
                    + repr(values) + "),encoding='utf8')\nprint('SOURCE44_OK')\n")
        script = host.python_command(embedded)
        answer = host.exec_pty(script) if pty else host.exec(script)
        assert answer[0] == 0 and "SOURCE44_OK" in answer[1], answer
        assert json.loads(oracle.read_text(encoding="utf8")) == values
        oracle.unlink()
        expansion = host.workspace / "expansion.txt"
        script = "printf '%s' \"$((44+8))\" > " + shlex.quote(expansion.as_posix())
        answer = host.exec_pty(script) if pty else host.exec(script)
        assert answer[0] == 0 and expansion.read_text() == "52", answer
        expansion.unlink()
        host.proofs.append({"privateProfilePTY": pty, "independentFileOracle": True,
                            "argvDataPreserved": True, "shellExpansionPreserved": True,
                            "embeddedSourcePreserved": True})
    host.proofs.append(host.attach_io(None, "no-command-interactive"))


def test_packaged_launchers_preserve_console_and_quiet_stdio(endpoint):
    from tray_launcher_probe import background_controls, build_layout
    host = endpoint
    root = build_layout(host.installed, host.top / "launcher-probe")
    host.proofs.append(background_controls(root))
    for name, console in (("pocketshell.exe", True), ("GatewayTray.exe", False)):
        oracle = root / (name + ".json")
        # The actual binaries are unchanged; only the throwaway Python module
        # writes console metadata. No real tray/setup/native owner prompt runs.
        command = shlex.quote((root / name).as_posix()) + " proof " + shlex.quote(str(oracle))
        answer = host.exec_pty(command)
        assert answer[0] == 0 and oracle.exists(), answer
        proof = json.loads(oracle.read_text(encoding="utf8"))
        assert proof["stdinConsole"] is console and proof["stdoutConsole"] is console
        if not console:
            assert proof["consoleWindow"] == 0
        host.proofs.append({"independentFileOracle": True, "entry": name, "console": console,
                            "validParentConsoleOnly": True})


@contextlib.contextmanager
def user_environment(host, nonce):
    """A user whose tools live only in the registry Path and whose login files set a marker.

    HKCU Path gets: a SHADOW dir (a.exe, pocketshell.exe) FIRST, a literal dir, and a
    %USERPROFILE%-relative REG_EXPAND_SZ dir (sshd-session's closed env has no %USERPROFILE%).
    ~/.bash_profile + ~/.bashrc export a marker that only a LOGIN shell may see.
    """
    import shutil
    import winreg
    from pocketshell.gateway.service_agent_install import known_folders
    profile = Path(known_folders()["USERPROFILE"])
    root = host.top / "registry-path-tools"
    shadow, literal, expand = root / "shadow bin", root / "literal bin", root / "expand bin"
    whoami = Path(os.environ["SystemRoot"]) / "System32/whoami.exe"
    for directory, names in ((shadow, ("a.exe", "pocketshell.exe")), (literal, ("psregprobe.exe",)),
                             (expand, ("psexpandprobe.exe",))):
        directory.mkdir(parents=True)
        for name in names:
            shutil.copyfile(whoami, directory / name)
    # A stand-in "claude" that keeps running (an agent that exits at once cannot be verified as a session).
    shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32/cmd.exe", literal / "claude.exe")
    entries = [str(shadow), str(literal), "%USERPROFILE%\\" + str(expand.relative_to(profile))]
    dotfiles = {name: profile / name for name in (".bash_profile", ".bashrc")}
    saved = {name: path.read_bytes() for name, path in dotfiles.items() if path.exists()}
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
    try:
        original = winreg.QueryValueEx(key, "Path")
    except FileNotFoundError:
        original = None
    try:
        base = original[0] if original else ""
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join([*entries, base] if base else entries))
        dotfiles[".bashrc"].write_text("export PSBASHRC_" + nonce + "=1\n", encoding="ascii")
        dotfiles[".bash_profile"].write_text("test -f ~/.bashrc && . ~/.bashrc\n", encoding="ascii")
        yield {"shadow": shadow, "literal": literal, "expand": expand}
    finally:
        for name, path in dotfiles.items():
            if name in saved:
                path.write_bytes(saved[name])
            else:
                path.unlink(missing_ok=True)
        if original is None:
            with contextlib.suppress(FileNotFoundError):
                winreg.DeleteValue(key, "Path")
        else:
            winreg.SetValueEx(key, "Path", 0, original[1], original[0])
        key.Close()


def environment_script(host, dirs, nonce, *, login, oracle, first, second):
    """One line of Bash: prints ENV43_<sum>_OK only if every environment fact holds."""
    root = host.installed.as_posix().lower()
    def lower(path):
        return Path(path).as_posix().lower()
    marker = 'PSBASHRC_' + nonce
    rc = f'[ "${{{marker}}}" = 1 ] || ok=FAIL-login-rc' if login else f'[ -z "${{{marker}}}" ] || ok=FAIL-exec-sourced-rc'
    return (f"v=$(({first}+{second})); ok=OK; "
            "chk(){ g=$(cygpath -m \"$(type -P $1)\" 2>/dev/null); g=${g,,}; [ \"$g\" = \"$2\" ] || ok=FAIL-$1:$g; }; "
            f"chk psregprobe '{lower(dirs['literal'])}/psregprobe.exe'; "
            f"chk psexpandprobe '{lower(dirs['expand'])}/psexpandprobe.exe'; "
            f"chk a '{root}/python/a.exe'; chk pocketshell '{root}/pocketshell.exe'; "
            '[ "$(a --version 2>&1)" = "a 0.1.13" ] || ok=FAIL-managed-a-version; '
            f"{rc}; printf 'ENV43_%s_%s\\n' \"$v\" \"$ok\" > {shlex.quote(oracle)}; cat {shlex.quote(oracle)}")


def test_registry_path_login_shell_and_session_environment(endpoint):
    """The maintainer's report: no claude/codex/npm/aliases in Windows endpoint shells.

    Real shipped sshd-session + aplexer. Covers SSH exec, SSH PTY command, the direct
    interactive login shell and an aplexer-created durable shell session, plus agent
    engine detection and spawn through `a`.
    """
    host = endpoint
    nonce = host.nonce[:12]
    with user_environment(host, nonce) as dirs:
        def script_for(login):
            return lambda oracle, first, second: (
                environment_script(host, dirs, nonce, login=login, oracle=oracle, first=first, second=second) + "\r",
                f"ENV43_{first + second}_OK")
        for pty in (False, True):
            first, second = 4200 + int(pty), 17
            oracle = (host.workspace / f"exec-env-{pty}.txt").as_posix()
            command = environment_script(host, dirs, nonce, login=False, oracle=oracle, first=first, second=second)
            answer = host.exec_pty(command) if pty else host.exec(command)
            expected = f"ENV43_{first + second}_OK"
            assert answer[0] == 0 and expected in answer[1], answer
            host.environment_proofs.append({"context": "ssh-exec-pty" if pty else "ssh-exec", "profileSkipped": True,
                                            "registryPath": True, "expandedUserProfileEntry": True,
                                            "managedToolsBeatShadow": True})
        proof = host.attach_io(None, "direct-login-environment", script=script_for(True))
        host.environment_proofs.append({"context": "ssh-interactive-login", "loginRc": True, "registryPath": True,
                                        "expandedUserProfileEntry": True, "managedToolsBeatShadow": True, **proof})
        session = host.create("environment-" + nonce[:8])
        proof = host.attach_io(session["id"], "aplexer-shell-session-environment", script=script_for(True))
        host.environment_proofs.append({"context": "aplexer-shell-session", "loginRc": True, "registryPath": True,
                                        "expandedUserProfileEntry": True, "managedToolsBeatShadow": True, **proof})
        host.kill(session["id"])
        # Agent engines are detected and launched through the same environment: the agent picker.
        code, output = host.exec("a --json engines")
        assert code == 0, output
        engines = {row["name"]: row["available"] for row in json.loads(output)}
        assert engines.get("claude") is True, engines
        cwd = shlex.quote(host.sftp_workspace())
        code, output = host.exec(f"pocketshell sessions create --json --cwd {cwd} --engine claude -- agent-{nonce[:8]}")
        assert code == 0, output
        agent = json.loads(output)
        host.ids.add(agent["id"])
        host.exec("pocketshell sessions kill --json -- " + shlex.quote(agent["id"]))
        host.environment_proofs.append({"context": "agent-engine", "engineAvailable": True, "agentSessionStarted": True})
