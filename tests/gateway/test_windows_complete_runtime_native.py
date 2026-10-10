# ruff: noqa: F811
"""Complete-runtime validation of the generic v3 closure on a real Windows host
(CI only; disposable runner). The whole matching closure is built in the job
from the OWNED backend artifacts (quiet OpenSSH 10.3p1 + the 717e49fe MSYS
runtime) + Git-for-Windows 2.56.0.2 + the accepted aplexer fc396 pair; only the
helper is a labelled CI stand-in (never run here: no enrollment).

The new-machine flow (revision D), as an ORDINARY user (unelevated token):

1. ``agent install --endpoint-keys generate --port P`` into a userData whose
   path has a SPACE and non-ASCII (``José Smith``): the generated sshd.conf /
   aplexer.toml are quoted UTF-8 and the real guardian e862645d must accept
   them;
2. ``agent bind --manifest --authority`` (pre-enrollment), ``agent start``: the
   real guardian starts the owned sshd; READY proves the GENERATED host key;
3. ``agent authorize-key`` with a test client key;
4. a key login runs the MSYS bash (the backend shell role) and the aplexer CLI
   (with the SetEnv backend environment); a PTY session; SFTP put/get through
   the owned sftp-server;
5. ``agent stop`` (in a ``finally`` that also covers a failed start/READY).

SCOPE (honest): ``acceptJob`` is a TEST-ONLY report-only seam (agent_harness):
the hosted runner's step job forbids a job-free launch, so the job membership is
ACCEPTED and REPORTED here; this is NOT a NoJob qualification. NOT YET
QUALIFIED here: the Aplexer SESSION lifecycle (create, typing, resize,
reconnect, detach/reattach). This test covers the engines query, a PTY shell
round trip with a computed reply, the backend bash and SFTP only.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "nt" or not os.environ.get("POCKETSHELL_TEST_CLOSURE_V3_OUT"),
    reason="complete-runtime validation: CI windows job with the v3 closure only",
)

HARNESS = Path(__file__).parent / "agent_harness.py"
SSH_DIR = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "OpenSSH"
TRIO = ["e862645ddc374801f1ae921be3bf66afeb0ccff03d82adb909ad1b4ec0bdd877",
        "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231",
        "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce"]


def _free_port():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def closure():
    out = Path(os.environ["POCKETSHELL_TEST_CLOSURE_V3_OUT"])
    staged = out / "root-a" / "releases" / "staged"
    catalog = out / "host-runtime-catalog.json"
    assert staged.is_dir() and catalog.is_file()
    return {"staged": staged, "catalog": catalog, "doc": json.loads(catalog.read_text(encoding="utf-8"))}


def _ssh_base(key, known, port):
    return ["-i", str(key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known}", "-o", "ConnectTimeout=20"]


def test_new_machine_complete_runtime(closure, tmp_path):
    from pocketshell.gateway import service_windows as win
    from unelevated import run_unelevated

    api = win.WindowsApi()
    if api.current_session() == 0:
        pytest.skip("the runner process is in session 0 (no interactive session for the active-console mode)")
    user_data = Path(os.environ["APPDATA"]) / f"José Smith e2e {uuid.uuid4().hex[:6]}" / "PocketShell"
    user_data.parent.mkdir(parents=True)
    port = _free_port()
    seams = tmp_path / "seams.json"
    seams.write_text(json.dumps({"helper": [], "manifest": [], "sources": [TRIO], "acceptJob": True}))
    env = dict(os.environ, XDG_CONFIG_HOME=str(tmp_path / "agent-config"), PYTHONIOENCODING="utf-8",
               PYTHONUTF8="1")

    def agent(*args, stdin_file=None):
        argv = [sys.executable, str(HARNESS), str(seams), "gateway", "agent", *args, "--json"]
        if stdin_file is not None:
            argv = ["cmd.exe", "/d", "/c", subprocess.list2cmdline(argv) + f' < "{stdin_file}"']
        code, out = run_unelevated(argv, env=env, cwd=str(tmp_path), timeout=900)
        text = out.decode("utf-8", "replace")
        print(f"$ (unelevated) pocketshell gateway agent {' '.join(args)} -> exit {code}\n{text[-4000:]}")
        start = text.find("{")
        return code, (json.loads(text[start:]) if start >= 0 else None)

    # 1. install (first use, generated keys)
    code, data = agent("install", "--operation-id", "e2e-install", "--user-data", str(user_data),
                       "--catalog", str(closure["catalog"]), "--staged", str(closure["staged"]),
                       "--endpoint-keys", "generate", "--port", str(port))
    assert code == 0, data
    receipt = data["receipt"]
    keys, endpoint = receipt["keys"], receipt["endpoint"]
    assert keys["mode"] == "generated" and keys["hostKeyPublic"].startswith("ssh-ed25519 ")
    assert receipt["installer"]["closure"]["rows"] == len(closure["doc"]["files"])
    print("measured closure:", receipt["installer"]["closure"])
    config = Path(endpoint["config"]).read_bytes().decode("utf-8")
    assert "José Smith" in config and f'"{str(user_data).replace(chr(92), "/")}' in config
    print(config)

    # 2. pre-enrollment bind + endpoint-only start (the real guardian e862645d + owned sshd)
    authority = str(user_data / "managed-runtime" / "authority.json")
    code, data = agent("bind", "--manifest", endpoint["manifest"], "--authority", authority)
    assert code == 0, data
    # diagnostics only (never an assertion): the owned daemon's own view of its
    # binary and the generated config, run unelevated like the guardian would
    manifest0 = json.loads(Path(endpoint["manifest"]).read_text(encoding="utf-8"))
    for diag in ([manifest0["daemon"], "-V"], [manifest0["daemon"], "-t", "-f", manifest0["config"]]):
        dcode, dout = run_unelevated(["cmd.exe", "/d", "/c", subprocess.list2cmdline(diag) + " 2>&1"], env=env,
                                     cwd=str(Path(manifest0["daemon"]).parent), timeout=60)
        print("DIAG", diag[1:], "->", dcode, hex(dcode & 0xFFFFFFFF), dout.decode("utf-8", "replace")[-2000:])
    print("SCOPE: acceptJob is a report-only CI seam (job membership accepted and reported), NOT NoJob "
          "qualification; the Aplexer session lifecycle is NOT YET QUALIFIED by this test")
    try:  # the finally also stops a start whose READY assertion fails
        code, data = agent("start", "--timeout", "300")
        if code != 0:
            for p in sorted(Path(endpoint["state"]).rglob("*.json")):
                print(p, p.read_text(encoding="utf-8", errors="replace")[:3000])
        assert code == 0 and data["state"] == "pre-enrollment", data
        assert data["endpoint"]["state"] == "ready" and data["endpoint"]["hostKey"]["proven"] is True
        assert data["outbound"]["state"] == "not-enrolled"
        print("launch (reported):", data["endpoint"].get("launch"))

        # 3. authorize ONE own client key
        key = tmp_path / "client_ed25519"
        subprocess.run([str(SSH_DIR / "ssh-keygen.exe"), "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        code, data = agent("authorize-key", "--public-key-stdin", stdin_file=str(key) + ".pub")
        assert code == 0 and data["authorized"]["type"] == "ssh-ed25519", data
        known = tmp_path / "known_hosts"
        known.write_text(f"[127.0.0.1]:{port} {keys['hostKeyPublic']}\n", encoding="ascii")
        manifest = json.loads(Path(endpoint["manifest"]).read_text(encoding="utf-8"))
        user = manifest["configBindings"]["allowUser"]
        base = _ssh_base(key, known, port)
        bash = manifest["configBindings"]["backendExecutable"].replace("/", "\\")
        a_exe = str(Path(manifest["python"]).parent / "a.exe")

        # 4a. non-PTY session: the default shell runs the backend bash and the aplexer CLI
        script = (f'"{bash}" --noprofile --norc -c "echo bash-$((6*7)); uname -s"\r\n'
                  f'"{a_exe}" --json engines\r\nexit 5\r\n')
        p = subprocess.run([str(SSH_DIR / "ssh.exe"), *base, "-p", str(port), f"{user}@127.0.0.1"],
                           input=script.encode("utf-8"), capture_output=True, timeout=120)
        out = p.stdout.decode("utf-8", "replace")
        print("non-PTY:", p.returncode, out[-3000:], p.stderr.decode(errors="replace")[-2000:])
        assert "bash-42" in out and "bash-42" not in script and "MSYS_NT" in out
        assert p.returncode == 5  # the real exit status of the remote command
        assert '"shell"' in out  # the aplexer CLI answered with its engines (incl. the shell engine)

        # 4b. PTY session (ssh-shellhost + conhost): a COMPUTED reply absent from the input
        pty_in = b"set /a 6*7+1000\r\nexit 7\r\n"
        p = subprocess.run([str(SSH_DIR / "ssh.exe"), *base, "-tt", "-p", str(port), f"{user}@127.0.0.1"],
                           input=pty_in, capture_output=True, timeout=120)
        out = p.stdout.decode("utf-8", "replace")
        print("PTY:", p.returncode, out[-2000:])
        assert "1042" in out and b"1042" not in pty_in
        assert p.returncode == 7  # the real exit status through the PTY

        # 4c. SFTP put/get through the owned sftp-server
        local = tmp_path / "payload.bin"
        local.write_bytes(os.urandom(256 * 1024))
        back = tmp_path / "back.bin"
        batch = tmp_path / "batch.txt"
        batch.write_text(f'put "{local}" e2e-payload.bin\nget e2e-payload.bin "{back}"\nrm e2e-payload.bin\n',
                         encoding="utf-8")
        p = subprocess.run([str(SSH_DIR / "sftp.exe"), *base, "-P", str(port), "-b", str(batch),
                            f"{user}@127.0.0.1"], capture_output=True, timeout=120)
        print("SFTP:", p.returncode, p.stdout.decode(errors="replace")[-2000:], p.stderr.decode(errors="replace"))
        assert p.returncode == 0 and back.read_bytes() == local.read_bytes()
    finally:
        # 5. stop (identity-bound)
        code, data = agent("stop", "--timeout", "60")
        assert code == 0 and data["state"] == "stopped", data
