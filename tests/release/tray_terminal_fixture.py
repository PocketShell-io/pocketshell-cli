"""Actual private native OpenSSH/Git Bash fixture for packaged tray terminal tests."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import shlex
import shutil
import socket
import struct
import subprocess
import threading
import time
from uuid import uuid4


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verified_public_files(payload, receipt):
    """Only the measured, pre-enrollment public producer closure may be copied."""
    for parent in (payload, *payload.parents):
        assert not parent.is_symlink() and not getattr(parent.lstat(), "st_file_attributes", 0) & 0x400
    catalog_path = payload / "host-runtime-catalog.json"
    assert digest(catalog_path) == receipt["catalogSHA256"]
    catalog = json.loads(catalog_path.read_bytes())
    assert catalog["source"] == receipt["source"]
    wanted = {}
    for row in catalog["files"]:
        path = PurePosixPath(row["path"])
        assert not path.is_absolute() and ".." not in path.parts and ":" not in str(path) and "\\" not in str(path)
        assert row["path"] not in wanted
        wanted[row["path"]] = row["sha256"]
    assert wanted and len(wanted) == receipt["files"]
    expected = {"runtime/" + path: value for path, value in wanted.items()}
    expected.update({path: value for path, value in wanted.items() if path.startswith("psc-ssh/")})
    expected["host-runtime-catalog.json"] = receipt["catalogSHA256"]
    expected["private-endpoint-build-receipt.json"] = receipt["privateEndpoint"]["receiptSHA256"]
    actual = {}
    for path in payload.rglob("*"):
        assert not path.is_symlink() and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        if path.is_file():
            assert path.stat().st_nlink == 1
            actual[path.relative_to(payload).as_posix()] = digest(path)
    assert actual == expected
    backend = json.loads((payload / "private-endpoint-build-receipt.json").read_bytes())
    assert backend["source"] == receipt["privateEndpoint"]["source"]
    assert backend["files"] == receipt["privateEndpoint"]["files"]
    assert all(wanted["endpoint/bin/" + path] == value for path, value in backend["files"].items())
    assert wanted["GatewayTray.exe"] == receipt["launcherSHA256"]
    assert wanted["pocketshell.exe"] == receipt["cliLauncher"]["sha256"]
    return expected


def stage_public_payload(payload, output, receipt_bytes):
    from pocketshell import windows_security as ws
    receipt = json.loads(receipt_bytes)
    measured = verified_public_files(payload, receipt)
    assert not output.exists() and output.parent.is_dir()
    # Only a fresh test-owned destination is protected; never change the
    # runner's temp ancestry. copyfile deliberately does not copy source ACLs.
    ws.write_private(output / "installer-receipt.json", receipt_bytes)
    destination = output / "payload"
    for relative in measured:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(payload / relative, target)
    assert verified_public_files(destination, receipt) == measured
    # Check the actual post-copy DACLs with the unchanged production reader.
    from pocketshell.gateway.service_agent_install import MAX_DOCUMENT, NativePaths
    from pocketshell.gateway.service_windows import WindowsApi
    api = WindowsApi()
    paths, sid = NativePaths(api), api.current_sid()
    result = paths.file(str(destination / "host-runtime-catalog.json"), sid,
                        private=False, max_bytes=MAX_DOCUMENT, root=str(destination))
    assert result["sha256"] == receipt["catalogSHA256"]
    rows = paths.inventory(str(destination / "runtime"), sid, private=False,
                           root=str(destination / "runtime"), max_files=16384)
    wanted = {row["path"]: row["sha256"] for row in json.loads(result["bytes"])["files"]}
    assert set(rows) == set(wanted)
    for relative in rows:
        checked = paths.file(str(destination / "runtime" / relative), sid, private=False,
                             max_bytes=0, root=str(destination / "runtime"))
        assert checked["sha256"] == wanted[relative]
    return destination


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


def shell_prompt_seen(output):
    # Conhost may paint Bash's trailing space with CSI cursor movement.
    # This only gates sending input; computed output and file proofs still
    # determine whether the real interactive command succeeded.
    rendered = re.sub(
        rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[ -/]*[@-~=>])",
        b"", output)
    return re.search(rb"(?:^|[\r\n])bash-[0-9]+(?:\.[0-9]+)*[$#] ?(?:\r?\n|$)", rendered) is not None


def interrupt_to_fresh_prompt(process, chunks, wait):
    offset = len(b"".join(chunks))
    process.stdin.write(b"\x03")
    process.stdin.flush()
    return wait(lambda: shell_prompt_seen(b"".join(chunks)[offset:]), 10)


class Endpoint:
    def __init__(self, payload, *, allow_dirty_component=False):
        self.payload = Path(payload).absolute()
        receipt_bytes = (self.payload.parent / "installer-receipt.json").read_bytes()
        receipt = json.loads(receipt_bytes)
        assert receipt["sourceDirty"] is False or allow_dirty_component
        self.qualification = "dirty-local-component" if receipt["sourceDirty"] else "clean-exact-head-artifact"
        self.installed = None
        self.ids = set()
        self.kill_proofs = []
        self.memory_observations = []
        self.oom_preservations = []
        self.nonce = uuid4().hex
        from pocketshell import windows_security as ws
        from pocketshell.gateway.service_agent_install import known_folders
        self.top = Path(known_folders()["USERPROFILE"]) / ("PocketShell Native Test " + self.nonce)
        ws.write_private(self.top / "test-owned.json", json.dumps({"nonce": self.nonce}).encode())
        self.payload = stage_public_payload(self.payload, self.top / "public-producer", receipt_bytes)
        self.stage = self.payload / "runtime"
        self.catalog = json.loads((self.payload / "host-runtime-catalog.json").read_bytes())
        self.workspace = self.top / "workspace data"
        ws.write_private(self.workspace / "test-owned.json", b'{"testOnly":true}')
        self.user_data = self.top / "host"
        self.env = {key: os.environ[key] for key in ("SystemRoot", "SystemDrive", "ProgramData")}
        self.env.update(XDG_CONFIG_HOME=str(self.top / "agent-config"), PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.harness = Path(__file__).with_name("tray_endpoint_harness.py")
        self.ssh = self.payload / "psc-ssh/ssh.exe"  # client only, never the PSC utility
        assert self.ssh.is_file()

    def _ordinary(self, argv, *, timeout=1800):
        from packaged_gateway_config_runner import elevated
        if elevated():
            from unelevated import run_unelevated
            return run_unelevated(argv, env=self.env, cwd=str(self.top), timeout=timeout)
        result = subprocess.run(argv, env=self.env, cwd=self.top, capture_output=True,
                                timeout=timeout, creationflags=0x08000000)
        return result.returncode, result.stdout + result.stderr

    def agent(self, *args):
        code, output = self._ordinary([str(self.stage / "python/python.exe"), "-I", "-B", str(self.harness),
                                      "gateway", "agent", *args, "--json", "--operation-id", uuid4().hex])
        text = output.decode("utf8", errors="replace")
        assert code == 0 or (args[0] == "stop" and code == 4), text[-6000:]
        return json.loads(text)

    def start(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from pocketshell import windows_security as ws
        doc = self.agent("install", "--user-data", str(self.user_data), "--catalog",
                         str(self.payload / "host-runtime-catalog.json"), "--staged", str(self.stage),
                         "--endpoint-keys", "generate", "--port", str(self.port), "--isolated-sessions")
        receipt = doc["receipt"]
        self.endpoint = receipt["endpoint"]
        self.installed = Path(receipt["location"]["root"]) / "releases" / receipt["release"]
        self.agent("bind", "--manifest", self.endpoint["manifest"], "--authority",
                   str(self.user_data / "managed-runtime/authority.json"))
        ready = self.agent("start", "--timeout", "300")
        assert ready["endpoint"]["state"] == "ready" and ready["endpoint"]["hostKey"]["proven"] is True
        manifest = json.loads(Path(self.endpoint["manifest"]).read_bytes())
        self.bindings = manifest["configBindings"]
        self.state_env = self.bindings["setEnv"]
        assert self.state_env["APLEXER_STATE_DIR"].replace("\\", "/").startswith(self.user_data.as_posix() + "/")
        self.user = self.bindings["allowUser"]
        client = Ed25519PrivateKey.generate()
        self.key = self.top / "client_ed25519"
        ws.write_private(self.key, client.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
        public = client.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                  serialization.PublicFormat.OpenSSH).decode()
        self.agent("authorize-key", "--public-key", public, "--confirmed")
        self.known = self.top / "known_hosts"
        self.known.write_text(f"[127.0.0.1]:{self.port} {receipt['keys']['hostKeyPublic']}\n", encoding="ascii")
        self.base = [str(self.ssh), "-F", "none", "-i", str(self.key), "-o", "IdentitiesOnly=yes",
                     "-o", "IdentityAgent=none", "-o", "GlobalKnownHostsFile=none", "-o", "BatchMode=yes",
                     "-o", "StrictHostKeyChecking=yes", "-o", 'UserKnownHostsFile="' + self.known.as_posix() + '"',
                     "-o", "ConnectTimeout=15", "-p", str(self.port)]
        self.destination = self.user + "@127.0.0.1"
        return self.check_provenance()

    def check_provenance(self):
        code, proof = self.exec(self.python_command(
            "import ctypes,hashlib,json,pathlib,subprocess,sys,pocketshell.windows_session_lifecycle as m;"
            "from ctypes import wintypes as w;k=ctypes.WinDLL('kernel32');a=ctypes.WinDLL('advapi32');"
            "k.GetCurrentProcess.restype=w.HANDLE;a.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)];"
            "a.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD)];"
            "t=w.HANDLE();v=w.DWORD();n=w.DWORD();assert a.OpenProcessToken(k.GetCurrentProcess(),8,ctypes.byref(t));"
            "assert a.GetTokenInformation(t,20,ctypes.byref(v),4,ctypes.byref(n));"
            "b=pathlib.Path(m.backend());"
            "print(json.dumps({'module':m.__file__,'elevated':bool(v.value),'isolated':bool(sys.flags.isolated),"
            "'backend':{'path':str(b),'version':subprocess.check_output([str(b),'--version'],text=True).strip(),"
            "'sha256':hashlib.sha256(b.read_bytes()).hexdigest()},"
            "'moduleFiles':{n:x.__file__ for n,x in sys.modules.copy().items() "
            "if n=='pocketshell' or n.startswith('pocketshell.')}}))"))
        assert code == 0
        self.provenance = json.loads(proof)
        expected = str(self.installed / "python/app.zip").replace("\\", "/").casefold() + "/"
        assert self.provenance["moduleFiles"] and all(
            path.replace("\\", "/").casefold().startswith(expected)
            for path in self.provenance["moduleFiles"].values())
        assert self.provenance["elevated"] is False and self.provenance["isolated"] is True
        assert digest(self.installed / "python/app.zip") == digest(self.stage / "python/app.zip")
        assert self.provenance["backend"]["version"] == "a 0.1.13"
        wanted_backend = next(
            row["sha256"] for row in self.catalog["files"] if row["path"] == "python/a.exe")
        assert self.provenance["backend"]["sha256"] == wanted_backend
        return self

    def python_command(self, code):
        return '"$POCKETSHELL_RUNTIME_ROOT/python/python.exe" -I -B -c ' + shlex.quote(code)

    def exec(self, command, *, timeout=45):
        result = subprocess.run([*self.base, self.destination, command], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout, creationflags=0x08000000)
        text = result.stdout.decode("utf8", errors="replace")
        if result.returncode:
            print("SSH failure:", result.returncode, text[-2000:], result.stderr.decode(errors="replace")[-2000:])
        return result.returncode, text

    def exec_pty(self, command):
        process = subprocess.Popen([*self.base, "-tt", self.destination, command], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=0x08000000)
        try:
            # Keep stdin open: closing it during conhost startup discards output.
            process.wait(timeout=30)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        stdout, stderr = process.communicate(timeout=5)
        return process.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    def sftp_workspace(self):
        init = b"\x01" + struct.pack(">I", 3)
        realpath = b"\x10" + struct.pack(">I", 1) + ssh_string(self.workspace.as_posix().encode())
        proc = subprocess.Popen([*self.base, "-s", self.destination, "sftp"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=0x08000000)
        incoming = queue.Queue()
        def read_exact(size):
            output = b""
            while len(output) < size:
                part = proc.stdout.read(size - len(output))
                if not part:
                    raise EOFError("SFTP channel closed before its reply")
                output += part
            return output
        def reader():
            try:
                while True:
                    size, = struct.unpack(">I", read_exact(4))
                    assert 1 <= size <= 1024 * 1024
                    incoming.put(read_exact(size))
            except BaseException as error:
                incoming.put(error)
        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        def exchange(packet):
            proc.stdin.write(struct.pack(">I", len(packet)) + packet)
            proc.stdin.flush()
            answer = incoming.get(timeout=30)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        try:
            version = exchange(init)
            assert version[0] == 2 and struct.unpack(">I", version[1:5])[0] == 3
            reply = exchange(realpath)
            assert reply[0] == 104, reply
        finally:
            proc.stdin.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)
            thread.join(timeout=2)
        assert struct.unpack(">II", reply[1:9]) == (1, 1)
        size = struct.unpack(">I", reply[9:13])[0]
        actual = reply[13:13+size].decode("utf8")
        canonical = actual[1:] if len(actual) > 3 and actual[0] == "/" and actual[2] == ":" else actual
        assert Path(canonical).resolve() == self.workspace.resolve()
        return actual

    def create(self, tag, *, cwd=None, mem=None):
        command = "pocketshell sessions create --json --cwd " + shlex.quote(cwd or self.sftp_workspace())
        if mem is not None:
            command += " --mem " + shlex.quote(mem)
        command += " -- " + shlex.quote(tag)
        code, output = self.exec(command)
        assert code == 0, output
        result = json.loads(output)
        from uuid import UUID
        ident = str(UUID(result["id"]))
        assert ident == result["id"] and result["schema"] == 3
        self.ids.add(ident)
        return result

    def attach_io(self, ident, label, *, allocation_probe=False, interrupt_probe=False):
        oracle = self.workspace / (label + ".txt")
        first, second = int(uuid4().hex[:4], 16), 7341
        expected = "NATIVE43_" + str(first + second)
        command = f"v=$(({first}+{second})); printf 'NATIVE43_%s\\n' \"$v\" > {shlex.quote(oracle.as_posix())}; printf 'NATIVE43_%s\\n' \"$v\"\r"
        if allocation_probe:
            from tray_memory_oracle import child_code
            allow = allocation_probe == "allow"
            pid_path = self.workspace / (label + "-pid.json")
            release = self.workspace / (label + "-release.txt")
            finish = self.workspace / (label + "-finish.txt")
            allocation_result = self.workspace / (label + "-allocation.json")
            code = child_code(first, second, oracle, pid_path, release, finish, allocation_result)
            command = self.python_command(code) + "\r"
        assert expected not in command
        remote = [] if ident is None else ["exec pocketshell sessions attach -- " + shlex.quote(ident)]
        process = subprocess.Popen([*self.base, "-tt", self.destination, *remote],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=0x08000000)
        chunks = []
        def reader():
            while True:
                data = os.read(process.stdout.fileno(), 4096)
                if not data:
                    break
                chunks.append(data)
        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        def seen(predicate, seconds):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if predicate():
                    return True
                if process.poll() is not None:
                    break
                time.sleep(.1)
            return False
        try:
            assert seen(lambda: shell_prompt_seen(b"".join(chunks)), 30), b"".join(chunks)[-2000:]
            if interrupt_probe:
                checkpoint = self.workspace / "interrupt-started.txt"
                assert not checkpoint.exists()
                ready = "INTERRUPT43_" + str(first + second)
                start = (f"v=$(({first}+{second})); printf started > " + shlex.quote(checkpoint.as_posix())
                         + "; printf '\\nINTERRUPT43_%s\\n' \"$v\"; sleep 60\r")
                assert ready not in start
                process.stdin.write(start.encode())
                process.stdin.flush()
                assert seen(lambda: checkpoint.exists() and ready.encode() in b"".join(chunks), 10), \
                    "The owned workload did not reach its computed interrupt checkpoint"
                time.sleep(.3)
                assert interrupt_to_fresh_prompt(process, chunks, seen), \
                    "Ctrl-C did not return the owned workload to a fresh prompt"
            process.stdin.write(command.encode())
            process.stdin.flush()
            assert seen(lambda: expected.encode() in b"".join(chunks) and oracle.exists(), 20), b"".join(chunks)[-2000:]
            assert oracle.read_text().strip() == expected
            if allocation_probe:
                from tray_memory_oracle import observer_code, validate
                assert seen(pid_path.exists, 10)
                python_sha = next(row["sha256"] for row in self.catalog["files"] if row["path"] == "python/python.exe")
                limit = 12 * 1024**3 if allow else 64 * 1024**2
                observer = observer_code(ident, pid_path, release, finish, allocation_result,
                                         self.installed / "python/a.exe", self.installed / "python/python.exe",
                                         python_sha, limit, allow)
                code, output = self.exec(self.python_command(observer), timeout=45)
                assert code == 0, output
                observation = json.loads(output)
                self.memory_observations.append(observation)
                validate(observation, ident=ident, limit=limit, allow=allow)
            return {"id": ident, "computedPTYOutput": expected, "independentFileOracle": True,
                    "interruptVerified": interrupt_probe, "memoryProbeVerified": bool(allocation_probe)}
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            thread.join(timeout=2)

    def rows(self):
        code, output = self.exec('"$POCKETSHELL_RUNTIME_ROOT/python/a.exe" --json snapshot')
        assert code == 0
        return json.loads(output)

    def kernel_oracle(self, ident):
        """Independent byte-layout kernel query; never calls production verify."""
        row, = [row for row in self.rows() if row["id"] == ident]
        script = ("import ctypes as c,json,struct;from ctypes import wintypes as w;"
                  "k=c.WinDLL('kernel32');k.OpenJobObjectW.argtypes=[w.DWORD,w.BOOL,w.LPCWSTR];"
                  "k.OpenJobObjectW.restype=w.HANDLE;"
                  "k.QueryInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p];"
                  "k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE;"
                  "k.IsProcessInJob.argtypes=[w.HANDLE,w.HANDLE,c.POINTER(w.BOOL)];"
                  "k.CloseHandle.argtypes=[w.HANDLE];"
                  f"h=k.OpenJobObjectW(4,False,'aplexer-{ident}');assert h;"
                  "b=c.create_string_buffer(144);assert k.QueryInformationJobObject(h,9,b,144,None);"
                  f"p=k.OpenProcess(0x1000,False,{row['workload_pid']});assert p;"
                  "v=w.BOOL();assert k.IsProcessInJob(p,h,c.byref(v)) and v.value;"
                  "print(json.dumps({'flags':struct.unpack_from('<I',b.raw,16)[0],"
                  "'bytes':struct.unpack_from('<Q',b.raw,120)[0],'member':bool(v.value)}));"
                  "k.CloseHandle(p);k.CloseHandle(h)")
        code, output = self.exec(self.python_command(script))
        assert code == 0
        proof = json.loads(output)
        assert proof["flags"] & 0x200 and proof["flags"] & 0x2000
        assert not proof["flags"] & (0x800 | 0x1000) and proof["member"] is True
        return proof

    def kill(self, ident, *, after_oom=False):
        assert ident in self.ids
        row, = [row for row in self.rows() if row["id"] == ident]
        pids = [row["worker_pid"], row["workload_pid"]]
        assert all(type(pid) is int and pid > 0 for pid in pids)
        code, output = self.exec("pocketshell sessions kill --json -- " + shlex.quote(ident))
        if after_oom:
            # The first explicit stop must remain an honest non-success when
            # native aplexer preserves its OOM postmortem instead of removing it.
            first = json.loads(output)
            assert code == 1 and first["schema"] == 3 and first["uncertain"] is False
            assert "not confirmed" in first["error"]
            retained, = [item for item in self.rows() if item["id"] == ident]
            assert retained["phase"] == retained["state"] == "exited"
            assert retained["worker_alive"] is False and retained["containment_empty"] is True
            assert [retained["worker_pid"], retained["workload_pid"]] == pids
            assert retained["exit"]["oom_killed"] is True
            absence = self.finished_absence(ident, pids)
            evidence = {"id": ident, "firstKill": first, "nativeEndedRecord": {
                key: retained[key] for key in ("phase", "state", "worker_alive", "containment_empty",
                                              "worker_pid", "workload_pid", "exit", "limits")},
                "absence": absence}
            from pocketshell import windows_security as ws
            saved = self.top / ("oom-before-explicit-cleanup-" + ident + ".json")
            ws.write_private(saved, json.dumps(evidence, indent=2).encode())
            self.oom_preservations.append({**evidence, "preservedBeforeExplicitCleanup": True,
                                           "preservationSHA256": digest(saved)})
            # A separate explicit request, after inspecting and durably saving
            # the ended record. The application never auto-retries a failed kill.
            code, output = self.exec("pocketshell sessions kill --json -- " + shlex.quote(ident))
        assert code == 0, output
        result = json.loads(output)
        assert result["id"] == ident and result["killed"] is True and result["reaped"] is True
        assert ident not in {row["id"] for row in self.rows()}
        script = ("import ctypes as c,json,time;from ctypes import wintypes as w;"
                  "k=c.WinDLL('kernel32',use_last_error=True);k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];"
                  "k.OpenProcess.restype=w.HANDLE;k.GetExitCodeProcess.argtypes=[w.HANDLE,c.POINTER(w.DWORD)];"
                  "k.CloseHandle.argtypes=[w.HANDLE];\n"
                  "def alive(pid):\n"
                  " h=k.OpenProcess(0x1000,False,pid)\n"
                  " if not h:\n"
                  "  assert c.get_last_error() in (87,1168);return False\n"
                  " try:\n"
                  "  v=w.DWORD();assert k.GetExitCodeProcess(h,c.byref(v));return v.value==259\n"
                  " finally:k.CloseHandle(h)\n"
                  f"pids={pids!r}\n"
                  "for attempt in range(100):\n"
                  " if not any(map(alive,pids)):break\n"
                  " time.sleep(.1)\n"
                  "assert not any(map(alive,pids));print(json.dumps({'ownedProcessesGone':pids}))")
        code, proof = self.exec(self.python_command(script))
        assert code == 0 and json.loads(proof)["ownedProcessesGone"] == pids
        self.kill_proofs.append({"id": ident, "ownedProcessesGone": pids,
                                 "explicitEndedCleanup": after_oom})
        self.ids.remove(ident)

    def finished_absence(self, ident, pids):
        # Do not retain process handles across the explicit ended-record kill:
        # even dead handles keep their PID objects allocated and ambiguous.
        script = ("import ctypes as c,json,time;from ctypes import wintypes as w;"
                  "k=c.WinDLL('kernel32',use_last_error=True);k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];"
                  "k.OpenProcess.restype=w.HANDLE;k.CloseHandle.argtypes=[w.HANDLE];"
                  "k.OpenJobObjectW.argtypes=[w.DWORD,w.BOOL,w.LPCWSTR];k.OpenJobObjectW.restype=w.HANDLE;\n"
                  "def absent(pid):\n"
                  " h=k.OpenProcess(0x1000,False,pid)\n"
                  " if h:k.CloseHandle(h);return False\n"
                  " assert c.get_last_error() in (87,1168);return True\n"
                  f"pids={pids!r}\n"
                  "for attempt in range(100):\n"
                  " if all(map(absent,pids)):break\n"
                  " time.sleep(.1)\n"
                  "assert all(map(absent,pids))\n"
                  f"job=k.OpenJobObjectW(4,False,'aplexer-{ident}')\n"
                  "if job:k.CloseHandle(job);raise AssertionError('Job still allocated')\n"
                  "assert c.get_last_error()==2\n"
                  "print(json.dumps({'ownedPIDsUnallocated':pids,'namedJobAbsent':True}))")
        code, output = self.exec(self.python_command(script))
        assert code == 0, output
        proof = json.loads(output)
        assert proof == {"ownedPIDsUnallocated": pids, "namedJobAbsent": True}
        return proof

    def close(self):
        # Also recover owned creations whose CLI result was lost, using ONLY
        # this fresh isolated namespace, exact native records and owned workspace.
        try:
            if self.installed is not None and hasattr(self, "state_env"):
                env = dict(self.env, **self.state_env)
                binary = self.installed / "python/a.exe"
                result = subprocess.run([str(binary), "--json", "snapshot"], env=env, cwd=self.top,
                                        capture_output=True, text=True, timeout=15, creationflags=0x08000000)
                if result.returncode == 0:
                    for row in json.loads(result.stdout):
                        workspace = Path(row.get("workspace", "")).resolve()
                        assert workspace.is_relative_to(self.top.resolve()), "Never clean a foreign workspace"
                        from uuid import UUID
                        ident = str(UUID(row["id"]))
                        assert ident == row["id"]
                        subprocess.run([str(binary), "--json", "kill", ident, "--grace-ms", "1000"], env=env,
                                       cwd=self.top, capture_output=True, timeout=15, creationflags=0x08000000)
        finally:
            binding = self.top / "agent-config/pocketshell/agent/binding.json"
            if self.installed is not None and binding.exists():
                self.agent("stop", "--timeout", "60")
