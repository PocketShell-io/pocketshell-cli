"""Instrument the artifact's unchanged entry binaries in a throwaway layout.

This extends the existing launcher native test technique. Only the copied
Python module is a probe; actual session operations keep their normal app.zip.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

PROBE = r'''
import ctypes,hashlib,json,msvcrt,os,pathlib,sys
k=ctypes.WinDLL("kernel32")
k.GetConsoleWindow.restype=ctypes.c_void_p
k.GetConsoleMode.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)]
def console(file):
 try:
  mode=ctypes.c_ulong();return bool(k.GetConsoleMode(msvcrt.get_osfhandle(file.fileno()),ctypes.byref(mode)))
 except (AttributeError,OSError,ValueError):return False
data={"consoleCP":k.GetConsoleCP(),"consoleWindow":k.GetConsoleWindow() or 0,"argv":sys.argv[3:],
      "stdinConsole":console(sys.stdin),"stdoutConsole":console(sys.stdout)}
if sys.argv[1]=="io":
 import msvcrt
 msvcrt.setmode(0,os.O_BINARY);msvcrt.setmode(1,os.O_BINARY)
 payload=sys.stdin.buffer.read();data["inputSHA256"]=hashlib.sha256(payload).hexdigest()
 sys.stdout.buffer.write(payload);sys.stdout.buffer.flush();sys.stderr.write("PROBE_STDERR")
pathlib.Path(sys.argv[2]).write_text(json.dumps(data),encoding="utf8")
raise SystemExit(7 if sys.argv[1]=="io" else 0)
'''


def build_layout(source, destination):
    source, root = Path(source), Path(destination)
    root.mkdir()
    for name in ("pocketshell.exe", "GatewayTray.exe"):
        shutil.copyfile(source / name, root / name)
        assert hashlib.sha256((root / name).read_bytes()).digest() == hashlib.sha256((source / name).read_bytes()).digest()
    shutil.copytree(source / "python", root / "python")
    package = root / "probe/pocketshell"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    for module in ("__main__.py", "tray_bundle.py"):
        (package / module).write_text(PROBE)
    pth, = (root / "python").glob("python*._pth")
    stdlib, = (root / "python").glob("python*.zip")
    pth.write_text("..\\probe\n" + stdlib.name + "\nDLLs\n")
    return root


def background_controls(root):
    payload = bytes(range(256)) * 16 + b"\x00\r\nKEY_BUFFER_TEST"
    binary = root / "pocketshell.exe"
    for name, flags in (("detached", 8), ("no-window", 0x08000000)):
        oracle = root / (name + ".json")
        process = subprocess.run([str(binary), "io", str(oracle), "space arg", "Ω"], input=payload,
                                 capture_output=True, creationflags=flags, timeout=30)
        assert process.returncode == 7 and process.stdout == payload and process.stderr == b"PROBE_STDERR"
        proof = json.loads(oracle.read_text(encoding="utf8"))
        assert proof["consoleWindow"] == 0 and not proof["stdinConsole"] and not proof["stdoutConsole"]
        assert proof["argv"] == ["space arg", "Ω"] and proof["inputSHA256"] == hashlib.sha256(payload).hexdigest()
    oracle = root / "mixed.json"
    with (root / "mixed-output.bin").open("wb") as output:
        process = subprocess.run([str(binary), "io", str(oracle)], input=payload, stdout=output,
                                 stderr=subprocess.PIPE, creationflags=8, timeout=30)
    proof = json.loads(oracle.read_text(encoding="utf8"))
    assert process.returncode == 7 and process.stderr == b"PROBE_STDERR"
    assert (root / "mixed-output.bin").read_bytes() == payload
    assert proof["consoleWindow"] == 0 and not proof["stdinConsole"] and not proof["stdoutConsole"]
    # Popen normally repairs stdio before spawning. Use its real Win32 backing
    # API to reproduce a GUI caller with missing handles and NO parent console.
    oracle = root / "no-parent.json"
    carrier = r'''
import _winapi,ctypes,subprocess,sys
assert ctypes.WinDLL("kernel32").GetConsoleCP()==0
startup=subprocess.STARTUPINFO();startup.dwFlags=0x100
startup.hStdInput=startup.hStdOutput=startup.hStdError=0
process,thread,pid,tid=_winapi.CreateProcess(sys.argv[1],subprocess.list2cmdline([sys.argv[1],"proof",sys.argv[2]]),
 None,None,False,8,None,None,startup)
try:
 if _winapi.WaitForSingleObject(process,20000)!=0:
  _winapi.TerminateProcess(process,99);raise RuntimeError("owned no-parent probe timed out")
 assert _winapi.GetExitCodeProcess(process)==0
finally:
 _winapi.CloseHandle(thread);_winapi.CloseHandle(process)
'''
    process = subprocess.run([str(root / "python/python.exe"), "-I", "-B", "-c", carrier,
                              str(binary), str(oracle)], input=b"", capture_output=True,
                             creationflags=8, timeout=30)
    assert process.returncode == 0, process.stderr.decode(errors="replace")
    proof = json.loads(oracle.read_text(encoding="utf8"))
    assert proof["consoleWindow"] == 0 and not proof["stdinConsole"] and not proof["stdoutConsole"]
    return {"independentFileOracle": True, "detachedAndPipeAndMixed": True, "binaryStdioPreserved": True,
            "childExitCodePreserved": True, "noParentConsole": True}
