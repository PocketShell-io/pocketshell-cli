"""Independent native-process observations for the intentional Windows OOM case."""
from __future__ import annotations

import re


OOM_EXIT = 0xC000012D


def _render(template, values):
    return re.sub(r"@([A-Z_]+)@", lambda match: repr(values[match.group(1)]), template)


def child_code(first, second, oracle, pid_path, release, finish, result):
    body = _render(r"""
import ctypes as c,json,os,pathlib,sys,time
marker='NATIVE43_'+str(@FIRST@+@SECOND@)
pathlib.Path(@ORACLE@).write_text(marker)
pathlib.Path(@PID@).write_text(json.dumps({'pid':os.getpid(),'isolated':bool(sys.flags.isolated)}))
print(marker,flush=True)
deadline=time.monotonic()+30
while not pathlib.Path(@RELEASE@).exists() and time.monotonic()<deadline: time.sleep(.05)
assert pathlib.Path(@RELEASE@).exists()
k=c.WinDLL('kernel32',use_last_error=True)
k.VirtualAlloc.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong,c.c_ulong];k.VirtualAlloc.restype=c.c_void_p
k.VirtualFree.argtypes=[c.c_void_p,c.c_size_t,c.c_ulong]
c.set_last_error(0)
p=k.VirtualAlloc(None,128*1024*1024,0x3000,4);error=c.get_last_error()
pathlib.Path(@RESULT@).write_text(json.dumps({'allocated':bool(p),'lastError':error}))
if p: assert k.VirtualFree(p,0,0x8000)
deadline=time.monotonic()+30
while not pathlib.Path(@FINISH@).exists() and time.monotonic()<deadline: time.sleep(.05)
assert pathlib.Path(@FINISH@).exists()
""", {"FIRST": first, "SECOND": second, "ORACLE": str(oracle), "PID": str(pid_path),
      "RELEASE": str(release), "FINISH": str(finish), "RESULT": str(result)})
    # One physical terminal input line, including quoted Python newlines.
    return "exec(" + repr(body) + ")"


def observer_code(ident, pid_path, release, finish, result, backend, python, python_sha, limit, allow):
    return _render(r"""
import ctypes as c,hashlib,json,pathlib,struct,subprocess,time
from ctypes import wintypes as w
assert c.sizeof(c.c_void_p)==8
ident=@IDENT@;expected_job='aplexer-'+ident
k=c.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
k.OpenJobObjectW.argtypes=[w.DWORD,w.BOOL,w.LPCWSTR];k.OpenJobObjectW.restype=w.HANDLE
k.IsProcessInJob.argtypes=[w.HANDLE,w.HANDLE,c.POINTER(w.BOOL)]
k.QueryInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p]
k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];k.WaitForSingleObject.restype=w.DWORD
k.GetExitCodeProcess.argtypes=[w.HANDLE,c.POINTER(w.DWORD)];k.CloseHandle.argtypes=[w.HANDLE]
def status():
 raw=json.loads(subprocess.check_output([@BACKEND@,'--json','status',ident],text=True,stderr=subprocess.PIPE,timeout=10,creationflags=0x08000000))
 assert raw['id']==ident and raw['state']=='running' and raw['worker_alive'] is True
 assert raw['cgroup']['job']==expected_job
 return raw['cgroup']
def allocation():
 path=pathlib.Path(@RESULT@)
 raw=path.read_bytes() if path.exists() else b''
 assert len(raw)<=4096
 value=None
 try: value=json.loads(raw)
 except (ValueError,UnicodeError): pass
 return {'bytes':len(raw),'value':value}
launch=json.loads(pathlib.Path(@PID@).read_text());pid=launch['pid']
assert type(pid) is int and pid>0 and launch['isolated'] is True
process=k.OpenProcess(0x1000|0x100000,False,pid);assert process
job=None
try:
 image=c.create_unicode_buffer(32768);size=w.DWORD(len(image));assert k.QueryFullProcessImageNameW(process,0,image,c.byref(size))
 assert pathlib.Path(image.value).resolve()==pathlib.Path(@PYTHON@).resolve()
 image_sha=hashlib.sha256(pathlib.Path(image.value).read_bytes()).hexdigest();assert image_sha==@PYTHON_SHA@
 job=k.OpenJobObjectW(4,False,expected_job);assert job
 member=w.BOOL();assert k.IsProcessInJob(process,job,c.byref(member)) and member.value
 limits=c.create_string_buffer(144);assert k.QueryInformationJobObject(job,9,limits,144,None)
 flags=struct.unpack_from('<I',limits.raw,16)[0];bound=struct.unpack_from('<Q',limits.raw,120)[0]
 assert flags&0x200 and flags&0x2000 and not flags&(0x800|0x1000) and bound==@LIMIT@
 # A query handle must not extend Job lifetime into later explicit cleanup.
 k.CloseHandle(job);job=None
 before=status();assert before['memory_limit_bytes']==bound
 pathlib.Path(@RELEASE@).write_text('public-test-release')
 if @ALLOW@:
  deadline=time.monotonic()+10
  while time.monotonic()<deadline and not isinstance(allocation()['value'],dict): time.sleep(.05)
  assert allocation()['value'].get('allocated') is True
  pathlib.Path(@FINISH@).write_text('public-test-finish')
 assert k.WaitForSingleObject(process,15000)==0
 native=w.DWORD();assert k.GetExitCodeProcess(process,c.byref(native))
 after=status()
 if not @ALLOW@ and native.value==0xC000012D:
  deadline=time.monotonic()+2
  while time.monotonic()<deadline and after['oom_kill_count']==before['oom_kill_count']:
   time.sleep(.05);after=status()
 observation={'pid':pid,'isolated':True,'childJobMember':True,'imageVerified':True,'imagePath':image.value,'imageSHA256':image_sha,
              'kernelFlags':flags,'kernelLimitBytes':bound,'before':before,'after':after,
              'nativeExit':native.value,'allocation':allocation()}
finally:
 if job:k.CloseHandle(job)
 k.CloseHandle(process)
# All observation handles are closed before the caller can explicitly remove
# the ended record. Holding dead-process handles keeps their PIDs allocated.
print(json.dumps(observation))
""", {"IDENT": ident, "PID": str(pid_path), "RELEASE": str(release), "FINISH": str(finish),
      "RESULT": str(result), "BACKEND": str(backend), "PYTHON": str(python), "PYTHON_SHA": python_sha,
      "LIMIT": limit, "ALLOW": allow})


def validate(observation, *, ident, limit, allow):
    assert observation["isolated"] is True and observation["childJobMember"] is True and observation["imageVerified"] is True
    assert type(observation["pid"]) is int and observation["pid"] > 0
    assert observation["kernelLimitBytes"] == limit
    flags = observation["kernelFlags"]
    assert flags & 0x200 and flags & 0x2000 and not flags & (0x800 | 0x1000)
    before, after = observation["before"], observation["after"]
    for status in (before, after):
        assert status["job"] == "aplexer-" + ident and status["memory_limit_bytes"] == limit
        assert type(status["oom_kill_count"]) is int and status["oom_kill_count"] >= 0
    assert type(observation["nativeExit"]) is int
    result = observation["allocation"]["value"]
    if allow:
        assert observation["nativeExit"] == 0 and isinstance(result, dict) and result.get("allocated") is True
        assert after["oom_kill_count"] == before["oom_kill_count"]
    else:
        assert observation["nativeExit"] == OOM_EXIT
        assert after["oom_kill_count"] == before["oom_kill_count"] + 1
        assert result is None or (isinstance(result, dict) and result.get("allocated") is False)
    # Windows peak bookkeeping may include a rejected commit attempt. Keep the
    # raw counter; it is not an assertion about successfully committed bytes.
