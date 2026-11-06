"""Read-only verification of aplexer's named Windows session containment job."""
from __future__ import annotations


class JobError(RuntimeError):
    pass


def verify(session_id: str, workload_pid: int, requested: int | None = None) -> dict:
    """Verify actual kernel memory bound and live workload membership.

    JobMemoryLimit measures committed private memory, not Linux resident RAM.
    No process is assigned, killed or modified by this check.
    """
    # Keep command registration/help independent of native API loading.
    import ctypes as c
    from ctypes import wintypes as w

    class _Basic(c.Structure):
        _fields_ = [("process_time", c.c_int64), ("job_time", c.c_int64), ("flags", w.DWORD),
                    ("min_working_set", c.c_size_t), ("max_working_set", c.c_size_t),
                    ("active_processes", w.DWORD), ("affinity", c.c_size_t),
                    ("priority", w.DWORD), ("scheduling", w.DWORD)]

    class _Extended(c.Structure):
        _fields_ = [("basic", _Basic), ("io", c.c_uint64 * 6), ("process_memory", c.c_size_t),
                    ("job_memory", c.c_size_t), ("peak_process", c.c_size_t), ("peak_job", c.c_size_t)]

    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.OpenJobObjectW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
    kernel.OpenJobObjectW.restype = w.HANDLE
    kernel.QueryInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
    kernel.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    job = kernel.OpenJobObjectW(4, False, "aplexer-" + session_id)
    if not job:
        raise JobError("Cannot verify the session's Windows containment job.")
    process = None
    try:
        limits = _Extended()
        if c.sizeof(limits) != 144 or not kernel.QueryInformationJobObject(
                job, 9, c.byref(limits), c.sizeof(limits), None):
            raise JobError("Cannot read the session's Windows job limits.")
        flags = limits.basic.flags
        if not flags & 0x200 or not flags & 0x2000 or flags & (0x800 | 0x1000) \
                or limits.job_memory <= 0 or (requested is not None and limits.job_memory > requested):
            raise JobError("The session's Windows job does not enforce the requested memory limit.")
        process = kernel.OpenProcess(0x1000, False, workload_pid)
        member, status = w.BOOL(), w.DWORD()
        if not process or not kernel.IsProcessInJob(process, job, c.byref(member)) or not member.value \
                or not kernel.GetExitCodeProcess(process, c.byref(status)) or status.value != 259:
            raise JobError("The live workload is not verified in the session's containment job.")
        return {"mode": "windows_job", "memory_limit_bytes": limits.job_memory,
                "accounting": "committed_private_memory", "kill_on_close": True, "breakaway": False}
    finally:
        if process:
            kernel.CloseHandle(process)
        kernel.CloseHandle(job)


def verify_finished(session_id: str, worker_pid: int, workload_pid: int) -> None:
    """Read-only absence proof before an explicit ended-record removal.

    Snapshot PIDs do not contain their kernel birth identity. A still-allocated
    PID, including a dead object or a reused PID, therefore remains ambiguous
    and is refused. No process is signalled and no Job is modified here.
    """
    import ctypes as c
    from ctypes import wintypes as w

    from uuid import UUID
    try:
        valid_id = isinstance(session_id, str) and str(UUID(session_id)) == session_id
    except ValueError:
        valid_id = False
    if not valid_id:
        raise JobError("The finished session UUID is not verified.")
    pids = (worker_pid, workload_pid)
    if any(type(pid) is not int or not 0 < pid <= 0xFFFFFFFF for pid in pids) or worker_pid == workload_pid:
        raise JobError("The finished session's process identities are not verified.")
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.OpenJobObjectW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
    kernel.OpenJobObjectW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    for pid in pids:
        process = kernel.OpenProcess(0x1000, False, pid)
        if process:
            kernel.CloseHandle(process)
            raise JobError("A finished-session PID is still allocated; its identity cannot be verified.")
        if c.get_last_error() not in (87, 1168):
            raise JobError("Cannot prove that the finished session's processes are absent.")
    job = kernel.OpenJobObjectW(4, False, "aplexer-" + session_id)
    if job:
        kernel.CloseHandle(job)
        raise JobError("The finished session's containment Job still exists.")
    if c.get_last_error() != 2:
        raise JobError("Cannot prove that the finished session's containment Job is absent.")
