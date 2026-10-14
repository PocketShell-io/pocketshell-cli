"""A foreground tray owns its workers; they do not claim CLI independence.

The ordinary CLI still requires a target outside every inherited job. The tray
instead holds a dedicated KILL_ON_JOB_CLOSE job for its entire lifetime. Every
target is assigned and measured while suspended, after the existing image,
token, owner and session checks. Its truthful custody record names the tray.
Closing/crashing the tray closes the job and kills its owned worker family.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import os
import uuid

from pocketshell.gateway.service_common import ServiceError
from pocketshell.gateway.service_windows import WindowsApi


class TrayWindowsApi(WindowsApi):
    def __init__(self):
        super().__init__()
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        k = self.kernel
        k.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        k.CreateJobObjectW.restype = w.HANDLE
        k.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        k.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
        k.CloseHandle.argtypes = [w.HANDLE]
        self.job = k.CreateJobObjectW(None, None)  # unnamed, never inherited
        if not self.job:
            raise ServiceError("Cannot create the tray's worker job")
        limits = (c.c_byte * 144)()  # x64 JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        c.c_uint32.from_buffer(limits, 16).value = 0x2000  # KILL_ON_JOB_CLOSE
        if not k.SetInformationJobObject(self.job, 9, limits, c.sizeof(limits)):
            self.close()
            raise ServiceError("Cannot configure the tray's worker job")
        self.owner_pid = os.getpid()
        self.owner_birth = self.process_birth(self.owner_pid)
        if not self.owner_birth:
            self.close()
            raise ServiceError("Cannot measure the tray's process identity")

    def _job_policy(self, child_handle, *, caller_in_job, broke_away, child_in_job, nearest_kill):
        if caller_in_job is None or child_in_job is None or not self.job:
            raise ServiceError("Unverifiable tray worker context")
        if not self.kernel.AssignProcessToJobObject(self.job, child_handle):
            raise ServiceError(f"Cannot assign the suspended worker to the tray job ({c.get_last_error()})")
        member = w.BOOL()
        if not self.kernel.IsProcessInJob(child_handle, self.job, c.byref(member)) or not member.value:
            raise ServiceError("The worker was not measured in the tray's owned job")
        return {"inJob": True, "brokeAway": bool(broke_away), "callerInJob": bool(caller_in_job),
                "callerJobKillOnClose": bool(caller_in_job) and nearest_kill is not False,
                "supervision": {"kind": "tray-owned", "pid": self.owner_pid,
                                "creationFILETIME": self.owner_birth, "killOnClose": True}}

    def close(self):
        if getattr(self, "job", None):
            self.kernel.CloseHandle(self.job)
            self.job = None


_api = None


def api():
    global _api
    if _api is None:
        _api = TrayWindowsApi()
    return _api


def start():
    from pocketshell.gateway import service_common, service_user_agent
    doc, code = service_user_agent.start(api=api(), runner=service_common.run_child, timeout=300,
                                         operation_id=uuid.uuid4().hex)
    if code != 0:
        error = doc.get("error") or {}
        raise RuntimeError(error.get("message") or f"Gateway start failed ({code})")
    return doc


def configure_background():
    """The reviewed guardian also supports an invisible ordinary-user session 0.

    Keep its SID, DACL, private desktop, host-key and job checks intact. The
    ordinary interactive CLI's default readiness contract remains unchanged.
    """
    from pocketshell.gateway import service_endpoint, service_user_agent
    service_user_agent.MODE = (service_endpoint.MODE_S4U if api().current_session() == 0
                               else service_endpoint.MODE_ACTIVE_CONSOLE)


def close():
    global _api
    if _api is not None:
        _api.close()
        _api = None
