"""Native declarations extracted from constructor903255; no fixture entrypoint."""
import ctypes as C, ctypes.wintypes as W, hashlib
u=C.WinDLL('user32',use_last_error=True);k=C.WinDLL('kernel32',use_last_error=True);adv=C.WinDLL('advapi32',use_last_error=True)
class SA(C.Structure):_fields_=[('nLength',W.DWORD),('lpSecurityDescriptor',W.LPVOID),('bInheritHandle',W.BOOL)]
class USEROBJECTFLAGS(C.Structure):_fields_=[('fInherit',W.BOOL),('fReserved',W.BOOL),('dwFlags',W.DWORD)]
class SI(C.Structure):
    _fields_=[('cb',W.DWORD),('lpReserved',W.LPWSTR),('lpDesktop',W.LPWSTR),('lpTitle',W.LPWSTR),('dwX',W.DWORD),('dwY',W.DWORD),('dwXSize',W.DWORD),('dwYSize',W.DWORD),('dwXCountChars',W.DWORD),('dwYCountChars',W.DWORD),('dwFillAttribute',W.DWORD),('dwFlags',W.DWORD),('wShowWindow',W.WORD),('cbReserved2',W.WORD),('lpReserved2',W.LPVOID),('hStdInput',W.HANDLE),('hStdOutput',W.HANDLE),('hStdError',W.HANDLE)]
class PI(C.Structure):_fields_=[('hProcess',W.HANDLE),('hThread',W.HANDLE),('dwProcessId',W.DWORD),('dwThreadId',W.DWORD)]
class SIEX(C.Structure):_fields_=[('StartupInfo',SI),('lpAttributeList',W.LPVOID)]
k.InitializeProcThreadAttributeList.argtypes=[W.LPVOID,W.DWORD,W.DWORD,C.POINTER(C.c_size_t)]
k.UpdateProcThreadAttribute.argtypes=[W.LPVOID,W.DWORD,C.c_size_t,W.LPVOID,C.c_size_t,W.LPVOID,W.LPVOID]
k.DeleteProcThreadAttributeList.argtypes=[W.LPVOID]
k.DeleteProcThreadAttributeList.restype=None
k.GetExitCodeProcess.argtypes=[W.HANDLE,C.POINTER(W.DWORD)]
k.IsProcessInJob.argtypes=[W.HANDLE,W.HANDLE,C.POINTER(W.BOOL)]
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
CB=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
u.EnumDesktopWindows.argtypes=[W.HANDLE,CB,W.LPARAM]
u.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
u.GetWindowThreadProcessId.restype=W.DWORD
u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,C.c_int];u.IsWindowVisible.argtypes=[W.HWND]
u.OpenInputDesktop.argtypes=[W.DWORD,W.BOOL,W.DWORD];u.OpenInputDesktop.restype=W.HANDLE
class BASIC(C.Structure):_fields_=[('PerProcessUserTimeLimit',C.c_longlong),('PerJobUserTimeLimit',C.c_longlong),('LimitFlags',W.DWORD),('MinimumWorkingSetSize',C.c_size_t),('MaximumWorkingSetSize',C.c_size_t),('ActiveProcessLimit',W.DWORD),('Affinity',C.c_size_t),('PriorityClass',W.DWORD),('SchedulingClass',W.DWORD)]
class IO(C.Structure):_fields_=[(n,C.c_ulonglong) for n in ('ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount')]
class LIMITS(C.Structure):_fields_=[('BasicLimitInformation',BASIC),('IoInfo',IO),('ProcessMemoryLimit',C.c_size_t),('JobMemoryLimit',C.c_size_t),('PeakProcessMemoryUsed',C.c_size_t),('PeakJobMemoryUsed',C.c_size_t)]
class ACCOUNTING(C.Structure):_fields_=[('TotalUserTime',C.c_longlong),('TotalKernelTime',C.c_longlong),('ThisPeriodTotalUserTime',C.c_longlong),('ThisPeriodTotalKernelTime',C.c_longlong),('TotalPageFaultCount',W.DWORD),('TotalProcesses',W.DWORD),('ActiveProcesses',W.DWORD),('TotalTerminatedProcesses',W.DWORD)]
k.QueryInformationJobObject.argtypes=[W.HANDLE,C.c_int,W.LPVOID,W.DWORD,C.POINTER(W.DWORD)]
class JOBPIDS(C.Structure):_fields_=[('NumberOfAssignedProcesses',W.DWORD),('NumberOfProcessIdsInList',W.DWORD),('ProcessIdList',C.c_size_t*64)]
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
k.GetProcessTimes.argtypes=[W.HANDLE,C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME),C.POINTER(W.FILETIME)]
k.GetTickCount64.restype=C.c_ulonglong
k.CreateJobObjectW.argtypes=[W.LPVOID,W.LPCWSTR];k.CreateJobObjectW.restype=W.HANDLE
k.SetInformationJobObject.argtypes=[W.HANDLE,C.c_int,W.LPVOID,W.DWORD]
k.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE]
k.TerminateJobObject.argtypes=[W.HANDLE,W.UINT]
k.ResumeThread.argtypes=[W.HANDLE];k.ResumeThread.restype=W.DWORD
u.GetThreadDesktop.argtypes=[W.DWORD];u.GetThreadDesktop.restype=W.HANDLE
u.GetProcessWindowStation.restype=W.HANDLE
k.GetCurrentThreadId.restype=W.DWORD;k.GetCurrentProcessId.restype=W.DWORD
k.ProcessIdToSessionId.argtypes=[W.DWORD,C.POINTER(W.DWORD)];k.WTSGetActiveConsoleSessionId.restype=W.DWORD
u.GetUserObjectInformationW.argtypes=[W.HANDLE,C.c_int,W.LPVOID,W.DWORD,C.POINTER(W.DWORD)]
u.GetUserObjectSecurity.argtypes=[W.HANDLE,C.POINTER(W.DWORD),W.LPVOID,W.DWORD,C.POINTER(W.DWORD)]
adv.GetSecurityDescriptorOwner.argtypes=[W.LPVOID,C.POINTER(W.LPVOID),C.POINTER(W.BOOL)]
adv.GetSecurityDescriptorDacl.argtypes=[W.LPVOID,C.POINTER(W.BOOL),C.POINTER(W.LPVOID),C.POINTER(W.BOOL)]
adv.GetSecurityDescriptorControl.argtypes=[W.LPVOID,C.POINTER(W.WORD),C.POINTER(W.DWORD)]
adv.GetAce.argtypes=[W.LPVOID,W.DWORD,C.POINTER(W.LPVOID)]
adv.ConvertSidToStringSidW.argtypes=[W.LPVOID,C.POINTER(W.LPWSTR)]
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[W.LPCWSTR,W.DWORD,C.POINTER(W.LPVOID),C.POINTER(W.DWORD)]
u.CreateDesktopW.argtypes=[W.LPCWSTR,W.LPCWSTR,W.LPVOID,W.DWORD,W.DWORD,C.POINTER(SA)];u.CreateDesktopW.restype=W.HANDLE
u.CloseDesktop.argtypes=[W.HANDLE]
k.CreateProcessW.argtypes=[W.LPCWSTR,W.LPWSTR,W.LPVOID,W.LPVOID,W.BOOL,W.DWORD,W.LPVOID,W.LPCWSTR,C.POINTER(SI),C.POINTER(PI)]
k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.TerminateProcess.argtypes=[W.HANDLE,W.UINT];k.CloseHandle.argtypes=[W.HANDLE];k.LocalFree.argtypes=[W.LPVOID]
k.LocalFree.restype=W.LPVOID
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def desktop_flags(desk):
    flags=USEROBJECTFLAGS();needed=W.DWORD()
    if not u.GetUserObjectInformationW(desk,1,C.byref(flags),C.sizeof(flags),C.byref(needed)):raise C.WinError(C.get_last_error())
    if needed.value!=C.sizeof(flags):raise RuntimeError('Unexpected USEROBJECTFLAGS size')
    return {'fInherit':bool(flags.fInherit),'fReserved':bool(flags.fReserved),'dwFlags':flags.dwFlags}
def object_name(handle):
    name=C.create_unicode_buffer(256);needed=W.DWORD()
    if not u.GetUserObjectInformationW(handle,2,name,C.sizeof(name),C.byref(needed)):raise C.WinError(C.get_last_error())
    return name.value
def sid_text(sid):
    text=W.LPWSTR()
    if not adv.ConvertSidToStringSidW(sid,C.byref(text)):raise C.WinError(C.get_last_error())
    try:return text.value
    finally:k.LocalFree(C.cast(text,W.LPVOID))
def verify_desktop_acl(desk, owner_sid):
    flags=W.DWORD(5);needed=W.DWORD()
    u.GetUserObjectSecurity(desk,C.byref(flags),None,0,C.byref(needed))
    if not needed.value:raise C.WinError(C.get_last_error())
    buf=C.create_string_buffer(needed.value)
    if not u.GetUserObjectSecurity(desk,C.byref(flags),buf,len(buf),C.byref(needed)):raise C.WinError(C.get_last_error())
    owner=W.LPVOID();defaulted=W.BOOL();acl=W.LPVOID();present=W.BOOL();control=W.WORD();revision=W.DWORD()
    if not adv.GetSecurityDescriptorOwner(buf,C.byref(owner),C.byref(defaulted)):raise C.WinError(C.get_last_error())
    if sid_text(owner)!=owner_sid:raise RuntimeError('Desktop owner mismatch')
    if not adv.GetSecurityDescriptorControl(buf,C.byref(control),C.byref(revision)):raise C.WinError(C.get_last_error())
    if not control.value & 0x1000:raise RuntimeError('Desktop DACL is not protected')
    if not adv.GetSecurityDescriptorDacl(buf,C.byref(present),C.byref(acl),C.byref(defaulted)):raise C.WinError(C.get_last_error())
    if not present.value or not acl:raise RuntimeError('Desktop missing DACL')
    count=C.c_ushort.from_address(acl.value+4).value
    if count!=3:raise RuntimeError('Desktop must have exactly three ACEs')
    actual=set()
    for index in range(count):
        ace=W.LPVOID()
        if not adv.GetAce(acl,index,C.byref(ace)):raise C.WinError(C.get_last_error())
        header=(C.c_ubyte*4).from_address(ace.value)
        mask=W.DWORD.from_address(ace.value+4).value
        if header[0]!=0 or header[1]!=0 or mask not in (0x10000000,0xf01ff):raise RuntimeError('Unexpected desktop ACE type/flags/mask')
        actual.add(sid_text(W.LPVOID(ace.value+8)))
    if actual!={'S-1-5-18','S-1-5-32-544',owner_sid}:raise RuntimeError('Desktop trustees mismatch')
    return {'ownerSID':sid_text(owner),'protectedDACL':True,'allowTrustees':sorted(actual),'ACECount':count}
