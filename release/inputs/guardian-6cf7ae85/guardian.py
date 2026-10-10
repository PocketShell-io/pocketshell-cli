"""Isolated durable guardian candidate. No task registration or enrollment.
Own private Job and held daemon identity; caller supplies a protected closed manifest.
"""
import argparse, ctypes as C, ctypes.wintypes as W, hashlib, importlib.util, json, msvcrt, os, pathlib, socket, subprocess, sys, time, uuid
HERE=pathlib.Path(__file__).resolve().parent
# Frozen sibling source checks before importing native definitions or policy.
API_SHA='cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231';POLICY_SHA='e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce'
for name,pin in (('native_api.py',API_SHA),('policy.py',POLICY_SHA)):
    if hashlib.sha256((HERE/name).read_bytes()).hexdigest()!=pin:raise RuntimeError('Guardian source custody mismatch')
sys.path.insert(0,str(HERE))
import native_api as a
from policy import absolute, below, validate_manifest, validate_context, validate_stop, config_guard, require_source_pins, servicing_role, require_regular_links
k,u=a.k,a.u

class TOKEN_STATISTICS(C.Structure):
    _fields_=[('TokenIdLow',W.DWORD),('TokenIdHigh',W.LONG),('AuthLow',W.DWORD),('AuthHigh',W.LONG),('Expiration',C.c_longlong),('TokenType',W.DWORD),('ImpersonationLevel',W.DWORD),('DynamicCharged',W.DWORD),('DynamicAvailable',W.DWORD),('GroupCount',W.DWORD),('PrivilegeCount',W.DWORD),('ModifiedLow',W.DWORD),('ModifiedHigh',W.LONG)]
a.adv.OpenProcessToken.argtypes=[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)]
a.adv.GetTokenInformation.argtypes=[W.HANDLE,C.c_int,W.LPVOID,W.DWORD,C.POINTER(W.DWORD)]

def token_context():
    token=W.HANDLE()
    if not a.adv.OpenProcessToken(W.HANDLE(-1),8,C.byref(token)):raise C.WinError(C.get_last_error())
    try:
        needed=W.DWORD();a.adv.GetTokenInformation(token,1,None,0,C.byref(needed))
        if not 0<needed.value<=16384:raise RuntimeError('Token metadata bound refused')
        buf=C.create_string_buffer(needed.value)
        if not a.adv.GetTokenInformation(token,1,buf,len(buf),C.byref(needed)):raise C.WinError(C.get_last_error())
        sid=a.sid_text(C.cast(buf,C.POINTER(W.LPVOID))[0])
        session=W.DWORD();token_session=W.DWORD()
        if not k.ProcessIdToSessionId(k.GetCurrentProcessId(),C.byref(session)):raise C.WinError(C.get_last_error())
        if not a.adv.GetTokenInformation(token,12,C.byref(token_session),C.sizeof(token_session),C.byref(needed)) or token_session.value!=session.value:raise RuntimeError('Process/token session mismatch')
        stats=TOKEN_STATISTICS()
        if not a.adv.GetTokenInformation(token,10,C.byref(stats),C.sizeof(stats),C.byref(needed)) or needed.value!=C.sizeof(stats):raise RuntimeError('Token statistics layout mismatch')
        station=u.GetProcessWindowStation()
        return {'ownerSID':sid,'session':session.value,'station':a.object_name(station),'stationVisible':bool(a.desktop_flags(station)['dwFlags']&1),'desktop':a.object_name(u.GetThreadDesktop(k.GetCurrentThreadId())),'activeConsoleSession':k.WTSGetActiveConsoleSessionId(),'authenticationLUID':str((stats.AuthHigh&0xffffffff)<<32|stats.AuthLow)}
    finally:
        if not k.CloseHandle(token):raise C.WinError(C.get_last_error())

def ordinary(path,directory=False,allow_servicing=False):
    path=pathlib.Path(path)
    for item in [path,*path.parents]:
        st=item.lstat()
        if getattr(st,'st_file_attributes',0)&0x400:raise RuntimeError('Reparse path refused')
    st=path.stat()
    if directory:
        if not path.is_dir():raise RuntimeError('Directory required')
    else:
        if not path.is_file():raise RuntimeError('Regular file required')
        require_regular_links(path,st.st_nlink,allow_servicing)
    return path

TRUSTED_INSTALLER='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
def check_acl(path,owner_sid,role='private',protected=False,servicing=False):
    owner=W.LPVOID();group=W.LPVOID();dacl=W.LPVOID();sacl=W.LPVOID();sd=W.LPVOID()
    a.adv.GetNamedSecurityInfoW.argtypes=[W.LPWSTR,C.c_int,W.DWORD,C.POINTER(W.LPVOID),C.POINTER(W.LPVOID),C.POINTER(W.LPVOID),C.POINTER(W.LPVOID),C.POINTER(W.LPVOID)]
    code=a.adv.GetNamedSecurityInfoW(str(path),1,5,C.byref(owner),C.byref(group),C.byref(dacl),C.byref(sacl),C.byref(sd))
    if code:raise RuntimeError('Path ACL query failed '+str(code))
    try:
        trusted={owner_sid,'S-1-5-18','S-1-5-32-544',TRUSTED_INSTALLER}
        if servicing:trusted.discard(owner_sid) # Servicing images require system-owned, non-user-writable authority.
        actual_owner=a.sid_text(owner)
        if actual_owner not in ({owner_sid} if role=='private' else trusted):raise RuntimeError('Path owner authority mismatch')
        ctrl=W.WORD();rev=W.DWORD()
        if not a.adv.GetSecurityDescriptorControl(sd,C.byref(ctrl),C.byref(rev)) or (protected and not ctrl.value&0x1000):raise RuntimeError('Protected private root required')
        if not dacl:raise RuntimeError('NULL path DACL refused')
        count=C.c_ushort.from_address(dacl.value+4).value
        for i in range(count):
            ace=W.LPVOID()
            if not a.adv.GetAce(dacl,i,C.byref(ace)):raise C.WinError(C.get_last_error())
            header=(C.c_ubyte*4).from_address(ace.value)
            if header[0] not in (0,1):raise RuntimeError('Unsupported path ACE refused')
            if header[0]!=0 or header[1]&8:continue # Deny cannot grant; INHERIT_ONLY does not apply to this object.
            sid=a.sid_text(W.LPVOID(ace.value+8));mask=W.DWORD.from_address(ace.value+4).value
            if sid in trusted:continue
            # Parent create-file/create-directory rights alone do not authorize replacing the protected child.
            mutation=0x500d0150 if role=='ancestor' else 0x500d0116
            if role=='private' or mask&mutation:raise RuntimeError('Foreign path mutation/read authority refused')
    finally:
        if k.LocalFree(sd):raise RuntimeError('ACL descriptor release failed')

def path_authority(path,owner_sid,private=False,directory=False,protected=False,allow_servicing=False):
    if allow_servicing and (private or directory or not servicing_role(str(path))):raise RuntimeError('Servicing role misuse refused')
    p=ordinary(path,directory,allow_servicing)
    for parent in reversed(p.parents):check_acl(parent,owner_sid,'ancestor')
    check_acl(p,owner_sid,'private' if private else 'file',protected,allow_servicing)
    return p

def times(handle):
    b,e,kt,ut=W.FILETIME(),W.FILETIME(),W.FILETIME(),W.FILETIME()
    if not k.GetProcessTimes(handle,C.byref(b),C.byref(e),C.byref(kt),C.byref(ut)):raise C.WinError(C.get_last_error())
    return str(b.dwHighDateTime<<32|b.dwLowDateTime)

class TCPROW(C.Structure):_fields_=[('state',W.DWORD),('localAddress',W.DWORD),('localPort',W.DWORD),('remoteAddress',W.DWORD),('remotePort',W.DWORD),('pid',W.DWORD)]
ip=C.WinDLL('iphlpapi',use_last_error=True)
ip.GetExtendedTcpTable.argtypes=[W.LPVOID,C.POINTER(W.DWORD),W.BOOL,W.DWORD,C.c_int,W.DWORD]
def listeners(port):
    size=W.DWORD();code=ip.GetExtendedTcpTable(None,C.byref(size),False,2,3,0)
    if code!=122 or not 4<=size.value<=1048576:raise RuntimeError('Listener allocation refused')
    data=C.create_string_buffer(size.value)
    code=ip.GetExtendedTcpTable(data,C.byref(size),False,2,3,0)
    if code:raise RuntimeError('Listener query failed '+str(code))
    count=W.DWORD.from_buffer(data).value
    if 4+count*C.sizeof(TCPROW)>len(data):raise RuntimeError('Listener count exceeds buffer')
    rows=[]
    for i in range(count):
        r=TCPROW.from_buffer(data,4+i*C.sizeof(TCPROW))
        if socket.ntohs(r.localPort&0xffff)==port:rows.append({'pid':r.pid,'address':socket.inet_ntoa(int(r.localAddress).to_bytes(4,'little'))})
    return rows

def new_job():
    job=k.CreateJobObjectW(None,None)
    if not job:raise C.WinError(C.get_last_error())
    try:
        limits=a.LIMITS();limits.BasicLimitInformation.LimitFlags=0x2000
        if not k.SetInformationJobObject(job,9,C.byref(limits),C.sizeof(limits)):raise C.WinError(C.get_last_error())
        return job
    except Exception:
        k.CloseHandle(job);raise

def start_owned(image,arguments,desktop,job,label,pi):
    # PI storage belongs to caller before creation, retaining custody even on failure.
    files=[];attrs=None;initialized=False;returned=False
    try:
        for path,mode in ((os.devnull,'rb'),(LOG_ROOT/(label+'.stdout.log'),'wb'),(LOG_ROOT/(label+'.stderr.log'),'wb')):
            stream=open(path,mode,buffering=0);files.append(stream);os.set_inheritable(stream.fileno(),True)
        handles=(W.HANDLE*4)(*[msvcrt.get_osfhandle(stream.fileno()) for stream in files],desktop)
        if len(set(int(handle) for handle in handles))!=4 or not a.desktop_flags(desktop)['fInherit']:raise RuntimeError('Exactly three stdio and one actual inheritable HDESKTOP required')
        size=C.c_size_t();k.InitializeProcThreadAttributeList(None,1,0,C.byref(size))
        if not size.value:raise C.WinError(C.get_last_error())
        attrs=C.create_string_buffer(size.value)
        if not k.InitializeProcThreadAttributeList(attrs,1,0,C.byref(size)):raise C.WinError(C.get_last_error())
        initialized=True
        if not k.UpdateProcThreadAttribute(attrs,0,0x20002,handles,C.sizeof(handles),None,None):raise C.WinError(C.get_last_error())
        si=a.SIEX();si.StartupInfo.cb=C.sizeof(si);si.StartupInfo.lpDesktop=STATION+'\\'+DESKTOP
        si.StartupInfo.dwFlags=0x101;si.StartupInfo.wShowWindow=0
        si.StartupInfo.hStdInput,si.StartupInfo.hStdOutput,si.StartupInfo.hStdError=handles[:3]
        si.lpAttributeList=C.cast(attrs,W.LPVOID)
        command=C.create_unicode_buffer(subprocess.list2cmdline([str(image),*arguments]))
        if not k.CreateProcessW(str(image),command,None,None,True,0x08080404,C.cast(ENV_BLOCK,W.LPVOID),str(ROOT),C.byref(si.StartupInfo),C.byref(pi)):raise C.WinError(C.get_last_error())
        if not k.AssignProcessToJobObject(job,pi.hProcess):raise C.WinError(C.get_last_error())
        member=W.BOOL()
        if not k.IsProcessInJob(pi.hProcess,job,C.byref(member)) or not member.value:raise RuntimeError('Actual owned process Job assignment absent')
        if k.ResumeThread(pi.hThread)==0xffffffff:raise C.WinError(C.get_last_error())
        returned=True;return pi
    finally:
        errors=[]
        if not returned and pi.hProcess:
            stopped=False
            try:
                if k.WaitForSingleObject(pi.hProcess,0)!=0:
                    if not k.TerminateProcess(pi.hProcess,1):raise C.WinError(C.get_last_error())
                    if k.WaitForSingleObject(pi.hProcess,5000)!=0:raise RuntimeError('Exact owned startup process did not stop')
                stopped=True
            except Exception as exc:errors.append(str(exc))
            # On stop failure keep held handles in caller PI for its checked cleanup.
            if stopped:
                for attribute in ('hThread','hProcess'):
                    handle=getattr(pi,attribute)
                    if handle:
                        if not k.CloseHandle(handle):errors.append('Owned startup '+attribute+' close failed '+str(C.get_last_error()))
                        else:setattr(pi,attribute,None)
        if initialized:k.DeleteProcThreadAttributeList(attrs)
        for stream in files:
            try:stream.close()
            except Exception as exc:errors.append('Owned startup stream close failed '+str(exc))
        if errors:raise RuntimeError('Checked owned startup cleanup failed: '+repr(errors))

def release(pi):
    for attribute in ('hThread','hProcess'):
        handle=getattr(pi,attribute)
        if handle:
            if not k.CloseHandle(handle):raise C.WinError(C.get_last_error())
            setattr(pi,attribute,None)


def startup_members(job,pins,result):
    listed=a.JOBPIDS()
    if not k.QueryInformationJobObject(job,3,C.byref(listed),C.sizeof(listed),None):raise C.WinError(C.get_last_error())
    if listed.NumberOfAssignedProcesses>64 or listed.NumberOfProcessIdsInList>64:raise RuntimeError('Startup Job diagnostic bound exceeded')
    rows=result.setdefault('startupMembers',[]);allow={os.path.normcase(absolute(p)):h for p,h in pins.items()}
    for i in range(listed.NumberOfProcessIdsInList):
        pid=int(listed.ProcessIdList[i]);handle=k.OpenProcess(0x1000,False,pid)
        if not handle:raise RuntimeError('Unknown startup Job process open failure '+str(C.get_last_error()))
        try:
            member=W.BOOL()
            if not k.IsProcessInJob(handle,job,C.byref(member)) or not member.value:raise RuntimeError('Startup exact Job membership refused')
            birth=times(handle);image=C.create_unicode_buffer(32768);size=W.DWORD(len(image));code=W.DWORD()
            row={'pid':pid,'creationFILETIME':birth,'exactOwnedJobMembership':True};rows.append(row)
            if not k.QueryFullProcessImageNameW(handle,0,image,C.byref(size)):
                row['imageQueryError']=C.get_last_error()
                if not k.GetExitCodeProcess(handle,C.byref(code)) or code.value==259:raise RuntimeError('Live/unknown startup image query refusal')
                stamps=[]
                for _ in range(2):
                    b,e,kt,ut=W.FILETIME(),W.FILETIME(),W.FILETIME(),W.FILETIME()
                    if not k.GetProcessTimes(handle,C.byref(b),C.byref(e),C.byref(kt),C.byref(ut)):raise C.WinError(C.get_last_error())
                    stamps.append((str(b.dwHighDateTime<<32|b.dwLowDateTime),e.dwHighDateTime<<32|e.dwLowDateTime))
                if stamps[0]!=stamps[1] or stamps[0][0]!=birth or stamps[0][1]<int(birth) or not stamps[0][1]:raise RuntimeError('Unknown exited observation refused')
                row.update(provenExited=True,exitCode=code.value,exitFILETIME=str(stamps[0][1]));continue
            row['image']=image.value
            pin=allow.get(os.path.normcase(os.path.abspath(image.value)))
            if not pin or a.digest(ordinary(image.value,allow_servicing=servicing_role(image.value)))!=pin:raise RuntimeError('Startup image outside exact manifest custody')
        finally:
            if not k.CloseHandle(handle):raise C.WinError(C.get_last_error())
    return rows

def accounting(job):
    info=a.ACCOUNTING()
    if not k.QueryInformationJobObject(job,1,C.byref(info),C.sizeof(info),None):raise C.WinError(C.get_last_error())
    return info.ActiveProcesses

k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,W.LPVOID,W.DWORD,W.DWORD,W.HANDLE];k.CreateFileW.restype=W.HANDLE

def allocate_generation(base,owner_sid):
    lock_path=base/'INSTANCE.lock'
    if lock_path.exists():path_authority(lock_path,owner_sid,True)
    lock=k.CreateFileW(str(lock_path),0x80000000,0,None,4,0x00200000,None) # OPEN_ALWAYS, OPEN_REPARSE_POINT, exclusive share.
    if not lock or lock==W.HANDLE(-1).value:raise RuntimeError('Another invocation or lock failure; no generation reuse')
    try:
        path_authority(lock_path,owner_sid,True)
        generation=base/('generation-'+uuid.uuid4().hex)
        generation.mkdir() # Fresh own child; do not clear or reuse any historical state.
        path_authority(generation,owner_sid,True,True)
        return generation,lock
    except Exception:
        if not k.CloseHandle(lock):raise RuntimeError('Generation lock cleanup failed')
        raise

def publish_current(base,generation,ready,manifest_sha,owner_sid):
    current=base/'CURRENT.json'
    if current.exists():path_authority(current,owner_sid,True)
    payload={'version':1,'generation':str(generation),'ready':str(ready),'manifestSHA256':manifest_sha}
    temporary=generation/'CURRENT.tmp'
    temporary.write_text(json.dumps(payload,indent=2),encoding='utf8')
    os.replace(temporary,current) # Replace only this declared public pointer; retain every generation's evidence.

def main():
    global ROOT,LOG_ROOT,STATION,DESKTOP,ENV_BLOCK
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',required=True);parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if (C.sizeof(W.DWORD),C.sizeof(W.HANDLE),C.sizeof(TOKEN_STATISTICS),C.sizeof(a.SI),C.sizeof(a.SIEX),C.sizeof(a.PI))!=(4,8,56,104,112,24):raise RuntimeError('Qualified x64 Windows native ABI mismatch')
    manifest_path=ordinary(absolute(args.manifest))
    if manifest_path.stat().st_size>65536:raise RuntimeError('Manifest bound exceeded')
    manifest_bytes=manifest_path.read_bytes();manifest_sha=hashlib.sha256(manifest_bytes).hexdigest()
    m=validate_manifest(json.loads(manifest_bytes));context=validate_context(token_context(),m['ownerSID'])
    ROOT=path_authority(m['root'],m['ownerSID'],True,True,True);state=path_authority(m['state'],m['ownerSID'],True,True);LOG_ROOT=state
    below(str(manifest_path),str(ROOT));path_authority(manifest_path,m['ownerSID'],True)
    require_source_pins(m['pins'],[str(pathlib.Path(__file__)),str(HERE/'native_api.py'),str(HERE/'policy.py')])
    for p in (pathlib.Path(__file__),HERE/'native_api.py',HERE/'policy.py'):
        below(str(p),str(ROOT));path_authority(p,m['ownerSID'],True)
    path_authority(m['config'],m['ownerSID'],True)
    for p,pin in m['pins'].items():
        if a.digest(path_authority(p,m['ownerSID'],allow_servicing=servicing_role(p)))!=pin:raise RuntimeError('Startup exact file custody mismatch')
    if a.digest(pathlib.Path(sys.executable))!=m['pins'][m['python']] or os.path.normcase(os.path.abspath(sys.executable))!=os.path.normcase(absolute(m['python'])):raise RuntimeError('Actual Python executable mismatch')
    config_guard(pathlib.Path(m['config']).read_text(encoding='utf8'),m['port'],m['configBindings'])
    for key in ('hostKey','authorizedKeys'):path_authority(m['configBindings'][key],m['ownerSID'],True)
    for key in ('sftp','backendExecutable','backendDLL'):path_authority(m['configBindings'][key],m['ownerSID'])
    path_authority(m['configBindings']['backendConfig'],m['ownerSID'],True)
    for key in ('APLEXER_RUNTIME_DIR','APLEXER_STATE_DIR','XDG_CONFIG_HOME','XDG_STATE_HOME','XDG_DATA_HOME','XDG_CACHE_HOME'):path_authority(m['configBindings']['setEnv'][key],m['ownerSID'],True,True)
    import tomllib
    backend=tomllib.loads(pathlib.Path(m['configBindings']['backendConfig']).read_text(encoding='utf8'))
    shell=backend.get('engines',{}).get('shell',{})
    if shell.get('command')!=[m['configBindings']['backendExecutable'],'--noprofile','--norc','-i'] or shell.get('env_unset')!=['BASH_ENV','ENV','ZDOTDIR']:raise RuntimeError('Pinned interactive backend command mismatch')
    for p in (m['environment']['TEMP'],m['environment']['TMP']):path_authority(p,m['ownerSID'],True,True)
    if args.check_only:
        print(json.dumps({'phase':'preflight-only','manifestSHA256':manifest_sha,'context':context,'port':m['port'],'sourceSHA256':a.digest(pathlib.Path(__file__)),'daemonSpawned':False,'stateAllocated':False}),flush=True)
        return 0
    STATION=context['station'];DESKTOP='PocketShellPrivate_'+uuid.uuid4().hex
    ENV_BLOCK=C.create_unicode_buffer('\0'.join(key+'='+value for key,value in sorted(m['environment'].items(),key=lambda x:x[0].casefold()))+'\0\0')
    if listeners(m['port']):raise RuntimeError('Candidate port occupied')
    state_base=state;state,instance_lock=allocate_generation(state_base,m['ownerSID']);LOG_ROOT=state
    ready,stop,closed=[state/name for name in ('READY.json','STOP.json','CLOSED.json')]
    result={'accepted':False,'manifestSHA256':manifest_sha,'context':context,'cleanupErrors':[]};desk=None;job=None;sd=W.LPVOID();pi=a.PI()
    failed=False
    try:
        sddl='O:'+m['ownerSID']+'D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;'+m['ownerSID']+')'
        if not a.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,C.byref(sd),None):raise C.WinError(C.get_last_error())
        sa=a.SA(C.sizeof(a.SA),sd,True);desk=u.CreateDesktopW(DESKTOP,None,None,0,0x201ff,C.byref(sa))
        if not desk:raise C.WinError(C.get_last_error())
        result['privateDesktop']=STATION+'\\'+DESKTOP;result['desktopACL']=a.verify_desktop_acl(desk,m['ownerSID'])
        job=new_job();start_owned(pathlib.Path(m['daemon']),['-D','-f',m['config']],desk,job,'daemon',pi)
        birth=times(pi.hProcess);deadline=time.monotonic()+10
        while True:
            startup_members(job,m['pins'],result)
            if listeners(m['port'])==[{'pid':pi.dwProcessId,'address':'127.0.0.1'}]:break
            if k.WaitForSingleObject(pi.hProcess,0)!=258 or time.monotonic()>deadline:raise RuntimeError('Exact private listener absent')
            time.sleep(.05)
        result.update(pid=pi.dwProcessId,creationFILETIME=birth,guardianPID=k.GetCurrentProcessId(),sourceSHA256=a.digest(pathlib.Path(__file__)),port=m['port'],heldProcessHandle=True,ownedJob=True)
        ready.write_text(json.dumps(result,indent=2),encoding='utf8')
        publish_current(state_base,state,ready,manifest_sha,m['ownerSID'])
        print(json.dumps({'phase':'ready','pid':pi.dwProcessId,'creationFILETIME':birth,'guardianPID':k.GetCurrentProcessId(),'port':m['port']}),flush=True)
        while not stop.exists():
            if k.WaitForSingleObject(pi.hProcess,1000)!=258:raise RuntimeError('Held daemon exited unexpectedly')
        path_authority(stop,m['ownerSID'],True)
        if stop.stat().st_size>4096:raise RuntimeError('Stop bound exceeded')
        validate_stop(json.loads(stop.read_text(encoding='utf8')),pi.dwProcessId,birth,manifest_sha)
        result['requestedOwnedJobStop']=True
    except Exception as exc:
        result['failure']=str(exc);failed=True
    finally:
        errors=result['cleanupErrors']
        if job:
            try:
                result['activeBeforeStop']=accounting(job)
                if result['activeBeforeStop'] and not k.TerminateJobObject(job,1 if failed else 0):raise C.WinError(C.get_last_error())
                deadline=time.monotonic()+5
                while accounting(job):
                    if time.monotonic()>deadline:raise RuntimeError('Owned Job drain timeout')
                    time.sleep(.05)
                result['activeAtClose']=accounting(job)
            except Exception as exc:errors.append(str(exc))
        if pi.hProcess:
            try:
                if k.WaitForSingleObject(pi.hProcess,5000)!=0:raise RuntimeError('Held daemon cleanup timeout')
                release(pi)
            except Exception as exc:errors.append(str(exc))
        if job and not k.CloseHandle(job):errors.append('Job close failed')
        if desk and not u.CloseDesktop(desk):errors.append('Private desktop close failed')
        if sd and k.LocalFree(sd):errors.append('Descriptor release failed')
        try:
            if listeners(m['port']):errors.append('Candidate listener remains')
        except Exception as exc:errors.append(str(exc))
        result['accepted']=not failed and not errors and result.get('requestedOwnedJobStop') is True and result.get('activeAtClose')==0
        if not k.CloseHandle(instance_lock):errors.append('Invocation lock close failed')
        result['accepted']=not failed and not errors and result.get('requestedOwnedJobStop') is True and result.get('activeAtClose')==0
        closed.write_text(json.dumps(result,indent=2),encoding='utf8')
        print(json.dumps({'phase':'closed','accepted':result['accepted'],'cleanupErrors':errors}),flush=True)
    return 0 if result['accepted'] else 1
if __name__=='__main__':sys.exit(main())
