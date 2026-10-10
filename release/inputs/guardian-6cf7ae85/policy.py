"""Portable closed manifest/context rules; no native execution."""
import ntpath, re, shlex

def absolute(value):
    if not isinstance(value,str) or not re.match(r'^[A-Za-z]:[\\/]',value) or any(x in value for x in ('\x00','\r','\n','"')):
        raise ValueError('Absolute local drive path required')
    if value.startswith(('\\\\','//')) or any(p in ('..','.') for p in re.split(r'[\\/]',value)[1:]):raise ValueError('Traversal or device path refused')
    if ':' in value[2:]:raise ValueError('Alternate data stream refused')
    return ntpath.normpath(value)

def below(value,root):
    value,root=absolute(value),absolute(root)
    if ntpath.commonpath([value,root]).casefold()!=root.casefold() or value.casefold()==root.casefold():raise ValueError('Path escapes protected root')
    return value

def validate_manifest(m):
    if set(m)!={'version','ownerSID','root','state','config','port','daemon','python','pins','environment','configBindings'} or m['version']!=1:raise ValueError('Closed manifest schema required')
    if not re.fullmatch(r'S-1-5-21-\d+-\d+-\d+-\d+',m['ownerSID']):raise ValueError('Own account SID required')
    root=absolute(m['root']);below(m['state'],root);below(m['config'],root);below(m['daemon'],root);absolute(m['python'])
    if type(m['port']) is not int or not 1024<=m['port']<=65535:raise ValueError('Unprivileged explicit port required')
    if not isinstance(m['pins'],dict) or not m['pins']:raise ValueError('Pinned file closure required')
    keys=set()
    for p,h in m['pins'].items():
        key=absolute(p).casefold()
        if key in keys or not isinstance(h,str) or not re.fullmatch('[a-f0-9]{64}',h):raise ValueError('Unique exact hash pins required')
        keys.add(key)
    for p in (m['daemon'],m['python'],m['config']):
        if absolute(p).casefold() not in keys:raise ValueError('Required startup file lacks pin')
    b=m['configBindings']
    if set(b)!={'hostKey','authorizedKeys','pidFile','allowUser','sftp','backendConfig','backendExecutable','backendDLL','setEnv'}:raise ValueError('Closed config binding roles required')
    for name in ('hostKey','authorizedKeys','pidFile','sftp','backendConfig','backendExecutable','backendDLL'):absolute(b[name])
    below(b['pidFile'],m['state'])
    for name in ('sftp','backendConfig','backendExecutable','backendDLL'):
        if absolute(b[name]).casefold() not in keys:raise ValueError('Config runtime role lacks pin')
    if not isinstance(b['allowUser'],str) or not re.fullmatch(r'[A-Za-z0-9_.-]+',b['allowUser']):raise ValueError('One explicit username required')
    allowed_env={'APLEXER_CONFIG','APLEXER_RUNTIME_DIR','APLEXER_STATE_DIR','APLEXER_RUN_IN_PLACE','APLEXER_SHELL','XDG_CONFIG_HOME','XDG_STATE_HOME','XDG_DATA_HOME','XDG_CACHE_HOME','BASH_ENV','ENV','ZDOTDIR'}
    if set(b['setEnv'])!=allowed_env or b['setEnv']['APLEXER_CONFIG']!=b['backendConfig'] or b['setEnv']['APLEXER_RUN_IN_PLACE']!='1' or any(b['setEnv'][key]!='' for key in ('APLEXER_SHELL','BASH_ENV','ENV','ZDOTDIR')):raise ValueError('Closed incoming backend environment required')
    for key,value in b['setEnv'].items():
        if not isinstance(value,str) or any(c in value for c in ('\x00','\r','\n')):raise ValueError('Invalid backend environment value')
        if key not in ('APLEXER_RUN_IN_PLACE','APLEXER_SHELL','BASH_ENV','ENV','ZDOTDIR'):absolute(value)
    env=m['environment']
    required={'SystemRoot','WINDIR','SystemDrive','ProgramData','USERPROFILE','HOME','TEMP','TMP'}
    if set(env)!=required or any(not isinstance(v,str) or any(c in v for c in ('\x00','\r','\n')) for v in env.values()):raise ValueError('Closed fixed environment required')
    if env['SystemDrive']!='C:' or env['SystemRoot'].casefold()!='c:/windows' or env['WINDIR'].casefold()!='c:/windows' or env['ProgramData'].casefold()!='c:/programdata':raise ValueError('Qualified system paths required')
    below(env['TEMP'],m['state']);below(env['TMP'],m['state']);absolute(env['USERPROFILE']);absolute(env['HOME'])
    return m

def validate_context(c, owner_sid):
    if c['ownerSID']!=owner_sid:raise ValueError('Own token SID mismatch')
    station=c['station']
    if not isinstance(station,str) or not station or any(x in station for x in ('\\','/','\x00','\r','\n')):raise ValueError('Actual station name invalid')
    if c['session']==0:
        if c['stationVisible'] or station.casefold()=='winsta0':raise ValueError('Session0 visible station refused')
    elif not (c['session']==c['activeConsoleSession'] and station=='WinSta0' and c['stationVisible'] and c['desktop']=='Default'):
        raise ValueError('Unsupported interactive context')
    return c

def validate_stop(request,pid,birth,manifest_sha):
    if request!={'pid':pid,'creationFILETIME':birth,'manifestSHA256':manifest_sha,'stopOwnedJob':True} or not isinstance(request['creationFILETIME'],str):raise ValueError('Exact held identity stop required')


def config_guard(text,port,bindings):
    keys={}
    allowed={'port','listenaddress','hostkey','pidfile','authorizedkeysfile','authenticationmethods','pubkeyauthentication','passwordauthentication','kbdinteractiveauthentication','permitemptypasswords','allowusers','disableforwarding','permittty','loglevel','subsystem','setenv'}
    for line in text.splitlines():
        tokens=shlex.split(line,comments=True)
        if not tokens:continue
        key=tokens[0].lower()
        if key not in allowed:raise ValueError('Undeclared config directive refused')
        keys.setdefault(key,[]).append(tokens[1:])
    expected={'port':[[str(port)]],'listenaddress':[['127.0.0.1']],'authenticationmethods':[['publickey']],'pubkeyauthentication':[['yes']],'passwordauthentication':[['no']],'kbdinteractiveauthentication':[['no']],'permitemptypasswords':[['no']],'disableforwarding':[['yes']],'permittty':[['yes']],'allowusers':[[bindings['allowUser']]]}
    if any(keys.get(k)!=v for k,v in expected.items()):raise ValueError('Closed loopback key-only config required')
    for directive,role in (('hostkey','hostKey'),('authorizedkeysfile','authorizedKeys'),('pidfile','pidFile')):
        rows=keys.get(directive)
        if not rows or len(rows)!=1 or len(rows[0])!=1 or absolute(rows[0][0]).casefold()!=absolute(bindings[role]).casefold():raise ValueError('Config path role mismatch')
    if keys.get('subsystem')!=[['sftp',bindings['sftp']]]:raise ValueError('Pinned private SFTP binding required')
    if len(keys.get('setenv',[]))!=1:raise ValueError('One closed SetEnv declaration required')
    env={}
    for item in keys['setenv'][0]:
        name,sep,value=item.partition('=')
        if not sep or name in env:raise ValueError('Duplicate/invalid SetEnv')
        env[name]=value
    if env!=bindings['setEnv']:raise ValueError('Backend environment binding mismatch')
    if len(keys.get('loglevel',[]))>1:raise ValueError('Duplicate log directive refused')

def require_source_pins(pins,paths):
    required={absolute(p).casefold() for p in paths};actual={absolute(p).casefold() for p in pins}
    if len(required)!=len(paths) or not required<=actual:raise ValueError('Guardian/API/policy source closure lacks manifest pins')

def servicing_role(value):
    return absolute(value).casefold() in ('c:\\windows\\system32\\cmd.exe','c:\\windows\\system32\\conhost.exe')

def require_regular_links(value,count,allow_servicing=False):
    if allow_servicing and not servicing_role(str(value)):raise ValueError('Unknown servicing image role')
    if count<1 or (count!=1 and not allow_servicing):raise RuntimeError('Regular single-link file required')
