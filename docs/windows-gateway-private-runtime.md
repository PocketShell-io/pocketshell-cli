# Private Windows gateway runtime

Account/gateway on Windows requires the explicitly pinned private native
`pocketshell-link` build from gateway source
8cbeb8f9593d37bab410e24edc1aa321397a4c3c, SHA256
57f3a86e2166b079e99479a985fd8cbc56a91260cf3d8dee76c446e60189ac63.
Set `POCKETSHELL_GATEWAY_HELPER` to its absolute .exe path in the protected
private runtime. Windows does not discover a helper through PATH or public
platform wheels. The digest gate establishes this reviewed artifact; the
separate bounded `version --json` gate checks protocol compatibility.

The Windows wrapper waits for the helper/OpenSSH child, inherits terminal
streams and returns the child's exit status. Console Ctrl+C reaches the
shared console child; the wrapper waits briefly for shutdown, then terminates
and reaps a remaining child. A SIGTERM handled by the wrapper also terminates
the child. POSIX continues to replace its process with execv/execve.

Enrollment tokens travel only over stdin: a caller pipe is inherited, while
a login-minted token gets its own anonymous child pipe. Tokens are never added
to argv, environment or files. Metadata probes have detached stdin, a10-second
deadline and4096-byte output bound. Windows uses PeekNamedPipe instead of Unix
selector readiness. Protocol failures are refused before minting a token.

The Python gateway proxy switches Windows CRT stdin/stdout to binary mode so
CRLF, Ctrl+Z, NUL and arbitrary SSH bytes survive unchanged. Diagnostics remain
on stderr. Native tests cover exact bytes, waited status, token-only stdin,
bounded metadata, and cancellation. A fixture child proves the process boundary;
it does not establish production enrollment, WSS connectivity or SSH trust.

Parent native test commands, from the exact reviewed source snapshot and
private interpreter (use parent-confirmed absolute paths):

```powershell
$env:POCKETSHELL_TEST_WINDOWS_HELPER = $Approved8cbHelper
& $ProtectedPython -m pytest tests/gateway/test_windows_helper_execution.py tests/test_windows_startup.py tests/account/test_windows_private_storage.py tests/gateway/test_windows_sshcmd.py -q
```

The exact-helper native protocol test must run rather than skip. Preserve
ADMIN and NONADMIN receipts under normal subprocess encoding. Existing
protected bin ACL/hash, credential/pin ACL and strict cp1252 tests remain
required. Sessions/tree/workspaces are outside this account/gateway slice and
remain separately owned.

Parent owns actual enrollment/run/proxy acceptance. Use an explicitly selected
audit device/config, independently verified loopback sshd host key and trusted
user key; preserve existing hosts and sessions. Capture real approved helper
enrollment, foreground run, externally routed device discovery, SSH host pin,
gateway SSH exec and PTY resize/input/output/exit. Record helper/CLI source and
artifact hashes. A passing protocol probe, fixture or listener cannot accept
these production behaviors. No global install or default-shell change is needed.
