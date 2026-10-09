# Windows client: `gateway ssh` / `gateway proxy`

How the native-Windows client reaches an enrolled host through the
gateway, what it requires, the exact quoting rules, and how to qualify a
real machine. The security model is unchanged from
[gateway.md §9](gateway.md#9-client-side-reach-an-enrolled-host). Every
hardening option, the pin-only host identity, `-F none`, the extra-argument
allowlist, platform TLS and token handling apply as written there.

## Runtime interface

```powershell
pocketshell login
pocketshell gateway pin home-lab          # paste the host's `gateway show --host-key` line
pocketshell gateway ssh home-lab -l me -i C:\Users\me\.ssh\id_ed25519
pocketshell gateway ssh home-lab -l me -- -t pocketshell sessions attach main
```

| Item | Requirement |
| --- | --- |
| ssh client | Win32-OpenSSH. Default: the inbox `%SystemRoot%\System32\OpenSSH\ssh.exe` (from 32-bit Python: `Sysnative\OpenSSH\ssh.exe`). Install it with *Settings → Optional features → OpenSSH Client*, or as administrator `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`. |
| `POCKETSHELL_SSH` | Optional override: an **absolute path to an existing** `ssh.exe`, e.g. a newer Win32-OpenSSH from the PowerShell/Win32-OpenSSH releases. `ssh` on `PATH` is never used, so Git for Windows, MSYS2 and Cygwin ssh are never picked silently. Their ProxyCommand goes through `/bin/sh`, and they handle consoles differently. |
| `-v` | `gateway ssh … -- -v …` prints `pocketshell: ssh executable <path> (<ssh -V>)` before ssh's own debug output. |
| Interpreter | Python ≥ 3.11 with `pocketshell[link]`. The ProxyCommand is `"<sys.executable>" -P -m pocketshell gateway proxy <id> […]`. `-P` stops a `pocketshell/` or `click.py` in the current directory from being imported. Under `pythonw.exe`, the `python.exe` next to it is used, because the proxy must be a console process that shares ssh.exe's console. |
| Interpreter path | May contain spaces, non-ASCII characters, `'`, `&`, `!`, `^`, `(`, `)`, `;`, `,`, `=`, `#` and `%` (`%` is doubled for ssh). **Refused:** `"`, `$`, backquote and control characters, plus paths that are not absolute or that end in `\` or whitespace. |
| Pin file / `-i` key paths | Absolute drive paths (`C:\…`). May contain spaces, non-ASCII characters, `'`, `#` and `~` inside a component (8.3 names). **Refused:** `"`, `%`, `$`, backquote, `=` and control characters. ssh expands `%`-tokens and `${ENV}` in these paths, and checks `-i` before expanding, so `%%` cannot work. The pin file lives in `%XDG_CONFIG_HOME%\pocketshell` if that is set, otherwise in `%USERPROFILE%\.config\pocketshell`. |
| Device id | `^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$`. A custom `--server` needs `--trust-gateway HOST` (see gateway.md §9.1). |

### Exit status, signals, consoles

- `gateway ssh` waits for ssh.exe and exits with its status: remote exit
  codes pass through, and ssh's own failures are 255.
  Not logged in is 3, before ssh starts.
- `gateway proxy` shares ssh.exe's console. It ignores console Ctrl+C and
  Ctrl+Break, which ssh.exe owns: in a PTY session Ctrl+C is sent to the
  host as a byte, and without a PTY ssh decides itself. The proxy ends only
  on stdin EOF (ssh is done), a WebSocket close, or its own error. A
  dropped gateway therefore ends the session promptly, with exit 255 from
  ssh and the cause on stderr, and you can simply reconnect.
  Remote aplexer sessions survive it (`pocketshell sessions attach …`
  again).
- Nothing opens a window. ssh.exe starts the ProxyCommand without
  `CREATE_NO_WINDOW` and without a shell, in its own console. When
  `gateway ssh` runs from a console, ssh.exe and the proxy share it. When it
  runs from a context with a hidden console (`CREATE_NO_WINDOW`), they share
  that hidden console. `pythonw` is never used for the proxy.
- Window resize is end to end: ConPTY → ssh.exe → an encrypted SSH
  `window-change` request. The proxy only moves bytes, unchanged in both
  directions (binary CRT mode, blocking reads in a thread, ≤ 32 KiB
  WebSocket messages, every chunk written straight to the stdout handle).

## How Win32-OpenSSH runs the ProxyCommand (and why the quoting is safe)

Source: [PowerShell/openssh-portable](https://github.com/PowerShell/openssh-portable).
This behavior is the same from v7.7.x (the inbox client in Windows 10
1809) through v9.8.x:

1. **Option parsing.** [`readconf.c`](https://github.com/PowerShell/openssh-portable/blob/latestw_all/readconf.c)
   `case oProxyCommand` keeps the rest of the `-o ProxyCommand=…` value
   verbatim. Since 8.7 the line is first tokenized by
   [`argv_split`](https://github.com/PowerShell/openssh-portable/blob/latestw_all/misc.c)
   as a syntax check, so quotes must balance and `\` escapes `' " \`
   and space.
2. **Token expansion.** [`sshconnect.c`](https://github.com/PowerShell/openssh-portable/blob/latestw_all/sshconnect.c)
   `expand_proxy_command` prefixes `exec ` and runs `percent_expand`
   (`%%` → `%`, plus `%h %p %r %n %k`). No `${ENV}` expansion happens here.
3. **No shell.** `ssh_proxy_connect` under `#ifdef FORK_NOT_SUPPORTED`
   calls `posix_spawnp(command + 5, argv = {command + 5})`. Neither
   `cmd.exe` nor `$SHELL` is involved.
4. **Command line.** [`contrib/win32/win32compat/w32fd.c`](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/w32fd.c)
   `spawn_child_internal` builds the line with
   [`misc.c` `build_commandline_string`](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/misc.c).
   A string that **starts with `"`** goes to
   `CreateProcessW(NULL, line, …, bInheritHandles=TRUE, …)` **verbatim**.
   Other strings are rewritten: v8.1+ inserts quotes after the first
   `.exe` + space, or around the whole string.
5. **Child argv.** python.exe splits the line with the
   [Microsoft C runtime rules](https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments).

So `%VAR%`, `^`, `&`, `|`, `<`, `>` and `!` are inert. The client builds:

```text
"C:/Users/First Last/venv/Scripts/python.exe" -P -m pocketshell gateway proxy home-lab [--server wss://h:p --trust-gateway h] [--insecure-dev]
```

The interpreter path always comes first and is double-quoted, so step 4
keeps the line verbatim. It uses `/` separators, so no backslash can
escape the closing quote in step 1 or step 5, and `%` is doubled for
step 2. Every other element is a validated token without quotes,
backslashes or whitespace. An IPv6 literal URL such as `wss://[::1]:8443`
is double-quoted. The same string is also correct under `/bin/sh -c`,
which is how an explicitly chosen MSYS/Git ssh would run it, because `$`
and backquote are refused.

Tests check this against independent oracles for each layer: argv_split,
percent_expand, the Win32-OpenSSH spawn, the MSVCRT split and `sh`. The
oracles live in `tests/gateway/test_winssh.py`; on Windows CI the real
ssh.exe runs it.

The `UserKnownHostsFile=` value is quoted when it contains whitespace, `'`
or `#`, because readconf tokenizes option values (`argv_split` /
`strdelim`). The `-i` path is a separate argv element.

## Verification

- **Linux / any OS:** `uv run --frozen pytest tests/gateway/test_winssh.py`
  runs every Windows code path through an explicit `platform="win32"`.
- **windows-latest CI** (`Windows gateway client` job): native unit tests,
  then `scripts/windows-e2e-sshd-setup.ps1`, which only runs in GitHub
  Actions and enables the runner's OpenSSH Server. The real e2e
  (`tests/gateway/test_windows_gateway_e2e.py`, gated by
  `POCKETSHELL_WINDOWS_E2E=1`) then covers:
  - remote output and exit status;
  - 4 MiB down and 3 MiB up, byte-exact;
  - wrong pin fails closed;
  - `-v` reports the inbox ssh;
  - interpreter, config and key paths with a space and non-ASCII characters;
  - a dropped gateway ends the session promptly;
  - every process stays in the launching console, with no new console or
    visible window, for both a hidden console and `CREATE_NO_WINDOW`;
  - console Ctrl+C tears everything down without a traceback;
  - the fleet qualifier below passes.

### Qualifying a real machine (laptop / Win35)

From a normal console, logged in and with the device pinned, run the
qualifier with the interpreter you use for pocketshell:

```powershell
& "C:\path\to\python.exe" scripts\windows-gateway-qualify.py `
    --device-id home-lab --pinned-key "ssh-ed25519 AAAA…" `
    --user me --identity C:\Users\me\.ssh\id_ed25519 `
    --remote-os posix --json $env:TEMP\ps-qualify.json
# Windows host: --remote-os windows (needs `python` on the host PATH, or pass
# --remote-cat "<remote command that echoes stdin to stdout byte-exactly>")
# custom gateway: add --server wss://gw.example --trust-gateway gw.example
```

The qualifier prints one `PASS`/`FAIL` line per check and a final
`RESULT:` line, and exits 0 only when everything passes. It changes nothing
global: it never logs in or out, never pins, and leaves ssh config, PATH,
profiles and DefaultShell alone. The wrong-pin check uses a throwaway pin
file. It shows no window: sessions share your console, and the Ctrl+C
check runs in a hidden console of its own, so your console never gets a
signal. Use `--remote-os windows` when the host is Windows. It then uses
cmd remote commands, and `python` from the host's PATH for the byte-exact
echo.

### Interactive checklist (cannot be automated)

Run `pocketshell gateway ssh <id> -l <user>` in **Windows Terminal** and
again in a classic **conhost** window:

1. **Resize:** in the remote shell run `tput cols; tput lines` (or `stty
   size`). Resize the window and run it again; the values follow. Run a
   full-screen program (`htop`, `vim`), resize while it runs, and check it
   redraws correctly.
2. **Ctrl+C inside the remote:** `sleep 100`, then Ctrl+C. The remote
   command stops, the session stays open, and nothing local exits. Repeat
   with Ctrl+Break. Win32-OpenSSH maps it to SIGTSTP; record what happens.
   The proxy must not exit on its own, and no traceback may appear.
3. **Escape:** `~.` on a fresh line ends the session at once, with exit 255.
4. **Detach and reconnect:** `pocketshell gateway ssh <id> -l <user> -- -t
   pocketshell sessions attach <name>`, then detach with the aplexer
   detach key. Reconnect with the same command and the session is intact.
   Disable Wi-Fi mid-session: the client exits within about 90 s
   (`ServerAliveInterval=30` × 3), or immediately if the gateway drops the
   socket. Reconnect after the network returns.
5. **Paste/large output:** paste a 5,000-line block into `cat > /tmp/x`,
   then `wc -l /tmp/x`. Run `seq 1 2000000` and check that Ctrl+C stops it
   promptly.
6. **No window:** while a session runs, Task Manager shows no extra console
   window. `python.exe` (the proxy) appears under `ssh.exe`, with no
   `conhost.exe` of its own.

## Host side: durable, hidden agent (`gateway service`)

This page is about the client. On a Windows machine that is itself an
enrolled **host**, keep its agent running with one per-user scheduled task
instead of a console window ([gateway.md §4.1](gateway.md#41-durable-start-pocketshell-gateway-service)):

```powershell
# as the enrolling user, from an elevated prompt (boot trigger + S4U)
pocketshell gateway service install --helper C:\path\pocketshell-link.exe --config-dir C:\path\keys --dry-run
pocketshell gateway service install --helper C:\path\pocketshell-link.exe --config-dir C:\path\keys
pocketshell gateway service status          # exit 0 running / 3 stopped / 4 absent; pid + session id
pocketshell gateway service uninstall       # removes only the task
```

The task (`\PocketShell\GatewayLink`) runs as your SID with LogonType S4U and
RunLevel LeastPrivilege in session 0, started at boot and re-checked every
5 minutes (`IgnoreNew`), and its single action launches the digest-allow-listed
`pocketshell-link.exe` **directly** — no `cmd.exe`, shell or redirection.
Every child process the command starts (`schtasks`, PowerShell for the task
state, the helper's `version`/`show`) uses `CREATE_NO_WINDOW`. Verified on
the windows-latest CI runner against the real Task Scheduler with a fake
helper (`tests/gateway/test_windows_gateway_service_native.py`).

The CLI's own `gateway run/show/enroll` wrappers still pin the historical
helper digest in the fleet-owned `helper.py`; the service path has its own
allow-list (`service_windows.ALLOWED_HELPER_SHA256`, today only the qualified
cd7c6f6 build `f9582de6…dabe1`). Unifying the two is a pending change for
that file's owner.

## Pending change in a fleet-owned file

`gateway ssh` currently waits for ssh.exe through
`helper.wait_windows_child`, which `client_cli._exec_ssh` calls. That
wrapper treats console Ctrl+C as cancellation: it records 130, waits 2 s,
then terminates ssh.exe. It also does not survive its own termination,
because ssh.exe is left running. `winssh.run_ssh` implements the intended
behavior and is tested natively:

- Ctrl+C and Ctrl+Break are ignored while ssh runs;
- ssh's own status is returned;
- a kill-on-close job object takes ssh.exe and the proxy down with the
  wrapper;
- `CREATE_NO_WINDOW` is used when the wrapper has no console.

Wiring it in is this change to `src/pocketshell/gateway/client_cli.py`.
It is not applied here because that file is owned by the Windows runtime
work:

```diff
 def _exec_ssh(path: str, argv: list[str], env: dict) -> None:
     """Replace this process with ssh (tests swap this seam)."""
     if sys.platform == "win32":
-        from pocketshell.gateway.helper import wait_windows_child
-        wait_windows_child(argv, env=env)
+        from pocketshell.gateway.winssh import run_ssh
+        raise SystemExit(run_ssh(argv, env))
     os.execve(path, argv, env)
```

Until then, interactive PTY sessions behave correctly anyway. ssh.exe puts
the console in raw mode, so Ctrl+C is a byte and not a console event. The
difference shows only for console Ctrl+C or Ctrl+Break in non-PTY sessions
(exit 130 instead of ssh's status), and for a killed wrapper.
