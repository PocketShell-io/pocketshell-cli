# Windows gateway tray installer

The Windows x64 installer belongs to `pocketshell-cli`: the tray uses the CLI's
gateway status, enrollment and owner-bound guardian instead of embedding a
second gateway implementation in Desktop. It bundles Python, Pillow, pystray,
the reviewed gateway helper (pocketshell-gateway 70f5a4b, with `gateway-auth`;
`build_tray_installer.py --helper` swaps it into the BASE closure), BOTH `a.exe` and `aplexer.exe`, the native aplexer
client (0.1.13, including `rpc --stdio` protocols 1 and 2), the private OpenSSH endpoint and Git Bash. No Python, uv, Git or aplexer
installation is required on the destination, including win35.
The installer also includes the standalone PSC Windows x64 package (Node,
client and security helper). It runs that package's per-user protected installer
and adds `psc` to the user PATH when writable, plus a **PSC Terminal** Start-menu
shortcut. A read-only user environment registry does not prevent installation;
use that shortcut or the absolute per-user `psc.cmd` shim.
Microsoft's signed portable OpenSSH client is bundled for PSC; no Windows
OpenSSH feature is required. Profile paths with spaces currently refuse.
The gateway's private SSH endpoint remains separate from PSC's inbox client.
PSC is optional: if its installation fails, gateway installation continues,
the installer warns with the location of `psc-install.log`, and the PSC Terminal
shortcut is omitted. The log remains in the gateway installation directory.
After installation open a new terminal, run `psc login`, `psc hosts sync`, and
`psc gateway pin DEVICE_ID 'ssh-ed25519 FULL_PUBLIC_KEY_BASE64'` using each
host's independently obtained key. Then use `psc hetzner ls` or
`psc hetzner connect`. PSC device login has its own current-user DPAPI store.

Run `PocketShellGateway-Setup-x64.exe` as the ordinary Windows user. First-use
Gateway Setup generates the local host key, opens browser sign-in, enrolls the
gateway and asks for the connecting client's SSH **public** `.pub` key. Approve
the browser code using your PocketShell account. These per-user identities
cannot be bundled in an installer. Cancelled setup can be resumed from the
Start menu's **Gateway Setup** shortcut without regenerating keys.

The tray starts at login. If the user's Run registry key is read-only (as
observed on win35), it uses a per-user Startup-folder shortcut instead.
Right-click for online/offline status, current
connections, active aplexer sessions, Start, Stop, Restart and Open Logs.
The tray owns its gateway workers in a Windows job and cleans them up when it
quits or crashes. This also works when Explorer itself has inherited job
restrictions. The ordinary CLI retains its separate independent-launch policy.
The helper reconnects after network outages. The tray checks dead local
processes every 30 seconds and asks the measured guardian to recover them.
Stop is remembered across app restarts and logins. An existing unrelated
gateway binding is refused rather than replaced. Client names and key comments
depend on available OpenSSH authentication records; a connection whose identity
is unavailable is shown as unknown, never guessed from the authorized key list.

Logs and the installed runtime are under
`%LOCALAPPDATA%\PocketShellGateway`. Uninstall disables startup, stops the bound
gateway and closes the tray; it preserves private keys, logs and session data.
This beta installer is unsigned and supports Windows x64 only.

For already-enrolled remote installations, the installed `GatewayTray.exe
--background` owns the gateway in the ordinary user's SSH session, without a
service or scheduled task. In session 0 it uses the guardian's reviewed invisible
station/private desktop contract and the same SID, key, hash and job checks.
It does not show a tray in another user's desktop. When the owning user signs
into Windows, the login tray requests that background owner's exit, releases
its job and starts the endpoint in the user's interactive session. Deliberate
Stop and uninstall also stop the background owner. Setup/enrollment must be
completed first; background startup never signs in or adopts another binding.

## Repair an existing enrolled installation after Windows Update

Install v0.5.9 or later as the **same Windows user**. Gateway Setup validates
the previous bundled closure, stops its owned workers, and upgrades the runtime
before redirecting the launcher. It keeps the device enrollment, host key,
authorized client keys and session directories. No new browser approval or
client host-key pin is needed. Interrupted repair resumes from its private
`tray-upgrade.json` journal on the next Gateway Setup run.

After extracting/installing the new EXE, the equivalent per-user command is:

```powershell
& "$env:LOCALAPPDATA\Programs\PocketShellGateway\runtime\python\python.exe" -I -B -m pocketshell.tray_bundle --repair
```

Use the **new staged runtime**, not an older `managed-runtime\releases` Python.
The old v0.5.8 installation has no safe general-purpose re-anchor command:
`agent bind` alone still checks the stale OS hashes. Do not edit receipt hashes
by hand or delete the authority, binding, keys or enrollment. Reinstalling this
release performs the validated repair instead.

New manifests hash only the bundled closure and generated configuration.
`cmd.exe` and `conhost.exe` use fixed `C:\Windows\System32` paths, checked
against reparse points and user/foreign write authority, including system-owned
file ACLs and the allowed Windows servicing hard links. Their old receipt
hashes are historical measurements, not integrity pins. A Windows update can
therefore replace these OS files without invalidating startup. Bundled-file
changes still refuse startup. The tray shows the failure in its error icon,
tooltip and notification, includes the Gateway Setup/Open Logs action, and
retries enabled gateways every 30 seconds. A deliberate Stop remains stopped.

## Build and check

Start from a reviewed **catalog-v3 resources archive** produced by
`scripts/release/build_closure.py`, not a copy of an arbitrary local installation.
Extract it to `BASE`. Obtain the catalog digest from that build's receipt.
The builder checks the exact inventory and every file hash before replacing the
Python application with this checkout and its frozen `tray` extra.

Build the GUI entry with the same pinned Go toolchain as the closure:

```powershell
$env:GOTOOLCHAIN = 'go1.26.8'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go -C native/launcher build -trimpath -buildvcs=false '-ldflags=-s -w -buildid= -H=windowsgui -X main.module=pocketshell.tray_bundle' -o C:/BUILD/GatewayTray.exe .
uv run --frozen python scripts/release/build_tray_installer.py --resources BASE --catalog-sha256 CATALOG_SHA256 --aplexer-cli-wheel C:/BUILD/aplexer-0.1.13-py3-none-win_amd64.whl --aplexer-client-wheel C:/BUILD/aplexer_client-0.1.13-cp311-abi3-win_amd64.whl --tray-launcher C:/BUILD/GatewayTray.exe --psc-zip C:/BUILD/psc-windows-x64-0.3.2.zip --psc-sha256 PSC_ZIP_SHA256 --ssh-zip C:/BUILD/OpenSSH-Win64.zip --ssh-sha256 SSH_ZIP_SHA256 --makensis C:/NSIS/makensis.exe --out FRESH_OUTPUT
uv run --frozen --extra tray python -m pytest tests/tray tests/release/test_tray_installer.py tests/gateway/test_gateway_status.py
uv run --frozen python scripts/release/smoke_tray_bundle.py --payload FRESH_OUTPUT/payload --install-check FRESH_TEST_USER_DATA
```

Download both Windows wheels from the aplexer `v0.1.13` GitHub release before
building. The builder verifies their pinned SHA256 values, replaces both managed
executables and the native Python client, and records their hashes and version in
`installer-receipt.json`. An older base closure cannot silently retain aplexer
0.1.11. On Windows the builder checks the bundled version, the session-list
command and `rpc --help`, then drives one framed `rpc --stdio --protocol 1`
ping against the bundled helper before producing the installer; the native
smoke check repeats that live ping. A tray whose bundled aplexer cannot serve
the resident RPC helper can no longer ship. Managed endpoint PATH puts the release's Python tools
first, then its CLI, Git Bash and System32; user-installed tools are excluded.

The native smoke check registers a tray icon briefly, queries actual aplexer
sessions and installs a fresh endpoint closure with generated keys. It does
not bind, log in, enroll or start a gateway. The build emits an installer and
`installer-receipt.json` with source, input catalog and artifact hashes.
For unattended file installation, use `/S`; run Gateway Setup in the destination
user's interactive desktop afterwards. Browser approval and public-key selection
are intentional first-use steps.

The tray builder also requires `--endpoint-backend OWNED_OPENSSH_OUTPUT` and
`--endpoint-backend-receipt-sha256 RECEIPT_SHA256`. Build the pinned backend with
`scripts/release/build_backend_windows.py --part openssh --work FRESH_WORK --out
BACKEND_OUTPUT`; its `openssh` directory includes the measured `receipt.json`.
The private OpenSSH source overlay derives Bash and command PATH from its own
release directory, not the registry's DefaultShell or user/system PATH. Plain
`pocketshell` and `a` commands from older PSC clients therefore resolve the
bundled executables without client provisioning. The builder verifies the
complete rebuilt executable/DLL inventory and every digest before staging it.

Obtain the PSC zip and SHA256 from the reviewed pocketshell-tui-client release
or its Windows package workflow artifact. The tray builder validates the zip
hash, complete inventory, and individual payload hashes before staging it.
The receipt records the PSC zip SHA256, version and client/Core commits.
The standalone install procedure is documented in that repository's
`docs/windows-package.md`. No dependencies download on the destination.
The portable client input is Microsoft's official Win32-OpenSSH release
`10.0.0.0p2-Preview`, `OpenSSH-Win64.zip`, SHA256
`23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5`.
The builder copies only `ssh.exe` and license notices, validates Microsoft's
signature, and records the archive and executable digests. PSC validates the
signature again on the installed copy. The package's own `install.ps1` is
replaced by the tray's `scripts/release/psc-install.ps1` (the builder pins the
reviewed upstream script and recatalogues the package). It uses the supplied
client and keeps existing inbox-client bindings and account state.
No system SSH service, feature, configuration or firewall rule is changed.

Re-running any installer over any existing PSC install succeeds, whether it is
the same version, older, newer or partly broken:

- PSC trees are content-addressed:
  `%LOCALAPPDATA%\PocketShell\psc\<version>-gateway-ssh10-<content id>`. The
  content id is a digest of every installed file and the bundled `ssh.exe`
  (`installer-receipt.json` records it as `psc.contentId`).
- A tree that verifies completely (inventory, digests, `ssh.exe`, bindings) is
  reused read-only.
- Anything else is built in a private staging directory and published with
  one directory rename. A broken tree is moved aside first. If it is in use, the
  new tree gets a unique sibling name.
- The `bin\psc.cmd` shim is switched last, with an atomic file replace, after
  the new tree passed the native security preflight, `--version` and `hosts`.
- Bindings use the OS folder paths, not the caller's environment, so an
  install from an SSH session without `SystemRoot` works.
- Superseded trees from this installer are removed, except the active tree
  and the previously active one. Locked leftovers only log a warning.

If this package cannot be activated but the previous PSC still works, the
installer exits 3: the previous PSC stays active and `psc-install.log` gets a
warning, with no dialog. Only when no working PSC exists does the installer
report a PSC failure (the gateway still installs). `psc-install.log` ends with
`PSC installer exit code: N`. The release workflow runs real installers in this
order: previous release, new, new again, new over a broken tree, previous over
new, new again (`tests/release/test_windows_psc_upgrade_native.py`).
Account, pins and hosts stay in separate state
directories. Gateway uninstall retains the independent PSC install and PATH
shim, just as it retains gateway private state.
