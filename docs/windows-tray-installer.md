# Windows gateway tray installer

The Windows x64 installer belongs to `pocketshell-cli`: the tray uses the CLI's
gateway status, enrollment and owner-bound guardian instead of embedding a
second gateway implementation in Desktop. It bundles Python, Pillow, pystray,
the reviewed gateway helper, BOTH `a.exe` and `aplexer.exe`, the native aplexer
client, the private OpenSSH endpoint and Git Bash. No Python, uv, Git or aplexer
installation is required on the destination, including win35.
The installer also includes the standalone PSC Windows x64 package (Node,
client and security helper). It runs that package's per-user protected installer
and adds `psc` to the user PATH, plus a **PSC Terminal** Start-menu shortcut.
Windows OpenSSH Client is required for PSC; profile paths with spaces refuse.
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
uv run --frozen python scripts/release/build_tray_installer.py --resources BASE --catalog-sha256 CATALOG_SHA256 --tray-launcher C:/BUILD/GatewayTray.exe --psc-zip C:/BUILD/psc-windows-x64-0.3.2.zip --psc-sha256 PSC_ZIP_SHA256 --makensis C:/NSIS/makensis.exe --out FRESH_OUTPUT
uv run --frozen --extra tray python -m pytest tests/tray tests/release/test_tray_installer.py tests/gateway/test_gateway_status.py
uv run --frozen python scripts/release/smoke_tray_bundle.py --payload FRESH_OUTPUT/payload --install-check FRESH_TEST_USER_DATA
```

The native smoke check registers a tray icon briefly, queries actual aplexer
sessions and installs a fresh endpoint closure with generated keys. It does
not bind, log in, enroll or start a gateway. The build emits an installer and
`installer-receipt.json` with source, input catalog and artifact hashes.
For unattended file installation, use `/S`; run Gateway Setup in the destination
user's interactive desktop afterwards. Browser approval and public-key selection
are intentional first-use steps.

Obtain the PSC zip and SHA256 from the reviewed pocketshell-tui-client release
or its Windows package workflow artifact. The tray builder validates the zip
hash, complete inventory, and individual payload hashes before staging it.
The receipt records the PSC zip SHA256, version and client/Core commits.
The standalone install procedure is documented in that repository's
`docs/windows-package.md`. No dependencies download on the destination.
PSC versions are installed in `%LOCALAPPDATA%\PocketShell\psc\<version>`;
reinstalling the identical package verifies and reuses that version. Changed
bytes or executable bindings require a fresh version. Account, pins and hosts stay in separate state
directories. Gateway uninstall retains the independent PSC install and PATH
shim, just as it retains gateway private state.
