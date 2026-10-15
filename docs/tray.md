# PocketShell Gateway System Tray App

`pocketshell tray` is a lightweight, background system tray application (Windows and Linux) that runs like Dropbox or OneDrive in your system notification area. It provides real-time visibility into your PocketShell gateway connection, connected clients, and active aplexer sessions.

---

## 1. Installation

The tray application requires optional GUI dependencies (`Pillow` and `pystray`), packaged in the `tray` optional extra:

```bash
# Using uv tool install:
uv tool install "pocketshell[tray]"

# Or pip install into your environment:
pip install "pocketshell[tray]"
```

On Linux desktop environments, ensure standard X11 or Wayland libraries are available.

---

## 2. Running the Tray App

### Interactive launch

```bash
pocketshell tray
```

On Windows, to run without a command prompt window, launch using `pythonw`:

```powershell
pythonw -m pocketshell tray
```

Or run the built `PocketShellTray.exe` binary.

### Options

| Flag | Description |
|---|---|
| `--install-autostart` | Configure the tray app to start automatically at user login |
| `--remove-autostart` | Remove the tray app from user login autostart |
| `--poll-interval <sec>` | Polling frequency in seconds (default: `5.0`) |
| `--status-cmd <cmd>` | Override the default `pocketshell gateway status --json` query command |

---

## 3. Autostart at Login

You can configure autostart via CLI or through the tray context menu:

- **CLI setup**:
  ```bash
  pocketshell tray --install-autostart
  pocketshell tray --remove-autostart
  ```
- **Context Menu**:
  Click the tray icon and check/uncheck **Start at login**.

### Platform details:
- **Windows**: Stored under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with value name `PocketShellTray`, executing `pythonw -m pocketshell tray` with no console window.
- **Linux**: Stored at `~/.config/autostart/pocketshell-tray.desktop`.

---

## 4. Status States & Remediation

The tray icon displays a terminal glyph with a colored status dot. Hovering reveals the tooltip with a summary sentence and connection counts: `Summary (N connected · M sessions)`.

| State | Dot Color | Meaning | What to do |
|---|---|---|---|
| **Online** | **Green** | Gateway host agent is running and connected to the broker, and the local SSH server is reachable. | System is operational. Incoming connections are accepted. |
| **Degraded** | **Amber** | Gateway agent is connected to the broker, but the local loopback SSH server is unreachable. | Start your local SSH server: on Windows ordinary runtime, start the endpoint task `\PocketShell\GatewayEndpoint` or Windows OpenSSH service (`Start-Service sshd`); on Linux, run `systemctl start ssh` / `sshd`. |
| **Offline** | **Red** | Gateway host agent is not running or disconnected from the broker. | Start the gateway via tray menu: click **Start gateway**, or run `pocketshell gateway start`. |
| **Not Installed** | **Grey** | Machine is not enrolled in PocketShell gateway. | Enroll the machine first by running `pocketshell gateway enroll`. |
| **Error** | **Red** | Unable to poll gateway status or broken configuration. | Check the error description in the tooltip, or click **Open logs folder** to inspect daemon logs. |

---

## 5. Tray Menu Structure

Right-clicking (or left-clicking on Windows) the tray icon opens the context menu:

1. **`PocketShell: <State>`**: Displays the current status (disabled header).
2. **`Connected now (N)`**: Submenu listing all active SSH client sessions connected through the gateway:
   - Format: `<user> · <key comment or fingerprint> · <since>`
3. **`Sessions (M)`**: Submenu listing active aplexer sessions:
   - Format: `<name> · <engine> · <agent_state>`
4. **`Start gateway`**: Starts the gateway background service (enabled when offline/not installed/error).
5. **`Stop gateway`**: Stops the gateway background service (enabled when online/degraded).
6. **`Restart`**: Restarts the gateway agent and endpoint.
7. **`Open logs folder`**: Opens the PocketShell logs directory in Explorer (Windows) or the system file manager (Linux).
8. **`Copy device id`**: Copies the enrolled device ID to the system clipboard.
9. **`Start at login`**: Checkbox toggling autostart at user logon.
10. **`Quit tray`**: Closes the tray application (does **not** stop the background gateway service).

After **Sessions**, a **`Key policy: <policy>`** submenu shows which authorized
keys gateway SSH accepts on this host (key vault). See
[Gateway key policy](#gateway-key-policy).

### Gateway key policy

The submenu runs `pocketshell gateway auth show|set --json`, which wraps
`pocketshell-link gateway-auth` (pocketshell-gateway `70f5a4b` or later):

- **Host keys only**: `~/.ssh/authorized_keys`. This is the default, and an
  enrollment without a policy keeps it.
- **Vault keys only (managed)**: only the vault public keys installed on this host.
- **Host keys and vault keys**: both.

**Vault keys on this host** lists each managed key as type, `SHA256:`
fingerprint and comment, never key bytes. Vault public keys normally reach the
host from the web keys page or a client ("Apply to host"). The tray can also
import them from the clipboard or a file as authorized_keys lines. An import
replaces the whole managed set after confirmation. Private keys (anything
containing `PRIVATE KEY`), key options and certificates are refused before
anything runs. The host never sees a private key or the vault passphrase.

Refusals happen before the change and are explained:

- **Windows** gateways use a loopback SSH endpoint, which can only accept the
  host's own keys. The tray shows the policy as `host` and refuses vault-only,
  combined and managed-key imports. Enforcing them needs the private exec
  endpoint (Linux and macOS hosts).
- **Vault keys only** with no managed keys installed would refuse every login,
  so import keys first, or choose **Host keys and vault keys**.
- Removing every key while the policy is vault-only is refused for the same reason.

The helper validates everything again and fails closed. A change applies to the
next connection. The gateway never relays this setting, so an account token
alone cannot add a login key.

---

## 6. Notifications

The application delivers native system notifications (balloons):
- **State transitions**: When the gateway moves between states (e.g. `Offline` -> `Online`, or `Online` -> `Degraded`).
- **Client connections**: When a new remote user or key establishes an SSH connection through the gateway.
