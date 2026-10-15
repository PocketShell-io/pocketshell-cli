# pocketshell-link 70f5a4b Windows helper (key vault)

`pocketshell-link-windows-amd64.exe` is the Windows x64 host helper built from
pocketshell-gateway `70f5a4b9e8ee7461a7eedd8ebcfa18aefab90b9e` ("Add per-host
gateway auth policy to the host agent"), the first build with
`gateway-auth show|set`. sha256
`5672354b647d2ffddf7e69f753b90f1a031d9af7e57ca6d0c3ab002db28cedd8`,
8645120 bytes. `version --json` reports
`{"version":"git-70f5a4b9e8ee","protocol":"pocketshell-tunnel-v1","commit":"70f5a4b9e8ee7461a7eedd8ebcfa18aefab90b9e"}`.

Recipe (reproducible): clean checkout of that commit, Go 1.27.2,

```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=git-70f5a4b9e8ee -X main.commit=70f5a4b9e8ee7461a7eedd8ebcfa18aefab90b9e" \
  ./cmd/pocketshell-link
```

Two independent builds (key-vault W5 in pocketshell-gateway, W8 here)
produced identical bytes. The same recipe on cd7c6f6a0c7b reproduces the
previously allow-listed `f9582de6…dabe1`.

Pins: `service_windows.ALLOWED_HELPER_SHA256` (next to `f9582de6…`, which
stays so enrolled installs can be validated and repaired onto this build) and
`helper.WINDOWS_HELPER_SHA256`. `build_tray_installer.py --helper` replaces the
BASE closure's helper with this file after checking the digest.

Publication review (2026-10-15, `strings -n 6`, 21667 strings): no local or
user paths (`-trimpath`), no tokens, keys or credentials. Hosts embedded:
`gateway.pocketshell.io` (public gateway), `accounts.google.com`, the
production broker issuer `a7sota2qic.execute-api.eu-west-1.amazonaws.com`
(already public in this repo, `src/pocketshell/account/config.py`), plus Go
standard library references. Go symbol names include the private
`PocketShell-io/pocketshell-gateway` module paths, as in every helper already
shipped inside the public installer. Numeric dotted strings are ASN.1 OIDs.
