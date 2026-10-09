<#
.SYNOPSIS
  CI ONLY (disposable windows-latest runner): prepare the Windows OpenSSH
  Server on 127.0.0.1:22 for tests/gateway/test_windows_gateway_e2e.py.

  Installs/enables the OpenSSH.Server capability, starts sshd, creates a
  throwaway ed25519 user key, authorizes it (administrators_authorized_keys,
  as the runner user is an administrator), builds a second venv under a
  path with a space and non-ASCII characters, and exports the
  POCKETSHELL_E2E_* variables via $GITHUB_ENV.

  NEVER run this on a developer laptop or a fleet machine: it changes
  machine-wide sshd state. Use scripts/windows-gateway-qualify.ps1 there.
#>
$ErrorActionPreference = 'Stop'
$PSNativeCommandArgumentPassing = 'Standard'

if (-not $env:GITHUB_ACTIONS) { throw 'refusing to run outside GitHub Actions' }

$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
$keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'

if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
  Write-Host 'Installing OpenSSH.Server capability'
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Host
}
Set-Service sshd -StartupType Manual
Start-Service sshd
$deadline = (Get-Date).AddSeconds(60)
while (-not (Test-NetConnection 127.0.0.1 -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
  if ((Get-Date) -gt $deadline) { throw 'sshd did not start listening on 22' }
  Start-Sleep -Seconds 1
}
& $ssh -V

$keyDir = Join-Path $env:RUNNER_TEMP 'ps-e2e-keys'
New-Item -ItemType Directory -Force $keyDir | Out-Null
$key = Join-Path $keyDir 'id_ed25519'
& $keygen -q -t ed25519 -N '' -C 'pocketshell-ci' -f $key
if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen failed' }
icacls.exe $key /inheritance:r /grant "$($env:USERNAME):F" | Out-Null

$ak = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
Get-Content "$key.pub" | Set-Content -Path $ak -Encoding ascii
icacls.exe $ak /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null

$hostPub = (Get-Content (Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub') -Raw).Trim()

# Sanity: plain ssh to sshd works before anything of ours is involved.
& $ssh -i $key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL `
  -o GlobalKnownHostsFile=NUL "$($env:USERNAME)@127.0.0.1" echo sshd-ok
if ($LASTEXITCODE -ne 0) { throw 'direct ssh to sshd failed' }

# A second interpreter under a path with a space and non-ASCII characters.
$spaceDir = Join-Path $env:RUNNER_TEMP 'py space Ünï'
$venv = Join-Path $spaceDir 'venv'
uv venv --python $env:pythonLocation\python.exe $venv
$req = Join-Path $env:RUNNER_TEMP 'ps-e2e-requirements.txt'
uv export --frozen --no-dev --extra link --no-hashes --no-emit-project -o $req
$py = Join-Path $venv 'Scripts\python.exe'
uv pip install --python $py -r $req
uv pip install --python $py --no-deps .
& $py -c 'import pocketshell, websockets, sys; print(sys.executable)'
if ($LASTEXITCODE -ne 0) { throw 'spaced venv is not usable' }

$lines = @(
  'POCKETSHELL_WINDOWS_E2E=1',
  "POCKETSHELL_E2E_SSH_USER=$($env:USERNAME)",
  "POCKETSHELL_E2E_SSH_KEY=$key",
  "POCKETSHELL_E2E_HOST_PUB=$hostPub",
  'POCKETSHELL_E2E_SSH_PORT=22',
  "POCKETSHELL_E2E_SPACE_PYTHON=$py"
)
$lines | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
Write-Host 'sshd ready'
