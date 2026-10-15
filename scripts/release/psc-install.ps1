param([Parameter(Mandatory = $true)][string]$SshPath,
      [ValidatePattern('^gateway-ssh[0-9]+$')][string]$InstallVariant = 'gateway-ssh10')
# PSC installer for the PocketShell Gateway tray installer (pocketshell-cli).
# It replaces the standalone package's install.ps1 (whose reviewed upstream
# digest the builder checks) with the same verification and native security
# preflight, plus one rule: re-running ANY installer over ANY existing PSC
# install succeeds.
#
# - Every version tree is content-addressed: <version>-<variant>-<content id>
#   (a digest of every installed file and the bundled ssh.exe, baked in at
#   build time). A tree that verifies completely is reused read-only.
# - Anything else (missing, partial, tampered, other bindings) is rebuilt in a
#   private staging directory and published with one directory rename. A
#   broken tree is moved aside first, or, if it is locked, a unique sibling
#   name is used.
# - The bin\psc.cmd shim is switched last, with an atomic file replace, and
#   only after the new tree passed every check.
# Exit codes: 0 = this package is active; 3 = this package could not be
# activated but the previous working PSC stays active (a warning, never a
# failure dialog); 1 = no working PSC.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
foreach ($module in @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security')) {
    Import-Module -Name "$PSHOME\Modules\$module\$module.psd1" -Force
}
$ContentId = '@CONTENT_ID@'
if ($ContentId -notmatch '^[0-9a-f]{12}$') { throw 'PSC installer was not configured with a content id' }

function Assert-PlainPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '[\s%"<>|?*]' -or $Path.Substring(2).Contains(':')) {
        throw "PSC requires a local absolute path without spaces or shell characters: $Path"
    }
    $cursor = $Path
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "PSC refuses redirected paths: $cursor" }
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
function Protect-Item([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "PSC refuses links: $Path" }
    if ($item.PSIsContainer) { $acl = [Security.AccessControl.DirectorySecurity]::new() }
    else { $acl = [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($owner, $system)) {
        # No inheritance flags: the helper requires explicit ACEs on private objects.
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    # PowerShell 5 Set-Acl may need SeSecurityPrivilege on protected objects;
    # the .NET method writes only the owner and DACL set above.
    $item.SetAccessControl($acl)
}

function Invoke-Security([string]$Tree, [hashtable]$Request) {
    # Use the tree's own Node and native authority for the exact protocol.
    # Base64 argv avoids PowerShell 5/7 native stdin encoding differences.
    $json = $Request | ConvertTo-Json -Compress
    $encoded = [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($json))
    & "$Tree\node.exe" "$Tree\psc\scripts\install-preflight.mjs" $encoded
    if ($LASTEXITCODE -ne 0) { throw 'PSC native security preflight refused' }
}

# The OS folders, not the caller's environment: an SSH session may lack
# SystemRoot or carry a forward-slash WINDIR. PSC binds these values.
$systemRoot = [Environment]::GetFolderPath('Windows')
$systemDrive = $systemRoot.Substring(0, 2)
$programData = [Environment]::GetFolderPath('CommonApplicationData')
$localAppData = [Environment]::GetFolderPath('LocalApplicationData')

$manifest = Get-Content -LiteralPath "$PSScriptRoot\package-manifest.json" -Raw | ConvertFrom-Json
if ($manifest.version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid PSC package version' }
$base = "$localAppData\PocketShell\psc"
$name = "$($manifest.version)-$InstallVariant-$ContentId"
$bin = "$base\bin"
$shim = "$bin\psc.cmd"
foreach ($p in @($env:USERPROFILE, $localAppData, $base, "$base\$name", $bin, $SshPath, $systemRoot, $programData)) { Assert-PlainPath $p }
if (!(Test-Path -LiteralPath $SshPath -PathType Leaf) -or (Split-Path -Leaf $SshPath) -ine 'ssh.exe') {
    throw 'Win32 OpenSSH ssh.exe is required.'
}
$installedNames = @(@($manifest.files.PSObject.Properties.Name | Where-Object { $_ -ne 'install.ps1' }) +
    'psc/dist/windows-bindings.json' + 'ssh.exe' | Sort-Object)

function Get-Bindings([string]$Tree) {
    $helper = "$Tree\psc-security.exe"; $node = "$Tree\node.exe"; $entry = "$Tree\psc\dist\cli.js"; $ssh = "$Tree\ssh.exe"
    return [ordered]@{
        version = 2; sshFamily = 'win32-openssh'
        helper = $helper; helperSha256 = (Get-FileHash $helper).Hash.ToLowerInvariant()
        ssh = $ssh; sshSha256 = (Get-FileHash $ssh).Hash.ToLowerInvariant()
        node = $node; nodeSha256 = (Get-FileHash $node).Hash.ToLowerInvariant()
        entry = $entry; entrySha256 = (Get-FileHash $entry).Hash.ToLowerInvariant()
        systemRoot = $systemRoot; systemDrive = $systemDrive; programData = $programData
    }
}

# A tree is reusable only if it is exactly this package: inventory, every
# digest, the bundled ssh.exe and its bindings. Any error means "not reusable".
function Test-Tree([string]$Tree) {
    try {
        if (!(Test-Path -LiteralPath $Tree -PathType Container)) { return $false }
        $actual = @(Get-ChildItem -LiteralPath $Tree -Recurse -File -Force | ForEach-Object {
            $_.FullName.Substring($Tree.Length + 1).Replace('\', '/')
        } | Where-Object { $_ -ne 'package-manifest.json' } | Sort-Object)
        if (Compare-Object $installedNames $actual) { return $false }
        foreach ($row in $manifest.files.PSObject.Properties) {
            if ($row.Name -eq 'install.ps1') { continue }
            if ((Get-FileHash -LiteralPath (Join-Path $Tree $row.Name)).Hash.ToLowerInvariant() -ne $row.Value) { return $false }
        }
        if ((Get-FileHash -LiteralPath "$Tree\ssh.exe").Hash -ne (Get-FileHash -LiteralPath $SshPath).Hash) { return $false }
        $existing = Get-Content -LiteralPath "$Tree\psc\dist\windows-bindings.json" -Raw | ConvertFrom-Json
        $expected = Get-Bindings $Tree
        if (@($existing.PSObject.Properties).Count -ne $expected.Count) { return $false }
        foreach ($key in $expected.Keys) { if ($existing.$key -cne $expected[$key]) { return $false } }
        return $true
    } catch {
        return $false
    }
}

# The tree the current shim runs, when it still has its entry points.
function Get-ActiveTree {
    try {
        if (!(Test-Path -LiteralPath $shim -PathType Leaf)) { return $null }
        $match = [regex]::Match((Get-Content -LiteralPath $shim -Raw), 'call "([^"]+)\\psc\.cmd"')
        if (!$match.Success) { return $null }
        $tree = $match.Groups[1].Value
        foreach ($f in @('psc.cmd', 'node.exe', 'psc\dist\cli.js')) {
            if (!(Test-Path -LiteralPath "$tree\$f" -PathType Leaf)) { return $null }
        }
        return $tree
    } catch {
        return $null
    }
}

function Remove-Quietly([string]$Path) {
    try { if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force } }
    catch { Write-Warning "Could not remove $Path (in use?); it is left in place: $($_.Exception.Message)" }
}

function Publish-Tree {
    # Choose the final name before building: bindings record absolute paths.
    $final = "$base\$name"
    if (Test-Path -LiteralPath $final) {
        $aside = "$base\.trash-$([guid]::NewGuid().ToString('N'))"
        try {
            Rename-Item -LiteralPath $final -NewName (Split-Path -Leaf $aside)
            Remove-Quietly $aside
        } catch {
            Write-Warning "The existing $name tree is not reusable and is in use; installing beside it."
            $final = "$base\$name-r$([guid]::NewGuid().ToString('N').Substring(0, 8))"
        }
    }
    $stage = "$base\.stage-$([guid]::NewGuid().ToString('N'))"
    try {
        New-Item -ItemType Directory -Path $stage | Out-Null
        Protect-Item $stage
        Copy-Item -LiteralPath "$PSScriptRoot\node.exe", "$PSScriptRoot\psc-security.exe", "$PSScriptRoot\psc.cmd",
            "$PSScriptRoot\NODE-LICENSE.txt", "$PSScriptRoot\package-manifest.json" -Destination $stage
        Copy-Item -LiteralPath "$PSScriptRoot\psc" -Destination $stage -Recurse
        # Inbox or bundled files can be hardlinked or carry ACLs rejected by the
        # helper. Copy, verify Microsoft's signature on the actual copy, then protect.
        Copy-Item -LiteralPath $SshPath -Destination "$stage\ssh.exe"
        $signature = Get-AuthenticodeSignature -LiteralPath "$stage\ssh.exe"
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') {
            throw 'PSC requires a valid Microsoft-signed Win32 OpenSSH client'
        }
        # Bindings name the published paths; the digests are of the staged bytes.
        $bindings = Get-Bindings $stage
        foreach ($key in @('helper', 'ssh', 'node', 'entry')) { $bindings[$key] = $bindings[$key].Replace($stage, $final) }
        [IO.File]::WriteAllText("$stage\psc\dist\windows-bindings.json", ($bindings | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        Get-ChildItem -LiteralPath $stage -Recurse -Force | ForEach-Object { Protect-Item $_.FullName }
        # One rename publishes the complete tree.
        Rename-Item -LiteralPath $stage -NewName (Split-Path -Leaf $final)
    } catch {
        Remove-Quietly $stage
        throw
    }
    if (!(Test-Tree $final)) { Remove-Quietly $final; throw 'The published PSC tree did not verify' }
    return $final
}

function Set-Shim([string]$Tree) {
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    Protect-Item $bin
    $text = "@echo off`r`ncall `"$Tree\psc.cmd`" %*`r`nexit /b %errorlevel%`r`n"
    if ((Test-Path -LiteralPath $shim -PathType Leaf) -and (Get-Content -LiteralPath $shim -Raw) -ceq $text) { return }
    $next = "$bin\.psc.cmd.$([guid]::NewGuid().ToString('N'))"
    [IO.File]::WriteAllText($next, $text, [Text.UTF8Encoding]::new($false))
    Protect-Item $next
    if (Test-Path -LiteralPath $shim) { [IO.File]::Replace($next, $shim, [NullString]::Value) }
    else { [IO.File]::Move($next, $shim) }
}

function Update-UserPath {
    $oldPath = [string][Environment]::GetEnvironmentVariable('Path', 'User')
    if ($bin -notin ($oldPath -split ';')) {
        try { [Environment]::SetEnvironmentVariable('Path', (($oldPath.TrimEnd(';') + ';' + $bin).TrimStart(';')), 'User') }
        catch [System.Security.SecurityException] { Write-Warning 'User PATH is read-only. Launch PSC Terminal from the Start menu.' }
    }
    $env:Path = "$bin;$env:Path"
    try {
        # Explorer refreshes its environment for subsequently opened terminals.
        if (!(('PscEnvironmentNotify' -as [type]))) {
            Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class PscEnvironmentNotify {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg,
        UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
}
'@
        }
        $notification = [UIntPtr]::Zero
        [void][PscEnvironmentNotify]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$notification)
    } catch {
        Write-Warning "Could not notify Explorer of the PATH change: $($_.Exception.Message)"
    }
}

# Remove only our own superseded content-addressed trees and leftovers;
# keep the active tree and the one the previous shim ran.
function Remove-Superseded([string]$Active, [string]$Previous) {
    Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match "^(\d+\.\d+\.\d+-$InstallVariant-[0-9a-f]{12}(-r[0-9a-f]{8})?|\.stage-[0-9a-f]{32}|\.trash-[0-9a-f]{32})$" -and
        $_.FullName -ne $Active -and $_.FullName -ne $Previous
    } | ForEach-Object { Remove-Quietly $_.FullName }
}

$previous = Get-ActiveTree
try {
    New-Item -ItemType Directory -Path $base -Force | Out-Null
    # The package itself must be complete and exact before anything is published.
    $expected = @($manifest.files.PSObject.Properties.Name) | Sort-Object
    $actual = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File | ForEach-Object {
        $_.FullName.Substring($PSScriptRoot.Length + 1).Replace('\', '/')
    } | Where-Object { $_ -ne 'package-manifest.json' }) | Sort-Object
    if (Compare-Object $expected $actual) { throw 'PSC package file inventory differs' }
    foreach ($row in $manifest.files.PSObject.Properties) {
        if ($row.Name -match '(^/|(^|/)\.\.(/|$)|:|\\)') { throw 'Unsafe package member' }
        if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $row.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $row.Value) {
            throw "PSC payload hash differs: $($row.Name)"
        }
    }
    $tree = Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "^$([regex]::Escape($name))(-r[0-9a-f]{8})?$" -and (Test-Tree $_.FullName) } |
        Select-Object -First 1 -ExpandProperty FullName
    if ($tree) { Write-Host "Reusing verified PSC tree $tree" }
    else { $tree = Publish-Tree; Write-Host "Installed PSC tree $tree" }
    # Native preflight creates private state without changing existing state ACLs.
    foreach ($root in @("$localAppData\PocketShell\pocketshell-client", "$localAppData\PocketShell\pocketshell-client-account", "$localAppData\PocketShell\pocketshell-client-runtime")) {
        Invoke-Security $tree @{version=1; op='preflight'; root=$root}
    }
    foreach ($path in @("$tree\node.exe", "$tree\psc\dist\cli.js", "$tree\ssh.exe")) {
        Invoke-Security $tree @{version=1; op='check-executable'; root=$tree; path=$path}
    }
    & "$tree\node.exe" "$tree\psc\dist\cli.js" --version
    if ($LASTEXITCODE -ne 0) { throw 'PSC installed version check failed' }
    & "$tree\node.exe" "$tree\psc\dist\cli.js" hosts
    if ($LASTEXITCODE -ne 0) { throw 'PSC installed hosts check failed' }
    Set-Shim $tree
    Update-UserPath
    Remove-Superseded $tree $previous
    Write-Host "PSC installed. Open a new terminal, then run psc login and psc hosts sync. Shim: $shim"
    exit 0
} catch {
    $reason = $_.Exception.Message
    if ($previous -and (Get-ActiveTree) -eq $previous) {
        Write-Warning "PSC $($manifest.version) was not activated ($reason). The previous PSC stays active: $previous"
        exit 3
    }
    Write-Error "PSC installation failed: $reason" -ErrorAction Continue
    exit 1
}
