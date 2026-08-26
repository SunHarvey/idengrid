#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Local')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Local')][string]$PackagePath,
    [Parameter(Mandatory=$true,ParameterSetName='Remote')][ValidatePattern('^https://')][string]$PackageUrl,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PackageSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$')][string]$Version
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
$ProgramRoot=Join-Path $env:ProgramFiles 'IdenGrid Edge'
$ProgramDataRoot=Join-Path $env:ProgramData 'IdenGrid\Edge'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated Windows PowerShell session.' }
}
function Assert-Sha256([string]$Path,[string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) { throw 'Package SHA256 verification failed.' }
}
function Expand-VerifiedBundle([string]$Archive,[string]$Destination) {
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\','/')
            if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains(':') -or $name.StartsWith('/') -or $name -match '(^|/)(\.|\.\.)(/|$)') { throw 'Bundle path contains an NTFS alternate data stream or unsafe path.' }
            $identity = $name.TrimEnd('/')
            if (-not $seen.Add($identity)) { throw 'Bundle ZIP contains a duplicate or case-colliding path.' }
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $entry.FullName.Replace('/','\')))
            if (-not $target.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'Bundle ZIP contains an unsafe path.' }
            if ([string]::IsNullOrEmpty($entry.Name)) { New-Item -ItemType Directory -Path $target -Force | Out-Null; continue }
            New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$target,$false)
        }
    } finally { $zip.Dispose() }
}
function Assert-BundleManifest([string]$Root,[string]$ExpectedVersion) {
    $manifestPath = Join-Path $Root 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Bundle manifest is missing.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.platform -ne 'windows' -or $manifest.architecture -ne 'x86_64' -or @($manifest.PSObject.Properties).Count -ne 5 -or $manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$' -or $manifest.files -isnot [array] -or @($manifest.files).Count -lt 1) { throw 'Bundle manifest is unsupported.' }
    if (-not [string]::IsNullOrEmpty($ExpectedVersion) -and $manifest.version -ne $ExpectedVersion) { throw 'Bundle version does not match the requested version.' }
    $listed = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $required = @('runtime/python.exe','bootstrap/register.py','service/IdenGridEdgeService.exe','service/IdenGridEdgeGateway.exe','service/IdenGridEdgeService.xml','service/IdenGridEdgeGateway.xml','templates/Caddyfile.template')
    foreach ($entry in $manifest.files) {
        if (@($entry.PSObject.Properties).Count -ne 3 -or $entry.path -isnot [string] -or [string]::IsNullOrWhiteSpace($entry.path) -or $entry.path.Equals('manifest.json',[StringComparison]::OrdinalIgnoreCase) -or $entry.path.Contains(':') -or $entry.path.Contains('\') -or $entry.path.StartsWith('/') -or $entry.path -match '(^|/)(\.\.|\.)($|/)' -or [IO.Path]::IsPathRooted($entry.path)) { throw 'Bundle path contains an NTFS alternate data stream or unsafe path.' }
        if (-not $listed.Add($entry.path)) { throw 'Bundle manifest contains a duplicate path.' }
        if (($entry.size -isnot [long] -and $entry.size -isnot [int]) -or [long]$entry.size -lt 0 -or [long]$entry.size -gt 8589934592) { throw 'Bundle manifest file size is invalid.' }
        if ($entry.sha256 -isnot [string] -or $entry.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Bundle manifest file SHA256 is malformed.' }
        $path = Join-Path $Root ($entry.path.Replace('/','\'))
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Bundle file is missing.' }
        if ((Get-Item -LiteralPath $path).Length -ne [long]$entry.size) { throw 'Bundle file size verification failed.' }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw 'Bundle file SHA256 verification failed.' }
    }
    foreach ($item in $required) { if (-not $listed.Contains($item)) { throw 'Bundle is missing a required file.' } }
    Get-ChildItem -LiteralPath $Root -File -Recurse | ForEach-Object {
        $relative=$_.FullName.Substring($Root.Length).TrimStart('\').Replace('\','/')
        if ($relative -ne 'manifest.json' -and -not $listed.Contains($relative)) { throw 'Bundle contains an unlisted file.' }
    }
    return $manifest
}
function Invoke-ServiceAction([string]$Wrapper,[string]$Action,[bool]$Required=$true) {
    & $Wrapper $Action
    if ($Required -and $LASTEXITCODE -ne 0) { throw "Service action failed: $Action" }
}
function Wait-EdgeHealth {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        try { if ((Invoke-WebRequest -Uri 'http://127.0.0.1:8787/healthz' -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { return } } catch { Start-Sleep -Seconds 1 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Loopback Edge health check failed.'
}
function Wait-PublicHealth([string]$HostName) {
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    $uri = 'https://' + $HostName + '/healthz'
    do {
        try { if ((Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { return } } catch { Start-Sleep -Seconds 2 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Public TLS Edge health check failed.'
}

Assert-Administrator
$current = Join-Path $ProgramRoot 'current'
if (-not (Test-Path -LiteralPath $current)) { throw 'IdenGrid Edge is not installed.' }
$oldTarget = [string](Get-Item -LiteralPath $current -Force).Target
if ([string]::IsNullOrWhiteSpace($oldTarget) -or -not (Test-Path -LiteralPath $oldTarget)) { throw 'Current version junction is invalid.' }
$newTarget = Join-Path (Join-Path $ProgramRoot 'versions') $Version
if (Test-Path -LiteralPath $newTarget) { throw 'The requested version directory already exists.' }
$statePath = Join-Path $ProgramDataRoot 'state\install-state.json'
if (-not (Test-Path -LiteralPath $statePath)) { throw 'Install state is missing.' }
$stateOriginal=[IO.File]::ReadAllBytes($statePath)
$publicHostname = [string](Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json).hostname
if ([string]::IsNullOrWhiteSpace($publicHostname)) { throw 'Install state hostname is missing.' }
$temp = Join-Path ([IO.Path]::GetTempPath()) ('idengrid-edge-upgrade-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$switched = $false
$oldMoved = $false
$upgradeSucceeded = $false
$previousBackup = Join-Path $ProgramRoot 'previous.backup'
$edgeWrapper = Join-Path $current 'service\IdenGridEdgeService.exe'
$gatewayWrapper = Join-Path $current 'service\IdenGridEdgeGateway.exe'
try {
    if ($PSCmdlet.ParameterSetName -eq 'Remote') {
        $uri = [Uri]$PackageUrl
        if ($uri.Scheme -ne 'https') { throw 'Package downloads require HTTPS.' }
        $bundle = Join-Path $temp 'bundle.zip'
        Invoke-WebRequest -Uri $uri -OutFile $bundle -UseBasicParsing
    } else { $bundle = (Resolve-Path -LiteralPath $PackagePath).Path }
    Assert-Sha256 $bundle $PackageSha256
    New-Item -ItemType Directory -Path $newTarget -Force | Out-Null
    Expand-VerifiedBundle $bundle $newTarget
    $bundleManifest=Assert-BundleManifest $newTarget $Version
    if ($bundleManifest.version -ne $Version) { throw 'Bundle version does not match the requested version.' }
    & (Join-Path $newTarget 'runtime\python.exe') -I -c 'import aiohttp, psutil, edge_tunnel'
    if ($LASTEXITCODE -ne 0) { throw 'Offline runtime self-check failed.' }
    & (Join-Path $newTarget 'runtime\python.exe') -I -m edge_tunnel --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Offline Edge CLI self-check failed.' }

    Invoke-ServiceAction $gatewayWrapper 'stop'
    Invoke-ServiceAction $edgeWrapper 'stop'
    $nextJunction = Join-Path $ProgramRoot 'current.next'
    $previous = Join-Path $ProgramRoot 'previous'
    if (Test-Path -LiteralPath $nextJunction) { Remove-Item -LiteralPath $nextJunction -Force }
    if (Test-Path -LiteralPath $previousBackup) { throw 'Stale previous backup requires operator attention.' }
    if (Test-Path -LiteralPath $previous) { Rename-Item -LiteralPath $previous -NewName 'previous.backup' }
    New-Item -ItemType Junction -Path $nextJunction -Target $newTarget | Out-Null
    Rename-Item -LiteralPath $current -NewName 'previous'
    $oldMoved = $true
    Rename-Item -LiteralPath $nextJunction -NewName 'current'
    $switched = $true

    $edgeWrapper = Join-Path $current 'service\IdenGridEdgeService.exe'
    $gatewayWrapper = Join-Path $current 'service\IdenGridEdgeGateway.exe'
    Invoke-ServiceAction $edgeWrapper 'start'
    Wait-EdgeHealth
    Invoke-ServiceAction $gatewayWrapper 'start'
    Wait-PublicHealth $publicHostname
    $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { New-Object psobject }
    $state | Add-Member -NotePropertyName version -NotePropertyValue $Version -Force
    $state | Add-Member -NotePropertyName upgraded_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    if (Test-Path -LiteralPath $previousBackup) { Remove-Item -LiteralPath $previousBackup -Force }
    $upgradeSucceeded=$true
    Write-Output "IdenGrid Edge upgraded to $Version."
} catch {
    $failure = $_.Exception.Message.Substring(0,[Math]::Min(300,$_.Exception.Message.Length))
    if ($oldMoved -and -not $switched -and (Test-Path -LiteralPath (Join-Path $ProgramRoot 'previous'))) {
        if (Test-Path -LiteralPath $current) { Remove-Item -LiteralPath $current -Force }
        Rename-Item -LiteralPath (Join-Path $ProgramRoot 'previous') -NewName 'current'
        $oldMoved = $false
        $edgeWrapper = Join-Path $current 'service\IdenGridEdgeService.exe'
        $gatewayWrapper = Join-Path $current 'service\IdenGridEdgeGateway.exe'
    }
    if ($switched) {
        # Rollback is junction-only: ProgramData config and Caddy ACME state are never replaced.
        try {
            & (Join-Path $current 'service\IdenGridEdgeGateway.exe') stop 2>$null
            & (Join-Path $current 'service\IdenGridEdgeService.exe') stop 2>$null
            Remove-Item -LiteralPath $current -Force
            Rename-Item -LiteralPath (Join-Path $ProgramRoot 'previous') -NewName 'current'
            $edgeWrapper = Join-Path $current 'service\IdenGridEdgeService.exe'
            $gatewayWrapper = Join-Path $current 'service\IdenGridEdgeGateway.exe'
            Invoke-ServiceAction $edgeWrapper 'start'
            Wait-EdgeHealth
            Invoke-ServiceAction $gatewayWrapper 'start'
            Wait-PublicHealth $publicHostname
        } catch { Write-Warning 'Rollback service recovery requires operator attention.' }
    } else {
        try { Invoke-ServiceAction $edgeWrapper 'start' $false; Wait-EdgeHealth; Invoke-ServiceAction $gatewayWrapper 'start' $false; Wait-PublicHealth $publicHostname } catch { Write-Warning 'Pre-switch service recovery requires operator attention.' }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $ProgramRoot 'previous')) -and (Test-Path -LiteralPath $previousBackup)) { Rename-Item -LiteralPath $previousBackup -NewName 'previous' }
    [IO.File]::WriteAllBytes($statePath,$stateOriginal)
    Write-Error ('Upgrade failed; rollback attempted: ' + $failure)
    throw
} finally {
    if (-not $upgradeSucceeded -and (Test-Path -LiteralPath $newTarget)) { Remove-Item -LiteralPath $newTarget -Recurse -Force }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
