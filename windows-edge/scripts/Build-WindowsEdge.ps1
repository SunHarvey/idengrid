#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$')][string]$Version,
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..\manifests\windows-x64-runtime.json'),
    [string]$SourceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Net.Http
$ApprovedRuntimeManifestSha256 = 'b339fe8f1e701a1e4b4eb9aa4f42307dbcaa9c324b5fa08afc9772ad5ca3411f'

function Assert-HttpsUri([string]$Value) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') {
        throw 'Runtime manifest contains a non-HTTPS URL.'
    }
}
function Assert-Sha256([string]$Path, [string]$Expected) {
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') { throw 'Expected SHA256 is malformed.' }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) { throw "SHA256 verification failed for $([IO.Path]::GetFileName($Path))." }
}
function Invoke-HttpsDownload([string]$Uri,[string]$Destination) {
    $handler=New-Object Net.Http.HttpClientHandler; $handler.AllowAutoRedirect=$true
    $client=New-Object Net.Http.HttpClient -ArgumentList (,$handler)
    try {
        $response=$client.GetAsync($Uri).GetAwaiter().GetResult()
        $ResponseUri=$response.RequestMessage.RequestUri
        if (-not $response.IsSuccessStatusCode -or $ResponseUri.Scheme -ne 'https') { throw 'Artifact download failed or redirected away from HTTPS.' }
        $input=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult(); $output=[IO.File]::Create($Destination)
        try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    } finally { $client.Dispose(); $handler.Dispose() }
}
function Expand-SafeZip([string]$Archive, [string]$Destination) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $root=[IO.Path]::GetFullPath($Destination).TrimEnd('\')+'\'
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $zip=[IO.Compression.ZipFile]::OpenRead($Archive)
    try { foreach($entry in $zip.Entries) {
        $name=$entry.FullName.Replace('\','/')
        if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains(':') -or $name.StartsWith('/') -or $name -match '(^|/)(\.|\.\.)(/|$)' -or -not $seen.Add($name.TrimEnd('/'))) { throw 'Runtime ZIP contains an unsafe or duplicate path.' }
        $target=[IO.Path]::GetFullPath((Join-Path $Destination $name.Replace('/','\')))
        if (-not $target.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'Runtime ZIP contains an unsafe path.' }
        if ([string]::IsNullOrEmpty($entry.Name)) { New-Item -ItemType Directory -Path $target -Force | Out-Null; continue }
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force | Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$target,$false)
    }} finally { $zip.Dispose() }
}
function Assert-RuntimeManifestSchema($Manifest) {
    $fail='runtime manifest schema validation failed'
    if ($Manifest -isnot [pscustomobject] -or @($Manifest.PSObject.Properties).Count -ne 4 -or $Manifest.schema_version -ne 1 -or $Manifest.platform -ne 'windows' -or $Manifest.architecture -ne 'x86_64' -or $Manifest.artifacts -isnot [array] -or @($Manifest.artifacts).Count -lt 1) { throw $fail }
    $names=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase); $files=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($artifact in $Manifest.artifacts) {
        if ($artifact -isnot [pscustomobject] -or @($artifact.PSObject.Properties).Count -ne 6 -or $artifact.name -isnot [string] -or $artifact.name -notmatch '^[a-z0-9_-]+$' -or $artifact.kind -notin @('cpython','wheel','caddy','winsw') -or $artifact.version -isnot [string] -or [string]::IsNullOrEmpty($artifact.version) -or $artifact.filename -isnot [string] -or $artifact.filename -notmatch '^[A-Za-z0-9_.+-]+$' -or [IO.Path]::GetFileName($artifact.filename) -ne $artifact.filename -or $artifact.url -isnot [string] -or $artifact.sha256 -isnot [string] -or $artifact.sha256 -notmatch '^[0-9a-f]{64}$' -or -not $names.Add($artifact.name) -or -not $files.Add($artifact.filename)) { throw $fail }
        Assert-HttpsUri $artifact.url
    }
    foreach($kind in @('cpython','caddy','winsw')) { if (@($Manifest.artifacts | Where-Object kind -eq $kind).Count -ne 1) { throw $fail } }
}
function Write-ReproducibleZip([string]$Source, [string]$Destination) {
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Force }
    $stream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew)
    try {
        $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            Get-ChildItem -LiteralPath $Source -File -Recurse | Sort-Object FullName | ForEach-Object {
                $relative = $_.FullName.Substring($Source.Length).TrimStart('\').Replace('\','/')
                $entry = $zip.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [DateTimeOffset]::Parse('2000-01-01T00:00:00Z')
                $input = [IO.File]::OpenRead($_.FullName)
                $output = $entry.Open()
                try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
}

$manifestDigest=(Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($manifestDigest -ne $ApprovedRuntimeManifestSha256) { throw 'Runtime manifest is not on the production allowlist.' }
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
Assert-RuntimeManifestSchema $manifest
$work = Join-Path ([IO.Path]::GetTempPath()) ('idengrid-edge-build-' + [Guid]::NewGuid().ToString('N'))
$downloads = Join-Path $work 'downloads'
$stage = Join-Path $work ('IdenGrid-Edge-' + $Version)
$runtime = Join-Path $stage 'runtime'
$sitePackages = Join-Path $runtime 'Lib\site-packages'
New-Item -ItemType Directory -Path $downloads,$runtime,$sitePackages,(Join-Path $stage 'app'),(Join-Path $stage 'bootstrap'),(Join-Path $stage 'gateway'),(Join-Path $stage 'service'),(Join-Path $stage 'scripts'),(Join-Path $stage 'templates') -Force | Out-Null
try {
    foreach ($artifact in $manifest.artifacts) {
        Assert-HttpsUri $artifact.url
        if ($artifact.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Runtime manifest contains a malformed SHA256.' }
        $target = Join-Path $downloads $artifact.filename
        Invoke-HttpsDownload $artifact.url $target
        Assert-Sha256 $target $artifact.sha256
        switch ($artifact.kind) {
            'cpython' { Expand-SafeZip $target $runtime }
            'wheel'   { Expand-SafeZip $target $sitePackages }
            'caddy'   {
                $caddyExtract = Join-Path $work 'caddy'
                Expand-SafeZip $target $caddyExtract
                Copy-Item -LiteralPath (Join-Path $caddyExtract 'caddy.exe') -Destination (Join-Path $stage 'gateway\caddy.exe')
            }
            'winsw'   {
                Copy-Item -LiteralPath $target -Destination (Join-Path $stage 'service\IdenGridEdgeService.exe')
                Copy-Item -LiteralPath $target -Destination (Join-Path $stage 'service\IdenGridEdgeGateway.exe')
            }
            default { throw 'Runtime manifest contains an unsupported artifact kind.' }
        }
    }
    @('python311.zip','.','Lib\site-packages','..\app') | Set-Content -LiteralPath (Join-Path $runtime 'python311._pth') -Encoding ASCII
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'edge-tunnel\edge_tunnel') -Destination (Join-Path $stage 'app\edge_tunnel') -Recurse
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'windows-edge\bootstrap\register.py') -Destination (Join-Path $stage 'bootstrap\register.py')
    Copy-Item -Path (Join-Path $SourceRoot 'windows-edge\service\*') -Destination (Join-Path $stage 'service') -Force
    Copy-Item -Path (Join-Path $SourceRoot 'windows-edge\scripts\*') -Destination (Join-Path $stage 'scripts') -Force
    Copy-Item -Path (Join-Path $SourceRoot 'windows-edge\templates\*') -Destination (Join-Path $stage 'templates') -Force
    Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $stage 'runtime-manifest.json')
    @"
IdenGrid Edge Windows bundle third-party components are pinned in runtime-manifest.json.
CPython: Python Software Foundation License; aiohttp and dependencies: their respective licenses;
Caddy: Apache-2.0; WinSW: MIT; psutil: BSD-3-Clause.
Distributors must review and include upstream license texts before external release.
"@ | Set-Content -LiteralPath (Join-Path $stage 'THIRD_PARTY_NOTICES.txt') -Encoding UTF8

    $python = Join-Path $runtime 'python.exe'
    & $python -I -c 'import aiohttp, cryptography, psutil, edge_tunnel; print("runtime import check passed")'
    if ($LASTEXITCODE -ne 0) { throw 'Bundled Python import check failed.' }
    & $python -I -m edge_tunnel --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Bundled Edge CLI check failed.' }

    $entries = @()
    Get-ChildItem -LiteralPath $stage -File -Recurse | Where-Object Name -ne 'manifest.json' | Sort-Object FullName | ForEach-Object {
        $entries += [pscustomobject][ordered]@{ path=$_.FullName.Substring($stage.Length).TrimStart('\').Replace('\','/'); size=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    [pscustomobject][ordered]@{ schema_version=1; version=$Version; platform='windows'; architecture='x86_64'; files=$entries } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding UTF8

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $zipName = "IdenGrid-Edge-Windows-Server-2025-x64-v$Version.zip"
    $zipPath = Join-Path $OutputDirectory $zipName
    $validator = Join-Path $SourceRoot 'scripts\build_windows_edge_package.py'
    if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) { throw 'Package validator is unavailable.' }
    & $python -I $validator --source $stage --output $zipPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Package allowlist validation failed.' }
    Write-Output $zipPath
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
