param(
    [string]$ApiBaseUrl = $env:IDENGRID_API_BASE_URL,
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimePath,
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimeManifestPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedRuntimeManifestSha256,
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimeArchivePath,
    [Parameter(Mandatory = $true)]
    [string]$MediaGateResultPath,
    [switch]$BraveAdBlockOnlyMode,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "artifacts\IdenGrid.Windows")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($ApiBaseUrl)) {
    throw "Set IDENGRID_API_BASE_URL to the HTTPS control origin."
}

$origin = [Uri]$ApiBaseUrl
if (-not $origin.IsAbsoluteUri -or $origin.Scheme -ne "https" -or -not [string]::IsNullOrEmpty($origin.UserInfo) -or -not [string]::IsNullOrEmpty($origin.Query) -or -not [string]::IsNullOrEmpty($origin.Fragment)) {
    throw "IDENGRID_API_BASE_URL must be an HTTPS origin without credentials, query, or fragment."
}

$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$outputParent = Split-Path -Parent $output
$outputLeaf = Split-Path -Leaf $output
if ([string]::IsNullOrWhiteSpace($outputLeaf)) {
    throw "OutputDirectory must name a directory."
}
New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
$nonce = [Guid]::NewGuid().ToString("N")
$stagingOutput = Join-Path $outputParent ($outputLeaf + ".staging-" + $nonce)
$backupOutput = Join-Path $outputParent ($outputLeaf + ".backup-" + $nonce)
$tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("idengrid-build-" + $nonce)
$configPath = Join-Path $tempDirectory "client-config.json"
$oldOutputMoved = $false
$promotionComplete = $false

try {
    $runtimeValidator = Join-Path $PSScriptRoot "Test-IdenGridBrowserRuntimeManifest.ps1"
    $browserRuntime = & $runtimeValidator `
        -BrowserRuntimePath $BrowserRuntimePath `
        -BrowserRuntimeManifestPath $BrowserRuntimeManifestPath `
        -ExpectedRuntimeManifestSha256 $ExpectedRuntimeManifestSha256 `
        -BrowserRuntimeArchivePath $BrowserRuntimeArchivePath `
        -MediaGateResultPath $MediaGateResultPath

    New-Item -ItemType Directory -Path $tempDirectory | Out-Null
    New-Item -ItemType Directory -Path $stagingOutput | Out-Null
    $configJson = @{
        api_base_url = $origin.AbsoluteUri
        brave_ad_block_only_mode = [bool]$BraveAdBlockOnlyMode
    } | ConvertTo-Json -Compress
    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($configPath, $configJson, $utf8NoBom)

    dotnet publish (Join-Path $PSScriptRoot "src\IdenGrid.Windows.Wpf\IdenGrid.Windows.Wpf.csproj") `
        -c Release `
        -r win-x64 `
        --self-contained true `
        -p:DebugType=None `
        -p:DebugSymbols=false `
        -p:ClientConfigPath=$configPath `
        -o $stagingOutput
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed with exit code $LASTEXITCODE."
    }

    $browserDestination = Join-Path $stagingOutput "Components\Browser"
    New-Item -ItemType Directory -Path $browserDestination | Out-Null
    Get-ChildItem -LiteralPath $browserRuntime.RuntimePath -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $browserDestination -Recurse -Force
    }
    # Revalidate the complete copied tree to close the gap between validating
    # the mutable source directory and packaging it after dotnet publish.
    $packagedBrowserRuntime = & $runtimeValidator `
        -BrowserRuntimePath $browserDestination `
        -BrowserRuntimeManifestPath $BrowserRuntimeManifestPath `
        -ExpectedRuntimeManifestSha256 $ExpectedRuntimeManifestSha256 `
        -BrowserRuntimeArchivePath $BrowserRuntimeArchivePath `
        -MediaGateResultPath $MediaGateResultPath
    Copy-Item -LiteralPath $browserRuntime.ManifestPath -Destination (Join-Path $browserDestination "idengrid-runtime-manifest.json") -Force
    $packagedExecutableHash = ([string](Get-FileHash -LiteralPath (Join-Path $browserDestination "brave.exe") -Algorithm SHA256).Hash).ToLowerInvariant()
    if ($packagedExecutableHash -ne $browserRuntime.RuntimeExecutableSha256 -or
        $packagedExecutableHash -ne $packagedBrowserRuntime.RuntimeExecutableSha256) {
        throw "Packaged browser executable changed after provenance validation."
    }
    $packagedManifestHash = ([string](Get-FileHash -LiteralPath (Join-Path $browserDestination "idengrid-runtime-manifest.json") -Algorithm SHA256).Hash).ToLowerInvariant()
    if ($packagedManifestHash -ne $browserRuntime.ManifestSha256) {
        throw "Packaged browser manifest changed after provenance validation."
    }

    # Fail closed: portable output must never contain mutable identity state,
    # credentials, private keys, logs, crash dumps, or debug diagnostics.
    $forbiddenPatterns = @(
        "Cookies", "Cookies-journal", "Login Data", "Login Data-journal",
        "Web Data", "Web Data-journal", "History", "History-journal",
        "Visited Links", "Local State", "Preferences", "Secure Preferences",
        "Network Persistent State", "TransportSecurity", "*.log", "*.dmp",
        "*.mdmp", "*.pma", "*.etl", "*.pdb", "*.pem", "*.key", "*.pfx", "*.p12"
    )
    $forbidden = New-Object System.Collections.Generic.List[string]
    foreach ($item in Get-ChildItem -LiteralPath $stagingOutput -Recurse -Force) {
        $relative = $item.FullName.Substring($stagingOutput.Length).TrimStart('\', '/')
        if ($item.PSIsContainer) {
            if ($item.Name -match '^(?i:User Data|Default|Guest Profile|System Profile|Profile [0-9]+|Crash Reports|Diagnostics?|Logs?)$') {
                $forbidden.Add($relative)
            }
            continue
        }
        $matchesPattern = $false
        foreach ($pattern in $forbiddenPatterns) {
            if ($item.Name -like $pattern) { $matchesPattern = $true; break }
        }
        if ($matchesPattern -or $item.Name -match '(?i)(^|[._-])(access[_-]?token|refresh[_-]?token|token|secret)([._-]|$)') {
            $forbidden.Add($relative)
        }
    }
    if ($forbidden.Count -gt 0) {
        throw "Portable output contains forbidden private or diagnostic artifacts: $($forbidden -join ', ')"
    }

    if (Test-Path -LiteralPath $output) {
        Move-Item -LiteralPath $output -Destination $backupOutput
        $oldOutputMoved = $true
    }
    try {
        Move-Item -LiteralPath $stagingOutput -Destination $output
        $promotionComplete = $true
    }
    catch {
        if ($oldOutputMoved -and -not (Test-Path -LiteralPath $output) -and (Test-Path -LiteralPath $backupOutput)) {
            Move-Item -LiteralPath $backupOutput -Destination $output
            $oldOutputMoved = $false
        }
        throw
    }

    if ($oldOutputMoved) {
        # Promotion is already committed. A locked stale backup must not turn a
        # successful build into a failure that implies the old output was restored.
        Remove-Item -LiteralPath $backupOutput -Recurse -Force -ErrorAction SilentlyContinue
        $oldOutputMoved = $false
    }
}
finally {
    Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stagingOutput -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $promotionComplete -and $oldOutputMoved -and -not (Test-Path -LiteralPath $output) -and (Test-Path -LiteralPath $backupOutput)) {
        Move-Item -LiteralPath $backupOutput -Destination $output -ErrorAction SilentlyContinue
    }
}
