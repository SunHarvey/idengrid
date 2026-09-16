param(
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimePath,
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimeManifestPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedRuntimeManifestSha256,
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimeArchivePath,
    [Parameter(Mandatory = $true)]
    [string]$MediaGateResultPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-NormalizedSha256([string]$Path) {
    return ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToLowerInvariant()
}

function Test-RuntimeRelativePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains('\') -or
        [System.IO.Path]::IsPathRooted($Path) -or
        $Path.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) {
        return $false
    }
    foreach ($segment in $Path.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -eq "." -or
            $segment -eq ".." -or
            $segment.EndsWith(".") -or
            $segment.EndsWith(" ") -or
            $segment -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$' -or
            $segment.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            return $false
        }
    }
    return $true
}

$runtime = [System.IO.Path]::GetFullPath($BrowserRuntimePath)
$manifestPath = [System.IO.Path]::GetFullPath($BrowserRuntimeManifestPath)
$archivePath = [System.IO.Path]::GetFullPath($BrowserRuntimeArchivePath)
$gatePath = [System.IO.Path]::GetFullPath($MediaGateResultPath)
if (-not (Test-Path -LiteralPath $runtime -PathType Container)) {
    throw "Browser runtime directory does not exist."
}
foreach ($requiredFile in @($manifestPath, $archivePath, $gatePath)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required browser provenance file does not exist: $requiredFile"
    }
}

$manifestHash = Get-NormalizedSha256 $manifestPath
if ($ExpectedRuntimeManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
    throw "ExpectedRuntimeManifestSha256 must be a SHA-256 hex digest."
}
if ($manifestHash -ne $ExpectedRuntimeManifestSha256.ToLowerInvariant()) {
    throw "Browser runtime manifest SHA-256 does not match ExpectedRuntimeManifestSha256."
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($field in "runtime_id", "source_revision", "archive_sha256", "distribution_review_reference", "browser_executable", "browser_executable_sha256") {
    if ([string]::IsNullOrWhiteSpace([string]$manifest.$field)) {
        throw "Browser runtime manifest is missing $field."
    }
}
foreach ($hashField in "archive_sha256", "browser_executable_sha256") {
    if ([string]$manifest.$hashField -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "Browser runtime manifest $hashField must be a SHA-256 hex digest."
    }
}

if ($manifest.PSObject.Properties.Name -notcontains "runtime_files") {
    throw "Browser runtime manifest is missing runtime_files."
}
$runtimeFiles = @($manifest.runtime_files)
if ($runtimeFiles.Count -eq 0) {
    throw "Browser runtime manifest runtime_files must not be empty."
}
$declaredFiles = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $runtimeFiles) {
    if ($null -eq $entry -or
        $entry.PSObject.Properties.Name -notcontains "path" -or
        $entry.PSObject.Properties.Name -notcontains "size" -or
        $entry.PSObject.Properties.Name -notcontains "sha256") {
        throw "Browser runtime manifest runtime_files entries require path, size, and sha256."
    }
    $relativePath = [string]$entry.path
    if (-not (Test-RuntimeRelativePath $relativePath)) {
        throw "Browser runtime manifest runtime_files contains an invalid relative path: $relativePath"
    }
    if ($relativePath.Equals("idengrid-runtime-manifest.json", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Browser runtime manifest must remain outside the runtime file inventory."
    }
    if ($declaredFiles.ContainsKey($relativePath)) {
        throw "Browser runtime manifest runtime_files contains a duplicate path: $relativePath"
    }
    $declaredSize = 0L
    $sizeText = [Convert]::ToString($entry.size, [Globalization.CultureInfo]::InvariantCulture)
    if (-not [int64]::TryParse(
        $sizeText,
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$declaredSize) -or $declaredSize -lt 0) {
        throw "Browser runtime manifest runtime_files size must be a non-negative integer: $relativePath"
    }
    if ([string]$entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "Browser runtime manifest runtime_files sha256 must be a SHA-256 hex digest: $relativePath"
    }
    $declaredFiles.Add($relativePath, [pscustomobject]@{
        Size = $declaredSize
        Sha256 = ([string]$entry.sha256).ToLowerInvariant()
    })
}

$actualFiles = New-Object 'System.Collections.Generic.Dictionary[string,System.IO.FileInfo]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($file in Get-ChildItem -LiteralPath $runtime -File -Recurse -Force) {
    $relativePath = $file.FullName.Substring($runtime.Length).TrimStart('\', '/').Replace('\', '/')
    if ($actualFiles.ContainsKey($relativePath)) {
        throw "Browser runtime contains a duplicate path: $relativePath"
    }
    $actualFiles.Add($relativePath, $file)
}
if ($actualFiles.Count -ne $declaredFiles.Count) {
    throw "Browser runtime file set does not match runtime_files."
}
foreach ($relativePath in $declaredFiles.Keys) {
    if (-not $actualFiles.ContainsKey($relativePath)) {
        throw "Browser runtime file set does not match runtime_files: $relativePath"
    }
    $expected = $declaredFiles[$relativePath]
    $actual = $actualFiles[$relativePath]
    if ($actual.Length -ne $expected.Size) {
        throw "Browser runtime file size does not match runtime_files: $relativePath"
    }
    if ((Get-NormalizedSha256 $actual.FullName) -ne $expected.Sha256) {
        throw "Browser runtime file SHA-256 does not match runtime_files: $relativePath"
    }
}

$actualArchiveHash = Get-NormalizedSha256 $archivePath
if ($actualArchiveHash -ne ([string]$manifest.archive_sha256).ToLowerInvariant()) {
    throw "Browser source archive SHA-256 does not match archive_sha256."
}

$browserExecutable = [string]$manifest.browser_executable
if ([System.IO.Path]::GetFileName($browserExecutable) -ne $browserExecutable -or
    -not $browserExecutable.Equals("brave.exe", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Browser runtime manifest browser_executable must be the original brave.exe file name."
}
$runtimeExecutable = Join-Path $runtime $browserExecutable
if (-not (Test-Path -LiteralPath $runtimeExecutable -PathType Leaf)) {
    throw "Browser runtime does not contain the declared browser executable."
}
$actualExecutableHash = Get-NormalizedSha256 $runtimeExecutable
if ($actualExecutableHash -ne ([string]$manifest.browser_executable_sha256).ToLowerInvariant()) {
    throw "Browser executable SHA-256 does not match browser_executable_sha256."
}

$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($runtimeExecutable)
if (-not ([string]$version.OriginalFilename).Equals("brave.exe", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Browser executable OriginalFilename is not brave.exe."
}
if ([string]::IsNullOrWhiteSpace([string]$version.ProductName) -or [string]$version.ProductName -notmatch '(?i)^Brave(?: Browser)?$') {
    throw "Browser executable ProductName is not Brave."
}

$signature = Get-AuthenticodeSignature -LiteralPath $runtimeExecutable
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
    throw "Browser executable must have a valid Authenticode signature."
}
$signerSubject = [string]$signature.SignerCertificate.Subject
$signerName = $signature.SignerCertificate.GetNameInfo(
    [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
    $false)
if (-not $signerName.Equals("Brave Software, Inc.", [StringComparison]::Ordinal) -or
    $signerSubject -notmatch '(?i)Brave Software(?:\\,|,) Inc\.') {
    throw "Browser executable Authenticode signer must be Brave Software, Inc."
}

$gate = Get-Content -LiteralPath $gatePath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($gate.passed -ne $true) {
    throw "External browser media gate did not pass."
}
if ([string]$gate.browser_executable_sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
    ([string]$gate.browser_executable_sha256).ToLowerInvariant() -ne $actualExecutableHash) {
    throw "Media gate result is not bound to this browser executable."
}
if ([string]$gate.runtime_manifest_sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
    ([string]$gate.runtime_manifest_sha256).ToLowerInvariant() -ne $manifestHash) {
    throw "Media gate result is not bound to this runtime manifest."
}
if ($null -eq $gate.active_session -or [string]$gate.active_session.state -ne "Active" -or
    [string]$gate.active_session.protocol -notin @("Console", "RDP") -or
    [string]::IsNullOrWhiteSpace([string]$gate.active_session.user)) {
    throw "Media gate result does not identify an active console/RDP session."
}
if ($null -eq $gate.fixture -or ([string]$gate.fixture.url -notmatch '^https://') -or
    [double]$gate.fixture.current_time_seconds -le 1 -or
    [int64]$gate.fixture.total_video_frames -le 0 -or
    [int64]$gate.fixture.decoded_aac_bytes -le 0) {
    throw "Media gate result lacks decoded H.264/AAC fixture evidence."
}

[pscustomobject]@{
    RuntimePath = $runtime
    ManifestPath = $manifestPath
    ArchivePath = $archivePath
    MediaGateResultPath = $gatePath
    RuntimeId = [string]$manifest.runtime_id
    SourceRevision = [string]$manifest.source_revision
    RuntimeExecutable = $runtimeExecutable
    RuntimeExecutableSha256 = $actualExecutableHash
    ManifestSha256 = $manifestHash
}
