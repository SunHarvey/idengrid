param(
    [string]$ApiBaseUrl = $env:IDENGRID_API_BASE_URL,
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

$tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("idengrid-build-" + [Guid]::NewGuid().ToString("N"))
$configPath = Join-Path $tempDirectory "client-config.json"
New-Item -ItemType Directory -Path $tempDirectory | Out-Null

try {
    @{ api_base_url = $origin.AbsoluteUri } |
        ConvertTo-Json -Compress |
        Set-Content -Path $configPath -Encoding utf8NoBOM

    dotnet publish (Join-Path $PSScriptRoot "src\IdenGrid.Windows.Wpf\IdenGrid.Windows.Wpf.csproj") `
        -c Release `
        -r win-x64 `
        --self-contained true `
        -p:ClientConfigPath=$configPath `
        -o $OutputDirectory
}
finally {
    Remove-Item -Recurse -Force $tempDirectory -ErrorAction SilentlyContinue
}
