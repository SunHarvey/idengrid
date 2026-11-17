param(
    [string]$SourceScript = (Join-Path $PSScriptRoot '..\Test-IdenGridBrowserMedia.ps1'),
    [string]$InteractiveUser = $env:USERNAME
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Compile the actual interop block used by the media gate, without running playback.
$source = Get-Content -LiteralPath $SourceScript -Raw -Encoding UTF8
$block = [regex]::Match($source, "(?s)Add-Type -TypeDefinition @'\r?\n(?<code>.*?)\r?\n'@")
if (-not $block.Success) { throw 'Media gate WTS interop block not found.' }
Add-Type -TypeDefinition $block.Groups['code'].Value -ErrorAction Stop

$requestedName = ($InteractiveUser -split '\\')[-1]
$requestedName = ($requestedName -split '@')[0]
$matches = @([IdenGridWtsSessions]::ActiveConsoleOrRdp() |
    Where-Object { (($_.User -split '\\')[-1]).Equals($requestedName, [StringComparison]::OrdinalIgnoreCase) })
if ($matches.Count -ne 1) {
    throw "Expected exactly one real Active console/RDP session for $requestedName; found $($matches.Count)."
}
if ($matches[0].State -ne 'Active' -or $matches[0].Protocol -ne 'RDP') {
    throw "Expected a real Active RDP session; got state=$($matches[0].State), protocol=$($matches[0].Protocol)."
}
Write-Output "WTS_REGRESSION_PASS session=$($matches[0].SessionId) user=$($matches[0].User) state=$($matches[0].State) protocol=$($matches[0].Protocol)"
