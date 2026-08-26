#requires -Version 5.1
[CmdletBinding()]
param([string]$Root)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = (Resolve-Path (Join-Path $ScriptRoot '..')).Path }
$failures = New-Object System.Collections.Generic.List[string]
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { $failures.Add($Message) } }
function Read-Utf8([string]$Relative) { return [IO.File]::ReadAllText((Join-Path $Root $Relative),[Text.Encoding]::UTF8) }
$required = @('README.md','bootstrap/register.py','tools\sign_release_manifest.py','manifests\windows-x64-runtime.schema.json','manifests\windows-x64-runtime.json','manifests\windows-x64-runtime.example.json','scripts\Build-WindowsEdge.ps1','scripts\Install-IdenGridEdge.ps1','scripts\Upgrade-IdenGridEdge.ps1','scripts\Uninstall-IdenGridEdge.ps1','scripts\Get-IdenGridEdgeStatus.ps1','service\IdenGridEdgeService.xml','service\IdenGridEdgeGateway.xml','templates\Caddyfile.template','templates\edge.json.example')
foreach ($file in $required) { Assert-True (Test-Path -LiteralPath (Join-Path $Root $file) -PathType Leaf) "Missing $file" }
$manifest = Read-Utf8 'manifests\windows-x64-runtime.example.json' | ConvertFrom-Json
Assert-True ($manifest.schema_version -eq 1) 'Manifest schema version must be 1.'
Assert-True ($manifest.platform -eq 'windows' -and $manifest.architecture -eq 'x86_64') 'Manifest target must be Windows x86-64.'
foreach ($artifact in $manifest.artifacts) {
    Assert-True ($artifact.url -match '^https://') "Non-HTTPS artifact: $($artifact.name)"
    Assert-True ($artifact.sha256 -match '^[0-9a-f]{64}$') "Unpinned artifact: $($artifact.name)"
}
$artifactNames = @($manifest.artifacts | ForEach-Object { $_.name })
foreach ($name in @('cryptography','cffi','pycparser')) { Assert-True ($artifactNames -contains $name) "Missing bootstrap dependency: $name" }
[xml]$edge = Read-Utf8 'service\IdenGridEdgeService.xml'
[xml]$gateway = Read-Utf8 'service\IdenGridEdgeGateway.xml'
Assert-True ($edge.service.serviceaccount.user -eq 'LocalService') 'Edge must run as LocalService.'
Assert-True ($gateway.service.serviceaccount.user -eq 'NetworkService') 'Gateway must run as NetworkService.'
Assert-True (@($gateway.service.env | Where-Object name -eq 'XDG_DATA_HOME').Count -eq 1) 'Gateway must persist Caddy data in ProgramData.'
Assert-True ($edge.service.arguments -match '--config' -and $edge.service.arguments -match '--port 8787') 'Edge service must use config path and port 8787.'
$xmlText = (Read-Utf8 'service\IdenGridEdgeService.xml') + (Read-Utf8 'service\IdenGridEdgeGateway.xml')
Assert-True ($xmlText -notmatch '(?i)ticket_secret|EDGE_TICKET_SECRET') 'A secret reference appears in service XML.'
$caddy = Read-Utf8 'templates\Caddyfile.template'
Assert-True ($caddy -match '127\.0\.0\.1:8787') 'Gateway must proxy only to loopback 8787.'
Assert-True ($caddy -notmatch '(?m)^\s*log\s*\{') 'Caddy access logging must remain disabled.'
$install = Read-Utf8 'scripts\Install-IdenGridEdge.ps1'
Assert-True ($install -match "IdenGrid Edge HTTP" -and $install -match "IdenGrid Edge HTTPS") 'Named firewall rules are missing.'
Assert-True ($install -notmatch 'LocalPort\s+8787') 'Installer must never open firewall port 8787.'
Assert-True ($install -match 'function Invoke-Icacls' -and $install -match 'Wait-PublicHealth') 'Installer must enforce ACL success and public health.'
Assert-True ($install -match 'function Expand-VerifiedBundle' -and $install -match 'GetFullPath') 'Installer must reject ZIP path traversal.'
Assert-True ($install -match "ParameterSetName='Server'" -and $install -match "ParameterSetName='LabConfig'") 'Installer must expose formal Server and experimental LabConfig parameter sets.'
Assert-True ($install -match 'release-manifest\.json' -and $install -match 'Test-Ed25519Signature' -and $install -match 'bootstrap\\register\.py') 'Formal installer must verify the detached signed manifest before invoking bootstrap.'
Assert-True ($install -match 'Wf/s6zRs0\+FjSCqM1BQb5vXIpyv4Ivxm5nAS2wWZGxk=' -and $install -notmatch 'REPLACE_WITH_PRODUCTION') 'Installer must embed the production release public key.'
Assert-True ($install -match 'Bundle contains an unlisted file' -and $install -match 'Bundle manifest contains a duplicate path') 'Installer must enforce a closed bundle manifest.'
Assert-True ($install -match 'Assert-Sha256 \$bundle \$claimPackageSha256') 'Claim package SHA must be checked against the pre-downloaded bundle.'
Assert-True ($install -match "Report-InstallPhase 'gateway'" -and $install -match "Report-InstallPhase 'service'" -and $install -match "Report-InstallPhase 'ready'") 'Formal installer must report gateway, service, and ready phases.'
Assert-True ($install -notmatch '(?i)\$env:.*(?:token|secret)|--(?:token|secret|private-key)') 'Secrets and registration credentials must not enter environment variables or command arguments.'
$upgrade = Read-Utf8 'scripts\Upgrade-IdenGridEdge.ps1'
Assert-True ($upgrade -match '(?i)rollback' -and $upgrade -match 'New-Item -ItemType Junction' -and $upgrade -match '\$oldMoved' -and $upgrade -match 'Wait-PublicHealth') 'Upgrade must use junction rollback and health gates.'
Assert-True ($upgrade -match 'function Expand-VerifiedBundle' -and $upgrade -match 'GetFullPath') 'Upgrade must reject ZIP path traversal.'
Assert-True ($upgrade -match 'Bundle version does not match the requested version' -and $upgrade -match 'Remove-Item -LiteralPath \$newTarget -Recurse -Force') 'Upgrade must enforce version identity and clean failed targets.'
Assert-True ($upgrade -match "ParameterSetName='Server'" -and $upgrade -match 'Read-StrictReleaseManifest' -and $upgrade -match 'Assert-ManagedVersionJunction' -and $upgrade -match 'Refusing version downgrade') 'Formal upgrade must use signed releases, safe junctions, and reject downgrade.'
$uninstall = Read-Utf8 'scripts\Uninstall-IdenGridEdge.ps1'
Assert-True ($uninstall -match '\[switch\]\$PurgeData' -and $uninstall -match 'ShouldProcess') 'ProgramData purge must be explicit and confirmed.'
Assert-True ($uninstall -match 'Assert-AllowedRoot' -and $uninstall -match 'Assert-FirewallRuleMatchesState' -and ([regex]::Matches($uninstall,'ShouldProcess\(').Count -eq 1)) 'Uninstall must use fixed roots, recorded firewall identity, and one transaction confirmation.'
$build = Read-Utf8 'scripts\Build-WindowsEdge.ps1'
Assert-True ($build -match 'Assert-RuntimeManifestSchema' -and $build -match 'ApprovedRuntimeManifestSha256' -and $build -match 'Expand-SafeZip') 'Build must enforce schema, allowlist, and safe ZIP extraction.'
foreach ($script in Get-ChildItem -LiteralPath (Join-Path $Root 'scripts') -Filter '*.ps1') {
    $text = [IO.File]::ReadAllText($script.FullName)
    Assert-True ($text -match '#requires -Version 5\.1') "$($script.Name) must target Windows PowerShell 5.1."
    Assert-True ($text -notmatch 'ForEach-Object -Parallel|ConvertFrom-Json -AsHashtable|Invoke-Expression') "$($script.Name) uses a forbidden PowerShell feature."
}
if ($failures.Count -gt 0) { $failures | ForEach-Object { Write-Error $_ }; throw "$($failures.Count) static contract test(s) failed." }
Write-Output 'All Windows Edge static contracts passed.'
