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
$required = @('README.md','bootstrap/register.py','tools\sign_release_manifest.py','manifests\windows-x64-runtime.schema.json','manifests\windows-x64-runtime.json','manifests\windows-x64-runtime.example.json','manifests\windows-x64-runtime-expected.json','scripts\Build-WindowsEdge.ps1','scripts\Install-IdenGridEdge.ps1','scripts\Upgrade-IdenGridEdge.ps1','scripts\Uninstall-IdenGridEdge.ps1','scripts\Get-IdenGridEdgeStatus.ps1','service\IdenGridEdgeService.xml','service\IdenGridEdgeGateway.xml','templates\Caddyfile.template','templates\edge.json.example')
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
foreach ($service in @($edge.service,$gateway.service)) {
    Assert-True ($service.log.mode -eq 'roll-by-size') 'WinSW must avoid the crash-prone roll-by-size-time mode.'
    Assert-True ($service.log.sizeThreshold -eq '10240' -and $service.log.keepFiles -eq '10') 'WinSW size logging must be bounded.'
    $logProperties=@($service.log.PSObject.Properties.Name)
    foreach($forbidden in @('autoRollAtTime','zipOlderThanNumDays','pattern','zipDateFormat')) {
        Assert-True ($logProperties -notcontains $forbidden) "WinSW time rotation field must remain disabled: $forbidden"
    }
}
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
Assert-True ($uninstall -match 'Assert-NoUnexpectedReparsePoints' -and $uninstall -match 'Assert-ServiceAbsent') 'Uninstall must reject unmanaged reparse points and verify SCM deletion.'
$build = Read-Utf8 'scripts\Build-WindowsEdge.ps1'
Assert-True ($build -match 'Assert-RuntimeManifestSchema' -and $build -match 'ApprovedRuntimeManifestSha256' -and $build -match 'Expand-SafeZip') 'Build must enforce schema, allowlist, and safe ZIP extraction.'
foreach($source in @($install,$upgrade,$build)){Assert-True ($source -match '536870912' -and $source -match '4294967296' -and $source -match 'CompressedLength' -and $source -match 'reserved Windows device name') 'Every ZIP extraction path must pre-scan resource and Windows namespace limits.'}
foreach($source in @($install,$upgrade,$build)){Assert-True ($source -match "Contains\('//" -and $source -match 'targetIdentity=\$target\.Normalize' -and $source -match 'targetIdentities\.Add' -and $source -match 'CONIN\\\$' -and $source -match 'CONOUT\\\$' -and $source -match 'CLOCK\\\$' -and $source -match '\\u00B9' -and $source -match '\\u00B2' -and $source -match '\\u00B3') 'Every ZIP extraction path must reject final Windows identity collisions and all reserved device aliases.'}
Assert-True ($install -match 'Write-ProtectedConfigAtomically' -and $install -match 'Protect-ConfigDirectory' -and $install -match 'Assert-ServiceAbsent') 'Install must protect Secrets before creation and fail closed on SCM rollback.'
Assert-True ($install -match "Assert-ServiceAbsent 'IdenGridEdge'" -and $install -match "Assert-ServiceAbsent 'IdenGridEdgeGateway'" -and $install -match 'Get-CimInstance Win32_Service' -and $install -match 'ErrorAction Stop') 'Install rollback must query both fixed service names fail-closed before deleting binaries.'
Assert-True ($build -match 'windows-x64-runtime-expected\.json' -and $build -match 'ApprovedRuntimeExpectedManifestSha256' -and $build -match 'expected-runtime-manifest') 'Build must digest-gate and enforce the fixed runtime expected manifest.'
Assert-True ($upgrade -match 'upgrade-journal\.json' -and $upgrade -match 'Recover-UpgradeJournal' -and $upgrade -match 'Write-JsonAtomically') 'Upgrade must journal and atomically commit state.'
Assert-True ($upgrade -match 'Repair-ManagedServiceRegistration \$current' -and $upgrade -match 'Invoke-ServiceAction \$expectedWrapper ''uninstall''' -and $upgrade -match 'Invoke-ServiceAction \$expectedWrapper ''install''') 'Upgrade and journal recovery must re-register WinSW services against current.'
Assert-True ($upgrade -match 'Assert-ServiceImagePath' -and $upgrade -match 'Assert-ManagedServicesRunning \$current' -and $upgrade -match "State -ne 'Running'") 'Upgrade health gates must verify SCM running state and exact current ImagePath.'
Assert-True ($upgrade -match 'Assert-RegisteredWrapperIsManaged' -and $upgrade -match 'Stop-Service -Name \$ServiceName' -and $upgrade -notmatch 'Stop-Process|taskkill') 'Upgrade must stop only validated managed SCM services and never kill arbitrary processes.'
Assert-True ($upgrade -match 'Stop-ManagedGatewayOrphans' -and $upgrade -match 'Get-CimInstance Win32_Process' -and $upgrade -match 'ExecutablePath' -and $upgrade -match 'CommandLine' -and $upgrade -match 'Invoke-CimMethod') 'Upgrade must identify managed Caddy by executable and command line before terminating an orphan.'
foreach ($script in Get-ChildItem -LiteralPath (Join-Path $Root 'scripts') -Filter '*.ps1') {
    $text = [IO.File]::ReadAllText($script.FullName)
    Assert-True ($text -match '#requires -Version 5\.1') "$($script.Name) must target Windows PowerShell 5.1."
    Assert-True ($text -notmatch 'ForEach-Object -Parallel|ConvertFrom-Json -AsHashtable|Invoke-Expression') "$($script.Name) uses a forbidden PowerShell feature."
    $tokens=$null;$parseErrors=$null
    [Management.Automation.Language.Parser]::ParseFile($script.FullName,[ref]$tokens,[ref]$parseErrors)|Out-Null
    Assert-True (@($parseErrors).Count -eq 0) "$($script.Name) does not parse under Windows PowerShell 5.1."
}
if ($failures.Count -gt 0) { $failures | ForEach-Object { Write-Error $_ }; throw "$($failures.Count) static contract test(s) failed." }
Write-Output 'All Windows Edge static contracts passed.'
