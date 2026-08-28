#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProgramRoot = (Join-Path $env:ProgramFiles 'IdenGrid Edge'),
    [string]$ProgramDataRoot = (Join-Path $env:ProgramData 'IdenGrid\Edge'),
    [string]$PublicHealthUrl
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Get-Health([string]$Uri) {
    if ([string]::IsNullOrWhiteSpace($Uri)) { return $null }
    try {
        $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 5
        return [pscustomobject]@{ok=($response.StatusCode -eq 200);status_code=$response.StatusCode;error=$null}
    } catch { return [pscustomobject]@{ok=$false;status_code=$null;error='unavailable'} }
}
function Get-ServiceSafe([string]$Name) {
    $service = Get-CimInstance Win32_Service -Filter ("Name='" + $Name.Replace("'","''") + "'") -ErrorAction SilentlyContinue
    if ($null -eq $service) { return [pscustomobject]@{installed=$false;state='Missing';account=$null} }
    return [pscustomobject]@{installed=$true;state=$service.State;account=$service.StartName}
}
$current = Join-Path $ProgramRoot 'current'
$statePath = Join-Path $ProgramDataRoot 'state\install-state.json'
$version = $null
if (Test-Path -LiteralPath $statePath) { try { $version=(Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json).version } catch { $version='invalid-state' } }
$listeners = @()
try { $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object LocalPort -in @(80,443,8787) | Select-Object LocalAddress,LocalPort,OwningProcess) } catch { }
$firewall = foreach ($name in @('IdenGrid Edge HTTP','IdenGrid Edge HTTPS')) {
    $rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    [pscustomobject]@{name=$name;present=($null -ne $rule);enabled=if($rule){[string]$rule.Enabled}else{$null}}
}
$manifestOk = $null
if (Test-Path -LiteralPath (Join-Path $current 'manifest.json')) {
    try {
        $manifest = Get-Content -LiteralPath (Join-Path $current 'manifest.json') -Raw | ConvertFrom-Json
        $manifestOk = $true
        foreach ($entry in $manifest.files) {
            $file = Join-Path $current ($entry.path.Replace('/','\'))
            if (-not (Test-Path -LiteralPath $file) -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { $manifestOk=$false; break }
        }
    } catch { $manifestOk=$false }
}
$configAcl = $null
$configPath = Join-Path $ProgramDataRoot 'config\edge.json'
if (Test-Path -LiteralPath $configPath) {
    try {
        $acl = Get-Acl -LiteralPath $configPath
        $unexpected = @($acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -notin @('NT AUTHORITY\SYSTEM','NT AUTHORITY\LOCAL SERVICE')
        })
        $configAcl = [pscustomobject]@{protected=$acl.AreAccessRulesProtected;unexpected_allow_count=$unexpected.Count}
    } catch { $configAcl = [pscustomobject]@{protected=$null;unexpected_allow_count=$null} }
}
$edgeListeners = @($listeners | Where-Object LocalPort -eq 8787)
$unexpectedEdgeListeners = @($edgeListeners | Where-Object LocalAddress -notin @('127.0.0.1','::1'))
$loopbackOnly = ($edgeListeners.Count -gt 0 -and $unexpectedEdgeListeners.Count -eq 0)
$certificateExpiry = $null
$certificateFiles = @(Get-ChildItem -LiteralPath (Join-Path $ProgramDataRoot 'caddy\data') -Filter '*.crt' -File -Recurse -ErrorAction SilentlyContinue)
if ($certificateFiles.Count -gt 0) {
    $expiries = @()
    foreach ($certificateFile in $certificateFiles) {
        try { $expiries += (New-Object Security.Cryptography.X509Certificates.X509Certificate2($certificateFile.FullName)).NotAfter.ToUniversalTime() } catch { }
    }
    if ($expiries.Count -gt 0) { $certificateExpiry = ($expiries | Sort-Object | Select-Object -First 1).ToString('o') }
}
[pscustomobject][ordered]@{
    installed=(Test-Path -LiteralPath $current)
    version=$version
    edge_service=Get-ServiceSafe 'IdenGridEdge'
    gateway_service=Get-ServiceSafe 'IdenGridEdgeGateway'
    listeners=$listeners
    loopback_8787_only=$loopbackOnly
    firewall_rules=$firewall
    local_health=Get-Health 'http://127.0.0.1:8787/healthz'
    public_health=if($PublicHealthUrl){Get-Health $PublicHealthUrl}else{$null}
    manifest_hashes_valid=$manifestOk
    config_present=(Test-Path -LiteralPath $configPath)
    config_acl=$configAcl
    caddy_state_present=(Test-Path -LiteralPath (Join-Path $ProgramDataRoot 'caddy\data'))
    certificate_earliest_expiry=$certificateExpiry
} | ConvertTo-Json -Depth 6
