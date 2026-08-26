#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$PurgeData)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgramRoot=Join-Path $env:ProgramFiles 'IdenGrid Edge'
$ProgramDataRoot=Join-Path $env:ProgramData 'IdenGrid\Edge'
$FirewallGroup='IdenGrid Edge Managed Rules'
$FirewallDescription='Managed exclusively by IdenGrid Edge'
function Assert-Administrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated Windows PowerShell session.' }
}
function Assert-AllowedRoot([string]$Path,[string]$Expected,[string]$Sentinel,[bool]$RequireSentinel) {
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowed=[IO.Path]::GetFullPath($Expected).TrimEnd('\')
    if (-not $full.Equals($allowed,[StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing operation outside the fixed product root.' }
    if (Test-Path -LiteralPath $full) {
        if ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Product root cannot be a reparse point.' }
        if ($RequireSentinel -and -not (Test-Path -LiteralPath (Join-Path $full $Sentinel) -PathType Leaf)) { throw 'Product installation sentinel is missing.' }
    }
    return $full
}
function Invoke-WinSWChecked([string]$Wrapper,[string]$Action) {
    & $Wrapper $Action 2>$null
    if ($LASTEXITCODE -ne 0) { throw "WinSW $Action failed; uninstall stopped before deleting files." }
}
Assert-Administrator
$ProgramRoot=Assert-AllowedRoot $ProgramRoot (Join-Path $env:ProgramFiles 'IdenGrid Edge') 'current\service\IdenGridEdgeService.exe' $true
$ProgramDataRoot=Assert-AllowedRoot $ProgramDataRoot (Join-Path $env:ProgramData 'IdenGrid\Edge') 'state\install-state.json' $PurgeData.IsPresent
$current=Join-Path $ProgramRoot 'current'
if (Test-Path -LiteralPath $current) {
    $gateway=Join-Path $current 'service\IdenGridEdgeGateway.exe'
    $edge=Join-Path $current 'service\IdenGridEdgeService.exe'
    if ((Test-Path -LiteralPath $gateway) -and $PSCmdlet.ShouldProcess('IdenGridEdgeGateway','Stop managed Gateway service')) { Invoke-WinSWChecked $gateway 'stop' }
    if ((Test-Path -LiteralPath $edge) -and $PSCmdlet.ShouldProcess('IdenGridEdge','Stop managed Edge service')) { Invoke-WinSWChecked $edge 'stop' }
    if ((Test-Path -LiteralPath $gateway) -and $PSCmdlet.ShouldProcess('IdenGridEdgeGateway','Uninstall managed Gateway service')) { Invoke-WinSWChecked $gateway 'uninstall' }
    if ((Test-Path -LiteralPath $edge) -and $PSCmdlet.ShouldProcess('IdenGridEdge','Uninstall managed Edge service')) { Invoke-WinSWChecked $edge 'uninstall' }
}
$rules=@(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Where-Object { $_.Description -eq $FirewallDescription -and $_.Name -in @('IdenGridEdge-HTTP','IdenGridEdge-HTTPS') })
foreach($rule in $rules) {
    if ($PSCmdlet.ShouldProcess($rule.Name,'Remove product-owned firewall rule')) { Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop }
}
if ((Test-Path -LiteralPath $ProgramRoot) -and $PSCmdlet.ShouldProcess($ProgramRoot,'Delete fixed IdenGrid Edge program root')) { Remove-Item -LiteralPath $ProgramRoot -Recurse -Force }
if ($PurgeData) {
    if ((Test-Path -LiteralPath $ProgramDataRoot) -and $PSCmdlet.ShouldProcess($ProgramDataRoot,'Permanently delete Edge config, logs, and certificate state')) {
        Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force
        Write-Output 'IdenGrid Edge and ProgramData were removed.'
    } else { Write-Warning 'ProgramData purge was not performed; data was retained.' }
} else {
    Write-Output "IdenGrid Edge was removed. Data retained at $ProgramDataRoot."
}
