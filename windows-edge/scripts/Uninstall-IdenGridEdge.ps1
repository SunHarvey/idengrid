#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$PurgeData)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgramRoot=Join-Path $env:ProgramFiles 'IdenGrid Edge'
$ProgramDataRoot=Join-Path $env:ProgramData 'IdenGrid\Edge'
function Assert-Administrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from an elevated Windows PowerShell session.'}
}
function Assert-AllowedRoot([string]$Path,[string]$Expected,[string]$Sentinel,[bool]$RequireSentinel){
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\');$allowed=[IO.Path]::GetFullPath($Expected).TrimEnd('\')
    if(-not $full.Equals($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing operation outside the fixed product root.'}
    if(Test-Path -LiteralPath $full){
        if((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Product root cannot be a reparse point.'}
        if($RequireSentinel -and -not(Test-Path -LiteralPath (Join-Path $full $Sentinel) -PathType Leaf)){throw 'Product installation sentinel is missing.'}
    }
    return $full
}
function Assert-ManagedJunction([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    if(-not($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [string]::IsNullOrWhiteSpace([string]$item.Target)){throw 'Current version junction is invalid.'}
    $versions=[IO.Path]::GetFullPath((Join-Path $ProgramRoot 'versions')).TrimEnd('\')+'\'
    $target=[IO.Path]::GetFullPath([string]$item.Target)
    if(-not $target.StartsWith($versions,[StringComparison]::OrdinalIgnoreCase)){throw 'Current version junction escapes managed versions.'}
    foreach($leaf in @('manifest.json','service\IdenGridEdgeService.exe','service\IdenGridEdgeGateway.exe')){if(-not(Test-Path -LiteralPath (Join-Path $target $leaf) -PathType Leaf)){throw 'Installed version is incomplete.'}}
    return $target
}
function Assert-ServiceAbsent([string]$Name){
    if(Get-Service -Name $Name -ErrorAction SilentlyContinue){throw "Service $Name still exists; uninstall stopped before deleting files."}
}
function Assert-NoUnexpectedReparsePoints([string]$Root,[bool]$IsProgramData){
    $allowed=@('current','previous')
    $stack=New-Object Collections.Generic.Stack[string];$stack.Push([IO.Path]::GetFullPath($Root))
    while($stack.Count -gt 0){
        $directory=$stack.Pop()
        foreach($child in @(Get-ChildItem -LiteralPath $directory -Force)){
            if($child.Attributes -band [IO.FileAttributes]::ReparsePoint){
                if($IsProgramData){throw 'ProgramData cannot contain reparse points.'}
                $relative=$child.FullName.Substring(([IO.Path]::GetFullPath($Root)).Length).TrimStart('\\')
                if($relative -notin $allowed){throw 'ProgramRoot contains an unexpected reparse point.'}
                Assert-ManagedJunction $child.FullName|Out-Null
                continue
            }
            if($child.PSIsContainer){$stack.Push($child.FullName)}
        }
    }
}
function Invoke-WinSWChecked([string]$Wrapper,[string]$Action){
    & $Wrapper $Action 2>$null
    if ($LASTEXITCODE -ne 0) { throw "WinSW $Action failed; uninstall stopped before deleting files." }
}
function Assert-FirewallRuleMatchesState($Expected){
    if($Expected.created -ne $true){throw 'Firewall state does not record a created rule.'}
    $rule=Get-NetFirewallRule -Name ([string]$Expected.name) -ErrorAction Stop
    $filter=$rule|Get-NetFirewallPortFilter
    if($rule.DisplayName -ne $Expected.display_name -or $rule.Group -ne $Expected.group -or $rule.Description -ne $Expected.description -or [string]$rule.Enabled -ne [string]$Expected.enabled -or [string]$rule.Direction -ne [string]$Expected.direction -or [string]$rule.Action -ne [string]$Expected.action -or [string]$rule.Profile -ne [string]$Expected.profile -or [string]$filter.Protocol -ne [string]$Expected.protocol -or [string]$filter.LocalPort -ne [string]$Expected.local_port){throw 'Firewall rule no longer matches install state.'}
}
Assert-Administrator
$ProgramRoot=Assert-AllowedRoot $ProgramRoot (Join-Path $env:ProgramFiles 'IdenGrid Edge') 'current\service\IdenGridEdgeService.exe' $true
$ProgramDataRoot=Assert-AllowedRoot $ProgramDataRoot (Join-Path $env:ProgramData 'IdenGrid\Edge') 'state\install-state.json' $true
$statePath=Join-Path $ProgramDataRoot 'state\install-state.json'
$state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
if($state.schema_version -ne 1 -or $state.firewall_rules -isnot [array]){throw 'Install state is invalid.'}
$current=Join-Path $ProgramRoot 'current';$target=Assert-ManagedJunction $current
Assert-NoUnexpectedReparsePoints $ProgramRoot $false
Assert-NoUnexpectedReparsePoints $ProgramDataRoot $true
$gateway=Join-Path $target 'service\IdenGridEdgeGateway.exe';$edge=Join-Path $target 'service\IdenGridEdgeService.exe'
$state.firewall_rules|ForEach-Object{Assert-FirewallRuleMatchesState $_}
$description=if ($PurgeData) {'Stop and uninstall both services, remove recorded firewall rules, program files, and ProgramData'}else{'Stop and uninstall both services, remove recorded firewall rules and program files'}
if(-not $PSCmdlet.ShouldProcess('IdenGrid Edge',$description)){return}
Invoke-WinSWChecked $gateway 'stop'
Invoke-WinSWChecked $edge 'stop'
Invoke-WinSWChecked $gateway 'uninstall'
Invoke-WinSWChecked $edge 'uninstall'
Assert-ServiceAbsent 'IdenGridEdgeGateway'
Assert-ServiceAbsent 'IdenGridEdge'
foreach($expected in $state.firewall_rules){Remove-NetFirewallRule -Name ([string]$expected.name) -ErrorAction Stop}
Remove-Item -LiteralPath $ProgramRoot -Recurse -Force
if ($PurgeData) {Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force;Write-Output 'IdenGrid Edge and ProgramData were removed.'}else{Write-Output "IdenGrid Edge was removed. Data retained at $ProgramDataRoot."}
