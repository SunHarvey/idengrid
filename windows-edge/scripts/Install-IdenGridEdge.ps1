#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Server')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Server')][ValidatePattern('^https://[^/]+$')][string]$Server,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][switch]$LabConfig,
    [Parameter(ParameterSetName='LabConfig')][string]$PackagePath,
    [Parameter(ParameterSetName='LabConfig')][ValidatePattern('^https://')][string]$PackageUrl,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PackageSha256,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$')][string]$Version,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')][string]$Hostname,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][string]$ProtectedConfigPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Net.Http

$ProgramRoot = Join-Path $env:ProgramFiles 'IdenGrid Edge'
$ProgramDataRoot = Join-Path $env:ProgramData 'IdenGrid\Edge'
$ReleaseManifestRoute = '/edge-package/release-manifest.json'
$ReleaseSignatureRoute = '/edge-package/release-manifest.json.sig'
$ReleasePublicKeyBase64 = 'Wf/s6zRs0+FjSCqM1BQb5vXIpyv4Ivxm5nAS2wWZGxk='
$FirewallGroup = 'IdenGrid Edge Managed Rules'
$FirewallDescription = 'Managed exclusively by IdenGrid Edge'
$reportToken = $null
$formalInstall = $PSCmdlet.ParameterSetName -eq 'Server'
$currentPhase = 'installing'
$programRootExisted = Test-Path -LiteralPath $ProgramRoot
$programDataExisted = Test-Path -LiteralPath $ProgramDataRoot
$idengridDataRoot = Split-Path $ProgramDataRoot -Parent
$idengridDataRootExisted = Test-Path -LiteralPath $idengridDataRoot
$versionRoot = $null
$edgeWrapper = $null
$gatewayWrapper = $null
$edgeServiceInstalled = $false
$gatewayServiceInstalled = $false
$currentJunctionCreated = $false
$createdFirewallRules = New-Object Collections.Generic.List[object]
$programDataBackup = $null

function Test-Ed25519Signature([byte[]]$Message,[byte[]]$Signature,[byte[]]$PublicKey) {
    if (-not ('IdenGrid.Ed25519' -as [type])) {
        Add-Type -ReferencedAssemblies 'System.Numerics.dll' -TypeDefinition @'
using System;
using System.Numerics;
using System.Security.Cryptography;
namespace IdenGrid {
  public static class Ed25519 {
    static readonly BigInteger Q=(BigInteger.One<<255)-19, L=(BigInteger.One<<252)+BigInteger.Parse("27742317777372353535851937790883648493");
    static readonly BigInteger D=Mod(-121665*Inv(121666)), I=BigInteger.ModPow(2,(Q-1)/4,Q);
    public sealed class P { public BigInteger X,Y; public P(BigInteger x,BigInteger y){X=x;Y=y;} }
    static BigInteger Mod(BigInteger x){x%=Q; return x.Sign<0?x+Q:x;}
    static BigInteger Inv(BigInteger x){return BigInteger.ModPow(Mod(x),Q-2,Q);}
    static BigInteger FromLE(byte[] b){var u=new byte[b.Length+1];Buffer.BlockCopy(b,0,u,0,b.Length);return new BigInteger(u);}
    static P Decode(byte[] s){if(s.Length!=32)throw new Exception();var b=(byte[])s.Clone();int sign=b[31]>>7;b[31]&=127;var y=FromLE(b);if(y>=Q)throw new Exception();var y2=Mod(y*y);var x2=Mod((y2-1)*Inv(D*y2+1));var x=BigInteger.ModPow(x2,(Q+3)/8,Q);if(Mod(x*x-x2)!=0)x=Mod(x*I);if(Mod(x*x-x2)!=0||(x.IsZero&&sign==1))throw new Exception();if((x.IsEven?0:1)!=sign)x=Q-x;return new P(x,y);}
    static P Add(P p,P q){var t=Mod(D*p.X*q.X*p.Y*q.Y);return new P(Mod((p.X*q.Y+p.Y*q.X)*Inv(1+t)),Mod((p.Y*q.Y+p.X*q.X)*Inv(1-t)));}
    static P Mul(P p,BigInteger n){var r=new P(0,1);while(n>0){if(!n.IsEven)r=Add(r,p);p=Add(p,p);n>>=1;}return r;}
    static bool Eq(P a,P b){return Mod(a.X-b.X)==0&&Mod(a.Y-b.Y)==0;}
    public static bool Verify(byte[] m,byte[] sig,byte[] pk){try{if(sig==null||sig.Length!=64||pk==null||pk.Length!=32)return false;var rb=new byte[32];Buffer.BlockCopy(sig,0,rb,0,32);var sb=new byte[32];Buffer.BlockCopy(sig,32,sb,0,32);var s=FromLE(sb);if(s>=L)return false;var a=Decode(pk);var r=Decode(rb);byte[] h;using(var sha=SHA512.Create()){var all=new byte[64+m.Length];Buffer.BlockCopy(rb,0,all,0,32);Buffer.BlockCopy(pk,0,all,32,32);Buffer.BlockCopy(m,0,all,64,m.Length);h=sha.ComputeHash(all);}var k=FromLE(h)%L;var bx=BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202");var by=Mod(4*Inv(5));var b=new P(bx,by);return Eq(Mul(Mul(b,s),8),Mul(Add(r,Mul(a,k)),8));}catch{return false;}}
  }
}
'@
    }
    return [IdenGrid.Ed25519]::Verify($Message,$Signature,$PublicKey)
}
function Convert-HexBytes([string]$Hex) {
    $bytes=New-Object byte[] ($Hex.Length/2)
    for($i=0;$i -lt $bytes.Length;$i++){ $bytes[$i]=[Convert]::ToByte($Hex.Substring($i*2,2),16) }
    return $bytes
}
function Assert-Rfc8032Verifier {
    $pk=Convert-HexBytes 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    $sig=Convert-HexBytes 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
    $empty=New-Object byte[] 0
    if(-not(Test-Ed25519Signature $empty $sig $pk)){throw 'RFC 8032 Ed25519 verifier self-test failed.'}
    $tamperedMessage=New-Object byte[] 1;$tamperedMessage[0]=1
    if(Test-Ed25519Signature $tamperedMessage $sig $pk){throw 'Ed25519 verifier accepted a tampered message.'}
    $tamperedSignature=[byte[]]$sig.Clone();$tamperedSignature[0]=$tamperedSignature[0] -bxor 1
    if(Test-Ed25519Signature $empty $tamperedSignature $pk){throw 'Ed25519 verifier accepted a tampered signature.'}
    $nonCanonicalSignature=[byte[]]$sig.Clone()
    for($i=32;$i -lt 64;$i++){$nonCanonicalSignature[$i]=255}
    if(Test-Ed25519Signature $empty $nonCanonicalSignature $pk){throw 'Ed25519 verifier accepted non-canonical S.'}
}

function Read-StrictReleaseManifest([string]$ManifestPath,[string]$SignaturePath) {
    Assert-Rfc8032Verifier
    try { $publicKey = [Convert]::FromBase64String($ReleasePublicKeyBase64); $signature = [Convert]::FromBase64String(([IO.File]::ReadAllText($SignaturePath,[Text.Encoding]::ASCII)).Trim()) } catch { throw 'Release signature encoding is invalid.' }
    $raw = [IO.File]::ReadAllBytes($ManifestPath)
    if ($raw.Length -gt 4096 -or $publicKey.Length -ne 32 -or $signature.Length -ne 64 -or -not (Test-Ed25519Signature $raw $signature $publicKey)) { throw 'Release manifest Ed25519 signature verification failed.' }
    $doc = [Text.Encoding]::ASCII.GetString($raw) | ConvertFrom-Json
    if ($doc.schema_version -ne 1 -or @($doc.PSObject.Properties).Count -ne 2 -or @($doc.package.PSObject.Properties).Count -ne 4) { throw 'Signed release manifest format is invalid.' }
    $p=$doc.package
    if ($p.filename -notmatch '^IdenGrid-Edge-Windows-Server-2025-x64-v([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)\.zip$' -or $p.version -ne $Matches[1] -or $p.sha256 -notmatch '^[0-9a-f]{64}$' -or ($p.size -isnot [long] -and $p.size -isnot [int]) -or [long]$p.size -le 0 -or [long]$p.size -gt 8589934592) { throw 'Signed release manifest package is invalid.' }
    return $p
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated Windows PowerShell session.' }
}
function Assert-SupportedHost {
    if ([Environment]::Is64BitOperatingSystem -ne $true -or $env:PROCESSOR_ARCHITECTURE -notin @('AMD64','x86')) { throw 'Windows Server 2025 x64 is required.' }
    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($os.ProductType -eq 1 -or $build -lt 26100) { throw 'Windows Server 2025 x64 is required.' }
}
function Assert-Sha256([string]$Path,[string]$Expected) {
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') { throw 'Package SHA256 is malformed.' }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) { throw 'Package SHA256 verification failed.' }
}
function Invoke-HttpsDownload([string]$Uri,[string]$Destination) {
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $true
    $client = New-Object Net.Http.HttpClient -ArgumentList (,$handler)
    try {
        $response = $client.GetAsync($Uri).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode -or $response.RequestMessage.RequestUri.Scheme -ne 'https') { throw 'Download failed or redirected away from HTTPS.' }
        $input=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult(); $output=[IO.File]::Create($Destination)
        try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    } finally { $client.Dispose(); $handler.Dispose() }
}
function Assert-Claim($Claim,[string]$RawJson) {
    if ([Text.Encoding]::UTF8.GetByteCount($RawJson) -gt 65536) { throw 'Claim response exceeds 65536 bytes.' }
    $claimFields=@('node_id','node_name','domain','edge_ticket_secret','resources','package_url','package_sha256','report_token','enrollment_id','install_admin_ssh_key')
    if (@($Claim.PSObject.Properties.Name).Count -ne $claimFields.Count -or @($Claim.PSObject.Properties.Name | Where-Object { $_ -notin $claimFields }).Count -ne 0) { throw 'Approved installation data is invalid.' }
    foreach ($name in $claimFields) { if ($null -eq $Claim.PSObject.Properties[$name]) { throw 'Approved installation data is invalid.' } }
    if ($Claim.package_sha256 -isnot [string] -or $Claim.package_sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Approved installation data is invalid.' }
    if (($Claim.node_id -isnot [int] -and $Claim.node_id -isnot [long]) -or [long]$Claim.node_id -lt 1 -or $Claim.package_url -isnot [string] -or $Claim.package_url -ne ($Server + '/edge-package/' + $release.filename) -or ($Claim.enrollment_id -isnot [int] -and $Claim.enrollment_id -isnot [long]) -or [long]$Claim.enrollment_id -lt 1 -or $Claim.install_admin_ssh_key -isnot [bool]) { throw 'Approved installation data is invalid.' }
    if ($Claim.domain -isnot [string] -or $Claim.domain.Length -gt 253 -or $Claim.domain -notmatch '^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$') { throw 'Approved installation data is invalid.' }
    if ($Claim.node_name -isnot [string] -or $Claim.node_name.Length -lt 1 -or $Claim.node_name.Length -gt 64 -or $Claim.node_name -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Approved installation data is invalid.' }
    if ($Claim.edge_ticket_secret -isnot [string] -or $Claim.edge_ticket_secret.Length -lt 32 -or $Claim.edge_ticket_secret.Length -gt 512) { throw 'Approved installation data is invalid.' }
    if ($Claim.report_token -isnot [string] -or $Claim.report_token.Length -lt 16 -or $Claim.report_token.Length -gt 512) { throw 'Approved installation data is invalid.' }
    if ($Claim.resources -isnot [pscustomobject]) { throw 'Approved installation data is invalid.' }
    $resourceFields=@('max_connections','max_frame_bytes','max_bytes','idle_timeout','max_duration','connect_timeout','ticket_max_ttl')
    if (@($Claim.resources.PSObject.Properties.Name).Count -ne $resourceFields.Count -or @($Claim.resources.PSObject.Properties.Name | Where-Object { $_ -notin $resourceFields }).Count -ne 0) { throw 'Approved installation data is invalid.' }
    $limits=@{max_connections=65535;max_frame_bytes=67108864;max_bytes=1099511627776;ticket_max_ttl=300}
    foreach ($name in $limits.Keys) { $v=$Claim.resources.$name; if (($v -isnot [int] -and $v -isnot [long]) -or [long]$v -lt 1 -or [long]$v -gt [long]$limits[$name]) { throw 'Approved installation data is invalid.' } }
    foreach ($name in @('idle_timeout','max_duration','connect_timeout')) { $v=$Claim.resources.$name; if (($v -isnot [int] -and $v -isnot [long] -and $v -isnot [double]) -or [double]::IsNaN([double]$v) -or [double]::IsInfinity([double]$v) -or [double]$v -le 0) { throw 'Approved installation data is invalid.' } }
}
function Invoke-RobocopyMirror([string]$Source,[string]$Destination) {
    & robocopy.exe $Source $Destination /MIR /B /COPYALL /DCOPY:DAT /R:1 /W:1 /XJ /NFL /NDL /NJH /NJS | Out-Null
    if ($LASTEXITCODE -ge 8) { throw 'Transactional ProgramData copy failed.' }
}
function Restore-ProgramDataBackup {
    if (-not [string]::IsNullOrEmpty($programDataBackup) -and (Test-Path -LiteralPath $programDataBackup)) {
        if (Test-Path -LiteralPath $ProgramDataRoot) {
            & icacls.exe $ProgramDataRoot /grant '*S-1-5-32-544:(OI)(CI)F' /T /C | Out-Null
            Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force
        }
        New-Item -ItemType Directory -Path $ProgramDataRoot -Force | Out-Null
        Invoke-RobocopyMirror $programDataBackup $ProgramDataRoot
    }
}
function Expand-VerifiedBundle([string]$Archive,[string]$Destination) {
    # Pre-scan the complete central directory before writing extracted bytes.
    $MaxEntries=5000;$MaxEntryBytes=536870912L;$MaxTotalBytes=4294967296L;$MaxCompressionRatio=200L;$MaxManifestBytes=8388608L
    $root=[IO.Path]::GetFullPath($Destination).TrimEnd('\')+'\'
    $targetIdentities=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $approved=New-Object Collections.Generic.List[object]
    $reserved='^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?$';$total=0L
    $zip=[IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if($zip.Entries.Count -gt $MaxEntries){throw 'Bundle ZIP exceeds 5000 entries.'}
        foreach($entry in $zip.Entries){
            $name=$entry.FullName.Replace('\','/')
            if([string]::IsNullOrWhiteSpace($name)-or$name.Contains(':')-or$name.Contains('//')-or$name.StartsWith('/')-or$name -match '(^|/)(\.|\.\.)(/|$)'){throw 'Bundle ZIP contains an NTFS alternate data stream or unsafe path.'}
            $parts=@($name.TrimEnd('/').Split('/'))
            foreach($part in $parts){
                if($part.EndsWith('.')-or$part.EndsWith(' ')){throw 'Bundle ZIP path has a trailing dot or space.'}
                if($part -match $reserved){throw 'Bundle ZIP path uses a reserved Windows device name.'}
            }

            if($entry.Length -gt $MaxEntryBytes){throw 'Bundle ZIP entry exceeds 536870912 bytes.'}
            $total+=[long]$entry.Length
            if($total -gt $MaxTotalBytes){throw 'Bundle ZIP exceeds 4294967296 extracted bytes.'}
            if($entry.Length -gt 0 -and($entry.CompressedLength -le 0 -or[decimal]$entry.Length -gt([decimal]$entry.CompressedLength*$MaxCompressionRatio))){throw 'Bundle ZIP compression ratio exceeds 200.'}
            if($name.Equals('manifest.json',[StringComparison]::OrdinalIgnoreCase)-and$entry.Length -gt $MaxManifestBytes){throw 'Manifest exceeds package resource limits.'}
            $target=[IO.Path]::GetFullPath((Join-Path $Destination $name.Replace('/','\')))
            if(-not $target.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){throw 'Bundle ZIP contains an unsafe path.'}
            $targetIdentity=$target.Normalize([Text.NormalizationForm]::FormC)
            if(-not $targetIdentities.Add($targetIdentity)){throw 'Bundle ZIP contains a duplicate, case, or normalization collision.'}
            $approved.Add([pscustomobject]@{Entry=$entry;Target=$target})
        }
        New-Item -ItemType Directory -Path $Destination -Force|Out-Null
        foreach($item in $approved){
            $entry=$item.Entry;$target=$item.Target
            if([string]::IsNullOrEmpty($entry.Name)){New-Item -ItemType Directory -Path $target -Force|Out-Null;continue}
            New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($target)) -Force|Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$target,$false)
        }
    }finally{$zip.Dispose()}
}

function Assert-BundleManifest([string]$Root,[string]$ExpectedVersion) {
    $manifestPath = Join-Path $Root 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Bundle manifest is missing.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.platform -ne 'windows' -or $manifest.architecture -ne 'x86_64' -or @($manifest.PSObject.Properties).Count -ne 5 -or $manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$' -or $manifest.files -isnot [array] -or @($manifest.files).Count -lt 1) { throw 'Bundle manifest is unsupported.' }
    if (@($manifest.files).Count -gt 5000 -or (Get-Item -LiteralPath $manifestPath).Length -gt 8388608) { throw 'Manifest exceeds package resource limits.' }
    if (-not [string]::IsNullOrEmpty($ExpectedVersion) -and $manifest.version -ne $ExpectedVersion) { throw 'Bundle version does not match the requested version.' }
    $listed = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $manifestIdentities=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase);$manifestTotal=0L;$manifestReserved='^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$'
    $required = @('runtime/python.exe','bootstrap/register.py','service/IdenGridEdgeService.exe','service/IdenGridEdgeGateway.exe','service/IdenGridEdgeService.xml','service/IdenGridEdgeGateway.xml','templates/Caddyfile.template')
    foreach ($entry in $manifest.files) {
        if (@($entry.PSObject.Properties).Count -ne 3 -or $entry.path -isnot [string] -or [string]::IsNullOrWhiteSpace($entry.path) -or $entry.path.Equals('manifest.json',[StringComparison]::OrdinalIgnoreCase) -or $entry.path.Contains(':') -or $entry.path.Contains('\') -or $entry.path.StartsWith('/') -or $entry.path -match '(^|/)(\.\.|\.)($|/)' -or [IO.Path]::IsPathRooted($entry.path)) { throw 'Bundle path contains an NTFS alternate data stream or unsafe path.' }
        if (-not $listed.Add($entry.path)) { throw 'Bundle manifest contains a duplicate path.' }
        $manifestParts=@($entry.path.Split('/'));foreach($part in $manifestParts){if($part.EndsWith('.')-or$part.EndsWith(' ')){throw 'Bundle manifest path has a trailing dot or space.'};if($part -match $manifestReserved){throw 'Bundle manifest path uses a reserved Windows device name.'}}
        if(-not $manifestIdentities.Add((($manifestParts|ForEach-Object{$_.Normalize([Text.NormalizationForm]::FormC)})-join'/'))){throw 'Bundle manifest contains a normalization collision.'}
        if (($entry.size -isnot [long] -and $entry.size -isnot [int]) -or [long]$entry.size -lt 0 -or [long]$entry.size -gt 536870912) { throw 'Bundle manifest file size is invalid.' }
        $manifestTotal+=[long]$entry.size;if($manifestTotal -gt 4294967296){throw 'Manifest exceeds package resource limits.'}
        if ($entry.sha256 -isnot [string] -or $entry.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Bundle manifest file SHA256 is malformed.' }
        $path = Join-Path $Root ($entry.path.Replace('/','\'))
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Bundle file is missing.' }
        if ((Get-Item -LiteralPath $path).Length -ne [long]$entry.size) { throw 'Bundle file size verification failed.' }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw 'Bundle file SHA256 verification failed.' }
    }
    foreach ($item in $required) { if (-not $listed.Contains($item)) { throw 'Bundle is missing a required file.' } }
    Get-ChildItem -LiteralPath $Root -File -Recurse | ForEach-Object {
        $relative=$_.FullName.Substring($Root.Length).TrimStart('\').Replace('\','/')
        if ($relative -ne 'manifest.json' -and -not $listed.Contains($relative)) { throw 'Bundle contains an unlisted file.' }
    }
    return $manifest
}
function Remove-ManagedJunction([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $item.PSIsContainer) { throw 'Refusing to remove a non-junction path.' }
    [IO.Directory]::Delete([IO.Path]::GetFullPath($Path),$false)
    if (Test-Path -LiteralPath $Path) { throw 'Managed junction removal failed.' }
}
function Set-Junction([string]$Path,[string]$Target) {
    Remove-ManagedJunction $Path
    New-Item -ItemType Junction -Path $Path -Target $Target | Out-Null
}
function Get-ServiceImagePath([string]$Name) {
    return [string](Get-CimInstance Win32_Service -Filter ("Name='" + $Name.Replace("'","''") + "'") -ErrorAction SilentlyContinue).PathName
}
function Test-ServiceImagePath([string]$Name,[string]$Wrapper) {
    $image=Get-ServiceImagePath $Name
    if ([string]::IsNullOrWhiteSpace($image)) { return $false }
    return $image.Trim().Trim('"').Equals([IO.Path]::GetFullPath($Wrapper),[StringComparison]::OrdinalIgnoreCase)
}
function Assert-ServiceNamesAvailable {
    foreach($name in @('IdenGridEdge','IdenGridEdgeGateway')) { if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "A service named $name already exists." } }
}
function Invoke-WinSW([string]$Wrapper,[string]$Action,[string]$ServiceName) {
    & $Wrapper $Action
    if ($LASTEXITCODE -ne 0) {
        if ($Action -eq 'install' -and (Test-ServiceImagePath $ServiceName $Wrapper)) {
            if ($ServiceName -eq 'IdenGridEdge') { $script:edgeServiceInstalled=$true } else { $script:gatewayServiceInstalled=$true }
        }
        throw "Service action failed: $Action"
    }
}
function Invoke-Icacls([string]$Path,[string[]]$AclArguments) {
    & icacls.exe $Path $AclArguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to apply a required filesystem ACL.' }
}
function Assert-FirewallRule([string]$Name,[int]$Port) {
    $rule=Get-NetFirewallRule -Name $Name -ErrorAction Stop
    $filter=$rule | Get-NetFirewallPortFilter
    if ($rule.Group -ne $FirewallGroup -or $rule.Description -ne $FirewallDescription -or $rule.Enabled -ne 'True' -or $rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or $rule.Profile -ne 'Any' -or $filter.Protocol -ne 'TCP' -or [string]$filter.LocalPort -ne [string]$Port) { throw 'Managed firewall rule verification failed.' }
}
function Assert-ExactConfigAcl([string]$Path) {
    $acl=Get-Acl -LiteralPath $Path
    if ($acl.Owner -notin @('NT AUTHORITY\SYSTEM','S-1-5-18')) { throw 'Config owner verification failed.' }
    $rules=@($acl.Access | Where-Object { -not $_.IsInherited })
    $system=@($rules | Where-Object { $_.IdentityReference.Value -in @('NT AUTHORITY\SYSTEM','S-1-5-18') -and $_.AccessControlType -eq 'Allow' -and [int]$_.FileSystemRights -eq 0x001F01FF })
    $local=@($rules | Where-Object { $_.IdentityReference.Value -in @('NT AUTHORITY\LOCAL SERVICE','S-1-5-19') -and $_.AccessControlType -eq 'Allow' -and [int]$_.FileSystemRights -eq 0x00120089 })
    if ($rules.Count -ne 2 -or $system.Count -ne 1 -or $local.Count -ne 1) { throw 'Config DACL verification failed.' }
}
function Write-JsonAtomically([string]$Path,$Value) {
    $temporary=Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.'+[IO.Path]::GetFileName($Path)+'.'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($Value|ConvertTo-Json -Depth 6))
    $stream=New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    try{if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temporary,$Path,$null,$true)}else{[IO.File]::Move($temporary,$Path)}}finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
function Protect-ConfigDirectory([string]$ConfigDirectory) {
    foreach($parent in @($idengridDataRoot,$ProgramDataRoot)){
        Invoke-Icacls -Path $parent -AclArguments @('/setowner','*S-1-5-18')
        Invoke-Icacls -Path $parent -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-19:(OI)(CI)RX','*S-1-5-20:(OI)(CI)RX')
    }
    Invoke-Icacls -Path $ConfigDirectory -AclArguments @('/setowner','*S-1-5-18')
    # Administrators can create/delete names and finish hardening temporary files.
    # Object-only inheritance never grants access to the final file after /inheritance:r.
    Invoke-Icacls -Path $ConfigDirectory -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-19:(OI)(CI)R','*S-1-5-32-544:(OI)F')
}
function Write-ProtectedConfigAtomically([string]$Destination,[byte[]]$Bytes) {
    $directory=[IO.Path]::GetDirectoryName($Destination)
    $temporary=Join-Path $directory ('.edge.json.'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $stream=New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    try{
        Invoke-Icacls -Path $temporary -AclArguments @('/setowner','*S-1-5-18')
        Invoke-Icacls -Path $temporary -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-19:R')
        Assert-ExactConfigAcl $temporary
        if(Test-Path -LiteralPath $Destination){[IO.File]::Replace($temporary,$Destination,$null,$true)}else{[IO.File]::Move($temporary,$Destination)}
        Assert-ExactConfigAcl $Destination
    }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
function Assert-ServiceAbsent([string]$Name) {
    $services=@(Get-CimInstance Win32_Service -Filter ("Name='"+$Name.Replace("'","''")+"'") -ErrorAction Stop)
    if($services.Count -ne 0){throw 'Rollback requires operator repair: SCM service still exists.'}
}

function Invoke-InstallRollback {
    $scmSafe=$true
    foreach($service in @(
        @{Installed=$gatewayServiceInstalled;Wrapper=$gatewayWrapper;Name='IdenGridEdgeGateway'},
        @{Installed=$edgeServiceInstalled;Wrapper=$edgeWrapper;Name='IdenGridEdge'})){
        if($service.Installed -and -not[string]::IsNullOrEmpty([string]$service.Wrapper)){
            $wrapper=[string]$service.Wrapper
            & $wrapper stop 2>$null
            if($LASTEXITCODE -ne 0){$scmSafe=$false;Write-Warning ('Rollback stop failed for '+$service.Name)}
            & $wrapper uninstall 2>$null
            if($LASTEXITCODE -ne 0){$scmSafe=$false;Write-Warning ('Rollback uninstall failed for '+$service.Name)}
        }
    }
    try{
        Assert-ServiceAbsent 'IdenGridEdge'
        Assert-ServiceAbsent 'IdenGridEdgeGateway'
    }catch{$scmSafe=$false;Write-Warning $_.Exception.Message}
    if(-not $scmSafe){throw 'Rollback requires operator repair; ProgramRoot and version binaries were retained.'}
    foreach($rule in $createdFirewallRules){Remove-NetFirewallRule -Name $rule.name -ErrorAction SilentlyContinue}
    $current=Join-Path $ProgramRoot 'current'
    if($currentJunctionCreated -and(Test-Path -LiteralPath $current)){Remove-ManagedJunction $current}
    if(-not[string]::IsNullOrEmpty($versionRoot)-and(Test-Path -LiteralPath $versionRoot)){Remove-Item -LiteralPath $versionRoot -Recurse -Force}
    if(-not $programDataExisted -and(Test-Path -LiteralPath $ProgramDataRoot)){Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force}
    if($programDataExisted){Restore-ProgramDataBackup}
    if(-not $programRootExisted -and(Test-Path -LiteralPath $ProgramRoot)){Remove-Item -LiteralPath $ProgramRoot -Recurse -Force}
    if(-not $idengridDataRootExisted -and(Test-Path -LiteralPath $idengridDataRoot)){
        $remaining=@(Get-ChildItem -LiteralPath $idengridDataRoot -Force -ErrorAction SilentlyContinue)
        if($remaining.Count -eq 0){Remove-Item -LiteralPath $idengridDataRoot -Force}
    }
}

function Wait-EdgeHealth {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        try { $response = Invoke-WebRequest -Uri 'http://127.0.0.1:8787/healthz' -UseBasicParsing -TimeoutSec 3; if ($response.StatusCode -eq 200) { return } } catch { Start-Sleep -Seconds 1 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Loopback Edge health check failed.'
}
function Wait-PublicHealth([string]$HostName) {
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    $uri = 'https://' + $HostName + '/healthz'
    do {
        try { if ((Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) { return } } catch { Start-Sleep -Seconds 2 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Public TLS Edge health check failed.'
}
function Get-NormalizedError([string]$Stage) {
    if ($Stage -notmatch '^(installing|configuring|gateway|service|starting|ready)$') { return 'installation failed' }
    return ($Stage + ' stage failed')
}
function Report-InstallPhase([string]$Phase,[string]$ErrorText = $null) {
    if ([string]::IsNullOrEmpty($reportToken) -or -not $formalInstall) { return }
    $headers = @{ Authorization = ('Report ' + $reportToken) }
    $body = @{ phase=$Phase }
    if (-not [string]::IsNullOrEmpty($ErrorText)) { $body.error = $ErrorText }
    try {
        Invoke-RestMethod -Method Post -Uri ($Server + '/api/edge-enrollments/report') -Headers $headers -ContentType 'application/json' -Body ($body | ConvertTo-Json -Compress) | Out-Null
        return $true
    } catch {
        Write-Warning 'Install phase report was not acknowledged.'
        return $false
    }
}

Assert-Administrator
Assert-SupportedHost
Assert-ServiceNamesAvailable
if (Test-Path -LiteralPath (Join-Path $ProgramRoot 'current')) { throw 'IdenGrid Edge is already installed; use the upgrade script.' }
$temp = Join-Path ([IO.Path]::GetTempPath()) ('idengrid-edge-install-' + [Guid]::NewGuid().ToString('N'))
$expanded = Join-Path $temp 'expanded'
New-Item -ItemType Directory -Path $temp,$expanded | Out-Null
try {
    $bundle = Join-Path $temp 'bundle.zip'
    if ($PSCmdlet.ParameterSetName -eq 'Server') {
        $releaseManifestPath=Join-Path $temp 'release-manifest.json'
        $releaseSignaturePath=Join-Path $temp 'release-manifest.json.sig'
        Invoke-HttpsDownload ($Server + $ReleaseManifestRoute) $releaseManifestPath
        Invoke-HttpsDownload ($Server + $ReleaseSignatureRoute) $releaseSignaturePath
        $release=Read-StrictReleaseManifest $releaseManifestPath $releaseSignaturePath
        Invoke-HttpsDownload ($Server + '/edge-package/' + $release.filename) $bundle
        if ((Get-Item -LiteralPath $bundle).Length -ne [long]$release.size) { throw 'Signed package size verification failed.' }
        $publicPackageSha256=[string]$release.sha256
        Assert-Sha256 $bundle $publicPackageSha256
    } else {
        if (-not (Test-Path -LiteralPath $ProtectedConfigPath -PathType Leaf)) { throw 'Protected config file was not found.' }
        if ((Get-Item -LiteralPath $ProtectedConfigPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected config file cannot be a reparse point.' }
        $hasPackagePath = -not [string]::IsNullOrWhiteSpace($PackagePath)
        $hasPackageUrl = -not [string]::IsNullOrWhiteSpace($PackageUrl)
        if ($hasPackagePath -eq $hasPackageUrl) { throw 'LabConfig requires exactly one package path or HTTPS URL.' }
        if ($hasPackageUrl) {
            Invoke-HttpsDownload $PackageUrl $bundle
        } else {
            $bundle = (Resolve-Path -LiteralPath $PackagePath).Path
        }
        Assert-Sha256 $bundle $PackageSha256
    }

    Expand-VerifiedBundle $bundle $expanded
    $expectedBundleVersion = if ($formalInstall) { [string]$release.version } else { $Version }
    $bundleManifest = Assert-BundleManifest $expanded $expectedBundleVersion
    if ($PSCmdlet.ParameterSetName -eq 'Server') {
        $bootstrapPython = Join-Path $expanded 'runtime\python.exe'
        $bootstrapScript = Join-Path $expanded 'bootstrap\register.py'
        if (-not (Test-Path -LiteralPath $bootstrapPython -PathType Leaf) -or -not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) { throw 'Bundle bootstrap runtime is missing.' }
        $claimJson = & $bootstrapPython -I $bootstrapScript --server $Server
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($claimJson -join ''))) { throw 'Node registration failed.' }
        $claimJson = $claimJson -join ''
        $claim = $claimJson | ConvertFrom-Json
        Assert-Claim $claim $claimJson
        $claimPackageSha256 = [string]$claim.package_sha256
        if ($claimPackageSha256 -notmatch '^[0-9a-f]{64}$' -or $claimPackageSha256 -ne $publicPackageSha256) { throw 'Approved package does not match the verified public package.' }
        Assert-Sha256 $bundle $claimPackageSha256
        $Version = [string]$release.version
        $Hostname = [string]$claim.domain
        if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$' -or $Hostname -notmatch '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$') { throw 'Approved installation data is invalid.' }
        $reportToken = [string]$claim.report_token
        if ([string]::IsNullOrWhiteSpace($reportToken)) { throw 'Approved installation data is invalid.' }
    }

    $versionRoot = Join-Path (Join-Path $ProgramRoot 'versions') $Version
    if (Test-Path -LiteralPath $versionRoot) { throw 'The requested version directory already exists.' }
    if ($programDataExisted) {
        $programDataBackupCandidate=Join-Path $temp 'programDataBackup'
        New-Item -ItemType Directory -Path $programDataBackupCandidate | Out-Null
        Invoke-RobocopyMirror $ProgramDataRoot $programDataBackupCandidate
        $programDataBackup=$programDataBackupCandidate
    }
    New-Item -ItemType Directory -Path (Split-Path $versionRoot -Parent) -Force | Out-Null
    Move-Item -LiteralPath $expanded -Destination $versionRoot
    $dirs = @('config','caddy','caddy\data','caddy\config','logs\edge','logs\gateway','registration','state')
    foreach ($dir in $dirs) { New-Item -ItemType Directory -Path (Join-Path $ProgramDataRoot $dir) -Force | Out-Null }
    foreach ($managedDataRoot in @($idengridDataRoot,$ProgramDataRoot)) {
        Invoke-Icacls -Path $managedDataRoot -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-19:(OI)(CI)RX','*S-1-5-20:(OI)(CI)RX')
    }
    Invoke-Icacls -Path (Join-Path $ProgramDataRoot '*') -AclArguments @('/reset','/T','/C')
    $configTarget = Join-Path $ProgramDataRoot 'config\edge.json'
    Protect-ConfigDirectory (Join-Path $ProgramDataRoot 'config')
    Invoke-Icacls -Path $ProgramRoot -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-19:(OI)(CI)RX','*S-1-5-20:(OI)(CI)RX')
    Invoke-Icacls -Path $versionRoot -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F','*S-1-5-19:(OI)(CI)RX','*S-1-5-20:(OI)(CI)RX')
    Invoke-Icacls -Path (Join-Path $versionRoot '*') -AclArguments @('/reset','/T','/C')
    if ($PSCmdlet.ParameterSetName -eq 'Server') {
        $edgeConfig = [pscustomobject][ordered]@{
            schema_version=1; node_id=[string]$claim.node_name; ticket_secret=[string]$claim.edge_ticket_secret
            max_connections=[int]$claim.resources.max_connections; max_frame_bytes=[int]$claim.resources.max_frame_bytes
            max_bytes_per_connection=[long]$claim.resources.max_bytes; idle_timeout=[double]$claim.resources.idle_timeout
            max_connection_seconds=[double]$claim.resources.max_duration; connect_timeout=[double]$claim.resources.connect_timeout
            ticket_max_ttl=[int]$claim.resources.ticket_max_ttl
        }
        $edgeConfigJson = $edgeConfig | ConvertTo-Json -Compress
        Write-ProtectedConfigAtomically $configTarget ((New-Object Text.UTF8Encoding($false)).GetBytes($edgeConfigJson))
        Remove-Variable claimJson -ErrorAction SilentlyContinue
        Remove-Variable claim -ErrorAction SilentlyContinue
        Remove-Variable edgeConfig -ErrorAction SilentlyContinue
        Remove-Variable edgeConfigJson -ErrorAction SilentlyContinue
    } else {
        Write-ProtectedConfigAtomically $configTarget ([IO.File]::ReadAllBytes($ProtectedConfigPath))
    }
    $currentPhase = 'configuring'
    Report-InstallPhase 'configuring'
    $caddyText = (Get-Content -LiteralPath (Join-Path $versionRoot 'templates\Caddyfile.template') -Raw).Replace('{{EDGE_HOSTNAME}}',$Hostname.ToLowerInvariant())
    Set-Content -LiteralPath (Join-Path $ProgramDataRoot 'caddy\Caddyfile') -Value $caddyText -Encoding UTF8
    Invoke-Icacls -Path (Join-Path $ProgramDataRoot 'caddy') -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-20:(OI)(CI)M')
    Invoke-Icacls -Path (Join-Path $ProgramDataRoot 'logs\edge') -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-19:(OI)(CI)M','*S-1-5-32-544:(OI)(CI)R')
    Invoke-Icacls -Path (Join-Path $ProgramDataRoot 'logs\gateway') -AclArguments @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-20:(OI)(CI)M','*S-1-5-32-544:(OI)(CI)R')

    Set-Junction (Join-Path $ProgramRoot 'current') $versionRoot
    $currentJunctionCreated = $true
    $edgeWrapper = Join-Path $ProgramRoot 'current\service\IdenGridEdgeService.exe'
    $gatewayWrapper = Join-Path $ProgramRoot 'current\service\IdenGridEdgeGateway.exe'
    Invoke-WinSW $edgeWrapper 'install' 'IdenGridEdge'
    $edgeServiceInstalled = $true
    Invoke-WinSW $gatewayWrapper 'install' 'IdenGridEdgeGateway'
    $gatewayServiceInstalled = $true
    foreach ($rule in @(@{Name=('IdenGridEdge-HTTP-'+[Guid]::NewGuid().ToString('N'));Display='IdenGrid Edge HTTP';Port=80},@{Name=('IdenGridEdge-HTTPS-'+[Guid]::NewGuid().ToString('N'));Display='IdenGrid Edge HTTPS';Port=443})) {
        New-NetFirewallRule -Name $rule.Name -DisplayName $rule.Display -Group $FirewallGroup -Description $FirewallDescription -Direction Inbound -Action Allow -Enabled True -Protocol TCP -LocalPort $rule.Port -Profile Any | Out-Null
        $createdFirewallRules.Add([pscustomobject][ordered]@{name=$rule.Name;display_name=$rule.Display;group=$FirewallGroup;description=$FirewallDescription;direction='Inbound';action='Allow';enabled='True';protocol='TCP';local_port=$rule.Port;profile='Any';created=$true})
        Assert-FirewallRule $rule.Name $rule.Port
    }
    $currentPhase = 'service'
    Invoke-WinSW $edgeWrapper 'start' 'IdenGridEdge'
    Wait-EdgeHealth
    Report-InstallPhase 'service'
    $currentPhase = 'gateway'
    Invoke-WinSW $gatewayWrapper 'start' 'IdenGridEdgeGateway'
    Wait-PublicHealth $Hostname
    Report-InstallPhase 'gateway'
    $installState=[pscustomobject][ordered]@{schema_version=1;version=$Version;hostname=$Hostname.ToLowerInvariant();installed_at=[DateTime]::UtcNow.ToString('o');firewall_rules=@($createdFirewallRules)}
    Write-JsonAtomically (Join-Path $ProgramDataRoot 'state\install-state.json') $installState
    $currentPhase = 'ready'
    Report-InstallPhase 'ready'
    Write-Output "IdenGrid Edge $Version installed."
} catch {
    $normalized = Get-NormalizedError $currentPhase
    if (-not [string]::IsNullOrEmpty($reportToken)) { Report-InstallPhase 'failed' $normalized | Out-Null }
    Invoke-InstallRollback
    throw ('Installation failed: ' + $normalized)
} finally {
    Remove-Variable -Name @('claimJson','claim','edgeConfig','edgeConfigJson','reportToken') -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
