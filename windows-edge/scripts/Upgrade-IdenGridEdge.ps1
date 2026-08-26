#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Server')]
param(
    [Parameter(Mandatory=$true,ParameterSetName='Server')][ValidatePattern('^https://[^/]+$')][string]$Server,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][switch]$LabConfig,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][string]$PackagePath,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$PackageSha256,
    [Parameter(Mandatory=$true,ParameterSetName='LabConfig')][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$')][string]$Version
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Net.Http
$ReleasePublicKeyBase64='Wf/s6zRs0+FjSCqM1BQb5vXIpyv4Ivxm5nAS2wWZGxk='
$ReleaseManifestRoute='/edge-package/release-manifest.json'
$ReleaseSignatureRoute='/edge-package/release-manifest.json.sig'
$ProgramRoot=Join-Path $env:ProgramFiles 'IdenGrid Edge'
$ProgramDataRoot=Join-Path $env:ProgramData 'IdenGrid\Edge'

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
function Assert-Sha256([string]$Path,[string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) { throw 'Package SHA256 verification failed.' }
}
function Invoke-HttpsDownload([string]$Uri,[string]$Destination) {
    $handler=New-Object Net.Http.HttpClientHandler;$handler.AllowAutoRedirect=$true
    $client=New-Object Net.Http.HttpClient -ArgumentList (,$handler)
    try{$response=$client.GetAsync($Uri).GetAwaiter().GetResult();if(-not $response.IsSuccessStatusCode -or $response.RequestMessage.RequestUri.Scheme -ne 'https'){throw 'Download failed or redirected away from HTTPS.'};$input=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();$output=[IO.File]::Create($Destination);try{$input.CopyTo($output)}finally{$output.Dispose();$input.Dispose()}}finally{$client.Dispose();$handler.Dispose()}
}
function Compare-SemanticVersion([string]$Left,[string]$Right) {
    $lm=[regex]::Match($Left,'^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$');$rm=[regex]::Match($Right,'^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$')
    for($i=1;$i -le 3;$i++){if([long]$lm.Groups[$i].Value -gt [long]$rm.Groups[$i].Value){return 1};if([long]$lm.Groups[$i].Value -lt [long]$rm.Groups[$i].Value){return -1}}
    if($lm.Groups[4].Success -and -not $rm.Groups[4].Success){return -1};if(-not $lm.Groups[4].Success -and $rm.Groups[4].Success){return 1}
    $li=@($lm.Groups[4].Value.Split('.'));$ri=@($rm.Groups[4].Value.Split('.'));$count=[Math]::Max($li.Count,$ri.Count)
    for($i=0;$i -lt $count;$i++){
        if($i -ge $li.Count){return -1};if($i -ge $ri.Count){return 1}
        $ln=0L;$rn=0L;$leftNumeric=[long]::TryParse($li[$i],[ref]$ln);$rightNumeric=[long]::TryParse($ri[$i],[ref]$rn)
        if($leftNumeric -and $rightNumeric){if($ln -gt $rn){return 1};if($ln -lt $rn){return -1}}
        elseif($leftNumeric){return -1}elseif($rightNumeric){return 1}else{$comparison=[string]::CompareOrdinal($li[$i],$ri[$i]);if($comparison -ne 0){return $comparison}}
    }
    return 0
}
function Assert-ManagedVersionJunction([string]$Path,[string]$ExpectedVersion) {
    $item=Get-Item -LiteralPath $Path -Force
    if(-not($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-or[string]::IsNullOrWhiteSpace([string]$item.Target)){throw 'Managed version junction is invalid.'}
    $versions=[IO.Path]::GetFullPath((Join-Path $ProgramRoot 'versions')).TrimEnd('\')+'\';$target=[IO.Path]::GetFullPath([string]$item.Target)
    if(-not $target.StartsWith($versions,[StringComparison]::OrdinalIgnoreCase)){throw 'Managed version junction escapes versions root.'}
    if([string]::IsNullOrEmpty($ExpectedVersion)){$unsigned=Get-Content -LiteralPath (Join-Path $target 'manifest.json') -Raw|ConvertFrom-Json;$ExpectedVersion=[string]$unsigned.version}
    Assert-BundleManifest $target $ExpectedVersion | Out-Null
    foreach($leaf in @('runtime\python.exe','service\IdenGridEdgeService.exe','service\IdenGridEdgeGateway.exe')){if(-not(Test-Path -LiteralPath (Join-Path $target $leaf)-PathType Leaf)){throw 'Managed version critical file is missing.'}}
    return $target
}
function Remove-ManagedJunction([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item=Get-Item -LiteralPath $Path -Force
    if(-not($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-or-not $item.PSIsContainer){throw 'Refusing to remove a non-junction path.'}
    [IO.Directory]::Delete([IO.Path]::GetFullPath($Path),$false)
    if(Test-Path -LiteralPath $Path){throw 'Managed junction removal failed.'}
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
function Write-JsonAtomically([string]$Path,$Value) {
    $temporary=Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.'+[IO.Path]::GetFileName($Path)+'.'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($Value|ConvertTo-Json -Depth 6))
    $stream=New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    try{if(Test-Path -LiteralPath $Path){[IO.File]::Replace($temporary,$Path,$null,$true)}else{[IO.File]::Move($temporary,$Path)}}finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
function Recover-UpgradeJournal([string]$JournalPath,[string]$StatePath) {
    $current=Join-Path $ProgramRoot 'current';$previous=Join-Path $ProgramRoot 'previous';$newLink=Join-Path $ProgramRoot 'current.new';$legacyNext=Join-Path $ProgramRoot 'current.next'
    if(Test-Path -LiteralPath $legacyNext){Remove-ManagedJunction $legacyNext}
    if(-not(Test-Path -LiteralPath $JournalPath)){if(Test-Path -LiteralPath $newLink){throw 'Unjournaled current.new requires operator repair.'};return}
    if((Get-Item -LiteralPath $JournalPath).Length -gt 16384){throw 'Upgrade journal is invalid.'}
    $journal=Get-Content -LiteralPath $JournalPath -Raw|ConvertFrom-Json
    if(@($journal.PSObject.Properties).Count -ne 4 -or $journal.schema_version -ne 1 -or $journal.phase -notin @('prepared','switching','switched') -or $journal.old_version -notmatch '^\d+\.\d+\.\d+' -or $journal.new_version -notmatch '^\d+\.\d+\.\d+') {throw 'Upgrade journal is invalid.'}
    $state=Get-Content -LiteralPath $StatePath -Raw|ConvertFrom-Json
    if([string]$state.version -eq [string]$journal.new_version){
        Assert-ManagedVersionJunction $current ([string]$journal.new_version)|Out-Null
        if(Test-Path -LiteralPath $newLink){Remove-ManagedJunction $newLink}
        $previousBackup=Join-Path $ProgramRoot 'previous.backup'
        if(Test-Path -LiteralPath $previousBackup){Assert-ManagedVersionJunction $previousBackup $null|Out-Null;Remove-ManagedJunction $previousBackup}
        Remove-Item -LiteralPath $JournalPath -Force
        return
    }
    if([string]$state.version -ne [string]$journal.old_version){throw 'Upgrade journal and install state are inconsistent.'}
    if(Test-Path -LiteralPath $current){
        try{$active=Assert-ManagedVersionJunction $current ([string]$journal.old_version)}catch{
            Assert-ManagedVersionJunction $current ([string]$journal.new_version)|Out-Null
            if(-not(Test-Path -LiteralPath $previous)){throw 'Upgrade recovery cannot restore current.'}
            Assert-ManagedVersionJunction $previous ([string]$journal.old_version)|Out-Null
            Remove-ManagedJunction $current;Rename-Item -LiteralPath $previous -NewName 'current'
        }
    }elseif(Test-Path -LiteralPath $previous){
        Assert-ManagedVersionJunction $previous ([string]$journal.old_version)|Out-Null
        Rename-Item -LiteralPath $previous -NewName 'current'
    }else{throw 'Upgrade recovery found no valid current junction.'}
    if(Test-Path -LiteralPath $newLink){Remove-ManagedJunction $newLink}
    Assert-ManagedVersionJunction $current ([string]$journal.old_version)|Out-Null
    $previousBackup=Join-Path $ProgramRoot 'previous.backup'
    if(-not(Test-Path -LiteralPath $previous)-and(Test-Path -LiteralPath $previousBackup)){Assert-ManagedVersionJunction $previousBackup $null|Out-Null;Rename-Item -LiteralPath $previousBackup -NewName 'previous'}
    Remove-Item -LiteralPath $JournalPath -Force
}

function Invoke-ServiceAction([string]$Wrapper,[string]$Action,[bool]$Required=$true) {
    & $Wrapper $Action
    if ($Required -and $LASTEXITCODE -ne 0) { throw "Service action failed: $Action" }
}
function Wait-EdgeHealth {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        try { if ((Invoke-WebRequest -Uri 'http://127.0.0.1:8787/healthz' -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { return } } catch { Start-Sleep -Seconds 1 }
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

Assert-Administrator
$current=Join-Path $ProgramRoot 'current'
$statePath=Join-Path $ProgramDataRoot 'state\install-state.json'
$journalPath=Join-Path $ProgramDataRoot 'state\upgrade-journal.json'
if(-not(Test-Path -LiteralPath $statePath -PathType Leaf)){throw 'Install state is missing.'}
Recover-UpgradeJournal $journalPath $statePath
$stateOriginal=[IO.File]::ReadAllBytes($statePath);$state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json;$stateOriginalObject=$state
$currentVersion=[string]$state.version;$publicHostname=[string]$state.hostname
if($currentVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$' -or [string]::IsNullOrWhiteSpace($publicHostname)){throw 'Install state is invalid.'}
$oldTarget=Assert-ManagedVersionJunction $current $currentVersion
$temp=Join-Path ([IO.Path]::GetTempPath()) ('idengrid-edge-upgrade-'+[Guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $temp|Out-Null
$switched=$false;$oldMoved=$false;$upgradeSucceeded=$false;$newTarget=$null;$previousBackup=Join-Path $ProgramRoot 'previous.backup'
$edgeWrapper=Join-Path $oldTarget 'service\IdenGridEdgeService.exe';$gatewayWrapper=Join-Path $oldTarget 'service\IdenGridEdgeGateway.exe'
try {
    $bundle=Join-Path $temp 'bundle.zip'
    if($PSCmdlet.ParameterSetName -eq 'Server'){
        $manifestPath=Join-Path $temp 'release-manifest.json';$signaturePath=Join-Path $temp 'release-manifest.json.sig'
        Invoke-HttpsDownload ($Server+$ReleaseManifestRoute) $manifestPath;Invoke-HttpsDownload ($Server+$ReleaseSignatureRoute) $signaturePath
        $release=Read-StrictReleaseManifest $manifestPath $signaturePath;$Version=[string]$release.version
        Invoke-HttpsDownload ($Server+'/edge-package/'+$release.filename) $bundle
        if((Get-Item -LiteralPath $bundle).Length -ne [long]$release.size){throw 'Signed package size verification failed.'}
        Assert-Sha256 $bundle ([string]$release.sha256)
    }else{$bundle=(Resolve-Path -LiteralPath $PackagePath).Path;Assert-Sha256 $bundle $PackageSha256}
    if((Compare-SemanticVersion $Version $currentVersion) -le 0){throw 'Refusing version downgrade or reinstall.'}
    $newTarget=Join-Path (Join-Path $ProgramRoot 'versions') $Version
    if(Test-Path -LiteralPath $newTarget){throw 'The requested version directory already exists.'}

    New-Item -ItemType Directory -Path $newTarget -Force | Out-Null
    Expand-VerifiedBundle $bundle $newTarget
    $bundleManifest=Assert-BundleManifest $newTarget $Version
    if ($bundleManifest.version -ne $Version) { throw 'Bundle version does not match the requested version.' }
    & icacls.exe $newTarget /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' '*S-1-5-20:(OI)(CI)RX' | Out-Null
    if($LASTEXITCODE-ne 0){throw 'Failed to apply version root ACL.'}
    & icacls.exe (Join-Path $newTarget '*') /reset /T /C | Out-Null
    if($LASTEXITCODE-ne 0){throw 'Failed to reset version child ACLs.'}
    & (Join-Path $newTarget 'runtime\python.exe') -I -B -c 'import aiohttp,psutil,edge_tunnel'
    if ($LASTEXITCODE -ne 0) { throw 'Offline runtime self-check failed.' }
    & (Join-Path $newTarget 'runtime\python.exe') -I -B -m edge_tunnel --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Offline Edge CLI self-check failed.' }

    $oldTarget=Assert-ManagedVersionJunction $current $currentVersion
    $edgeWrapper=Join-Path $oldTarget 'service\IdenGridEdgeService.exe';$gatewayWrapper=Join-Path $oldTarget 'service\IdenGridEdgeGateway.exe'
    Invoke-ServiceAction $gatewayWrapper 'stop'
    Invoke-ServiceAction $edgeWrapper 'stop'
    $nextJunction = Join-Path $ProgramRoot 'current.new'
    $previous = Join-Path $ProgramRoot 'previous'
    if (Test-Path -LiteralPath $nextJunction) { Remove-ManagedJunction $nextJunction }
    if (Test-Path -LiteralPath $previousBackup) { throw 'Stale previous backup requires operator attention.' }
    Write-JsonAtomically $journalPath ([pscustomobject][ordered]@{schema_version=1;phase='prepared';old_version=$currentVersion;new_version=$Version})
    if (Test-Path -LiteralPath $previous) { Assert-ManagedVersionJunction $previous $null | Out-Null; Rename-Item -LiteralPath $previous -NewName 'previous.backup' }
    New-Item -ItemType Junction -Path $nextJunction -Target $newTarget | Out-Null
    Write-JsonAtomically $journalPath ([pscustomobject][ordered]@{schema_version=1;phase='switching';old_version=$currentVersion;new_version=$Version})
    # Directory junction replacement is not atomic on Windows; the durable journal makes the tiny rename gap recoverable and fail closed.
    Rename-Item -LiteralPath $current -NewName 'previous'
    $oldMoved = $true
    Rename-Item -LiteralPath $nextJunction -NewName 'current'
    $switched = $true
    Write-JsonAtomically $journalPath ([pscustomobject][ordered]@{schema_version=1;phase='switched';old_version=$currentVersion;new_version=$Version})

    $activeTarget=Assert-ManagedVersionJunction $current $Version
    $edgeWrapper=Join-Path $activeTarget 'service\IdenGridEdgeService.exe'
    $gatewayWrapper=Join-Path $activeTarget 'service\IdenGridEdgeGateway.exe'
    Invoke-ServiceAction $edgeWrapper 'start'
    Wait-EdgeHealth
    Invoke-ServiceAction $gatewayWrapper 'start'
    Wait-PublicHealth $publicHostname
    $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { New-Object psobject }
    $state | Add-Member -NotePropertyName version -NotePropertyValue $Version -Force
    $state | Add-Member -NotePropertyName upgraded_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    Write-JsonAtomically $statePath $state
    if (Test-Path -LiteralPath $previousBackup) { Remove-ManagedJunction $previousBackup }
    if(Test-Path -LiteralPath $journalPath){Remove-Item -LiteralPath $journalPath -Force}
    $upgradeSucceeded=$true
    Write-Output "IdenGrid Edge upgraded to $Version."
} catch {
    $failure = $_.Exception.Message.Substring(0,[Math]::Min(300,$_.Exception.Message.Length))
    if ($oldMoved -and -not $switched -and (Test-Path -LiteralPath (Join-Path $ProgramRoot 'previous'))) {
        if (Test-Path -LiteralPath $current) { Remove-ManagedJunction $current }
        Rename-Item -LiteralPath (Join-Path $ProgramRoot 'previous') -NewName 'current'
        $oldMoved = $false
        $restoredTarget=Assert-ManagedVersionJunction $current $currentVersion
        $edgeWrapper=Join-Path $restoredTarget 'service\IdenGridEdgeService.exe'
        $gatewayWrapper=Join-Path $restoredTarget 'service\IdenGridEdgeGateway.exe'
    }
    if ($switched) {
        # Rollback is junction-only: ProgramData config and Caddy ACME state are never replaced.
        try {
            $failedTarget=Assert-ManagedVersionJunction $current $Version
            & (Join-Path $failedTarget 'service\IdenGridEdgeGateway.exe') stop 2>$null
            & (Join-Path $failedTarget 'service\IdenGridEdgeService.exe') stop 2>$null
            Remove-ManagedJunction $current
            Rename-Item -LiteralPath (Join-Path $ProgramRoot 'previous') -NewName 'current'
            $restoredTarget=Assert-ManagedVersionJunction $current $currentVersion
            $edgeWrapper=Join-Path $restoredTarget 'service\IdenGridEdgeService.exe'
            $gatewayWrapper=Join-Path $restoredTarget 'service\IdenGridEdgeGateway.exe'
            Invoke-ServiceAction $edgeWrapper 'start'
            Wait-EdgeHealth
            Invoke-ServiceAction $gatewayWrapper 'start'
            Wait-PublicHealth $publicHostname
        } catch { Write-Warning 'Rollback service recovery requires operator attention.' }
    } else {
        try { $restoredTarget=Assert-ManagedVersionJunction $current $currentVersion; $edgeWrapper=Join-Path $restoredTarget 'service\IdenGridEdgeService.exe'; $gatewayWrapper=Join-Path $restoredTarget 'service\IdenGridEdgeGateway.exe'; Invoke-ServiceAction $edgeWrapper 'start' $false; Wait-EdgeHealth; Invoke-ServiceAction $gatewayWrapper 'start' $false; Wait-PublicHealth $publicHostname } catch { Write-Warning 'Pre-switch service recovery requires operator attention.' }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $ProgramRoot 'previous')) -and (Test-Path -LiteralPath $previousBackup)) { Rename-Item -LiteralPath $previousBackup -NewName 'previous' }
    $stateRestore=$stateOriginalObject
    Write-JsonAtomically $statePath $stateRestore
    try{Assert-ManagedVersionJunction $current $currentVersion|Out-Null;if(Test-Path -LiteralPath $journalPath){Remove-Item -LiteralPath $journalPath -Force}}catch{Write-Warning 'Upgrade journal retained for entry recovery.'}
    Write-Error ('Upgrade failed; rollback attempted: ' + $failure)
    throw
} finally {
    foreach($stale in @((Join-Path $ProgramRoot 'current.next'))){if(Test-Path -LiteralPath $stale){Remove-ManagedJunction $stale}}
    if(-not(Test-Path -LiteralPath $journalPath)){ $currentNew=Join-Path $ProgramRoot 'current.new';if(Test-Path -LiteralPath $currentNew){Remove-ManagedJunction $currentNew} }
    if (-not $upgradeSucceeded -and -not (Test-Path -LiteralPath $journalPath) -and -not [string]::IsNullOrEmpty($newTarget) -and (Test-Path -LiteralPath $newTarget)) { Remove-Item -LiteralPath $newTarget -Recurse -Force }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
