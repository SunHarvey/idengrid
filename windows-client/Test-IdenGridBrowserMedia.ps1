param(
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimePath,
    [Parameter(Mandatory = $true)]
    [string]$BrowserRuntimeManifestPath,
    [Parameter(Mandatory = $true)]
    [string]$ResultPath,
    [string]$InteractiveUser = $env:USERNAME,
    [string]$FixtureUrl = "https://storage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class IdenGridWtsSessions
{
    public sealed class SessionInfo
    {
        public int SessionId { get; set; }
        public string User { get; set; }
        public string State { get; set; }
        public string Protocol { get; set; }
    }

    private enum WTS_CONNECTSTATE_CLASS { WTSActive, WTSConnected, WTSConnectQuery, WTSShadow, WTSDisconnected, WTSIdle, WTSListen, WTSReset, WTSDown, WTSInit }
    private enum WTS_INFO_CLASS { WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory, WTSOEMId, WTSSessionId, WTSUserName, WTSWinStationName, WTSDomainName, WTSConnectState, WTSClientBuildNumber, WTSClientName, WTSClientDirectory, WTSClientProductId, WTSClientHardwareId, WTSClientAddress, WTSClientDisplay, WTSClientProtocolType }

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionID;
        public IntPtr pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("Wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, WTS_INFO_CLASS infoClass, out IntPtr buffer, out int bytesReturned);

    private static string QueryString(int sessionId, WTS_INFO_CLASS infoClass)
    {
        IntPtr buffer;
        int bytes;
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytes)) return "";
        try { return Marshal.PtrToStringUni(buffer) ?? ""; }
        finally { WTSFreeMemory(buffer); }
    }

    private static ushort QueryUShort(int sessionId, WTS_INFO_CLASS infoClass)
    {
        IntPtr buffer;
        int bytes;
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytes) || bytes < 2) return UInt16.MaxValue;
        try { return (ushort)Marshal.ReadInt16(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    public static SessionInfo[] ActiveConsoleOrRdp()
    {
        IntPtr buffer;
        int count;
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out count))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var result = new List<SessionInfo>();
        try
        {
            int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
            for (int index = 0; index < count; index++)
            {
                var native = (WTS_SESSION_INFO)Marshal.PtrToStructure(IntPtr.Add(buffer, index * size), typeof(WTS_SESSION_INFO));
                if (native.State != WTS_CONNECTSTATE_CLASS.WTSActive) continue;
                string user = QueryString(native.SessionID, WTS_INFO_CLASS.WTSUserName);
                if (String.IsNullOrWhiteSpace(user)) continue;
                string domain = QueryString(native.SessionID, WTS_INFO_CLASS.WTSDomainName);
                ushort protocol = QueryUShort(native.SessionID, WTS_INFO_CLASS.WTSClientProtocolType);
                if (protocol != 0 && protocol != 2) continue;
                result.Add(new SessionInfo {
                    SessionId = native.SessionID,
                    User = String.IsNullOrWhiteSpace(domain) ? user : domain + "\\" + user,
                    State = "Active",
                    Protocol = protocol == 0 ? "Console" : "RDP"
                });
            }
        }
        finally { WTSFreeMemory(buffer); }
        return result.ToArray();
    }
}
'@

function Get-NormalizedSha256([string]$Path) {
    return ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash).ToLowerInvariant()
}

$runtime = [System.IO.Path]::GetFullPath($BrowserRuntimePath)
$manifestPath = [System.IO.Path]::GetFullPath($BrowserRuntimeManifestPath)
$resultFile = [System.IO.Path]::GetFullPath($ResultPath)
Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath $runtime -PathType Container)) { throw "Browser runtime directory does not exist." }
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Browser runtime manifest does not exist." }
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$browserExecutable = [string]$manifest.browser_executable
if ([System.IO.Path]::GetFileName($browserExecutable) -ne $browserExecutable -or
    -not $browserExecutable.Equals("brave.exe", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Browser runtime manifest browser_executable must be brave.exe."
}
$browser = Join-Path $runtime $browserExecutable
if (-not (Test-Path -LiteralPath $browser -PathType Leaf)) { throw "Browser runtime does not contain its declared executable." }
$browserHash = Get-NormalizedSha256 $browser
if ([string]$manifest.browser_executable_sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
    $browserHash -ne ([string]$manifest.browser_executable_sha256).ToLowerInvariant()) {
    throw "Browser executable SHA-256 does not match the runtime manifest."
}
$manifestHash = Get-NormalizedSha256 $manifestPath
if ([string]::IsNullOrWhiteSpace($InteractiveUser)) { throw "An active interactive Windows user is required." }
$fixtureUri = [Uri]$FixtureUrl
if (-not $fixtureUri.IsAbsoluteUri -or -not $fixtureUri.Scheme.Equals("https", [StringComparison]::OrdinalIgnoreCase)) {
    throw "FixtureUrl must use HTTPS."
}

$requestedName = $InteractiveUser
if ($requestedName.Contains('\')) { $requestedName = ($requestedName -split '\\')[-1] }
if ($requestedName.Contains('@')) { $requestedName = ($requestedName -split '@')[0] }
$activeSession = [IdenGridWtsSessions]::ActiveConsoleOrRdp() |
    Where-Object { (($_.User -split '\\')[-1]).Equals($requestedName, [StringComparison]::OrdinalIgnoreCase) } |
    Select-Object -First 1
if ($null -eq $activeSession) {
    throw "The specified user does not have an active console or RDP session."
}

$probeId = [Guid]::NewGuid().ToString("N")
$root = Join-Path ([System.IO.Path]::GetTempPath()) "idengrid-media-gate-$probeId"
$taskName = "IdenGrid-Media-Gate-$probeId"
$debugPort = Get-Random -Minimum 20000 -Maximum 50000
if (Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $debugPort -ErrorAction SilentlyContinue) {
    throw "IdenGrid media gate debug port is already in use."
}
$profile = Join-Path $root "profile"
$page = Join-Path $root "media-gate.html"
$started = $false

try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $fixtureJson = $FixtureUrl | ConvertTo-Json -Compress
    @"
<!doctype html><meta charset="utf-8"><title>starting</title>
<video id="v" muted autoplay playsinline></video>
<script>
const video = document.getElementById('v');
video.src = $fixtureJson;
const h264 = video.canPlayType('video/mp4; codecs="avc1.42E01E"');
const aac = video.canPlayType('audio/mp4; codecs="mp4a.40.2"');
function report(kind) {
  const quality = video.getVideoPlaybackQuality ? video.getVideoPlaybackQuality() : {};
  document.title = JSON.stringify({
    kind,
    h264,
    aac,
    currentTime: Number(video.currentTime.toFixed(2)),
    readyState: video.readyState,
    paused: video.paused,
    error: video.error ? video.error.code : null,
    totalVideoFrames: quality.totalVideoFrames || 0,
    decodedAudioBytes: Number(video.webkitAudioDecodedByteCount || 0)
  });
}
video.addEventListener('playing', () => report('playing'));
video.addEventListener('timeupdate', () => report('timeupdate'));
video.addEventListener('error', () => report('error'));
setTimeout(() => report('timeout'), 20000);
</script>
"@ | Set-Content -LiteralPath $page -Encoding UTF8

    $uri = (New-Object Uri($page)).AbsoluteUri
    $arguments = @(
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-component-update",
        "--autoplay-policy=no-user-gesture-required",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=$debugPort",
        "--user-data-dir=`"$profile`"",
        "`"$uri`""
    ) -join " "
    $action = New-ScheduledTaskAction -Execute $browser -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $activeSession.User -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $started = $true

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(35)
    $title = $null
    $lastTargetUrls = @()
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $targets = Invoke-RestMethod -Uri "http://127.0.0.1:$debugPort/json" -TimeoutSec 2
            $lastTargetUrls = @($targets | ForEach-Object { [string]$_.url })
            $probe = $targets | Where-Object { [string]$_.url -eq $uri } | Select-Object -First 1
            if ($null -ne $probe) {
                $title = [System.Net.WebUtility]::HtmlDecode([string]$probe.title)
                if ($title -ne "starting") {
                    $candidate = $title | ConvertFrom-Json
                    if ([double]$candidate.currentTime -gt 1 -and [int]$candidate.totalVideoFrames -gt 0 -and [int64]$candidate.decodedAudioBytes -gt 0) {
                        break
                    }
                }
            }
        }
        catch { }
        Start-Sleep -Milliseconds 500
    }
    if ([string]::IsNullOrWhiteSpace($title) -or $title -eq "starting") {
        throw "Interactive media gate did not return browser playback evidence. Targets=$($lastTargetUrls -join ';')"
    }
    $playback = $title | ConvertFrom-Json
    $ok = $playback.h264 -in "maybe", "probably" `
        -and $playback.aac -in "maybe", "probably" `
        -and $null -eq $playback.error `
        -and [double]$playback.currentTime -gt 1 `
        -and [int]$playback.totalVideoFrames -gt 0 `
        -and [int64]$playback.decodedAudioBytes -gt 0
    if (-not $ok) { throw "H.264/AAC decoded playback gate failed." }

    $gateResult = [ordered]@{
        schema_version = 1
        passed = $true
        generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
        browser_executable_sha256 = $browserHash
        runtime_manifest_sha256 = $manifestHash
        active_session = [ordered]@{
            user = [string]$activeSession.User
            session_id = [int]$activeSession.SessionId
            state = [string]$activeSession.State
            protocol = [string]$activeSession.Protocol
        }
        fixture = [ordered]@{
            url = $FixtureUrl
            h264_can_play = [string]$playback.h264
            aac_can_play = [string]$playback.aac
            current_time_seconds = [double]$playback.currentTime
            ready_state = [int]$playback.readyState
            paused = [bool]$playback.paused
            total_video_frames = [int]$playback.totalVideoFrames
            decoded_aac_bytes = [int64]$playback.decodedAudioBytes
        }
        decoded_evidence = [ordered]@{
            chromium_counter = "webkitAudioDecodedByteCount"
            decoded_aac_bytes = [int64]$playback.decodedAudioBytes
            total_video_frames = [int]$playback.totalVideoFrames
        }
    }
    $resultDirectory = Split-Path -Parent $resultFile
    if (-not [string]::IsNullOrWhiteSpace($resultDirectory)) {
        New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
    }
    $resultStaging = $resultFile + ".staging-" + [Guid]::NewGuid().ToString("N")
    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($resultStaging, ($gateResult | ConvertTo-Json -Depth 6), $utf8NoBom)
    Move-Item -LiteralPath $resultStaging -Destination $resultFile -Force
    [pscustomobject]$gateResult
}
finally {
    if ($started) {
        Get-CimInstance Win32_Process -Filter "Name='$browserExecutable'" |
            Where-Object { $_.ExecutablePath -like "$(Split-Path $browser -Parent)*" -and $_.CommandLine -like "*$profile*" } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
