param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,
    [int]$ProbeSeconds = 5
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Executable)) {
    throw "Executable not found: $Executable"
}

$process = Start-Process -FilePath $Executable -PassThru
try {
    Start-Sleep -Seconds $ProbeSeconds
    $process.Refresh()
    if ($process.HasExited) {
        throw "IdenGrid exited during startup probe: $($process.ExitCode)"
    }
    Write-Output "IdenGrid Windows launch smoke passed: PID=$($process.Id)"
}
finally {
    $process.Refresh()
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
    }
}
