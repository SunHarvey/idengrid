$ErrorActionPreference = "Stop"
$Executable = "C:\Users\Administrator\IdenGrid-Dev\artifacts\IdenGrid.Windows.Dev\IdenGrid.Windows.exe"
$Log = "C:\Users\Administrator\IdenGrid-Dev\artifacts\windows-launch-error.txt"

try {
    if (-not (Test-Path $Executable)) {
        throw "找不到客户端文件：$Executable"
    }

    $process = Start-Process -FilePath $Executable -PassThru
    Start-Sleep -Seconds 8
    $process.Refresh()
    if ($process.HasExited) {
        $exitCode = [int]$process.ExitCode
        throw ("Client exited during startup. ExitCode={0}" -f $exitCode)
    }

    Remove-Item $Log -Force -ErrorAction SilentlyContinue
    exit 0
}
catch {
    $details = @(
        (Get-Date -Format o),
        ("Message: " + $_.Exception.Message),
        ("Exception: " + $_.Exception.GetType().FullName),
        ("Position: " + $_.InvocationInfo.PositionMessage),
        ("Stack: " + $_.ScriptStackTrace)
    )
    Set-Content -Path $Log -Value $details -Encoding UTF8
    Write-Host ""
    Write-Host "IdenGrid startup failed" -ForegroundColor Red
    Write-Host ("Message: " + $_.Exception.Message)
    Write-Host ("Position: " + $_.InvocationInfo.PositionMessage)
    Write-Host ("Diagnostic log: " + $Log)
    exit 1
}
