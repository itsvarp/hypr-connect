$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$config = Join-Path $PSScriptRoot 'mrp-agent.env'
if (-not (Test-Path -LiteralPath $config)) { throw 'Önce install-windows.ps1 çalıştırılmalı.' }
foreach ($line in Get-Content -LiteralPath $config) {
    $parts = $line.Split('=', 2)
    if ($parts.Count -eq 2 -and $parts[0] -cmatch '^MRP_[A-Z_]+$') {
        [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
    }
}
$binary = Join-Path $PSScriptRoot 'target/release/hypr-connect-agent.exe'
$logDir = Join-Path $env:MRP_FILES_DIR '.hypr-connect-private'
$process = Start-Process -FilePath $binary -ArgumentList @('--config', ('"' + $config + '"')) -WorkingDirectory $PSScriptRoot -NoNewWindow -PassThru -Wait -RedirectStandardOutput (Join-Path $logDir 'agent.log') -RedirectStandardError (Join-Path $logDir 'agent-error.log')
exit $process.ExitCode
