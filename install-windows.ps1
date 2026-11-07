# Run from an elevated PowerShell. The agent runs in the user's interactive session.
$ErrorActionPreference = 'Stop'
$config = Join-Path $PSScriptRoot 'mrp-agent.env'
$values = @{}
if (Test-Path -LiteralPath $config) {
    foreach ($line in Get-Content -LiteralPath $config) {
        $parts = $line.Split('=', 2)
        if ($parts.Count -eq 2 -and $parts[0] -cmatch '^MRP_[A-Z_]+$') { $values[$parts[0]] = $parts[1] }
    }
}
if (-not $values['MRP_TOKEN'] -or $values['MRP_TOKEN'].Length -lt 16 -or $values['MRP_TOKEN'] -eq 'mrp-local') {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $values['MRP_TOKEN'] = [Convert]::ToBase64String($bytes)
}
if (-not $values['MRP_FILES_DIR']) {
    $values['MRP_FILES_DIR'] = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Hypr Connect Files'
}
$values['MRP_BIND'] = '0.0.0.0:8765'
$ethernet = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Wi-Fi|Wireless' } | Select-Object -First 1
if (-not $ethernet) { throw 'Wake on LAN için bağlı Ethernet kartı bulunamadı.' }
$values['MRP_MAC'] = $ethernet.MacAddress.Replace('-', ':')
# Discover the current IP at every startup instead of preserving an old DHCP lease.
$values.Remove('MRP_ADVERTISE_ADDRESS')
$values.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" } | Set-Content -LiteralPath $config -Encoding utf8
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $config /inheritance:r /grant:r "${identity}:(F)" 'SYSTEM:(F)' 'BUILTIN\Administrators:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Ayar dosyası izinleri düzenlenemedi.' }
$private = Join-Path $values['MRP_FILES_DIR'] '.hypr-connect-private'
New-Item -ItemType Directory -Path $private -Force | Out-Null
& icacls.exe $private /inheritance:r /grant:r "${identity}:(OI)(CI)(F)" 'SYSTEM:(OI)(CI)(F)' 'BUILTIN\Administrators:(OI)(CI)(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'TLS klasör izinleri düzenlenemedi.' }
$binary = Join-Path $PSScriptRoot 'target/release/hypr-connect-agent.exe'
if (-not (Test-Path -LiteralPath $binary)) { throw 'Önce cargo build --release çalıştırılmalı.' }
if (-not (Get-NetFirewallRule -Name 'HyprConnect-Agent' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'HyprConnect-Agent' -DisplayName 'Hypr Connect (local network)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 -RemoteAddress LocalSubnet -Profile Private,Public -Program $binary -ErrorAction Stop | Out-Null
}
Set-NetFirewallRule -Name 'HyprConnect-Agent' -Profile Private,Public -ErrorAction Stop | Out-Null
Get-NetFirewallRule -Name 'HyprConnect-Agent' | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress LocalSubnet -ErrorAction Stop | Out-Null
$runner = Join-Path $PSScriptRoot 'start-agent.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`"" -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'Hypr Connect Agent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -Value 0 -ErrorAction Stop
Stop-ScheduledTask -TaskName 'Hypr Connect Agent' -ErrorAction SilentlyContinue
Get-Process -Name 'hypr-connect-agent' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $binary } | Stop-Process -Force -ErrorAction Stop
Start-Sleep -Seconds 2
foreach ($legacyLog in @('agent.log', 'agent-error.log')) {
    $legacyPath = Join-Path $PSScriptRoot $legacyLog
    if (Test-Path -LiteralPath $legacyPath) {
        Move-Item -LiteralPath $legacyPath -Destination (Join-Path $private "legacy-$legacyLog") -Force -ErrorAction Stop
    }
}
$staged = Join-Path $PSScriptRoot 'target/staging/release/hypr-connect-agent.exe'
if (Test-Path -LiteralPath $staged) {
    Copy-Item -LiteralPath $staged -Destination $binary -Force -ErrorAction Stop
}
Start-ScheduledTask -TaskName 'Hypr Connect Agent' -ErrorAction Stop
Write-Output "Hypr Connect Agent installed and started. Pairing QR: $(Join-Path $private 'agent.log')"

