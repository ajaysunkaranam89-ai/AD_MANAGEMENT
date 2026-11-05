<#
.SYNOPSIS
  Installs AD Admin Portal on a Windows server as a background service
  (a Scheduled Task that starts at boot and restarts on failure).

.DESCRIPTION
  Run from the portal folder in an elevated PowerShell:
      .\setup\Install-Portal.ps1 -Port 3200 -OpenFirewall
  Requirements: Node.js 20 or newer (https://nodejs.org) installed on the server.
  After installing, open http://<server>:<port> and complete the setup wizard.
  The one-time setup token is in data\setup-token.txt.

  To remove:  .\setup\Install-Portal.ps1 -Uninstall
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [int] $Port = 3200,
  [switch] $OpenFirewall,
  [string] $TaskName = 'AD Admin Portal',
  [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script in an elevated (Run as administrator) PowerShell window.'
}

if ($Uninstall) {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed task '$TaskName'. Your settings and audit logs in $root\data and $root\logs were kept."
  }
  Get-NetFirewallRule -DisplayName $TaskName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  return
}

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { throw 'Node.js was not found. Install Node.js 20 LTS or newer from https://nodejs.org and run this again.' }
$ver = [version]((& $node --version).TrimStart('v'))
if ($ver.Major -lt 20) { throw "Node.js $ver is too old. Install version 20 or newer." }

Push-Location $root
try {
  if ($PSCmdlet.ShouldProcess($root, 'Install npm packages')) {
    if (Test-Path package-lock.json) { & npm ci --omit=dev --no-audit --no-fund } else { & npm install --omit=dev --no-audit --no-fund }
    if ($LASTEXITCODE -ne 0) { throw 'npm install failed' }
  }
} finally { Pop-Location }

New-Item -ItemType Directory -Force (Join-Path $root 'data'), (Join-Path $root 'logs') | Out-Null
# Only Administrators and SYSTEM may read settings (they contain the encrypted service-account password and key)
& icacls (Join-Path $root 'data') /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null

$action = New-ScheduledTaskAction -Execute $node -Argument "`"$root\src\server.js`"" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 `
  -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  $task = Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'AD Admin Portal - web based Active Directory user and group management'
  # pass the port through the environment by writing it into .env if not set already
  $envFile = Join-Path $root '.env'
  if (-not (Test-Path $envFile) -or -not (Select-String -Path $envFile -Pattern '^PORT=' -Quiet)) { Add-Content $envFile "PORT=$Port" }
  Start-ScheduledTask -TaskName $TaskName
}

if ($OpenFirewall -and $PSCmdlet.ShouldProcess("TCP $Port", 'Open Windows Firewall')) {
  Get-NetFirewallRule -DisplayName $TaskName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName $TaskName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Domain | Out-Null
}

Start-Sleep -Seconds 3
$tokenFile = Join-Path $root 'data\setup-token.txt'
Write-Host ''
Write-Host "AD Admin Portal installed and started." -ForegroundColor Green
Write-Host "  Open:   http://$($env:COMPUTERNAME):$Port"
if (Test-Path $tokenFile) { Write-Host "  Setup token: $(Get-Content $tokenFile)" -ForegroundColor Yellow }
Write-Host '  Put it behind HTTPS (IIS / nginx reverse proxy with TRUST_PROXY=true in .env, or HTTPS_CERT_FILE/HTTPS_KEY_FILE).'
