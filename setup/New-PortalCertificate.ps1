<#
.SYNOPSIS
  Gets an HTTPS certificate for the AD Admin Portal and configures the portal to use it.

.DESCRIPTION
  Run in an elevated PowerShell on the portal server, from the portal folder.

  -Source EnterpriseCA (recommended): requests a certificate from your Active Directory
     Certificate Services (template "WebServer" by default). Domain PCs already trust it,
     so browsers show no warning.
  -Source SelfSigned: creates a self-signed certificate (browsers will warn; for testing).

  The certificate is exported to certs\portal.pfx (protected with a random passphrase)
  and the portal's .env is updated with HTTPS_PFX_FILE / HTTPS_PFX_PASSPHRASE.
  Restart the portal afterwards.

.EXAMPLE
  .\setup\New-PortalCertificate.ps1 -DnsName adportal.corp.local -Source EnterpriseCA -Port 443 -RedirectHttp
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string[]] $DnsName = @([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName),
  [ValidateSet('EnterpriseCA', 'SelfSigned')] [string] $Source = 'EnterpriseCA',
  [string] $Template = 'WebServer',
  [int] $Port = 443,
  [switch] $RedirectHttp
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$certDir = Join-Path $root 'certs'
New-Item -ItemType Directory -Force $certDir | Out-Null

if ($Source -eq 'EnterpriseCA') {
  if ($PSCmdlet.ShouldProcess(($DnsName -join ', '), "Request certificate from enterprise CA (template $Template)")) {
    $req = Get-Certificate -Template $Template -DnsName $DnsName -SubjectName "CN=$($DnsName[0])" -CertStoreLocation Cert:\LocalMachine\My
    if ($req.Status -ne 'Issued') { throw "Certificate request status: $($req.Status). An administrator may need to approve it on the CA." }
    $cert = $req.Certificate
  }
} else {
  if ($PSCmdlet.ShouldProcess(($DnsName -join ', '), 'Create self-signed certificate')) {
    $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2) -KeyExportPolicy Exportable
  }
}
if (-not $cert) { return }

$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$pass = [Convert]::ToBase64String($bytes)
$pfx = Join-Path $certDir 'portal.pfx'
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password (ConvertTo-SecureString $pass -AsPlainText -Force) | Out-Null
& icacls $certDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null

$envFile = Join-Path $root '.env'
$lines = if (Test-Path $envFile) { Get-Content $envFile | Where-Object { $_ -notmatch '^(HTTPS_PFX_FILE|HTTPS_PFX_PASSPHRASE|PORT|HTTP_REDIRECT_PORT)=' } } else { @() }
$lines += "PORT=$Port", "HTTPS_PFX_FILE=./certs/portal.pfx", "HTTPS_PFX_PASSPHRASE=$pass"
if ($RedirectHttp) { $lines += 'HTTP_REDIRECT_PORT=80' }
Set-Content $envFile $lines -Encoding utf8
& icacls $envFile /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null

Write-Host "Certificate $($cert.Thumbprint) for $($DnsName -join ', ') saved to certs\portal.pfx" -ForegroundColor Green
Write-Host "Restart the portal, then open https://$($DnsName[0])$(if ($Port -ne 443) { ":$Port" })"
