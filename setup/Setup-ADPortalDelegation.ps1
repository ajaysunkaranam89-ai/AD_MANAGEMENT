<#
.SYNOPSIS
  Prepares Active Directory for the AD Admin Portal:
  creates the service account and the two portal role groups, and delegates
  only the rights the portal needs on the managed OUs (no Domain Admin).

.DESCRIPTION
  Run on a domain controller (or a machine with RSAT) as a Domain Admin.
  REVIEW THE PARAMETERS BEFORE RUNNING. Use -WhatIf first to see what it will do.

  Rights granted to the service account:
    User OUs  : create/delete user objects, full control over user objects
                (same as the "Create, delete and manage user accounts" +
                "Reset user passwords" delegation-wizard tasks)
    Group OUs : create/delete group objects, full control over group objects

  Accounts protected by AdminSDHolder (Domain Admins etc.) do not inherit these
  rights, so the portal cannot change them even if they sit in a managed OU.

.EXAMPLE
  .\Setup-ADPortalDelegation.ps1 -UserOUs "OU=Staff,DC=corp,DC=local" `
      -GroupOUs "OU=Groups,DC=corp,DC=local" `
      -ServiceAccountOU "OU=Service Accounts,DC=corp,DC=local" -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)] [string[]] $UserOUs,
  [Parameter(Mandatory)] [string[]] $GroupOUs,
  [Parameter(Mandatory)] [string]   $ServiceAccountOU,
  [string] $ServiceAccountName = 'svc-adportal',
  [string] $RoleGroupOU = $GroupOUs[0],
  [string] $AdminGroupName = 'ADPortal-Admins',
  [string] $HelpdeskGroupName = 'ADPortal-Helpdesk'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = (Get-ADDomain).NetBIOSName

# 1. Service account
if (-not (Get-ADUser -Filter "sAMAccountName -eq '$ServiceAccountName'")) {
  if ($PSCmdlet.ShouldProcess($ServiceAccountName, 'Create service account')) {
    $pwd = Read-Host "Password for $ServiceAccountName" -AsSecureString
    New-ADUser -Name $ServiceAccountName -SamAccountName $ServiceAccountName -Path $ServiceAccountOU `
      -AccountPassword $pwd -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true `
      -Description 'AD Admin Portal service account (delegated rights only)'
  }
} else { Write-Host "Service account $ServiceAccountName already exists" }

# 2. Portal role groups
foreach ($g in @(
    @{ Name = $AdminGroupName;    Desc = 'AD Admin Portal - full user & group management' },
    @{ Name = $HelpdeskGroupName; Desc = 'AD Admin Portal - reset password / unlock / enable-disable' })) {
  if (-not (Get-ADGroup -Filter "sAMAccountName -eq '$($g.Name)'")) {
    if ($PSCmdlet.ShouldProcess($g.Name, 'Create role group')) {
      New-ADGroup -Name $g.Name -SamAccountName $g.Name -GroupScope Global -GroupCategory Security -Path $RoleGroupOU -Description $g.Desc
    }
  } else { Write-Host "Group $($g.Name) already exists" }
}

# 3. Delegation with dsacls
$who = "$domain\$ServiceAccountName"
function Grant([string]$ou, [string]$inherit, [string]$perm) {
  if ($PSCmdlet.ShouldProcess($ou, "dsacls $inherit $perm for $who")) {
    & dsacls.exe $ou $inherit /G "${who}:$perm" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "dsacls failed on $ou ($perm)" }
  }
}

foreach ($ou in $UserOUs) {
  Write-Host "Delegating user management on $ou"
  Grant $ou '/I:T' 'CCDC;user'          # create/delete users in this OU and sub-OUs
  Grant $ou '/I:S' 'GA;;user'           # full control over user objects (incl. reset password, move)
  Grant $ou '/I:T' 'RP;;organizationalUnit'
}
foreach ($ou in $GroupOUs) {
  Write-Host "Delegating group management on $ou"
  Grant $ou '/I:T' 'CCDC;group'
  Grant $ou '/I:S' 'GA;;group'
}

Write-Host ''
Write-Host 'Done. Next steps:' -ForegroundColor Green
Write-Host "  - Add IT admins to $AdminGroupName and support staff to $HelpdeskGroupName"
Write-Host '  - Moving users between OUs also needs CCDC;user on BOTH source and target OU (covered above for managed OUs)'
Write-Host '  - Make sure LDAPS (636) works: Test-NetConnection <dc> -Port 636'
