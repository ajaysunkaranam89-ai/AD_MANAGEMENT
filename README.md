# AD Admin Portal

**by Piersoft**

A web portal for managing Active Directory users and groups from a browser, so IT teams don't need to RDP to the domain controller. Any organisation can install it and configure it from a **setup wizard**, with no code or config-file editing. Each team member signs in with their own domain account, and every action is written to an **audit log** (who did what, to whom, when, from which IP, and whether it worked).

## Features

| Area | What the team can do |
|---|---|
| **Dashboard** | Totals for users, enabled, disabled, **locked now** (with Unlock), inactive 90+ days, and groups; recent changes |
| **Users** | Search (words in any order); filter by enabled / disabled / locked; create (default OU, groups, username format, e-mail, **manager**, **account expiry for contractors**); edit; **reset password**; **unlock**; **enable / disable**; move; **Offboard** (disable, remove groups, scramble password, stamp the date, move to the leavers OU); delete |
| **Bulk** | Select users, then unlock, enable, disable, move or offboard them all at once. **Import CSV** creates many accounts (preview, validation, generated passwords to download once) |
| **Groups** | Search; view members; create; edit; delete; add or remove members (search people by name) |
| **Reports** | Inactive N days, never signed in, old passwords, never-expiring passwords, expiring or expired contractor accounts, disabled, locked, service accounts, privileged accounts, group members. **Export to CSV/Excel** |
| **Approvals** | Choose actions that need a **second admin** (delete user or group, offboard, move, add to group). Requests wait under Approvals and run only after another admin approves |
| **Audit log** | Every action, sign-in and failure. Filter and **export CSV**. **Tamper-evident**: entries are hash-chained, and *Verify integrity* shows whether anything was edited or deleted. Optional copy to **syslog/SIEM** and the **Windows Event Log** |
| **E-mail** | Notify the IT mailbox and the user's manager on create, reset, unlock, disable, offboard, delete, group changes and approval requests. Passwords are never e-mailed |
| **Settings** (web UI) | Branding; AD connection with auto-discovery; managed and **excluded** OUs; admin and helpdesk groups and permissions; new-user defaults; security; notifications; workflow; daily **backups** |

### Roles

Portal access is controlled by membership of two AD groups that each organisation picks in Settings. Nested membership works.

- **Admin**: everything, including Settings, approvals and the audit log.
- **Helpdesk**: whatever the admin allows in Settings. The default is view, reset password, unlock, and enable/disable. Helpdesk users can never change a portal admin's account or the portal's access groups.

### Security

- **Least privilege**:
  - Changes go through a delegated service account, never a Domain Admin.
  - Only the **managed OUs** are touched; **excluded OUs** never are.
  - Privileged accounts and groups (`adminCount`, DnsAdmins, Group Policy Creator Owners and others) are always read-only. Unlocking is the one action still allowed on them.
- **Service accounts**: accounts with an SPN, or enabled accounts whose password never expires, need the username typed before a reset, disable, move, delete or offboard.
- **Sign-in**:
  - Domain password, plus optional **two-step sign-in** (TOTP authenticator app; admins can reset a lost phone).
  - **Per-account pause** before the AD lockout threshold, so the portal can't be used to lock people out.
  - Optional **IP allow-list**.
- **Sessions**:
  - Idle timeout and a **maximum session length**.
  - Group membership is **re-checked every few minutes**, so removed admins lose access quickly.
  - Cookie settings: HttpOnly, SameSite=Strict, and Secure on HTTPS.
- **Settings**:
  - Changing Settings asks for the admin's **password again**.
  - Saving is verified against AD and can't lock you out (by group or by IP).
  - First-time setup needs a one-time **setup token**.
- **Secrets**:
  - The service-account and SMTP passwords are encrypted with AES-256-GCM.
  - On Windows the key is protected by **DPAPI** (machine-bound).
  - LDAPS with **certificate verification** against your CA.
- **Transport**: HTTPS (PFX or PEM, TLS 1.2+, optional HTTP→HTTPS redirect); see `setup/New-PortalCertificate.ps1`.
- **Hardening**: CSRF header check, rate limits, security headers, LDAP-injection-safe escaping, CSV formula-injection protection, and no external scripts or CDNs.
---|---|
| **Users** | Search and filter (enabled / disabled / locked); view profile, groups and account status; create users (with default OU, groups, username format and e-mail); edit profile; **reset password** (generator, "must change at next sign-in", unlock); **unlock**; **enable / disable**; move to another OU; delete |
| **Groups** | Search; view members; create (security or distribution, global / domain local / universal); edit; delete; **add / remove members** |
| **Audit log** | Filter by text, person, action, result and date; **export to CSV**. Stored as one file per month in `logs/`. Passwords are never logged. |
| **Settings** (web UI) | Organisation name and logo; AD connection with **Test connection**, which auto-detects the domain, OUs, groups and UPN suffixes; managed OUs; admin and helpdesk groups; **what the helpdesk role may do**; new-user defaults; session timeout |

### Roles

Portal access is controlled by membership of two AD groups that each organisation picks in Settings. Nested membership works.

- **Admin**: everything, including Settings and the audit log.
- **Helpdesk**: whatever the admin allows in Settings. The default is view, reset password, unlock, and enable/disable.

### Safety rails

- The portal only touches the **managed OUs** chosen in Settings.
- **Privileged accounts and groups** (`adminCount=1`, such as Domain Admins) are always read-only.
- Changes run through a **least-privilege service account** with delegated rights, never a Domain Admin. Its password is stored **encrypted** (AES-256-GCM).
- **First-time setup needs a one-time setup token**, which is printed in the server console and saved in `data/setup-token.txt`. This stops anyone else on the network from configuring the portal first.
- Saving settings is checked against AD first, including a check that **you can't lock yourself out**.
- You can't disable or delete your own account. Deletes require typing the name to confirm.
- Security measures: LDAPS only, a session cookie that is HttpOnly, SameSite=Strict and idle-timed-out, a CSRF header check, rate limiting on sign-in and setup, security headers, and LDAP injection-safe escaping.

---

## Quick start: try the demo (no AD needed)

```bash
npm install
npm run mock
```

Open http://localhost:3200 and sign in as `portal.admin` (admin) or `helpdesk`, password `Demo@1234`. The data is fake and lives in memory.

## Documentation

- **[User Guide](docs/USER_GUIDE.md)**: signing in, roles and permissions, and every screen (users, groups, bulk import, offboarding, reports, approvals, audit log, settings), plus troubleshooting.

## Install for your organisation

### 1. Prepare Active Directory (once)

1. **LDAPS must work on a domain controller.** AD only allows password changes over an encrypted connection.
   ```powershell
   Test-NetConnection dc01.yourdomain.local -Port 636
   ```
   If the port is closed, the DC needs a certificate, for example from AD Certificate Services.

2. **Create the service account and portal groups, and delegate rights.** Run this on a DC as Domain Admin. Use `-WhatIf` first:
   ```powershell
   .\setup\Setup-ADPortalDelegation.ps1 -UserOUs "OU=Staff,DC=yourdomain,DC=local" `
       -GroupOUs "OU=Groups,DC=yourdomain,DC=local" `
       -ServiceAccountOU "OU=Service Accounts,DC=yourdomain,DC=local" -WhatIf
   ```
   This creates `svc-adportal`, `ADPortal-Admins` and `ADPortal-Helpdesk`. Add your IT staff to the two groups.

### 2. Install the portal

**Windows server** (needs Node.js 20+ from nodejs.org). Run this in an elevated PowerShell from the portal folder:

```powershell
.\setup\Install-Portal.ps1 -Port 3200 -OpenFirewall
```

It installs the packages, registers a background task that starts at boot and restarts on failure, and prints the setup token.

**Docker / Kubernetes:**

```bash
docker build -t ad-admin-portal .
docker run -d -p 3200:3200 -v adportal-data:/app/data -v adportal-logs:/app/logs ad-admin-portal
docker logs <container>   # shows the setup token
```

Keep `/app/data` and `/app/logs` on persistent storage, and run a single replica.

### 3. Run the setup wizard

Open `http://<server>:3200`, enter the setup token, then:

1. **Organisation**: enter the name and upload a logo.
2. **Connect to AD**: enter the DC name, service account and password, and optionally your root CA certificate (Base-64). Then click **Test connection & load OUs**.
3. **What the portal manages**: tick the user OUs and group OUs.
4. **Who can use the portal**: pick the admin and helpdesk groups, and tick what helpdesk may do.
5. **New-user defaults**: set the UPN suffix, e-mail domain, username format, default OU, default groups, and the must-change and enabled defaults.
6. **Security**: set the session timeout.

Click **Finish setup** and sign in with an account in the admin group. You can change everything later under **Settings**.

### 4. Use HTTPS

Put the portal behind IIS (ARR), nginx or an ingress with a certificate and set `TRUST_PROXY=true` in `.env`. Alternatively, set `HTTPS_CERT_FILE` / `HTTPS_KEY_FILE`. Keep it on the internal network or VPN.

## Troubleshooting "Test connection"

| Message | Fix |
|---|---|
| Name could not be resolved | Use the DC's full DNS name; check DNS from the portal server |
| Cannot reach the domain controller over LDAPS | Open TCP 636; enable LDAPS (the DC needs a certificate) |
| Certificate does not match the server name | Use the DNS name in the DC's certificate, not the IP |
| Certificate is not trusted | Upload your root CA certificate exported as **Base-64 (.cer)** |
| Service account sign-in failed | Check `user@domain` and the password; make sure the account isn't locked or expired |
| No permission for this action in AD | Re-run `Setup-ADPortalDelegation.ps1` for that OU |

## Files and backups

| Path | Contents |
|---|---|
| `data/settings.json` | Settings saved from the wizard, with the service-account password encrypted |
| `data/.settings-key`, `data/.session-secret` | Auto-generated secrets. Back them up together with `settings.json`. |
| `logs/audit-YYYY-MM.jsonl` | Audit trail, one JSON line per action, hash-chained |
| `data/approvals.json`, `data/mfa.json` | Approval requests; authenticator enrolments (encrypted) |
| `data/.settings-key.dpapi` | Settings key protected with Windows DPAPI (this machine only). Set `SETTINGS_KEY` if settings must move between servers |

`.env` is optional and only needed for server options. See [.env.example](.env.example).

## Project layout

```
src/server.js        Express app, routes, permission checks, auditing
src/settings.js      Settings storage (encrypted), validation, setup token
src/roles.js         Permissions and role mapping
src/audit.js         Audit log writer/reader + CSV export
src/ad/ldap.js       Active Directory over LDAPS (ldapts), connection test/discovery
src/ad/mock.js       In-memory demo directory
public/              Web UI (plain HTML/CSS/JS, no build step)
setup/               AD delegation script, Windows installer
```
