# AD Admin Portal

**by Piersoft**

A web portal for managing Active Directory users and groups from a browser, so IT teams don't need to RDP to the domain controller. Any organisation can install it and configure it from a **setup wizard**, with no code or config-file editing. Each team member signs in with their own domain account, and every action is written to an **audit log** (who did what, to whom, when, from which IP, and whether it worked).

## Features

| Area | What the team can do |
|---|---|
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
| `logs/audit-YYYY-MM.jsonl` | Audit trail, one JSON line per action |

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

© Piersoft
