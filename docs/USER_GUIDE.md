# AD Admin Portal – User Guide

This guide is for the IT staff who use the portal every day: **admins** and **helpdesk** users. For installation and first-time setup, see the [README](../README.md).

---

## Contents

1. [Signing in](#1-signing-in)
2. [Roles and permissions](#2-roles-and-permissions)
3. [Dashboard](#3-dashboard)
4. [Users](#4-users)
5. [Groups](#5-groups)
6. [Bulk actions and CSV import](#6-bulk-actions-and-csv-import)
7. [Reports](#7-reports)
8. [Approvals](#8-approvals)
9. [Audit log](#9-audit-log)
10. [Settings (admins)](#10-settings-admins)
11. [Safety rules you will notice](#11-safety-rules-you-will-notice)
12. [Troubleshooting and FAQ](#12-troubleshooting-and-faq)

---

## 1. Signing in

1. Open the portal address your IT team gave you, for example `https://adportal.company.local`.
2. Enter your **own domain username** (`john.smith`, `DOMAIN\john.smith` or `john.smith@company.local`) and your **normal Windows password**. The portal has no separate accounts or passwords.
3. If **two-step sign-in** is switched on, you also enter a 6-digit code from an authenticator app (see below).

You can only sign in if you are a member of the portal's **admin** or **helpdesk** AD group. Otherwise you'll see *"You are not authorised to use this portal"*. Ask an admin to add you to the right group.

### Two-step sign-in (authenticator app)

The first time you sign in after it is switched on:

1. Install an authenticator app on your phone, for example **Microsoft Authenticator** or **Google Authenticator**.
2. Scan the **QR code** shown by the portal. If you can't scan it, choose *Can't scan? Enter this key instead*.
3. Type the 6-digit code from the app and click **Confirm and sign in**.

From then on, the portal asks for a code after your password each time you sign in. If you lose or change your phone, ask an admin to **reset your two-step sign-in** (Settings → Security). You will then set it up again at your next sign-in.

### Sessions

- You are signed out after a period of **inactivity** (default 30 minutes).
- You are also signed out after a **maximum session length** (default 8 hours), even if you are active.
- If you are removed from the portal groups, you lose access within a few minutes, even if you are signed in.

### Wrong password protection

After **2 wrong passwords** for the same account, the portal pauses sign-in for that account for 15 minutes **without trying the password against Active Directory**. This stops the portal from ever locking your AD account. You can still sign in to Windows as normal during the pause.

---

## 2. Roles and permissions

Access is controlled by **AD group membership**, chosen by an admin in **Settings → Who can use the portal**. Nested groups count.

| Role | Who | What they can do |
|---|---|---|
| **Admin** | Members of the admin group | Everything, including Settings, approving requests, the audit log, resetting two-step sign-in, and backups |
| **Helpdesk** | Members of the helpdesk group (optional) | Only the permissions an admin ticks in **Settings → Role permissions** |

### Permission list

| Permission | Meaning | Helpdesk default |
|---|---|:-:|
| View users | Search and open user accounts | ✔ |
| View groups | Search and open groups | ✔ |
| Reset passwords | Set a new password, optionally forcing a change at next sign-in | ✔ |
| Unlock accounts | Clear an AD lockout | ✔ |
| Enable / disable users | Turn an account on or off | ✔ |
| Create users | New user form | |
| Edit user details | Name, title, department, phone, manager, expiry… | |
| Move users between OUs | Change the OU | |
| Delete users | Permanently delete (consider Offboard instead) | |
| Offboard leavers | Disable, remove groups, scramble password, move to leavers OU | |
| Bulk import users from CSV | Create many accounts from a file | |
| Create / edit / delete groups | Group management | |
| Add / remove group members | Change membership | |
| View & export reports | Reports page | |
| View & export audit log | Audit log page | |
| Approve or reject requests | Four-eyes approvals | admin only |
| Change portal settings | Settings page | admin only |

### Limits that apply to helpdesk users

Helpdesk users can **never**:

- change the account of a **portal admin** (reset, disable, edit, move, delete, offboard);
- change the portal's **admin or helpdesk groups**, or any group nested inside the admin group;
- open Settings or approve requests.

These rules are enforced on the server. Hiding a button is not what protects them.

---

## 3. Dashboard

The home page shows:

- **Totals**: all users, enabled, disabled, **locked out now**, no sign-in for 90+ days, and groups. Click *Total users* or *Groups* to open the list.
- **Locked accounts**, with an **Unlock** button next to each, live from AD.
- **Recent changes** (admins): the latest actions from the audit log.

---

## 4. Users

### Finding someone

- Type in the search box: **name, username, e-mail or employee ID**. Words can be in any order, so `smith john` finds *John Smith*.
- Use the filter to show **Enabled**, **Disabled** or **Locked** accounts only.
- Click a row to open the account on the right.

Status badges in the list:

| Badge | Meaning |
|---|---|
| Enabled / Disabled | Whether the account can sign in |
| Locked | Locked out by AD after wrong passwords; an **Unlock** button appears |
| Password expired / Must change password | Password state |
| Protected | Privileged account (e.g. Domain Admins member). It can be viewed and unlocked; other changes must be made on a domain controller |
| Service | Looks like a service account (registered service name, or an enabled account whose password never expires). Risky changes ask you to type the username |
| Expired | Contractor/temporary account past its end date |

### Account actions

Open a user, then use the buttons at the top:

| Button | What it does |
|---|---|
| **Reset password** | A strong password is generated (you can type your own). Tick *must change at next sign-in* and *unlock*. The new password is shown **once**; give it to the person by phone or in person, never by e-mail |
| **Unlock** | Clears an AD lockout. Shown only when the account is locked |
| **Disable / Enable** | Stops or allows sign-in |
| **Edit** | Profile fields, **Manager**, and **Account expires after** (last working day for contractors) |
| **Move** | Move to another OU. Group Policies of the new OU will apply |
| **Offboard** | Leaver process (see below). Keeps the account so it can be restored |
| **Delete** | Permanently deletes the account. You must type the username. If the AD Recycle Bin is enabled, a domain admin can still restore it |

Under **Groups** you can remove the user from a group (✕) or add them to another: start typing a group name and pick it from the list.

### Creating a user

**Users → + New user**:

1. Type the first and last name. The **display name**, **username** (using your organisation's format, e.g. `first.last`) and **e-mail** are filled in for you; you can change them.
2. Choose the **OU**. Your default OU is pre-selected.
3. A strong **initial password** is generated. Keep *must change at next sign-in* ticked.
4. Optional: job title, department, phone, **manager**, and **account expiry** (contractors).
5. Tick the **groups**. Default groups are pre-selected, and you can search the list.
6. Click **Create user** and give the shown password to the person securely.

### Offboarding a leaver

**Offboard** does the standard leaver steps in one go:

1. Disables the account.
2. Changes the password to a random value nobody knows (optional).
3. Removes the account from all groups the portal manages. Protected groups stay and are listed.
4. Writes *"Left – offboarded YYYY-MM-DD by &lt;you&gt;"* into the description.
5. Moves the account to the **leavers OU**, if one is set in Settings → Workflow.

You must type the username to confirm. The result lists every step.

---

## 5. Groups

- Search by group name or description, and click a group to see its **members**.
- **Add member**: type a person's **name**, username or a group name, then pick from the list.
- **Remove member**: ✕ next to the member.
- **+ New group**: name, OU, scope (Global / Domain local / Universal), type (Security / Distribution), description.
- **Edit** changes the description, e-mail and notes. **Delete** requires typing the group name.

Groups that are protected (e.g. Domain Admins, DnsAdmins), outside the managed OUs, or that control access to the portal itself are **read-only** here.

---

## 6. Bulk actions and CSV import

### Bulk actions

1. On **Users**, tick the boxes in front of several users, or tick the header box to select all shown.
2. A blue bar appears: **Unlock**, **Enable**, **Disable**, **Move…** or **Offboard…**.
3. For disable, move and offboard you must type the **number of users** to confirm. Service accounts are skipped unless you tick *Also apply to service accounts*.
4. A result list shows *Done*, *Pending* (sent for approval) or *Failed* for each user.

### Importing new users from CSV

**Users → Import CSV**:

1. Click **Download template** and fill it in (Excel can save as CSV). One row per person; only a name is required.
   Supported columns: First name, Last name, Username, E-mail, Job title, Department, Employee ID, Mobile, Manager (username), Expires (YYYY-MM-DD or DD/MM/YYYY), Groups (separate several with `;`), OU.
2. Choose the defaults for every row: OU, groups, must change password, enabled.
3. Choose the file. A **preview** checks every row (missing name, invalid or duplicate username, bad date). Rows with problems are skipped.
4. Click **Create N user(s)**.
5. Click **Download passwords (CSV)** straight away. Initial passwords are shown **only once** and are not stored anywhere. Hand them over securely and delete the file afterwards.

Up to 500 rows can be imported at a time.

---

## 7. Reports

**Reports** answers common account-hygiene questions. Pick a report, adjust **N days** where shown, and click **Run**. Click **Export CSV (Excel)** to save it.

| Report | Use it to… |
|---|---|
| No sign-in for N days | Find unused accounts to disable |
| Never signed in | Find accounts created but never used |
| Password not changed for N days | Spot stale passwords |
| Password never expires | Review exceptions to the password policy |
| Must change password at next sign-in | Accounts waiting for their first sign-in |
| Accounts expiring in the next N days | Contractors whose end date is near |
| Expired accounts that are still enabled | Clean-up |
| Disabled accounts / Locked out now | Status overviews |
| Service-like accounts / Protected accounts | Reviews for security audits |
| All users | Full export |
| Members of a group | Membership list for an access review |

*Last sign-in* comes from AD's replicated `lastLogonTimestamp`, which can be up to 14 days behind.

---

## 8. Approvals

An admin can decide that some actions need a **second admin** (Settings → Workflow), for example **Delete a user**, **Delete a group**, **Offboard**, **Move to another OU**, or **Add someone to a group**.

- When you do such an action, it is **not** carried out straight away. You see *"Sent for approval"* and the request appears under **Approvals**.
- Another admin opens **Approvals**, reads the request, and clicks **Approve** (the action runs immediately in AD) or **Reject**, optionally with a note.
- You **cannot approve your own request**. You can **Cancel** it while it is waiting.
- The number on the **Approvals** menu item shows how many requests are waiting.
- Requests expire after 7 days. History is kept for 90 days, and every step is in the audit log.

---

## 9. Audit log

Every action is recorded: who, what, which account, when, from which computer, and whether it worked. That includes failed attempts and sign-ins.

- **Filter** by text, person, action, result and date, then click **Apply**.
- **Export CSV** saves the filtered entries.
- **Verify integrity** checks that no entry was changed or deleted. Each entry is chained to the previous one with a fingerprint, so any edit breaks the chain and is reported with the file and line.
- Click *Full details* on a row to see before/after values (e.g. which fields were edited).

Passwords are **never** written to the audit log or included in e-mails.

---

## 10. Settings (admins)

Saving Settings asks for **your password again**. The connection, OUs and groups are checked against AD before anything is saved, and the portal refuses changes that would lock you out.

| Section | What you set |
|---|---|
| 1. Organization | Company name and logo shown on the sign-in page and menu |
| 2. Connect to Active Directory | Domain controller, service account, root CA certificate, certificate checking. **Test connection & load OUs** confirms everything works |
| 3. What the portal manages | **User OUs**, **Group OUs** and **Excluded OUs** (never touched, e.g. admin or service-account OUs). *Entire domain* is available |
| 4. Who can use the portal | **Admin group**, **helpdesk group**, and the **role permissions** table |
| 5. New-user defaults | UPN suffix, e-mail domain, username format, default OU, default groups, must-change and enabled defaults |
| 6. Security | Inactivity timeout, maximum session length, group re-check interval, failed sign-ins before pausing, **require two-step sign-in**, **IP allow-list**, password re-entry, syslog/SIEM and Windows Event Log. Includes the list of people with an authenticator set up, with a **Reset** button |
| 7. E-mail notifications | SMTP server, From address, IT mailbox, *also e-mail the manager*, which events to send, and **Send test e-mail** |
| 8. Workflow | **Leavers OU** for Offboard, and which actions **need approval** |
| 9. Backup | Daily backup folder (local or network share), how many to keep, and **Back up now** |

Tips:

- Keep *failed sign-ins before pausing* **below** your AD lockout threshold.
- Before switching on **two-step sign-in**, tell your team: everyone sets up an authenticator at their next sign-in.
- When adding an **IP allow-list**, include your own network. Saving refuses a list that excludes you.

---

## 11. Safety rules you will notice

| You see | Why |
|---|---|
| *"Protected (privileged) AD object"* | Domain Admins and similar accounts and groups can only be changed on a domain controller. You can still **unlock** protected accounts |
| *"Type the username to confirm"* | The account looks like a **service account**; changing it can break applications |
| *"Only portal admins can change a portal admin's account"* | Helpdesk users can't take over admin accounts |
| *"You cannot disable/delete your own account"* | Prevents accidental self-lockout |
| *"Sent for approval"* | This action needs a second admin (see [Approvals](#8-approvals)) |
| Items missing from lists | They are outside the managed OUs or inside an excluded OU |

---

## 12. Troubleshooting and FAQ

**I can't sign in: "Invalid username or password".**
Check the username and your Windows password. After 2 wrong attempts the portal pauses for 15 minutes; this doesn't lock your AD account.

**"You are not authorised to use this portal".**
Your account is not in the portal's admin or helpdesk group. Ask an admin.

**"Your password has expired or must be changed".**
Change it on your PC (Ctrl+Alt+Del → Change a password), then sign in again.

**I lost my phone with the authenticator app.**
Ask an admin: Settings → Security → *Authenticator apps set up* → **Reset** next to your name.

**I was signed out unexpectedly.**
You were inactive too long, reached the maximum session length, two-step sign-in was just switched on, or your group membership changed.

**A user is locked again right after I unlocked them.**
Something is still trying an old password: a phone mail app, mapped drive, saved credentials or a scheduled task. Fix that device; the portal can't.

**Password reset says it doesn't meet the domain policy.**
Use the **Generate** button, or make it longer and more complex. The domain may also block recently used passwords.

**I can't find a user or group.**
It may be outside the managed OUs, in an excluded OU, or (for groups) protected. Ask an admin to check Settings → What the portal manages.

**"The service account does not have permission for this action in AD".**
The portal's service account lacks delegated rights on that OU. An admin should re-run `setup\Setup-ADPortalDelegation.ps1` for it.

**The page shows "Not secure".**
The portal is being used over plain HTTP. Ask the administrator to enable HTTPS (`setup\New-PortalCertificate.ps1`).

**Where do I see who changed something?**
**Audit log**: search for the account name, then open *Full details* for before/after values.
