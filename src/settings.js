// Settings saved from the web UI: data/settings.json
// The service-account password is encrypted at rest with AES-256-GCM.
// Key: SETTINGS_KEY env var if set, otherwise a random key in data/.settings-key.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { config, applySettings, applyCommon, isConfigured, DATA_DIR, MOCK, USERNAME_FORMATS } from './config.js';
import { AdError, text, inScope, normDn } from './ad/common.js';
import { ALL_PERMISSIONS, DEFAULT_HELPDESK, ADMIN_ONLY } from './roles.js';

// Demo mode keeps its own file so it never mixes with a real configuration
const FILE = path.join(DATA_DIR, MOCK ? 'settings-demo.json' : 'settings.json');
const KEY_FILE = path.join(DATA_DIR, '.settings-key');
const SESSION_FILE = path.join(DATA_DIR, '.session-secret');
const TOKEN_FILE = path.join(DATA_DIR, 'setup-token.txt');

fs.mkdirSync(DATA_DIR, { recursive: true });

function secretFile(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  return fs.readFileSync(file, 'utf8').trim();
}

// On Windows the key file is protected with DPAPI (machine scope): a copy of the
// data folder cannot be decrypted on another computer. Set SETTINGS_KEY instead
// if settings must move between servers.
const DPAPI_FILE = path.join(DATA_DIR, '.settings-key.dpapi');

function dpapi(mode, b64) {
  const ps = 'Add-Type -AssemblyName System.Security; $in = [Console]::In.ReadToEnd().Trim(); '
    + `$o = [Security.Cryptography.ProtectedData]::${mode}([Convert]::FromBase64String($in), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine); `
    + '[Convert]::ToBase64String($o)';
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { input: b64, windowsHide: true, timeout: 30000 }).toString().trim();
}

function keyMaterial() {
  if (process.env.SETTINGS_KEY) return process.env.SETTINGS_KEY;
  if (process.platform !== 'win32') return secretFile(KEY_FILE);
  if (fs.existsSync(DPAPI_FILE)) {
    try {
      return Buffer.from(dpapi('Unprotect', fs.readFileSync(DPAPI_FILE, 'utf8')), 'base64').toString('utf8');
    } catch (e) {
      throw new Error(`The settings key is protected for another computer and cannot be unlocked here (${e.message.split('\n')[0]}). Re-run setup or set SETTINGS_KEY.`);
    }
  }
  const plain = secretFile(KEY_FILE);
  try {
    fs.writeFileSync(DPAPI_FILE, dpapi('Protect', Buffer.from(plain).toString('base64')), { mode: 0o600 });
    const back = Buffer.from(dpapi('Unprotect', fs.readFileSync(DPAPI_FILE, 'utf8')), 'base64').toString('utf8');
    if (back === plain) fs.rmSync(KEY_FILE, { force: true }); // only after a successful round trip
    else fs.rmSync(DPAPI_FILE, { force: true });
  } catch (e) {
    fs.rmSync(DPAPI_FILE, { force: true });
    console.error('DPAPI not available, keeping the file-based settings key:', e.message.split('\n')[0]);
  }
  return plain;
}

let cachedKey = null;
const key = () => cachedKey || (cachedKey = crypto.createHash('sha256').update(keyMaterial()).digest());

export function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return `enc:v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
}

export function decrypt(value) {
  if (!value?.startsWith('enc:v1:')) return value || '';
  const [, , iv, tag, ct] = value.split(':');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
}

// In demo (mock) mode the directory is fake, so only the non-AD options take effect.
function apply(s) {
  if (!MOCK) return applySettings(s);
  config.branding = { orgName: s.branding?.orgName || '', logo: s.branding?.logo || '' };
  config.helpdeskPermissions = s.roles?.helpdeskPermissions || null;
  config.sessionTimeoutMinutes = s.session?.timeoutMinutes || config.sessionTimeoutMinutes;
  const { upnSuffix, defaultUserOU, upnSuffixes, ...rest } = s.provisioning || {};
  config.provisioning = { ...config.provisioning, ...rest };
  applyCommon(s);
}

export const sessionSecret =() => process.env.SESSION_SECRET || secretFile(SESSION_FILE);

let saved = null; // last saved settings (password decrypted, in memory only)
let draft = null; // settings entered in demo mode, offered to pre-fill the real setup wizard
let setupToken = null;
const DEMO_FILE = path.join(DATA_DIR, 'settings-demo.json');

export function initSettings() {
  if (fs.existsSync(FILE)) {
    try {
      const raw = JSON.parse(fs.readFileSync(FILE, 'utf8'));
      raw.connection.bindPassword = decrypt(raw.connection.bindPassword);
      if (raw.notifications?.smtpPassword) raw.notifications.smtpPassword = decrypt(raw.notifications.smtpPassword);
      saved = raw;
      apply(saved);
    } catch (e) {
      console.error(`Could not read ${FILE}: ${e.message}. The portal will start in setup mode.`);
    }
  }
  // Settings typed into the demo (npm run mock) are NOT trusted automatically - anyone
  // who knows the demo password could have entered them. They only pre-fill the setup
  // wizard, which still needs the setup token and a review + "Finish setup".
  if (!MOCK && !saved && !config.ldap.url && fs.existsSync(DEMO_FILE)) {
    try {
      const d = JSON.parse(fs.readFileSync(DEMO_FILE, 'utf8'));
      if (d.connection?.host) {
        d.connection.bindPassword = decrypt(d.connection.bindPassword);
        draft = d;
        console.log('Found settings entered in demo mode - they will pre-fill the setup wizard.');
      }
    } catch { /* ignore unreadable draft */ }
  }
  if (!isConfigured()) {
    setupToken = fs.existsSync(TOKEN_FILE) ? fs.readFileSync(TOKEN_FILE, 'utf8').trim() : crypto.randomBytes(9).toString('base64url');
    fs.writeFileSync(TOKEN_FILE, setupToken, { mode: 0o600 });
    console.log('\n================================================================');
    console.log(' AD Admin Portal is not configured yet. Open it in a browser and');
    console.log(' complete the setup. You will be asked for this setup token:');
    console.log(`\n     ${setupToken}\n`);
    console.log(` (also saved in ${TOKEN_FILE})`);
    console.log('================================================================\n');
  }
}

export function checkSetupToken(t) {
  if (!setupToken || !t) return false;
  const a = Buffer.from(String(t).trim());
  const b = Buffer.from(setupToken);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Settings as currently in effect (from the UI file, or derived from .env)
const extras = () => ({
  security: { ...config.security },
  notifications: { ...config.notifications },
  workflow: { ...config.workflow },
  backup: { ...config.backup },
});

function effective() {
  if (saved) return { ...extras(), ...saved };
  if (draft) return { ...extras(), ...draft };
  if (MOCK) {
    // Demo: the directory is fake, so start with an empty connection form
    return {
      connection: { host: '', port: 636, baseDn: '', bindUser: '', bindPassword: '', caPem: '', rejectUnauthorized: true },
      scope: { userOUs: config.userOUs, groupOUs: config.groupOUs },
      branding: { ...config.branding },
      roles: { adminGroup: config.roleGroups.admin, helpdeskGroup: config.roleGroups.helpdesk, helpdeskPermissions: config.helpdeskPermissions || DEFAULT_HELPDESK },
      provisioning: { upnSuffix: config.upnSuffix, ...config.provisioning },
      session: { timeoutMinutes: config.sessionTimeoutMinutes },
      ...extras(),
    };
  }
  const m = config.ldap.url.match(/^ldaps?:\/\/([^:/]+)(?::(\d+))?/i);
  return {
    connection: {
      host: m?.[1] || '', port: Number(m?.[2] || 636), baseDn: config.ldap.baseDn, bindUser: config.ldap.bindDn,
      bindPassword: config.ldap.bindPassword, caPem: config.ldap.caCert && fs.existsSync(config.ldap.caCert) ? fs.readFileSync(config.ldap.caCert, 'utf8') : '',
      rejectUnauthorized: config.ldap.rejectUnauthorized,
    },
    scope: { userOUs: config.userOUs, groupOUs: config.groupOUs },
    branding: { ...config.branding },
    roles: { adminGroup: config.roleGroups.admin, helpdeskGroup: config.roleGroups.helpdesk, helpdeskPermissions: config.helpdeskPermissions || DEFAULT_HELPDESK },
    provisioning: { upnSuffix: config.upnSuffix, ...config.provisioning },
    session: { timeoutMinutes: config.sessionTimeoutMinutes },
    ...extras(),
  };
}

// Safe to send to the browser: no password
export function publicSettings() {
  const s = JSON.parse(JSON.stringify(effective()));
  s.connection.passwordSet = !!s.connection.bindPassword;
  delete s.connection.bindPassword;
  if (s.notifications) { s.notifications.smtpPasswordSet = !!s.notifications.smtpPassword; delete s.notifications.smtpPassword; }
  return { settings: s, source: saved ? 'ui' : draft ? 'demo-draft' : config.ldap.url ? 'env' : 'none', configured: isConfigured(), mock: MOCK };
}

// ---------------------------------------------------------------- validation

const bool = (v, def) => (v === undefined ? def : v === true || v === 'true');
const dn = (v, field) => {
  const s = text(v, field, { max: 512 });
  if (s && !/^[A-Za-z]+=[^,]+(,\s*[A-Za-z]+=[^,]+)*$/.test(s.replace(/\\,/g, ''))) throw new AdError(400, `${field} is not a valid distinguished name`);
  return s;
};
const dnArray = (v, field) => (Array.isArray(v) ? v : []).slice(0, 50).map((x) => dn(x, field)).filter(Boolean);
const hostRe = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;

export function normalizeConnection(input = {}) {
  const prev = effective().connection;
  const host = text(input.host, 'Domain controller', { max: 255, required: true });
  if (!hostRe.test(host)) throw new AdError(400, 'Domain controller must be a host name or IP address (no ldaps://)');
  const port = Number(input.port || 636);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new AdError(400, 'Port must be between 1 and 65535');
  let password = input.bindPassword ? String(input.bindPassword) : '';
  if (!password && prev.bindPassword && normDn(prev.bindUser) === normDn(input.bindUser || '')) password = prev.bindPassword; // keep existing
  if (!password) throw new AdError(400, 'Service account password is required');
  if (password.length > 256) throw new AdError(400, 'Password is too long');
  const caPem = String(input.caPem || '').trim();
  if (caPem && !/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/.test(caPem)) {
    throw new AdError(400, 'CA certificate must be in PEM / Base-64 format (-----BEGIN CERTIFICATE-----)');
  }
  if (caPem.length > 50000) throw new AdError(400, 'CA certificate is too large');
  return {
    host,
    port,
    baseDn: dn(input.baseDn, 'Base DN'),
    bindUser: text(input.bindUser, 'Service account', { max: 512, required: true }),
    bindPassword: password,
    caPem,
    rejectUnauthorized: bool(input.rejectUnauthorized, true),
  };
}

export function normalizeSettings(input = {}, { demo = false } = {}) {
  // Demo mode: the directory is fake, so connection / OUs / groups are optional.
  const need = (cond, msg) => { if (!demo && !cond) throw new AdError(400, msg); };
  const connection = demo && !input.connection?.host
    ? { host: '', port: 636, baseDn: '', bindUser: '', bindPassword: '', caPem: '', rejectUnauthorized: true }
    : normalizeConnection(input.connection);
  if (!demo && !connection.baseDn) throw new AdError(400, 'Base DN is required (use Test connection to detect it)');
  const scope = {
    userOUs: dnArray(input.scope?.userOUs, 'User OU'),
    groupOUs: dnArray(input.scope?.groupOUs, 'Group OU'),
  };
  need(scope.userOUs.length, 'Select at least one OU for users');
  need(scope.groupOUs.length, 'Select at least one OU for groups');
  for (const ou of [...scope.userOUs, ...scope.groupOUs]) {
    if (connection.baseDn && !inScope(ou, [connection.baseDn])) throw new AdError(400, `${ou} is not inside ${connection.baseDn}`);
  }
  const hp = Array.isArray(input.roles?.helpdeskPermissions) ? input.roles.helpdeskPermissions : DEFAULT_HELPDESK;
  const roles = {
    adminGroup: dn(input.roles?.adminGroup, 'Admin group'),
    helpdeskGroup: dn(input.roles?.helpdeskGroup, 'Helpdesk group'),
    helpdeskPermissions: [...new Set(hp.filter((x) => ALL_PERMISSIONS[x] && !ADMIN_ONLY.includes(x)))],
  };
  need(roles.adminGroup, 'Choose the AD group whose members are portal admins');
  for (const [g, label] of [[roles.adminGroup, 'Admin group'], [roles.helpdeskGroup, 'Helpdesk group']]) {
    if (g && connection.baseDn && !inScope(g, [connection.baseDn])) {
      throw new AdError(400, `${label} "${g}" is not in ${connection.baseDn}. Pick a group from this domain (or None for helpdesk).`);
    }
  }
  if (roles.helpdeskGroup && normDn(roles.helpdeskGroup) === normDn(roles.adminGroup)) throw new AdError(400, 'Admin and helpdesk groups must be different');
  const logo = String(input.branding?.logo || '');
  if (logo && !/^data:image\/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(logo)) throw new AdError(400, 'Logo must be a PNG, JPG, WebP or SVG image');
  if (logo.length > 400000) throw new AdError(400, 'Logo is too large (max ~300 KB)');
  const branding = { orgName: text(input.branding?.orgName, 'Organization name', { max: 80 }), logo };

  const p = input.provisioning || {};
  const suffix = (v, f) => { const s = text(v, f, { max: 255 }); if (s && !hostRe.test(s)) throw new AdError(400, `${f} must look like corp.local`); return s; };
  const upnSuffix = suffix(p.upnSuffix, 'UPN suffix');
  need(upnSuffix, 'UPN suffix is required (e.g. corp.local)');
  const defaultUserOU = dn(p.defaultUserOU, 'Default OU');
  if (defaultUserOU && scope.userOUs.length && !inScope(defaultUserOU, scope.userOUs)) throw new AdError(400, 'Default OU for new users must be inside a managed user OU');
  const provisioning = {
    upnSuffix,
    upnSuffixes: (Array.isArray(p.upnSuffixes) ? p.upnSuffixes : []).slice(0, 20).map((x) => suffix(x, 'UPN suffix')).filter(Boolean),
    emailDomain: suffix(p.emailDomain, 'E-mail domain'),
    usernameFormat: USERNAME_FORMATS.includes(p.usernameFormat) ? p.usernameFormat : 'first.last',
    defaultUserOU,
    defaultGroups: (Array.isArray(p.defaultGroups) ? p.defaultGroups : []).slice(0, 30).map((g) => text(g, 'Default group', { max: 64 })).filter(Boolean),
    mustChangeDefault: bool(p.mustChangeDefault, true),
    enabledDefault: bool(p.enabledDefault, true),
  };
  const timeout = Number(input.session?.timeoutMinutes || 30);
  if (!Number.isInteger(timeout) || timeout < 5 || timeout > 480) throw new AdError(400, 'Session timeout must be 5â€“480 minutes');
  return {
    branding, connection, scope, roles, provisioning, session: { timeoutMinutes: timeout },
    security: normalizeSecurity(input.security, connection.baseDn),
    notifications: normalizeNotifications(input.notifications),
    workflow: normalizeWorkflow(input.workflow, scope.userOUs),
    backup: normalizeBackup(input.backup),
  };
}

// ---------------------------------------------------------------- extra sections

const intIn = (v, def, min, max, label) => {
  const n = v === undefined || v === '' ? def : Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new AdError(400, `${label} must be between ${min} and ${max}`);
  return n;
};

function normalizeSecurity(input = {}, baseDn) {
  const prev = effective().security || {};
  const ipAllowlist = (Array.isArray(input.ipAllowlist) ? input.ipAllowlist : String(input.ipAllowlist || '').split(/[\s,;]+/))
    .map((x) => String(x).trim()).filter(Boolean).slice(0, 100);
  for (const e of ipAllowlist) {
    const [ip, bits] = e.split('/');
    const t = net.isIP(ip);
    if (!t || (bits !== undefined && !(Number.isInteger(Number(bits)) && Number(bits) >= 0 && Number(bits) <= (t === 4 ? 32 : 128)))) {
      throw new AdError(400, `"${e}" is not a valid IP address or range (e.g. 10.0.4.0/24)`);
    }
  }
  const excludedOUs = dnArray(input.excludedOUs ?? prev.excludedOUs, 'Excluded OU');
  for (const ou of excludedOUs) if (baseDn && !inScope(ou, [baseDn])) throw new AdError(400, `${ou} is not inside ${baseDn}`);
  return {
    maxFailuresPerUser: intIn(input.maxFailuresPerUser, prev.maxFailuresPerUser ?? 2, 1, 20, 'Failed sign-ins before the portal pauses an account'),
    sessionMaxHours: intIn(input.sessionMaxHours, prev.sessionMaxHours ?? 8, 1, 24, 'Maximum session length (hours)'),
    roleRecheckMinutes: intIn(input.roleRecheckMinutes, prev.roleRecheckMinutes ?? 5, 1, 60, 'Group re-check interval (minutes)'),
    requireMfa: bool(input.requireMfa, prev.requireMfa ?? false),
    ipAllowlist,
    excludedOUs,
    reauthForSettings: bool(input.reauthForSettings, prev.reauthForSettings ?? true),
    syslogHost: (() => {
      const h = text(input.syslogHost ?? prev.syslogHost, 'Syslog server', { max: 255 });
      if (h && !hostRe.test(h) && !net.isIP(h)) throw new AdError(400, 'Syslog server must be a host name or IP address');
      return h;
    })(),
    syslogPort: intIn(input.syslogPort, prev.syslogPort ?? 514, 1, 65535, 'Syslog port'),
    syslogProtocol: input.syslogProtocol === 'tcp' ? 'tcp' : 'udp',
    eventLog: bool(input.eventLog, prev.eventLog ?? false),
  };
}

function normalizeNotifications(input = {}) {
  const prev = effective().notifications || {};
  const enabled = bool(input.enabled, prev.enabled ?? false);
  const email = (v, label) => {
    const s = text(v, label, { max: 254 });
    if (s && !/^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$/.test(s)) throw new AdError(400, `${label} is not a valid e-mail address`);
    return s;
  };
  const smtpHost = text(input.smtpHost, 'SMTP server', { max: 255 });
  if (smtpHost && !hostRe.test(smtpHost)) throw new AdError(400, 'SMTP server must be a host name or IP address');
  const out = {
    enabled,
    smtpHost,
    smtpPort: intIn(input.smtpPort, prev.smtpPort ?? 587, 1, 65535, 'SMTP port'),
    smtpSecure: bool(input.smtpSecure, prev.smtpSecure ?? false),
    smtpUser: text(input.smtpUser, 'SMTP user', { max: 255 }),
    smtpPassword: input.smtpPassword ? String(input.smtpPassword).slice(0, 256) : (prev.smtpPassword || ''),
    from: email(input.from, 'From address'),
    itMailbox: email(input.itMailbox, 'IT mailbox'),
    notifyManager: bool(input.notifyManager, prev.notifyManager ?? true),
    events: (Array.isArray(input.events) ? input.events : prev.events || []).filter((x) => NOTIFY_EVENTS.includes(x)),
  };
  if (enabled && (!out.smtpHost || !out.from || !out.itMailbox)) throw new AdError(400, 'E-mail notifications need an SMTP server, a From address and an IT mailbox');
  return out;
}
export const NOTIFY_EVENTS = ['user.create', 'user.resetPassword', 'user.unlock', 'user.enable', 'user.offboard', 'user.delete', 'group.addMember', 'group.removeMember', 'approval.requested'];

function normalizeWorkflow(input = {}, userOUs = []) {
  const prev = effective().workflow || {};
  const leaverOU = dn(input.leaverOU ?? prev.leaverOU, 'Leavers OU');
  if (leaverOU && userOUs.length && !inScope(leaverOU, userOUs)) throw new AdError(400, 'The leavers OU must be inside a managed user OU');
  return {
    leaverOU,
    approvalActions: (Array.isArray(input.approvalActions) ? input.approvalActions : prev.approvalActions || []).filter((x) => APPROVAL_ACTIONS.includes(x)),
  };
}
export const APPROVAL_ACTIONS = ['user.delete', 'group.delete', 'user.offboard', 'user.move', 'group.addMember'];

function normalizeBackup(input = {}) {
  const prev = effective().backup || {};
  const folder = text(input.folder ?? prev.folder, 'Backup folder', { max: 400 });
  if (folder && !path.isAbsolute(folder)) throw new AdError(400, 'Backup folder must be a full path, e.g. D:\\Backups\\ADPortal or \\\\server\\share\\ADPortal');
  const enabled = bool(input.enabled, prev.enabled ?? false);
  if (enabled && !folder) throw new AdError(400, 'Choose a backup folder');
  return { enabled, folder, keep: intIn(input.keep, prev.keep ?? 14, 1, 365, 'Backups to keep') };
}

export const toLdapConn = (c) => ({
  url: `ldaps://${c.host}:${c.port || 636}`,
  caPem: c.caPem,
  rejectUnauthorized: c.rejectUnauthorized,
  baseDn: c.baseDn,
  bindDn: c.bindUser,
  bindPassword: c.bindPassword,
});

export function saveSettings(s) {
  const toDisk = JSON.parse(JSON.stringify(s));
  toDisk.connection.bindPassword = encrypt(s.connection.bindPassword);
  if (s.notifications?.smtpPassword) toDisk.notifications.smtpPassword = encrypt(s.notifications.smtpPassword);
  toDisk.savedAt = new Date().toISOString();
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(toDisk, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, FILE);
  saved = s;
  draft = null;
  apply(s);
  if (setupToken && isConfigured()) {
    setupToken = null;
    fs.rmSync(TOKEN_FILE, { force: true });
  }
}

// Summary for the audit log (never includes the password)
export function settingsSummary(s, before) {
  const sum = {
    server: `${s.connection.host}:${s.connection.port}`,
    baseDn: s.connection.baseDn,
    serviceAccount: s.connection.bindUser,
    userOUs: s.scope.userOUs,
    groupOUs: s.scope.groupOUs,
    adminGroup: s.roles.adminGroup,
    helpdeskGroup: s.roles.helpdeskGroup,
    helpdeskPermissions: s.roles.helpdeskPermissions,
    orgName: s.branding.orgName,
    logoChanged: before ? (before.branding?.logo || '') !== (s.branding.logo || '') : undefined,
    provisioning: s.provisioning,
    sessionTimeoutMinutes: s.session.timeoutMinutes,
  };
  if (before) {
    sum.passwordChanged = before.connection.bindPassword !== s.connection.bindPassword;
    sum.caChanged = (before.connection.caPem || '') !== (s.connection.caPem || '');
  }
  return sum;
}

export const currentSaved = () => effective();
