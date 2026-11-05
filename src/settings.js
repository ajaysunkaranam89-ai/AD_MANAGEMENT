// Settings saved from the web UI: data/settings.json
// The service-account password is encrypted at rest with AES-256-GCM.
// Key: SETTINGS_KEY env var if set, otherwise a random key in data/.settings-key.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config, applySettings, isConfigured, DATA_DIR, MOCK, USERNAME_FORMATS } from './config.js';
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

const key = () => crypto.createHash('sha256').update(process.env.SETTINGS_KEY || secretFile(KEY_FILE)).digest();

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return `enc:v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`;
}

function decrypt(value) {
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
function effective() {
  if (saved) return saved;
  if (draft) return draft;
  if (MOCK) {
    // Demo: the directory is fake, so start with an empty connection form
    return {
      connection: { host: '', port: 636, baseDn: '', bindUser: '', bindPassword: '', caPem: '', rejectUnauthorized: true },
      scope: { userOUs: config.userOUs, groupOUs: config.groupOUs },
      branding: { ...config.branding },
      roles: { adminGroup: config.roleGroups.admin, helpdeskGroup: config.roleGroups.helpdesk, helpdeskPermissions: config.helpdeskPermissions || DEFAULT_HELPDESK },
      provisioning: { upnSuffix: config.upnSuffix, ...config.provisioning },
      session: { timeoutMinutes: config.sessionTimeoutMinutes },
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
  };
}

// Safe to send to the browser: no password
export function publicSettings() {
  const s = JSON.parse(JSON.stringify(effective()));
  s.connection.passwordSet = !!s.connection.bindPassword;
  delete s.connection.bindPassword;
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
  return { branding, connection, scope, roles, provisioning, session: { timeoutMinutes: timeout } };
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
