import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config, MOCK, isConfigured, USERNAME_FORMATS } from './config.js';
import { can, permissionsFor, ALL_PERMISSIONS, DEFAULT_HELPDESK, ADMIN_ONLY } from './roles.js';
import { audit, queryAudit, toCsv } from './audit.js';
import { AdError, cleanUserFields, text, userSam, groupSam, password as checkPassword, normDn } from './ad/common.js';
import QRCode from 'qrcode';
import crypto from 'node:crypto';
import { notify, sendMail, EVENT_LABELS } from './notify.js';
import { createRequest, listRequests, getRequest, decide, pendingCount } from './approvals.js';
import { runBackup, lastBackup, startBackupSchedule } from './backup.js';
import { verifyAudit } from './audit.js';
import {
  accountKey, throttleCheck, throttleFail, throttleReset, ipAllowed,
  newTotpSecret, verifyTotp, otpauthUrl, mfaRecord, mfaEnroll, mfaUsed, mfaReset, mfaList,
} from './security.js';
import {
  initSettings, sessionSecret, checkSetupToken, publicSettings, normalizeConnection, normalizeSettings,
  toLdapConn, saveSettings, settingsSummary, currentSaved,
} from './settings.js';

initSettings(); // must run before the directory module reads config
const { directory: ad } = MOCK ? await import('./ad/mock.js') : await import('./ad/ldap.js');
const { directory: ldapDirectory } = await import('./ad/ldap.js'); // used by "Test connection" (also in demo mode)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const useHttps = !!((config.httpsCert && config.httpsKey) || config.httpsPfx);

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: { upgradeInsecureRequests: useHttps || config.trustProxy ? [] : null },
  },
  hsts: useHttps || config.trustProxy,
}));
// IP allow-list (Settings → Security). The server's own loopback is always allowed.
app.use((req, res, next) => {
  if (ipAllowed(req.ip)) return next();
  const msg = 'Access to the AD Admin Portal is not allowed from your network address.';
  if (req.path.startsWith('/api')) return res.status(403).json({ error: msg });
  res.status(403).type('text').send(msg);
});

const smallJson = express.json({ limit: '50kb' });
const settingsJson = express.json({ limit: '1mb' }); // settings may carry a logo + CA certificate
app.use((req, res, next) => (req.path.startsWith('/api/settings') ? settingsJson : smallJson)(req, res, next));
app.use(session({
  name: 'adportal.sid',
  secret: sessionSecret(),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: useHttps || config.trustProxy,
    maxAge: config.sessionTimeoutMinutes * 60 * 1000,
  },
}));

// CSRF defence: state-changing API calls must carry a custom header (browsers
// won't send it cross-site without CORS, and we allow no CORS) + SameSite=Strict cookie.
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.get('X-Requested-With') !== 'ad-portal') {
    return res.status(403).json({ error: 'Missing request header' });
  }
  res.set('Cache-Control', 'no-store');
  // Session idle timeout is configurable at runtime
  if (req.session?.user) req.session.cookie.maxAge = config.sessionTimeoutMinutes * 60 * 1000;
  // Until the portal is configured, only setup endpoints work
  if (!isConfigured() && !['/info', '/settings', '/settings/test'].includes(req.path)) {
    return res.status(503).json({ error: 'The portal is not configured yet. Complete the setup first.', setupRequired: true });
  }
  next();
});

// Serve index.html with versioned asset links so browsers always load the
// current app.js / app.css after an update (no stale UI from the cache).
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
function sendIndex(req, res) {
  const v = ['app.js', 'app.css'].map((f) => fs.statSync(path.join(PUBLIC_DIR, f)).mtimeMs.toString(36)).join('');
  const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8').replace(/(app\.(?:css|js))"/g, `$1?v=${v}"`);
  res.set('Cache-Control', 'no-cache');
  res.type('html').send(html);
}
app.get(['/', '/index.html'], sendIndex);
app.use(express.static(PUBLIC_DIR, { index: false }));

// ------------------------------------------------------------------ helpers

function sendError(res, e) {
  const status = e instanceof AdError ? e.status : 500;
  if (!(e instanceof AdError)) console.error(e);
  res.status(status).json({ error: e instanceof AdError ? e.message : 'Unexpected server error' });
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please sign in.' });
  next();
}

function requirePerm(perm) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ error: 'Please sign in.' });
    if (!can(req.session.user.role, perm)) return res.status(403).json({ error: 'Your role is not allowed to do this.' });
    next();
  };
}

// Read-only handler
const read = (perm, fn) => [requirePerm(perm), async (req, res) => {
  try { res.json(await fn(req)); } catch (e) { sendError(res, e); }
}];

// Change handler: always writes an audit entry, success or failure.
const change = (perm, action, targetOf, fn) => [requirePerm(perm), async (req, res) => {
  let target = '';
  try {
    target = targetOf(req);
    const r = (await fn(req)) || {};
    audit(req, action, r.target || target, { details: r.details });
    res.json({ ok: true, ...(r.body || {}) });
  } catch (e) {
    audit(req, action, target, { result: 'failure', error: e.message });
    sendError(res, e);
  }
}];

const self = (req, sam) => req.session.user.sam.toLowerCase() === String(sam).toLowerCase();
const bool = (v) => v === true || v === 'true';
const isAdmin = (req) => req.session.user?.role === 'admin';
const isRoleGroup = (dn) => [config.roleGroups.admin, config.roleGroups.helpdesk].filter(Boolean).some((g) => normDn(g) === normDn(dn));

// Escalation guards: a non-admin portal role (helpdesk) must not be able to take
// over a portal admin's account or grant itself admin rights through a group.
// Also: service-like accounts (password never expires / SPN) need the username typed
// as confirmation, because changing them can break applications.
async function guardUserTarget(req, sam, { confirm = false } = {}) {
  const u = await ad.getUser(sam);
  if (!isAdmin(req) && await ad.isMemberOf(u.dn, config.roleGroups.admin)) {
    throw new AdError(403, "Only portal admins can change a portal admin's account.");
  }
  if (confirm && u.serviceAccount && !req.approvalContext
    && String(req.body?.confirmServiceAccount || '').trim().toLowerCase() !== u.sam.toLowerCase()) {
    throw new AdError(428, `${u.sam} looks like a service account (password never expires or it has a service principal name). Changing it can break applications - type the username to confirm.`);
  }
  return u;
}

async function guardGroupTarget(req, sam, { deleting = false } = {}) {
  const g = await ad.getGroup(sam);
  if (isRoleGroup(g.dn)) {
    if (deleting) throw new AdError(400, 'This group controls access to the portal. Choose a different group in Settings before deleting it.');
    if (!isAdmin(req)) throw new AdError(403, 'Only portal admins can change the portal access groups.');
  }
  // a group nested inside the admin group grants admin rights too
  if (!isAdmin(req) && await ad.isMemberOf(g.dn, config.roleGroups.admin)) {
    throw new AdError(403, 'This group grants portal admin rights; only portal admins can change it.');
  }
}

// ------------------------------------------------------------------ auth

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts from this computer. Try again in 15 minutes.' },
});

async function roleFor(dn) {
  if (await ad.isMemberOf(dn, config.roleGroups.admin)) return 'admin';
  if (config.roleGroups.helpdesk && await ad.isMemberOf(dn, config.roleGroups.helpdesk)) return 'helpdesk';
  return null;
}

function startSession(req, res, u, role, viaMfa) {
  req.session.regenerate((err) => {
    if (err) return sendError(res, err);
    const now = Date.now();
    req.session.user = { sam: u.sam, dn: u.dn, displayName: u.displayName, role, loginAt: now, checkedAt: now, mfa: !!viaMfa };
    audit(req, 'login', u.sam, { details: viaMfa ? { mfa: true } : undefined });
    res.json({ ok: true });
  });
}

const pausedMsg = (mins) => `Too many failed sign-ins for this account. Try again in ${mins} minute${mins === 1 ? '' : 's'}. (The portal pauses before Active Directory would lock the account.)`;

app.post('/api/login', loginLimiter, async (req, res) => {
  const username = String(req.body?.username || '').trim().slice(0, 100);
  const account = accountKey(username);
  const wait = throttleCheck(account);
  if (wait) {
    audit(req, 'login', username, { result: 'failure', error: 'Paused after repeated failed sign-ins' });
    return res.status(429).json({ error: pausedMsg(wait) });
  }
  try {
    const u = await ad.authenticate(username, String(req.body?.password || ''));
    throttleReset(account);
    const role = await roleFor(u.dn);
    if (!role) {
      audit(req, 'login', u.sam, { result: 'failure', error: 'Not a member of a portal role group' });
      return res.status(403).json({ error: 'You are not authorised to use this portal. Ask an administrator to add you to the portal admin or helpdesk group.' });
    }
    if (!config.security.requireMfa) return startSession(req, res, u, role, false);

    // Second step: authenticator-app code (enrol on first sign-in)
    const rec = mfaRecord(accountKey(u.sam));
    const pending = { sam: u.sam, dn: u.dn, displayName: u.displayName, role, at: Date.now(), tries: 0 };
    if (!rec) pending.newSecret = newTotpSecret();
    req.session.regenerate(async (err) => {
      if (err) return sendError(res, err);
      req.session.pendingMfa = pending;
      if (rec) return res.json({ mfa: 'verify' });
      const qr = await QRCode.toString(otpauthUrl(pending.newSecret, u.sam), { type: 'svg', margin: 1, width: 200 });
      res.json({ mfa: 'enroll', secret: pending.newSecret, qr });
    });
  } catch (e) {
    if (e instanceof AdError && e.status === 401 && /Invalid username or password/.test(e.message)) throttleFail(account);
    audit(req, 'login', username, { result: 'failure', error: e.message });
    sendError(res, e);
  }
});

const mfaLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });

app.post('/api/login/mfa', mfaLimiter, (req, res) => {
  const p = req.session.pendingMfa;
  if (!p || Date.now() - p.at > 5 * 60 * 1000) {
    delete req.session.pendingMfa;
    return res.status(401).json({ error: 'The sign-in took too long. Please start again.', restart: true });
  }
  p.tries++;
  if (p.tries > 5) {
    delete req.session.pendingMfa;
    audit(req, 'login.mfa', p.sam, { result: 'failure', error: 'Too many wrong codes', actor: p.sam });
    return res.status(401).json({ error: 'Too many wrong codes. Please start again.', restart: true });
  }
  const acct = accountKey(p.sam);
  const rec = mfaRecord(acct);
  const step = verifyTotp(rec ? rec.secret : p.newSecret, req.body?.code, rec ? rec.lastStep : -1);
  if (step === null) {
    audit(req, 'login.mfa', p.sam, { result: 'failure', error: 'Wrong code', actor: p.sam });
    return res.status(401).json({ error: 'That code is not correct. Check that the time on your phone is right and try again.' });
  }
  if (rec) mfaUsed(acct, step);
  else { mfaEnroll(acct, p.newSecret, step); audit(req, 'mfa.enroll', p.sam, { actor: p.sam }); }
  delete req.session.pendingMfa;
  startSession(req, res, { sam: p.sam, dn: p.dn, displayName: p.displayName }, p.role, true);
});

app.post('/api/logout', (req, res) => {
  if (req.session.user) audit(req, 'logout', req.session.user.sam);
  req.session.destroy(() => {
    res.clearCookie('adportal.sid');
    res.json({ ok: true });
  });
});

// Session rules on every API call: absolute lifetime, periodic group re-check,
// and MFA if it was switched on after the session started.
app.use('/api', async (req, res, next) => {
  const u = req.session?.user;
  if (!u) return next();
  const end = (reason, message) => {
    audit(req, 'logout', u.sam, { details: { reason } });
    req.session.destroy(() => res.status(401).json({ error: message }));
  };
  const now = Date.now();
  if (now - (u.loginAt || 0) > config.security.sessionMaxHours * 3600000) return end('maximum session length reached', 'Your session has ended. Please sign in again.');
  if (config.security.requireMfa && !u.mfa) return end('MFA now required', 'Sign-in with an authenticator code is now required. Please sign in again.');
  if (now - (u.checkedAt || 0) > config.security.roleRecheckMinutes * 60000) {
    try {
      const role = await roleFor(u.dn);
      if (!role) return end('removed from portal access groups', 'Your access to this portal has been removed.');
      u.role = role;
      u.checkedAt = now;
    } catch { /* directory unreachable: keep the session and retry on the next request */ }
  }
  next();
});

app.get('/api/info', (req, res) => res.json({
  mock: MOCK,
  configured: isConfigured(),
  orgName: config.branding.orgName,
  logo: config.branding.logo,
}));

app.get('/api/me', requireLogin, (req, res) => {
  const { sam, displayName, role, loginAt } = req.session.user;
  const p = config.provisioning;
  res.json({
    sam, displayName, role, permissions: permissionsFor(role), mock: MOCK,
    upnSuffix: config.upnSuffix || 'corp.local',
    sessionEndsAt: new Date((loginAt || Date.now()) + config.security.sessionMaxHours * 3600000).toISOString(),
    reauthForSettings: config.security.reauthForSettings,
    approvalActions: config.workflow.approvalActions,
    leaverOU: config.workflow.leaverOU,
    pendingApprovals: can(role, 'approvals.approve') ? pendingCount() : 0,
    provisioning: {
      upnSuffixes: [...new Set([config.upnSuffix, ...(p.upnSuffixes || [])].filter(Boolean))],
      emailDomain: p.emailDomain, usernameFormat: p.usernameFormat, defaultUserOU: p.defaultUserOU,
      defaultGroups: p.defaultGroups, mustChangeDefault: p.mustChangeDefault, enabledDefault: p.enabledDefault,
    },
  });
});

// MFA enrolments (admins can reset a lost phone)
app.get('/api/mfa', ...read('settings.manage', () => mfaList()));
app.delete('/api/mfa/:account', ...change('settings.manage', 'mfa.reset', (req) => req.params.account, async (req) => {
  const acct = accountKey(text(req.params.account, 'Account', { max: 64, required: true }));
  if (!mfaReset(acct)) throw new AdError(404, 'That account has no authenticator enrolled.');
}));

// ------------------------------------------------------------------ settings / first-run setup

const settingsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 40,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
});

// Before setup: anyone holding the setup token (shown in the server console).
// After setup: signed-in admins only.
function settingsAuth(req, res, next) {
  if (!isConfigured()) {
    if (!checkSetupToken(req.get('X-Setup-Token'))) {
      audit(req, 'settings.setupToken', '', { result: 'failure', error: 'Invalid setup token' });
      return res.status(403).json({ error: 'Invalid setup token. It is printed in the server console and saved in data/setup-token.txt.', setupToken: true });
    }
    return next();
  }
  return requirePerm('settings.manage')(req, res, next);
}

app.get('/api/settings', settingsLimiter, settingsAuth, (req, res) => {
  res.json({
    ...publicSettings(),
    permissions: ALL_PERMISSIONS,
    adminOnly: ADMIN_ONLY,
    defaultHelpdesk: DEFAULT_HELPDESK,
    usernameFormats: USERNAME_FORMATS,
  });
});

app.post('/api/settings/test', settingsLimiter, settingsAuth, async (req, res) => {
  try {
    const conn = normalizeConnection(req.body?.connection);
    const r = await ldapDirectory.probe(toLdapConn(conn));
    audit(req, 'settings.test', `${conn.host}:${conn.port}`, { details: { baseDn: r.baseDn, server: r.server } });
    res.json(r);
  } catch (e) {
    audit(req, 'settings.test', String(req.body?.connection?.host || ''), { result: 'failure', error: e.message });
    sendError(res, e);
  }
});

app.post('/api/settings', settingsLimiter, settingsAuth, async (req, res) => {
  const firstRun = !isConfigured();
  try {
    // Re-enter your password before changing how the portal connects / who may use it
    if (!firstRun && config.security.reauthForSettings) {
      const me = req.session.user;
      const acct = accountKey(me.sam);
      const wait = throttleCheck(acct);
      if (wait) throw new AdError(429, pausedMsg(wait));
      try {
        await ad.authenticate(me.sam, String(req.body?.currentPassword || ''));
        throttleReset(acct);
      } catch (e) {
        if (e instanceof AdError && e.status === 401) {
          throttleFail(acct);
          throw new AdError(403, 'Your password is not correct. Settings were not saved.'); // 403, not 401: keep the session
        }
        throw e;
      }
    }
    const s = normalizeSettings(req.body?.settings, { demo: MOCK });
    if (s.security.ipAllowlist.length && !ipAllowed(req.ip, s.security.ipAllowlist)) {
      throw new AdError(400, `Your own address (${String(req.ip).replace(/^::ffff:/, '')}) is not in the IP allow-list, so saving would lock you out.`);
    }
    const before = currentSaved();
    // Validate against the real directory before saving (skipped in demo mode,
    // where only branding / helpdesk permissions / provisioning options apply).
    if (!MOCK) {
      const me = req.session.user;
      const r = await ldapDirectory.probe(toLdapConn(s.connection), { checkMember: me ? { userDn: me.dn, groupDn: s.roles.adminGroup } : null });
      const ouSet = new Set(r.ous.map(normDn));
      const missing = [...s.scope.userOUs, ...s.scope.groupOUs, ...s.security.excludedOUs, ...(s.workflow.leaverOU ? [s.workflow.leaverOU] : [])]
        .filter((ou) => !ouSet.has(normDn(ou)));
      if (missing.length) throw new AdError(400, `These OUs were not found: ${missing.join('; ')}`);
      const groupSet = new Set(r.groups.map((g) => normDn(g.dn)));
      for (const g of [s.roles.adminGroup, s.roles.helpdeskGroup].filter(Boolean)) {
        if (!groupSet.has(normDn(g))) throw new AdError(400, `Group not found: ${g}`);
      }
      if (me && r.currentUserIsAdmin === false) {
        throw new AdError(400, 'You are not a member of the new admin group, so saving would lock you out. Add yourself to it first.');
      }
    }
    saveSettings(s);
    audit(req, firstRun ? 'settings.setup' : 'settings.update', 'portal settings', { details: settingsSummary(s, firstRun ? null : before) });
    res.json({ ok: true, firstRun, ...publicSettings() });
  } catch (e) {
    audit(req, firstRun ? 'settings.setup' : 'settings.update', 'portal settings', { result: 'failure', error: e.message });
    sendError(res, e);
  }
});

app.get('/api/ous', ...read('user.read', () => ad.listOUs()));

app.get('/api/health', async (req, res) => {
  // public health check: no error details (they can reveal internal names)
  try { await ad.ping(); res.json({ ok: true }); } catch { res.status(503).json({ ok: false }); }
});

// ------------------------------------------------------------------ users

app.get('/api/users', ...read('user.read', (req) =>
  ad.searchUsers(text(req.query.q, 'Search', { max: 64 }), { status: String(req.query.status || 'all') })));

// Dashboard figures (one directory read, counted on the server)
app.get('/api/stats', ...read('user.read', async () => {
  const [u, g] = await Promise.all([ad.searchUsers('', { status: 'all' }), ad.searchGroups('')]);
  const items = u.items;
  const cutoff = Date.now() - 90 * 86400000;
  return {
    users: u.total,
    enabled: items.filter((x) => x.enabled).length,
    disabled: items.filter((x) => !x.enabled).length,
    inactive90: items.filter((x) => x.enabled && (!x.lastLogon || new Date(x.lastLogon).getTime() < cutoff)).length,
    mustChange: items.filter((x) => x.mustChangePassword).length,
    passwordExpired: items.filter((x) => x.passwordExpired).length,
    locked: items.filter((x) => x.locked).map(({ sam, displayName, department, ou, protected: p }) => ({ sam, displayName, department, ou, protected: p })),
    groups: g.total,
  };
}));

app.get('/api/users/:sam', ...read('user.read', (req) => ad.getUser(userSam(req.params.sam))));

// ------------------------------------------------------------------ shared action runner
// Every change that can be done one-by-one, in bulk or after approval goes through
// runAction: approval check -> guards -> AD change -> audit -> e-mail notification.

const dateOrEmpty = (v, label) => {
  const s = text(v, label, { max: 10 });
  if (s && !/^\d{4}-\d{2}-\d{2}$/.test(s)) throw new AdError(400, `${label} must be a date (YYYY-MM-DD)`);
  if (s) {
    const [y, m, d] = s.split('-').map(Number);
    const dt = new Date(Date.UTC(y, m - 1, d));
    if (dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) throw new AdError(400, `${label} is not a real date`);
  }
  return s;
};

function randomPassword(len = 16) {
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '@#$%&*!?'];
  const all = sets.join('');
  const pick = (s) => s[crypto.randomInt(s.length)];
  const chars = sets.map(pick);
  while (chars.length < len) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}

const EXEC = {
  'user.unlock': {
    perm: 'user.unlock',
    async run(req, { sam }) {
      const u = await ad.getUser(sam);
      await ad.unlockUser(sam);
      return { notify: { managerMail: u.managerInfo?.mail } };
    },
  },
  'user.enable': {
    perm: 'user.enable',
    async run(req, { sam, enabled }) {
      if (!enabled && self(req, sam)) throw new AdError(400, 'You cannot disable your own account.');
      const u = await guardUserTarget(req, sam, { confirm: !enabled });
      await ad.setUserEnabled(sam, !!enabled);
      return { details: { enabled: !!enabled }, notify: { managerMail: u.managerInfo?.mail, lines: [`New state: ${enabled ? 'enabled' : 'disabled'}`] } };
    },
  },
  'user.move': {
    perm: 'user.move',
    approval: true,
    describe: ({ sam, ou }) => `Move ${sam} to ${ou}`,
    async run(req, { sam, ou }) {
      await guardUserTarget(req, sam, { confirm: true });
      return { details: await ad.moveUser(sam, ou) };
    },
  },
  'user.delete': {
    perm: 'user.delete',
    approval: true,
    describe: ({ sam }) => `Delete user ${sam} permanently`,
    async run(req, { sam }) {
      if (self(req, sam)) throw new AdError(400, 'You cannot delete your own account.');
      const u = await guardUserTarget(req, sam, { confirm: true });
      const r = await ad.deleteUser(sam);
      return { details: r, notify: { managerMail: u.managerInfo?.mail } };
    },
  },
  'user.offboard': {
    perm: 'user.offboard',
    approval: true,
    describe: ({ sam }) => `Offboard leaver ${sam} (disable, remove from groups, move to leavers OU)`,
    async run(req, { sam, resetPassword = true }) {
      if (self(req, sam)) throw new AdError(400, 'You cannot offboard your own account.');
      const u = await guardUserTarget(req, sam, { confirm: true });
      const steps = [];
      if (u.enabled) { await ad.setUserEnabled(sam, false); steps.push('Account disabled'); } else steps.push('Account was already disabled');
      if (resetPassword && !u.protected) { await ad.resetPassword(sam, { password: randomPassword(24), mustChange: true, unlock: false }); steps.push('Password changed to a random value nobody knows'); }
      const removed = [];
      const kept = [];
      for (const g of u.groups) {
        if (!g.manageable) { kept.push(g.name); continue; }
        try { await ad.removeMember(g.sam, sam); removed.push(g.name); } catch (e) { kept.push(`${g.name} (${e.message})`); }
      }
      steps.push(`Removed from ${removed.length} group(s)${kept.length ? `; ${kept.length} left (protected or outside scope)` : ''}`);
      const note = `Left - offboarded ${new Date().toISOString().slice(0, 10)} by ${req.session.user.sam}`;
      await ad.updateUser(sam, { description: (u.description ? `${note} | ${u.description}` : note).slice(0, 256) });
      steps.push('Description stamped with the offboarding date');
      const leaverOU = config.workflow.leaverOU;
      if (leaverOU && normDn(u.ou) !== normDn(leaverOU)) { await ad.moveUser(sam, leaverOU); steps.push(`Moved to ${leaverOU}`); }
      return { details: { steps, removedGroups: removed, keptGroups: kept }, body: { steps, removed, kept }, notify: { managerMail: u.managerInfo?.mail, lines: steps } };
    },
  },
  'group.delete': {
    perm: 'group.delete',
    approval: true,
    describe: ({ sam }) => `Delete group ${sam} permanently`,
    async run(req, { sam }) {
      await guardGroupTarget(req, sam, { deleting: true });
      return { details: await ad.deleteGroup(sam) };
    },
  },
  'group.addMember': {
    perm: 'group.members',
    approval: true,
    describe: ({ group, member }) => `Add ${member} to group ${group}`,
    async run(req, { group, member }) {
      await guardGroupTarget(req, group);
      const r = await ad.addMember(group, member);
      return { details: { member, memberDn: r.member }, notify: { lines: [`Member: ${member}`] } };
    },
  },
  'group.removeMember': {
    perm: 'group.members',
    async run(req, { group, member }) {
      await guardGroupTarget(req, group);
      const r = await ad.removeMember(group, member);
      return { details: { member, memberDn: r.member }, notify: { lines: [`Member: ${member}`] } };
    },
  },
};

const targetOfAction = (action, p) => (action.startsWith('group.') ? (p.group || p.sam) : p.sam);

// Returns { status: 'done' | 'pending', ... }. Throws on failure (after auditing it).
async function runAction(req, action, params) {
  const def = EXEC[action];
  if (!can(req.session.user.role, def.perm)) throw new AdError(403, 'Your role is not allowed to do this.');
  const target = targetOfAction(action, params);
  if (def.approval && config.workflow.approvalActions.includes(action) && !req.approvalContext) {
    // run the guards now so obviously invalid requests are refused straight away
    if (action.startsWith('user.')) await guardUserTarget(req, params.sam, { confirm: true });
    else await guardGroupTarget(req, params.group || params.sam, { deleting: action === 'group.delete' });
    const r = createRequest({ action, params, target, summary: def.describe(params), requestedBy: req.session.user.sam, requestedByName: req.session.user.displayName });
    audit(req, 'approval.requested', target, { details: { id: r.id, action, summary: r.summary } });
    notify('approval.requested', { actor: req.session.user.sam, target, lines: [r.summary, 'Open the portal → Approvals to approve or reject.'] });
    return { status: 'pending', id: r.id, summary: r.summary };
  }
  try {
    const r = (await def.run(req, params)) || {};
    const details = { ...(r.details || {}), ...(req.approvalContext ? { approval: req.approvalContext } : {}) };
    audit(req, action, target, { details });
    if (r.notify !== undefined || ['user.unlock', 'user.delete'].includes(action)) {
      notify(action, { actor: req.session.user.sam, target, ...(r.notify || {}) });
    }
    return { status: 'done', ...(r.body || {}) };
  } catch (e) {
    audit(req, action, target, { result: 'failure', error: e.message, details: req.approvalContext ? { approval: req.approvalContext } : undefined });
    throw e;
  }
}

// One route per action (the UI) -> runAction; 202 = waiting for approval
const actionRoute = (action, paramsOf) => [requirePerm(EXEC[action].perm), async (req, res) => {
  try {
    const r = await runAction(req, action, paramsOf(req));
    res.status(r.status === 'pending' ? 202 : 200).json({ ok: true, ...r });
  } catch (e) { sendError(res, e); }
}];

// ------------------------------------------------------------------ users

function userInput(b) {
  return {
    ...cleanUserFields(b),
    accountExpires: b.accountExpires !== undefined ? dateOrEmpty(b.accountExpires, 'Account expiry date') : undefined,
    manager: b.manager !== undefined ? (b.manager ? userSam(b.manager) : '') : undefined,
  };
}

async function createOneUser(req, b, { generatePassword = false } = {}) {
  const fields = userInput(b);
  const d = {
    ...fields,
    sam: userSam(b.sam),
    ou: text(b.ou, 'OU', { max: 512, required: true }),
    password: generatePassword ? randomPassword() : checkPassword(b.password),
    upnSuffix: b.upnSuffix ? text(b.upnSuffix, 'UPN suffix', { max: 255 }) : '',
    mustChange: bool(b.mustChange),
    enabled: bool(b.enabled),
    groups: Array.isArray(b.groups) ? b.groups.slice(0, 50).map(groupSam) : [],
  };
  if (!d.givenName && !d.sn && !d.displayName) throw new AdError(400, 'First name, last name or display name is required');
  const allowedSuffixes = [config.upnSuffix, ...(config.provisioning.upnSuffixes || [])].map((x) => String(x).toLowerCase());
  if (d.upnSuffix && !allowedSuffixes.includes(d.upnSuffix.toLowerCase())) throw new AdError(400, 'That UPN suffix is not allowed');
  const r = await ad.createUser(d);
  const { password, ...safe } = d; // never log the password
  audit(req, 'user.create', d.sam, { details: { ...safe, dn: r.dn, warnings: r.warnings, ...(generatePassword ? { import: true } : {}) } });
  notify('user.create', { actor: req.session.user.sam, target: d.sam, lines: [`Name: ${d.displayName || `${d.givenName} ${d.sn}`}`, `OU: ${d.ou}`, d.groups.length ? `Groups: ${d.groups.join(', ')}` : ''].filter(Boolean) });
  return { ...r, password: d.password };
}

app.post('/api/users', requirePerm('user.create'), async (req, res) => {
  try {
    const r = await createOneUser(req, req.body || {});
    const { password, ...rest } = r;
    res.json({ ok: true, ...rest });
  } catch (e) {
    audit(req, 'user.create', String(req.body?.sam || ''), { result: 'failure', error: e.message });
    sendError(res, e);
  }
});

// Bulk import from CSV (rows parsed in the browser). Passwords are generated here
// and returned once so the operator can hand them over; they are never logged.
app.post('/api/users/import', requirePerm('user.import'), async (req, res) => {
  try {
    if (!can(req.session.user.role, 'user.create')) throw new AdError(403, 'Your role is not allowed to create users.');
    const rows = Array.isArray(req.body?.rows) ? req.body.rows.slice(0, 500) : [];
    if (!rows.length) throw new AdError(400, 'The file has no rows to import');
    const def = req.body?.defaults || {};
    const results = [];
    for (const [i, row] of rows.entries()) {
      const b = {
        ...row,
        ou: row.ou || def.ou,
        groups: [...new Set([...(def.groups || []), ...String(row.groups || '').split(/[;|]/).map((g) => g.trim()).filter(Boolean)])],
        mustChange: def.mustChange !== false,
        enabled: def.enabled !== false,
      };
      try {
        const r = await createOneUser(req, b, { generatePassword: true });
        results.push({ row: i + 1, sam: b.sam, ok: true, password: r.password, warnings: r.warnings });
      } catch (e) {
        audit(req, 'user.create', String(b.sam || ''), { result: 'failure', error: e.message, details: { import: true, row: i + 1 } });
        results.push({ row: i + 1, sam: b.sam, ok: false, error: e.message });
      }
    }
    res.json({ ok: true, results });
  } catch (e) { sendError(res, e); }
});

// Bulk actions on selected users
const BULK = { unlock: 'user.unlock', enable: 'user.enable', disable: 'user.enable', move: 'user.move', offboard: 'user.offboard' };
app.post('/api/users/bulk', requireLogin, async (req, res) => {
  try {
    const kind = String(req.body?.action || '');
    const action = BULK[kind];
    if (!action) throw new AdError(400, 'Unknown bulk action');
    if (!can(req.session.user.role, EXEC[action].perm)) throw new AdError(403, 'Your role is not allowed to do this.');
    const sams = (Array.isArray(req.body?.sams) ? req.body.sams : []).slice(0, 200).map(userSam);
    if (!sams.length) throw new AdError(400, 'No users selected');
    const ou = kind === 'move' ? text(req.body?.ou, 'OU', { max: 512, required: true }) : undefined;
    const confirmed = new Set((Array.isArray(req.body?.confirmServiceAccounts) ? req.body.confirmServiceAccounts : []).map((s) => String(s).toLowerCase()));
    const results = [];
    for (const sam of sams) {
      const params = { sam, ...(kind === 'enable' ? { enabled: true } : {}), ...(kind === 'disable' ? { enabled: false } : {}), ...(ou ? { ou } : {}) };
      req.body.confirmServiceAccount = confirmed.has(sam.toLowerCase()) ? sam : '';
      try {
        const r = await runAction(req, action, params);
        results.push({ sam, ok: true, status: r.status });
      } catch (e) { results.push({ sam, ok: false, error: e.message, needsConfirm: e.status === 428 }); }
    }
    res.json({ ok: true, results });
  } catch (e) { sendError(res, e); }
});

app.patch('/api/users/:sam', ...change('user.edit', 'user.update', (req) => req.params.sam, async (req) => {
  const sam = userSam(req.params.sam);
  const { accountExpires, manager, ...fields } = userInput(req.body || {});
  await guardUserTarget(req, sam);
  const r = await ad.updateUser(sam, fields, { accountExpires, manager });
  const after = Object.fromEntries(r.changed.map((k) => [k, fields[k]]));
  if (r.before.accountExpires !== undefined) after.accountExpires = accountExpires || 'never';
  if (r.before.manager !== undefined) after.manager = manager || '';
  return { details: { changed: [...r.changed, ...Object.keys(r.before).filter((k) => !r.changed.includes(k))], before: r.before, after }, body: r };
}));

app.post('/api/users/:sam/reset-password', ...change('user.resetPassword', 'user.resetPassword', (req) => req.params.sam, async (req) => {
  const sam = userSam(req.params.sam);
  const opts = { password: checkPassword(req.body?.password), mustChange: bool(req.body?.mustChange), unlock: bool(req.body?.unlock) };
  const u = await guardUserTarget(req, sam, { confirm: true });
  await ad.resetPassword(sam, opts);
  notify('user.resetPassword', { actor: req.session.user.sam, target: sam, managerMail: u.managerInfo?.mail, lines: [opts.mustChange ? 'The user must choose a new password at next sign-in.' : ''] });
  return { details: { mustChange: opts.mustChange, unlock: opts.unlock } };
}));

app.post('/api/users/:sam/unlock', ...actionRoute('user.unlock', (req) => ({ sam: userSam(req.params.sam) })));
app.post('/api/users/:sam/enabled', ...actionRoute('user.enable', (req) => ({ sam: userSam(req.params.sam), enabled: bool(req.body?.enabled) })));
app.post('/api/users/:sam/move', ...actionRoute('user.move', (req) => ({ sam: userSam(req.params.sam), ou: text(req.body?.ou, 'OU', { max: 512, required: true }) })));
app.post('/api/users/:sam/offboard', ...actionRoute('user.offboard', (req) => ({ sam: userSam(req.params.sam), resetPassword: req.body?.resetPassword !== false })));
app.delete('/api/users/:sam', ...actionRoute('user.delete', (req) => ({ sam: userSam(req.params.sam) })));

// ------------------------------------------------------------------ groups

app.get('/api/groups', ...read('group.read', (req) => ad.searchGroups(text(req.query.q, 'Search', { max: 64 }))));

app.get('/api/groups/:sam', ...read('group.read', (req) => ad.getGroup(groupSam(req.params.sam))));

app.post('/api/groups', ...change('group.create', 'group.create', (req) => req.body?.name || '', async (req) => {
  const b = req.body || {};
  const d = {
    name: groupSam(b.name),
    ou: text(b.ou, 'OU', { max: 512, required: true }),
    description: text(b.description, 'Description', { max: 256 }),
    info: text(b.info, 'Notes', { max: 1024 }),
    mail: text(b.mail, 'E-mail', { max: 128 }),
    scope: ['global', 'domainlocal', 'universal'].includes(b.scope) ? b.scope : 'global',
    type: b.type === 'distribution' ? 'distribution' : 'security',
  };
  const r = await ad.createGroup(d);
  return { target: d.name, details: { ...d, dn: r.dn }, body: r };
}));

app.patch('/api/groups/:sam', ...change('group.edit', 'group.update', (req) => req.params.sam, async (req) => {
  const b = req.body || {};
  const fields = {};
  if (b.description !== undefined) fields.description = text(b.description, 'Description', { max: 256 });
  if (b.info !== undefined) fields.info = text(b.info, 'Notes', { max: 1024 });
  if (b.mail !== undefined) fields.mail = text(b.mail, 'E-mail', { max: 128 });
  await guardGroupTarget(req, groupSam(req.params.sam));
  const r = await ad.updateGroup(groupSam(req.params.sam), fields);
  const after = Object.fromEntries(r.changed.map((k) => [k, fields[k]]));
  return { details: { changed: r.changed, before: r.before, after } };
}));

app.delete('/api/groups/:sam', ...actionRoute('group.delete', (req) => ({ sam: groupSam(req.params.sam) })));
app.post('/api/groups/:sam/members', ...actionRoute('group.addMember', (req) => ({ group: groupSam(req.params.sam), member: text(req.body?.member, 'Member', { max: 64, required: true }) })));
app.delete('/api/groups/:sam/members/:member', ...actionRoute('group.removeMember', (req) => ({ group: groupSam(req.params.sam), member: text(req.params.member, 'Member', { max: 64, required: true }) })));

// ------------------------------------------------------------------ approvals

const publicRequest = (r) => ({ ...r });

app.get('/api/approvals', requireLogin, (req, res) => {
  const all = listRequests();
  const mine = (r) => r.requestedBy.toLowerCase() === req.session.user.sam.toLowerCase();
  res.json(can(req.session.user.role, 'approvals.approve') ? all.map(publicRequest) : all.filter(mine).map(publicRequest));
});

app.post('/api/approvals/:id/:decision', requireLogin, async (req, res) => {
  const { id, decision } = req.params;
  try {
    const r = getRequest(String(id));
    if (!r) throw new AdError(404, 'Request not found');
    if (r.status !== 'pending') throw new AdError(409, `This request is already ${r.status}.`);
    const me = req.session.user.sam.toLowerCase();
    if (decision === 'cancel') {
      if (r.requestedBy.toLowerCase() !== me) throw new AdError(403, 'Only the person who asked can cancel a request.');
      decide(r.id, { status: 'cancelled', decidedBy: req.session.user.sam });
      audit(req, 'approval.cancelled', r.target, { details: { id: r.id, action: r.action } });
      return res.json({ ok: true });
    }
    if (!can(req.session.user.role, 'approvals.approve')) throw new AdError(403, 'Only portal admins can approve requests.');
    if (r.requestedBy.toLowerCase() === me) throw new AdError(403, 'Someone other than the requester must approve this.');
    const note = text(req.body?.note, 'Note', { max: 500 });
    if (decision === 'reject') {
      decide(r.id, { status: 'rejected', decidedBy: req.session.user.sam, note });
      audit(req, 'approval.rejected', r.target, { details: { id: r.id, action: r.action, requestedBy: r.requestedBy, note } });
      return res.json({ ok: true });
    }
    if (decision !== 'approve') throw new AdError(400, 'Unknown decision');
    req.approvalContext = { id: r.id, requestedBy: r.requestedBy, approvedBy: req.session.user.sam };
    try {
      const out = await runAction(req, r.action, r.params);
      decide(r.id, { status: 'approved', decidedBy: req.session.user.sam, note, result: out.steps ? out.steps.join('; ') : 'done' });
      audit(req, 'approval.approved', r.target, { details: { id: r.id, action: r.action, requestedBy: r.requestedBy } });
      res.json({ ok: true, ...out });
    } catch (e) {
      decide(r.id, { status: 'failed', decidedBy: req.session.user.sam, note, result: e.message });
      throw e;
    }
  } catch (e) { sendError(res, e); }
});

// ------------------------------------------------------------------ reports

const REPORTS = {
  inactive: { title: 'No sign-in for N days (enabled accounts)', days: 90, filter: (u, cut) => u.enabled && (!u.lastLogon || new Date(u.lastLogon) < cut) },
  'never-signed-in': { title: 'Never signed in (enabled accounts)', filter: (u) => u.enabled && !u.lastLogon },
  'password-old': { title: 'Password not changed for N days', days: 180, filter: (u, cut) => u.enabled && u.passwordLastSet && new Date(u.passwordLastSet) < cut },
  'password-never-expires': { title: 'Password never expires (enabled)', filter: (u) => u.enabled && u.passwordNeverExpires },
  'must-change': { title: 'Must change password at next sign-in', filter: (u) => u.mustChangePassword },
  'expiring-accounts': { title: 'Accounts expiring in the next N days', days: 30, filter: (u, cut, now) => u.accountExpires && new Date(u.accountExpires) > now && new Date(u.accountExpires) <= new Date(now.getTime() + (now - cut)) },
  'expired-accounts': { title: 'Expired accounts that are still enabled', filter: (u, cut, now) => u.enabled && u.accountExpires && new Date(u.accountExpires) <= now },
  disabled: { title: 'Disabled accounts', filter: (u) => !u.enabled },
  locked: { title: 'Locked out now', filter: (u) => u.locked },
  'service-accounts': { title: 'Service-like accounts', filter: (u) => u.serviceAccount },
  protected: { title: 'Protected / privileged accounts (adminCount)', filter: (u) => u.protected },
  'all-users': { title: 'All users', filter: () => true },
};

app.get('/api/reports', ...read('reports.read', () => Object.entries(REPORTS).map(([id, r]) => ({ id, title: r.title, days: r.days || null }))));

app.get('/api/reports/:id', ...read('reports.read', async (req) => {
  const id = String(req.params.id);
  if (id === 'group-members') {
    const g = await ad.getGroup(groupSam(req.query.group));
    return { title: `Members of ${g.name}`, rows: g.members.map((m) => ({ sam: m.sam, displayName: m.name, kind: m.kind, enabled: m.enabled })) };
  }
  const rep = REPORTS[id];
  if (!rep) throw new AdError(404, 'Unknown report');
  const days = Math.min(Math.max(Number(req.query.days) || rep.days || 0, 1), 3650);
  const now = new Date();
  const cut = new Date(now.getTime() - days * 86400000);
  const all = await ad.searchUsers('', { status: 'all' });
  const rows = all.items.filter((u) => rep.filter(u, cut, now)).map((u) => ({
    sam: u.sam, displayName: u.displayName, department: u.department, title: u.title, mail: u.mail,
    enabled: u.enabled, locked: u.locked, lastLogon: u.lastLogon, passwordLastSet: u.passwordLastSet,
    accountExpires: u.accountExpires, ou: u.ou,
  }));
  audit(req, 'report.view', id, { details: { rows: rows.length, days: rep.days ? days : undefined } });
  return { title: rep.title.replace('N days', `${days} days`), rows, truncated: all.truncated };
}));

// ------------------------------------------------------------------ audit

const auditFilters = (q) => ({
  q: String(q.q || '').slice(0, 100),
  actor: String(q.actor || '').slice(0, 64),
  action: String(q.action || '').slice(0, 64),
  result: String(q.result || '').slice(0, 16),
  from: String(q.from || '').slice(0, 10),
  to: String(q.to || '').slice(0, 10),
});

app.get('/api/audit', ...read('audit.read', (req) => queryAudit({ ...auditFilters(req.query), limit: 1000 })));

app.get('/api/audit/verify', ...read('audit.read', async (req) => {
  const r = await verifyAudit();
  audit(req, 'audit.verify', '', { result: r.ok ? 'success' : 'failure', details: r, error: r.ok ? undefined : r.problem });
  return r;
}));

// ------------------------------------------------------------------ settings extras

app.post('/api/settings/test-email', requirePerm('settings.manage'), async (req, res) => {
  try {
    const saved = currentSaved().notifications || {};
    const n = { ...saved, ...(req.body?.notifications || {}) };
    if (!req.body?.notifications?.smtpPassword) n.smtpPassword = saved.smtpPassword || '';
    if (!n.smtpHost || !n.from || !n.itMailbox) throw new AdError(400, 'Fill in the SMTP server, From address and IT mailbox first');
    await sendMail(n, { to: n.itMailbox, subject: '[AD Portal] Test message', text: `This is a test e-mail from the AD Admin Portal, sent by ${req.session.user.sam}.\nIf you can read this, notifications are set up correctly.` });
    audit(req, 'settings.testEmail', n.itMailbox);
    res.json({ ok: true });
  } catch (e) {
    audit(req, 'settings.testEmail', '', { result: 'failure', error: e.message });
    sendError(res, e instanceof AdError ? e : new AdError(400, `Sending failed: ${e.message}`));
  }
});

app.get('/api/settings/backup', ...read('settings.manage', () => lastBackup()));
app.post('/api/settings/backup', ...change('settings.manage', 'backup.run', () => 'backup', async () => {
  try { const r = runBackup(); return { details: r, body: r }; } catch (e) { throw new AdError(400, `Backup failed: ${e.message}`); }
}));

app.get('/api/audit.csv', requirePerm('audit.read'), async (req, res) => {
  try {
    const rows = await queryAudit({ ...auditFilters(req.query), limit: 100000 });
    audit(req, 'audit.export', '', { details: { rows: rows.length, filters: auditFilters(req.query) } });
    res.set('Content-Type', 'text/csv; charset=utf-8');
    res.set('Content-Disposition', `attachment; filename="ad-portal-audit-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send('﻿' + toCsv(rows));
  } catch (e) { sendError(res, e); }
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// ------------------------------------------------------------------ start

const tlsOptions = config.httpsPfx
  ? { pfx: fs.readFileSync(config.httpsPfx), passphrase: config.httpsPfxPassphrase, minVersion: 'TLSv1.2' }
  : { cert: useHttps ? fs.readFileSync(config.httpsCert) : undefined, key: useHttps ? fs.readFileSync(config.httpsKey) : undefined, minVersion: 'TLSv1.2' };
const server = useHttps ? https.createServer(tlsOptions, app) : http.createServer(app);

// Optional: answer plain HTTP on another port with a redirect to HTTPS
if (useHttps && config.httpRedirectPort) {
  http.createServer((req, res) => {
    const host = String(req.headers.host || 'localhost').replace(/:\d+$/, '');
    res.writeHead(301, { Location: `https://${host}${config.port === 443 ? '' : ':' + config.port}${req.url}` });
    res.end();
  }).listen(config.httpRedirectPort, process.env.HOST || undefined);
}

// Demo mode has a published password, so by default it only listens on this computer.
const host = process.env.HOST || (MOCK ? '127.0.0.1' : undefined);
server.listen(config.port, host, () => {
  console.log(`AD Admin Portal listening on ${useHttps ? 'https' : 'http'}://localhost:${config.port}${MOCK ? '  (MOCK directory - demo data, no real AD)' : ''}`);
  console.log(`Audit log: ${path.dirname(config.auditFile)}`);
});

// Daily backup (Settings → Backup)
const systemReq = { ip: 'localhost', session: {}, body: {} };
startBackupSchedule((err, r) => {
  if (err) audit(systemReq, 'backup.run', 'scheduled', { result: 'failure', error: err.message, actor: 'system' });
  else audit(systemReq, 'backup.run', 'scheduled', { details: r, actor: 'system' });
});
