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
import {
  initSettings, sessionSecret, checkSetupToken, publicSettings, normalizeConnection, normalizeSettings,
  toLdapConn, saveSettings, settingsSummary, currentSaved,
} from './settings.js';

initSettings(); // must run before the directory module reads config
const { directory: ad } = MOCK ? await import('./ad/mock.js') : await import('./ad/ldap.js');
const { directory: ldapDirectory } = await import('./ad/ldap.js'); // used by "Test connection" (also in demo mode)
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const useHttps = !!(config.httpsCert && config.httpsKey);

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

app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

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
async function guardUserTarget(req, sam) {
  if (isAdmin(req)) return;
  const u = await ad.getUser(sam);
  if (await ad.isMemberOf(u.dn, config.roleGroups.admin)) {
    throw new AdError(403, "Only portal admins can change a portal admin's account.");
  }
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
  message: { error: 'Too many sign-in attempts. Try again in 15 minutes.' },
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const username = String(req.body?.username || '').trim().slice(0, 100);
  try {
    const u = await ad.authenticate(username, String(req.body?.password || ''));
    let role = null;
    if (await ad.isMemberOf(u.dn, config.roleGroups.admin)) role = 'admin';
    else if (await ad.isMemberOf(u.dn, config.roleGroups.helpdesk)) role = 'helpdesk';
    if (!role) {
      audit(req, 'login', u.sam, { result: 'failure', error: 'Not a member of a portal role group' });
      return res.status(403).json({ error: 'You are not authorised to use this portal. Ask an administrator to add you to the portal admin or helpdesk group.' });
    }
    req.session.regenerate((err) => {
      if (err) return sendError(res, err);
      req.session.user = { sam: u.sam, dn: u.dn, displayName: u.displayName, role };
      audit(req, 'login', u.sam);
      res.json({ ok: true });
    });
  } catch (e) {
    audit(req, 'login', username, { result: 'failure', error: e.message });
    sendError(res, e);
  }
});

app.post('/api/logout', (req, res) => {
  if (req.session.user) audit(req, 'logout', req.session.user.sam);
  req.session.destroy(() => {
    res.clearCookie('adportal.sid');
    res.json({ ok: true });
  });
});

app.get('/api/info', (req, res) => res.json({
  mock: MOCK,
  configured: isConfigured(),
  orgName: config.branding.orgName,
  logo: config.branding.logo,
}));

app.get('/api/me', requireLogin, (req, res) => {
  const { sam, displayName, role } = req.session.user;
  const p = config.provisioning;
  res.json({
    sam, displayName, role, permissions: permissionsFor(role), mock: MOCK,
    upnSuffix: config.upnSuffix || 'corp.local',
    provisioning: {
      upnSuffixes: [...new Set([config.upnSuffix, ...(p.upnSuffixes || [])].filter(Boolean))],
      emailDomain: p.emailDomain, usernameFormat: p.usernameFormat, defaultUserOU: p.defaultUserOU,
      defaultGroups: p.defaultGroups, mustChangeDefault: p.mustChangeDefault, enabledDefault: p.enabledDefault,
    },
  });
});

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
    const s = normalizeSettings(req.body?.settings, { demo: MOCK });
    const before = currentSaved();
    // Validate against the real directory before saving (skipped in demo mode,
    // where only branding / helpdesk permissions / provisioning options apply).
    if (!MOCK) {
      const me = req.session.user;
      const r = await ldapDirectory.probe(toLdapConn(s.connection), { checkMember: me ? { userDn: me.dn, groupDn: s.roles.adminGroup } : null });
      const ouSet = new Set(r.ous.map(normDn));
      const missing = [...s.scope.userOUs, ...s.scope.groupOUs].filter((ou) => !ouSet.has(normDn(ou)));
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

app.post('/api/users', ...change('user.create', 'user.create', (req) => req.body?.sam || '', async (req) => {
  const b = req.body || {};
  const d = {
    ...cleanUserFields(b),
    sam: userSam(b.sam),
    ou: text(b.ou, 'OU', { max: 512, required: true }),
    password: checkPassword(b.password),
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
  return { target: d.sam, details: { ...safe, dn: r.dn, warnings: r.warnings }, body: r };
}));

app.patch('/api/users/:sam', ...change('user.edit', 'user.update', (req) => req.params.sam, async (req) => {
  const fields = cleanUserFields(req.body || {});
  await guardUserTarget(req, userSam(req.params.sam));
  const r = await ad.updateUser(userSam(req.params.sam), fields);
  const after = Object.fromEntries(r.changed.map((k) => [k, fields[k]]));
  return { details: { changed: r.changed, before: r.before, after }, body: r };
}));

app.post('/api/users/:sam/reset-password', ...change('user.resetPassword', 'user.resetPassword', (req) => req.params.sam, async (req) => {
  const sam = userSam(req.params.sam);
  const opts = { password: checkPassword(req.body?.password), mustChange: bool(req.body?.mustChange), unlock: bool(req.body?.unlock) };
  await guardUserTarget(req, sam);
  await ad.resetPassword(sam, opts);
  return { details: { mustChange: opts.mustChange, unlock: opts.unlock } };
}));

app.post('/api/users/:sam/unlock', ...change('user.unlock', 'user.unlock', (req) => req.params.sam, async (req) => {
  await ad.unlockUser(userSam(req.params.sam));
}));

app.post('/api/users/:sam/enabled', ...change('user.enable', 'user.enable', (req) => req.params.sam, async (req) => {
  const sam = userSam(req.params.sam);
  const enabled = bool(req.body?.enabled);
  if (!enabled && self(req, sam)) throw new AdError(400, 'You cannot disable your own account.');
  await guardUserTarget(req, sam);
  await ad.setUserEnabled(sam, enabled);
  return { details: { enabled } };
}));

app.post('/api/users/:sam/move', ...change('user.move', 'user.move', (req) => req.params.sam, async (req) => {
  await guardUserTarget(req, userSam(req.params.sam));
  const r = await ad.moveUser(userSam(req.params.sam), text(req.body?.ou, 'OU', { max: 512, required: true }));
  return { details: r };
}));

app.delete('/api/users/:sam', ...change('user.delete', 'user.delete', (req) => req.params.sam, async (req) => {
  const sam = userSam(req.params.sam);
  if (self(req, sam)) throw new AdError(400, 'You cannot delete your own account.');
  await guardUserTarget(req, sam);
  const r = await ad.deleteUser(sam);
  return { details: r };
}));

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

app.delete('/api/groups/:sam', ...change('group.delete', 'group.delete', (req) => req.params.sam, async (req) => {
  await guardGroupTarget(req, groupSam(req.params.sam), { deleting: true });
  const r = await ad.deleteGroup(groupSam(req.params.sam));
  return { details: r };
}));

app.post('/api/groups/:sam/members', ...change('group.members', 'group.addMember', (req) => req.params.sam, async (req) => {
  const member = text(req.body?.member, 'Member', { max: 64, required: true });
  await guardGroupTarget(req, groupSam(req.params.sam));
  const r = await ad.addMember(groupSam(req.params.sam), member);
  return { details: { member, memberDn: r.member } };
}));

app.delete('/api/groups/:sam/members/:member', ...change('group.members', 'group.removeMember', (req) => req.params.sam, async (req) => {
  const member = text(req.params.member, 'Member', { max: 64, required: true });
  await guardGroupTarget(req, groupSam(req.params.sam));
  const r = await ad.removeMember(groupSam(req.params.sam), member);
  return { details: { member, memberDn: r.member } };
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

const server = useHttps
  ? https.createServer({ cert: fs.readFileSync(config.httpsCert), key: fs.readFileSync(config.httpsKey) }, app)
  : http.createServer(app);

// Demo mode has a published password, so by default it only listens on this computer.
const host = process.env.HOST || (MOCK ? '127.0.0.1' : undefined);
server.listen(config.port, host, () => {
  console.log(`AD Admin Portal listening on ${useHttps ? 'https' : 'http'}://localhost:${config.port}${MOCK ? '  (MOCK directory - demo data, no real AD)' : ''}`);
  console.log(`Audit log: ${path.dirname(config.auditFile)}`);
});
