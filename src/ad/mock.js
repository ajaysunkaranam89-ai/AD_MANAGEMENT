// In-memory fake Active Directory for demos and UI testing (npm run mock).
// Same interface as ldap.js. Nothing here touches a real domain.
import { config } from '../config.js';
import {
  AdError, PROTECTED_MSG, USER_FIELDS, inScope, normDn, parentDn, rdnValue, describeGroupType, groupTypeValue,
} from './common.js';

const BASE = 'DC=corp,DC=local';
const ROOT = `OU=Company,${BASE}`;
const USERS = `OU=Users,${ROOT}`;
const GROUPS = `OU=Groups,${ROOT}`;
const DEMO_PASSWORD = 'Demo@1234';

Object.assign(config, {
  upnSuffix: 'corp.local',
  userOUs: [USERS],
  groupOUs: [GROUPS],
  roleGroups: { admin: `CN=ADPortal-Admins,${GROUPS}`, helpdesk: `CN=ADPortal-Helpdesk,${GROUPS}` },
});
// Demo directory structure is fixed; other provisioning options can be changed in Settings.
config.provisioning = { ...config.provisioning, upnSuffixes: ['example.com'], defaultUserOU: `OU=Operations,${USERS}` };
if (!config.provisioning.defaultGroups?.length) config.provisioning.defaultGroups = ['WiFi-Corp'];
if (!config.provisioning.emailDomain) config.provisioning.emailDomain = 'example.com';
if (!config.branding.orgName) config.branding.orgName = 'Example Corp (demo)';
config.ldap.baseDn = BASE;

const ous = [USERS, `OU=Finance,${USERS}`, `OU=IT,${USERS}`, `OU=HR,${USERS}`, `OU=Operations,${USERS}`, `OU=Disabled Users,${USERS}`, GROUPS];

const now = () => new Date().toISOString();
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();

const users = new Map(); // key: lower sam
const groups = new Map();

function mkUser(sam, givenName, sn, ouName, extra = {}) {
  const ou = ouName ? `OU=${ouName},${USERS}` : USERS;
  const displayName = `${givenName} ${sn}`;
  const u = {
    dn: `CN=${displayName},${ou}`, sam, upn: `${sam}@corp.local`,
    givenName, sn, displayName, mail: `${sam}@example.com`, title: '', department: ouName || '',
    company: 'Example Corp', office: 'Head Office', telephoneNumber: '', mobile: '', employeeID: '', description: '',
    enabled: true, locked: false, passwordExpired: false, mustChangePassword: false, passwordNeverExpires: false,
    passwordLastSet: daysAgo(20), lastLogon: daysAgo(1), accountExpires: null, created: daysAgo(400), changed: daysAgo(5),
    protected: false, password: DEMO_PASSWORD, ...extra,
  };
  users.set(sam.toLowerCase(), u);
  return u;
}

function mkGroup(name, description, members = [], extra = {}) {
  const g = {
    dn: `CN=${name},${extra.ou || GROUPS}`, sam: name, name, description, info: '', mail: '',
    groupType: groupTypeValue(extra.scope || 'global', extra.type || 'security'),
    created: daysAgo(500), changed: daysAgo(30), protected: !!extra.protected,
    members: new Set(members.map((s) => objBySam(s).dn)),
  };
  groups.set(name.toLowerCase(), g);
  return g;
}

mkUser('portal.admin', 'Portal', 'Admin', 'IT', { title: 'IT Manager', employeeID: 'EMP001' });
mkUser('helpdesk', 'Help', 'Desk', 'IT', { title: 'IT Support Executive', employeeID: 'EMP002' });
mkUser('arjun.mehta', 'Arjun', 'Mehta', 'IT', { title: 'System Administrator', employeeID: 'EMP003' });
mkUser('anita.sharma', 'Anita', 'Sharma', 'Finance', { title: 'Accounts Manager', employeeID: 'EMP101' });
mkUser('suresh.kumar', 'Suresh', 'Kumar', 'Finance', { title: 'Accountant', employeeID: 'EMP102', locked: true });
mkUser('priya.nair', 'Priya', 'Nair', 'HR', { title: 'HR Executive', employeeID: 'EMP201', mustChangePassword: true, lastLogon: null });
mkUser('rahul.verma', 'Rahul', 'Verma', 'Operations', { title: 'Site Engineer', employeeID: 'EMP301' });
mkUser('deepa.reddy', 'Deepa', 'Reddy', 'Operations', { title: 'Project Coordinator', employeeID: 'EMP302', passwordExpired: true });
mkUser('kiran.patel', 'Kiran', 'Patel', 'Disabled Users', { title: 'Former Site Supervisor', enabled: false, lastLogon: daysAgo(120) });
mkUser('it.superadmin', 'IT', 'Super Admin', 'IT', { title: 'Domain admin account', protected: true, passwordNeverExpires: true });

function objBySam(sam) {
  const k = sam.toLowerCase();
  const o = users.get(k) || groups.get(k);
  if (!o) throw new Error('mock: unknown ' + sam);
  return o;
}

mkGroup('ADPortal-Admins', 'Full access to the AD Admin Portal', ['portal.admin', 'arjun.mehta']);
mkGroup('ADPortal-Helpdesk', 'Helpdesk access to the AD Admin Portal (reset/unlock/enable)', ['helpdesk']);
mkGroup('Finance-Team', 'Finance department staff', ['anita.sharma', 'suresh.kumar']);
mkGroup('HR-Team', 'HR department staff', ['priya.nair']);
mkGroup('Operations-Team', 'Site & project operations', ['rahul.verma', 'deepa.reddy']);
mkGroup('VPN-Users', 'Remote access VPN', ['anita.sharma', 'rahul.verma', 'arjun.mehta']);
mkGroup('WiFi-Corp', 'Corporate Wi-Fi access', ['anita.sharma', 'suresh.kumar', 'priya.nair', 'rahul.verma', 'deepa.reddy']);
mkGroup('ERP-Users', 'ERP application users', ['anita.sharma', 'suresh.kumar', 'deepa.reddy']);
mkGroup('All-Staff', 'All staff distribution list', [], { type: 'distribution', scope: 'universal' });
groups.get('all-staff').members.add(groups.get('finance-team').dn);
groups.get('all-staff').members.add(groups.get('hr-team').dn);
groups.get('all-staff').members.add(groups.get('operations-team').dn);
mkGroup('Domain Admins', 'Designated administrators of the domain', ['it.superadmin'], { ou: `CN=Users,${BASE}`, protected: true });

// ---------------------------------------------------------------- helpers

const delay = () => new Promise((r) => setTimeout(r, 120));
const clone = (o) => JSON.parse(JSON.stringify(o, (k, v) => (v instanceof Set ? [...v] : v)));
const byDn = (dn) => [...users.values(), ...groups.values()].find((o) => normDn(o.dn) === normDn(dn));

function findUser(sam) {
  const u = users.get(String(sam).toLowerCase());
  if (!u || !inScope(u.dn, config.userOUs)) throw new AdError(404, `User "${sam}" was not found in the OUs this portal manages.`);
  return u;
}
function findGroup(sam) {
  const g = groups.get(String(sam).toLowerCase());
  if (!g) throw new AdError(404, `Group "${sam}" was not found.`);
  return g;
}
function writableUser(u) { if (u.protected) throw new AdError(403, PROTECTED_MSG); }
function writableGroup(g) {
  if (!inScope(g.dn, config.groupOUs)) throw new AdError(403, `Group "${g.sam}" is outside the OUs this portal manages.`);
  if (g.protected) throw new AdError(403, PROTECTED_MSG);
}
function checkPolicy(pwd, sam) {
  const cats = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pwd)).length;
  if (pwd.length < 8 || cats < 3 || pwd.toLowerCase().includes(sam.toLowerCase())) {
    throw new AdError(400, 'The password does not meet the domain password policy (length, complexity or history).');
  }
}
function assertOu(ou, list, kind) {
  if (!ou || !inScope(ou, list) || !ous.some((o) => normDn(o) === normDn(ou))) throw new AdError(400, `Choose a valid ${kind} OU managed by this portal.`);
}
const samTaken = (sam) => users.has(sam.toLowerCase()) || groups.has(sam.toLowerCase());

function shapeGroup(g) {
  const t = describeGroupType(g.groupType);
  const { members, groupType, ...rest } = g;
  return { ...clone(rest), ou: parentDn(g.dn), scope: t.scope, type: t.type, manageable: inScope(g.dn, config.groupOUs) && !g.protected };
}
function shapeUser(u) {
  const { password, ...rest } = u;
  return { ...clone(rest), ou: parentDn(u.dn) };
}
const touch = (o) => { o.changed = now(); };

// ---------------------------------------------------------------- API

export const directory = {
  name: 'mock',

  async authenticate(username, password) {
    await delay();
    const sam = String(username).replace(/^.*\\/, '').replace(/@.*$/, '').trim().toLowerCase();
    const u = users.get(sam);
    if (!u || !password || u.password !== password || !u.enabled || u.locked) throw new AdError(401, 'Invalid username or password.');
    return { dn: u.dn, sam: u.sam, displayName: u.displayName };
  },

  async isMemberOf(userDn, groupDn) {
    const g = byDn(groupDn);
    if (!g) return false;
    const seen = new Set();
    const walk = (grp) => {
      for (const m of grp.members) {
        if (normDn(m) === normDn(userDn)) return true;
        const sub = byDn(m);
        if (sub?.members && !seen.has(sub.dn)) { seen.add(sub.dn); if (walk(sub)) return true; }
      }
      return false;
    };
    return walk(g);
  },

  async listOUs() {
    const shape = (list) => ous.filter((o) => inScope(o, list)).map((dn) => ({ dn, name: dn.split(/,DC=/i)[0] }));
    return { userOUs: shape(config.userOUs), groupOUs: shape(config.groupOUs) };
  },

  async searchUsers(q, { status = 'all' } = {}) {
    await delay();
    const ql = (q || '').toLowerCase();
    const items = [...users.values()]
      .filter((u) => inScope(u.dn, config.userOUs))
      .filter((u) => !ql || [u.sam, u.displayName, u.mail, u.employeeID].some((v) => String(v).toLowerCase().includes(ql)))
      .filter((u) => status === 'all' || (status === 'enabled' && u.enabled) || (status === 'disabled' && !u.enabled) || (status === 'locked' && u.locked))
      .map(shapeUser)
      .sort((a, b) => a.displayName.localeCompare(b.displayName));
    return { items, total: items.length, truncated: false };
  },

  async getUser(sam) {
    await delay();
    const u = findUser(sam);
    const out = shapeUser(u);
    out.groups = [...groups.values()].filter((g) => [...g.members].some((m) => normDn(m) === normDn(u.dn))).map(shapeGroup)
      .sort((a, b) => a.name.localeCompare(b.name));
    return out;
  },

  async createUser(d) {
    await delay();
    assertOu(d.ou, config.userOUs, 'user');
    if (samTaken(d.sam)) throw new AdError(409, `Username "${d.sam}" already exists in the domain.`);
    checkPolicy(d.password, d.sam);
    const cn = d.displayName || `${d.givenName} ${d.sn}`.trim();
    const dn = `CN=${cn},${d.ou}`;
    if (byDn(dn)) throw new AdError(409, 'An object with that name already exists.');
    const u = { dn, sam: d.sam, upn: `${d.sam}@${d.upnSuffix || config.upnSuffix}`, enabled: !!d.enabled, locked: false, passwordExpired: false,
      mustChangePassword: !!d.mustChange, passwordNeverExpires: false, passwordLastSet: d.mustChange ? null : now(), lastLogon: null,
      accountExpires: null, created: now(), changed: now(), protected: false, password: d.password };
    for (const k of Object.keys(USER_FIELDS)) u[k] = d[k] || '';
    u.displayName = cn;
    users.set(d.sam.toLowerCase(), u);
    const warnings = [];
    for (const gs of d.groups || []) {
      try { const g = findGroup(gs); writableGroup(g); g.members.add(dn); } catch (e) { warnings.push(`Could not add to group ${gs}: ${e.message}`); }
    }
    return { sam: d.sam, dn, warnings };
  },

  async updateUser(sam, fields) {
    await delay();
    const u = findUser(sam); writableUser(u);
    const before = {};
    for (const [k, v] of Object.entries(fields)) if ((u[k] || '') !== v) { before[k] = u[k] || ''; u[k] = v; }
    if (Object.keys(before).length) touch(u);
    return { changed: Object.keys(before), before };
  },

  async resetPassword(sam, { password, mustChange, unlock }) {
    await delay();
    const u = findUser(sam); writableUser(u);
    checkPolicy(password, u.sam);
    Object.assign(u, { password, mustChangePassword: !!mustChange, passwordExpired: false, passwordLastSet: mustChange ? null : now() });
    if (unlock) u.locked = false;
    touch(u);
    return { dn: u.dn };
  },

  async unlockUser(sam) { await delay(); const u = findUser(sam); u.locked = false; touch(u); return { dn: u.dn }; },

  async setUserEnabled(sam, enabled) { await delay(); const u = findUser(sam); writableUser(u); u.enabled = !!enabled; touch(u); return { dn: u.dn }; },

  async moveUser(sam, targetOu) {
    await delay();
    assertOu(targetOu, config.userOUs, 'user');
    const u = findUser(sam); writableUser(u);
    if (normDn(parentDn(u.dn)) === normDn(targetOu)) throw new AdError(400, 'The user is already in that OU.');
    const from = u.dn;
    const to = `CN=${rdnValue(u.dn)},${targetOu}`;
    for (const g of groups.values()) if ([...g.members].some((m) => normDn(m) === normDn(from))) { g.members.delete(from); g.members.add(to); }
    u.dn = to; touch(u);
    return { from, to };
  },

  async deleteUser(sam) {
    await delay();
    const u = findUser(sam); writableUser(u);
    for (const g of groups.values()) g.members.delete(u.dn);
    users.delete(u.sam.toLowerCase());
    return { dn: u.dn };
  },

  async searchGroups(q) {
    await delay();
    const ql = (q || '').toLowerCase();
    const items = [...groups.values()].filter((g) => inScope(g.dn, config.groupOUs))
      .filter((g) => !ql || [g.sam, g.description].some((v) => v.toLowerCase().includes(ql)))
      .map(shapeGroup).sort((a, b) => a.name.localeCompare(b.name));
    return { items, total: items.length, truncated: false };
  },

  async getGroup(sam) {
    await delay();
    const g = findGroup(sam);
    if (!inScope(g.dn, config.groupOUs)) throw new AdError(404, `Group "${sam}" is outside the OUs this portal manages.`);
    const out = shapeGroup(g);
    out.members = [...g.members].map(byDn).filter(Boolean).map((m) => {
      const kind = m.members ? 'group' : 'user';
      return { dn: m.dn, sam: m.sam, name: m.displayName || m.name, kind, enabled: kind === 'group' ? true : m.enabled,
        inScope: inScope(m.dn, kind === 'group' ? config.groupOUs : config.userOUs) };
    }).sort((a, b) => a.name.localeCompare(b.name));
    return out;
  },

  async createGroup(d) {
    await delay();
    assertOu(d.ou, config.groupOUs, 'group');
    if (samTaken(d.name)) throw new AdError(409, `"${d.name}" already exists in the domain.`);
    const g = mkGroup(d.name, d.description, [], { ou: d.ou, scope: d.scope, type: d.type });
    Object.assign(g, { info: d.info || '', mail: d.mail || '', created: now(), changed: now() });
    return { sam: d.name, dn: g.dn };
  },

  async updateGroup(sam, fields) {
    await delay();
    const g = findGroup(sam); writableGroup(g);
    const before = {};
    for (const [k, v] of Object.entries(fields)) if ((g[k] || '') !== v) { before[k] = g[k] || ''; g[k] = v; }
    if (Object.keys(before).length) touch(g);
    return { changed: Object.keys(before), before };
  },

  async deleteGroup(sam) {
    await delay();
    const g = findGroup(sam); writableGroup(g);
    for (const other of groups.values()) other.members.delete(g.dn);
    groups.delete(g.sam.toLowerCase());
    return { dn: g.dn };
  },

  async addMember(groupSam, memberSam) {
    await delay();
    const g = findGroup(groupSam); writableGroup(g);
    const m = users.get(memberSam.toLowerCase()) || groups.get(memberSam.toLowerCase());
    if (!m) throw new AdError(404, `"${memberSam}" was not found.`);
    if (m === g) throw new AdError(400, 'A group cannot be a member of itself.');
    if (g.members.has(m.dn)) throw new AdError(409, `"${memberSam}" is already a member of ${groupSam}.`);
    g.members.add(m.dn); touch(g);
    return { group: g.dn, member: m.dn };
  },

  async removeMember(groupSam, memberSam) {
    await delay();
    const g = findGroup(groupSam); writableGroup(g);
    const m = users.get(memberSam.toLowerCase()) || groups.get(memberSam.toLowerCase());
    if (!m) throw new AdError(404, `"${memberSam}" was not found.`);
    if (!g.members.delete(m.dn)) throw new AdError(400, `"${memberSam}" is not a direct member of ${groupSam}.`);
    touch(g);
    return { group: g.dn, member: m.dn };
  },

  async ping() { return true; },
};

console.log(`[mock] Demo sign-in: portal.admin (admin role) or helpdesk (helpdesk role), password ${DEMO_PASSWORD}`);
