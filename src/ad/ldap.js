// Real Active Directory implementation (LDAPS) using the ldapts library.
import fs from 'node:fs';
import { Client, Change, Attribute } from 'ldapts';
import { config } from '../config.js';
import {
  AdError, UAC, PROTECTED_MSG, USER_FIELDS,
  escapeFilter, escapeDnValue, inScope, normDn, rdnValue, parentDn,
  arr, one, fileTimeToIso, genTimeToIso, groupTypeValue, describeGroupType,
} from './common.js';

const USER_ATTRS = [
  'distinguishedName', 'sAMAccountName', 'userPrincipalName', 'cn', 'adminCount', 'isCriticalSystemObject',
  'userAccountControl', 'lockoutTime', 'pwdLastSet', 'lastLogonTimestamp', 'whenCreated', 'whenChanged',
  'accountExpires', 'msDS-User-Account-Control-Computed', ...Object.values(USER_FIELDS),
];
const MAX_RESULTS = 5000;
const GROUP_ATTRS = [
  'distinguishedName', 'sAMAccountName', 'cn', 'description', 'info', 'mail', 'groupType',
  'adminCount', 'isCriticalSystemObject', 'whenCreated', 'whenChanged',
];

// ---------------------------------------------------------------- connection

function tlsOptions(conn) {
  const o = { rejectUnauthorized: conn.rejectUnauthorized !== false };
  if (conn.caPem) o.ca = [conn.caPem];
  else if (conn.caCert) o.ca = [fs.readFileSync(conn.caCert)];
  return o;
}

const newClient = (conn = config.ldap) => new Client({
  url: conn.url,
  tlsOptions: tlsOptions(conn),
  timeout: 20000,
  connectTimeout: 10000,
});

function mapError(e) {
  if (e instanceof AdError) return e;
  const msg = String(e?.message || e);
  const code = e?.code;
  if (/0000052D/i.test(msg) || (code === 19 && /pwd|password/i.test(msg))) {
    return new AdError(400, 'The password does not meet the domain password policy (length, complexity or history).');
  }
  switch (code) {
    case 19: return new AdError(400, `AD rejected the change (constraint violation): ${msg}`);
    case 32: return new AdError(404, 'Object not found in Active Directory.');
    case 49: return new AdError(401, 'Invalid username or password.');
    case 50: return new AdError(403, 'The portal service account does not have permission for this action in AD. Check the OU delegation (setup script).');
    case 53: return new AdError(400, `AD refused the operation: ${msg}`);
    case 66: return new AdError(400, 'The object is not empty (it has child objects).');
    case 68: return new AdError(409, 'An object with that name already exists.');
    default:
      if (/ENOTFOUND|EAI_AGAIN/i.test(msg)) {
        return new AdError(503, 'Domain controller name could not be resolved (DNS). Check the server name.');
      }
      if (/ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ECONNRESET|timeout/i.test(msg)) {
        return new AdError(503, 'Cannot reach the domain controller over LDAPS. Check the server name and that port 636 is open and LDAPS is enabled (the DC needs a certificate).');
      }
      if (/ALTNAME|Hostname\/IP does not match/i.test(msg)) {
        return new AdError(503, "The DC certificate does not match the server name you entered. Use the DC's full DNS name (e.g. dc01.corp.local), not an IP.");
      }
      if (/certificate|self.signed|CERT_|unable to verify/i.test(msg)) {
        return new AdError(503, 'The LDAPS certificate is not trusted. Upload your root CA certificate (Base-64 .cer / PEM) in Settings.');
      }
      return new AdError(500, `Active Directory error: ${msg}`);
  }
}

async function withService(fn) {
  const c = newClient();
  try {
    await c.bind(config.ldap.bindDn, config.ldap.bindPassword);
    return await fn(c);
  } catch (e) {
    throw mapError(e);
  } finally {
    await c.unbind().catch(() => {});
  }
}

async function search(c, base, filter, attributes, opts = {}) {
  const { searchEntries } = await c.search(base, {
    scope: opts.scope || 'sub',
    filter,
    attributes,
    paged: opts.scope === 'base' ? false : { pageSize: 500 },
  });
  return searchEntries;
}

async function searchMany(c, bases, filter, attributes) {
  const seen = new Set();
  const out = [];
  for (const base of bases) {
    for (const e of await search(c, base, filter, attributes)) {
      const k = normDn(e.dn);
      if (!seen.has(k)) { seen.add(k); out.push(e); }
    }
  }
  return out;
}

const replace = (type, values) => new Change({ operation: 'replace', modification: new Attribute({ type, values: arr(values) }) });
const addVal = (type, values) => new Change({ operation: 'add', modification: new Attribute({ type, values: arr(values) }) });
const delVal = (type, values) => new Change({ operation: 'delete', modification: new Attribute({ type, values: arr(values) }) });
const encodePwd = (p) => Buffer.from(`"${p}"`, 'utf16le');

const isProtected = (e) => one(e.adminCount) === '1' || String(one(e.isCriticalSystemObject)).toUpperCase() === 'TRUE'
  || PRIVILEGED_GROUPS.has(String(one(e.sAMAccountName) || '').toLowerCase());

// Groups that lead to domain-level control but are not always flagged by AdminSDHolder
// (e.g. DnsAdmins can run code on DCs). Never manageable from the portal.
const PRIVILEGED_GROUPS = new Set([
  'domain admins', 'enterprise admins', 'schema admins', 'administrators', 'account operators', 'server operators',
  'backup operators', 'print operators', 'replicator', 'domain controllers', 'read-only domain controllers',
  'enterprise read-only domain controllers', 'cloneable domain controllers', 'key admins', 'enterprise key admins',
  'dnsadmins', 'dnsupdateproxy', 'group policy creator owners', 'cert publishers', 'protected users',
  'incoming forest trust builders', 'windows authorization access group', 'ras and ias servers',
  'allowed rodc password replication group', 'denied rodc password replication group', 'hyper-v administrators',
  'storage replica administrators', 'remote management users', 'remote desktop users', 'distributed com users',
  'event log readers', 'certificate service dcom access', 'network configuration operators', 'cryptographic operators',
]);

// ---------------------------------------------------------------- shaping

function shapeUser(e, computed) {
  const uac = Number(one(e.userAccountControl) || 0);
  // msDS-User-Account-Control-Computed gives the real lock / password-expired state
  // (lockoutTime stays set after a lockout expires, so it over-reports locked accounts)
  const rawComp = computed !== undefined ? computed : one(e['msDS-User-Account-Control-Computed']);
  const comp = rawComp === undefined ? null : Number(rawComp || 0);
  const out = {
    dn: e.dn,
    ou: parentDn(e.dn),
    sam: one(e.sAMAccountName),
    upn: one(e.userPrincipalName) || '',
    enabled: !(uac & UAC.ACCOUNTDISABLE),
    locked: comp === null ? Number(one(e.lockoutTime) || 0) > 0 : !!(comp & UAC.LOCKOUT),
    passwordExpired: comp === null ? false : !!(comp & UAC.PASSWORD_EXPIRED),
    mustChangePassword: one(e.pwdLastSet) === '0',
    passwordNeverExpires: !!(uac & UAC.DONT_EXPIRE_PASSWORD),
    passwordLastSet: fileTimeToIso(e.pwdLastSet),
    lastLogon: fileTimeToIso(e.lastLogonTimestamp),
    accountExpires: fileTimeToIso(e.accountExpires),
    created: genTimeToIso(e.whenCreated),
    changed: genTimeToIso(e.whenChanged),
    protected: isProtected(e),
  };
  for (const [k, attr] of Object.entries(USER_FIELDS)) out[k] = one(e[attr]) || '';
  if (!out.displayName) out.displayName = one(e.cn) || out.sam;
  return out;
}

function shapeGroup(e) {
  const t = describeGroupType(one(e.groupType));
  return {
    dn: e.dn,
    ou: parentDn(e.dn),
    sam: one(e.sAMAccountName),
    name: one(e.cn) || one(e.sAMAccountName),
    description: one(e.description) || '',
    info: one(e.info) || '',
    mail: one(e.mail) || '',
    scope: t.scope,
    type: t.type,
    created: genTimeToIso(e.whenCreated),
    changed: genTimeToIso(e.whenChanged),
    protected: isProtected(e),
    manageable: inScope(e.dn, config.groupOUs) && !isProtected(e),
  };
}

// ---------------------------------------------------------------- lookups

const USER_CLASS = '(objectCategory=person)(objectClass=user)';

// Search text -> LDAP filter part: each word (max 5) must appear in at least one attribute
function wordsFilter(q, attrs) {
  const words = String(q || '').trim().split(/\s+/).filter(Boolean).slice(0, 5);
  return words.map((w) => `(|${attrs.map((a) => `(${a}=*${escapeFilter(w)}*)`).join('')})`).join('');
}

async function findUser(c, sam, { anywhere = false } = {}) {
  const f = `(&${USER_CLASS}(sAMAccountName=${escapeFilter(sam)}))`;
  const found = await search(c, config.ldap.baseDn, f, USER_ATTRS);
  const e = found[0];
  if (!e || (!anywhere && !inScope(e.dn, config.userOUs))) throw new AdError(404, `User "${sam}" was not found in the OUs this portal manages.`);
  return e;
}

async function findGroup(c, sam) {
  const f = `(&(objectClass=group)(sAMAccountName=${escapeFilter(sam)}))`;
  const e = (await search(c, config.ldap.baseDn, f, GROUP_ATTRS))[0];
  if (!e) throw new AdError(404, `Group "${sam}" was not found.`);
  return e;
}

function assertWritableUser(e) {
  if (isProtected(e)) throw new AdError(403, PROTECTED_MSG);
}

function assertWritableGroup(e) {
  if (!inScope(e.dn, config.groupOUs)) throw new AdError(403, `Group "${one(e.sAMAccountName)}" is outside the OUs this portal manages.`);
  if (isProtected(e)) throw new AdError(403, PROTECTED_MSG);
}

function assertOu(ou, ous, kind) {
  if (!ou || !inScope(ou, ous)) throw new AdError(400, `Choose a valid ${kind} OU managed by this portal.`);
}

async function samTaken(c, sam) {
  const f = `(sAMAccountName=${escapeFilter(sam)})`;
  return (await search(c, config.ldap.baseDn, f, ['distinguishedName'])).length > 0;
}

// ---------------------------------------------------------------- API

export const directory = {
  name: 'ldap',

  async authenticate(username, password) {
    const sam = String(username).replace(/^.*\\/, '').replace(/@.*$/, '').trim();
    if (!sam || !password) throw new AdError(401, 'Invalid username or password.');
    const entry = await withService(async (c) => {
      const f = `(&${USER_CLASS}(sAMAccountName=${escapeFilter(sam)}))`;
      return (await search(c, config.ldap.baseDn, f, ['distinguishedName', 'sAMAccountName', 'displayName', 'cn']))[0];
    });
    if (!entry) throw new AdError(401, 'Invalid username or password.');

    const c = newClient();
    try {
      await c.bind(entry.dn, password);
    } catch (e) {
      const m = String(e?.message || '');
      if (/data (532|773)/.test(m)) throw new AdError(401, 'Your password has expired or must be changed. Change it on your PC (Ctrl+Alt+Del) and try again.');
      if (e?.code === 49) throw new AdError(401, 'Invalid username or password.');
      throw mapError(e);
    } finally {
      await c.unbind().catch(() => {});
    }
    return { dn: entry.dn, sam: one(entry.sAMAccountName), displayName: one(entry.displayName) || one(entry.cn) || sam };
  },

  async isMemberOf(userDn, groupDn) {
    if (!groupDn) return false;
    return withService(async (c) => {
      // LDAP_MATCHING_RULE_IN_CHAIN also catches nested group membership
      const f = `(member:1.2.840.113556.1.4.1941:=${escapeFilter(userDn)})`;
      try {
        return (await search(c, groupDn, f, ['distinguishedName'], { scope: 'base' })).length > 0;
      } catch (e) {
        if (e?.code === 32) return false;
        throw e;
      }
    });
  },

  async listOUs() {
    return withService(async (c) => {
      const load = async (roots) => {
        const items = await searchMany(c, roots, '(|(objectClass=organizationalUnit)(&(objectClass=container)(cn=Users)))', ['distinguishedName', 'ou']);
        return items.map((e) => ({ dn: e.dn, name: e.dn.split(/,DC=/i)[0] })).sort((a, b) => a.name.localeCompare(b.name));
      };
      return { userOUs: await load(config.userOUs), groupOUs: await load(config.groupOUs) };
    });
  },

  // ---------------- users

  async searchUsers(q, { status = 'all' } = {}) {
    return withService(async (c) => {
      // Every word must match one of the name fields, in any order ("smith john" = "john smith")
      let f = USER_CLASS + wordsFilter(q, ['sAMAccountName', 'displayName', 'mail', 'givenName', 'sn', 'employeeID', 'userPrincipalName']);
      if (status === 'disabled') f += '(userAccountControl:1.2.840.113556.1.4.803:=2)';
      if (status === 'enabled') f += '(!(userAccountControl:1.2.840.113556.1.4.803:=2))';
      if (status === 'locked') f += '(lockoutTime>=1)'; // candidates; real state checked below
      let all = (await searchMany(c, config.userOUs, `(&${f})`, USER_ATTRS)).map((x) => shapeUser(x));
      if (status === 'locked') all = all.filter((u) => u.locked);
      all.sort((a, b) => a.displayName.localeCompare(b.displayName));
      return { items: all.slice(0, MAX_RESULTS), total: all.length, truncated: all.length > MAX_RESULTS };
    });
  },

  async getUser(sam) {
    return withService(async (c) => {
      const e = await findUser(c, sam);
      // constructed attribute: only returned on base-scope searches
      const comp = (await search(c, e.dn, '(objectClass=*)', ['msDS-User-Account-Control-Computed'], { scope: 'base' }))[0];
      const user = shapeUser(e, one(comp?.['msDS-User-Account-Control-Computed']));
      const groups = await search(c, config.ldap.baseDn, `(&(objectClass=group)(member=${escapeFilter(e.dn)}))`, GROUP_ATTRS);
      user.groups = groups.map(shapeGroup).sort((a, b) => a.name.localeCompare(b.name));
      return user;
    });
  },

  async createUser(d) {
    assertOu(d.ou, config.userOUs, 'user');
    return withService(async (c) => {
      if (await samTaken(c, d.sam)) throw new AdError(409, `Username "${d.sam}" already exists in the domain.`);
      const cn = d.displayName || `${d.givenName} ${d.sn}`.trim();
      const dn = `CN=${escapeDnValue(cn)},${d.ou}`;
      const entry = {
        objectClass: ['top', 'person', 'organizationalPerson', 'user'],
        cn,
        sAMAccountName: d.sam,
        userPrincipalName: `${d.sam}@${d.upnSuffix || config.upnSuffix}`,
        displayName: cn,
        userAccountControl: String(UAC.NORMAL_ACCOUNT | UAC.ACCOUNTDISABLE),
      };
      for (const [k, attr] of Object.entries(USER_FIELDS)) if (d[k] && k !== 'displayName') entry[attr] = d[k];
      await c.add(dn, entry);

      try {
        await c.modify(dn, [replace('unicodePwd', encodePwd(d.password))]);
        const changes = [];
        if (d.mustChange) changes.push(replace('pwdLastSet', '0'));
        if (d.enabled) changes.push(replace('userAccountControl', String(UAC.NORMAL_ACCOUNT)));
        if (changes.length) await c.modify(dn, changes);
      } catch (err) {
        await c.del(dn).catch(() => {}); // roll back half-created account
        throw mapError(err);
      }

      const warnings = [];
      for (const g of d.groups || []) {
        try {
          const ge = await findGroup(c, g);
          assertWritableGroup(ge);
          await c.modify(ge.dn, [addVal('member', dn)]);
        } catch (err) {
          warnings.push(`Could not add to group ${g}: ${mapError(err).message}`);
        }
      }
      return { sam: d.sam, dn, warnings };
    });
  },

  async updateUser(sam, fields) {
    return withService(async (c) => {
      const e = await findUser(c, sam);
      assertWritableUser(e);
      const changes = [];
      const before = {};
      for (const [k, v] of Object.entries(fields)) {
        const attr = USER_FIELDS[k];
        const old = one(e[attr]) || '';
        if (old === v) continue;
        before[k] = old;
        changes.push(v ? replace(attr, v) : new Change({ operation: 'replace', modification: new Attribute({ type: attr, values: [] }) }));
      }
      if (changes.length) await c.modify(e.dn, changes);
      return { changed: Object.keys(before), before };
    });
  },

  async resetPassword(sam, { password, mustChange, unlock }) {
    return withService(async (c) => {
      const e = await findUser(c, sam);
      assertWritableUser(e);
      await c.modify(e.dn, [replace('unicodePwd', encodePwd(password))]);
      const changes = [replace('pwdLastSet', mustChange ? '0' : '-1')];
      if (unlock) changes.push(replace('lockoutTime', '0'));
      await c.modify(e.dn, changes);
      return { dn: e.dn };
    });
  },

  // Unlocking is allowed even for protected accounts: it only clears the lockout
  // counter and grants nothing (the person still needs the right password).
  async unlockUser(sam) {
    return withService(async (c) => {
      const e = await findUser(c, sam);
      await c.modify(e.dn, [replace('lockoutTime', '0')]);
      return { dn: e.dn };
    });
  },

  async setUserEnabled(sam, enabled) {
    return withService(async (c) => {
      const e = await findUser(c, sam);
      assertWritableUser(e);
      const uac = Number(one(e.userAccountControl) || UAC.NORMAL_ACCOUNT);
      const next = enabled ? uac & ~UAC.ACCOUNTDISABLE : uac | UAC.ACCOUNTDISABLE;
      await c.modify(e.dn, [replace('userAccountControl', String(next))]);
      return { dn: e.dn };
    });
  },

  async moveUser(sam, targetOu) {
    assertOu(targetOu, config.userOUs, 'user');
    return withService(async (c) => {
      const e = await findUser(c, sam);
      assertWritableUser(e);
      if (normDn(parentDn(e.dn)) === normDn(targetOu)) throw new AdError(400, 'The user is already in that OU.');
      const rdn = e.dn.match(/^((?:\\.|[^,])*)/)[1];
      const newDn = `${rdn},${targetOu}`;
      await c.modifyDN(e.dn, newDn);
      return { from: e.dn, to: newDn };
    });
  },

  async deleteUser(sam) {
    return withService(async (c) => {
      const e = await findUser(c, sam);
      assertWritableUser(e);
      await c.del(e.dn);
      return { dn: e.dn };
    });
  },

  // ---------------- groups

  async searchGroups(q) {
    return withService(async (c) => {
      const f = '(objectClass=group)' + wordsFilter(q, ['sAMAccountName', 'cn', 'description']);
      const all = (await searchMany(c, config.groupOUs, `(&${f})`, GROUP_ATTRS)).map(shapeGroup);
      all.sort((a, b) => a.name.localeCompare(b.name));
      return { items: all.slice(0, MAX_RESULTS), total: all.length, truncated: all.length > MAX_RESULTS };
    });
  },

  async getGroup(sam) {
    return withService(async (c) => {
      const e = await findGroup(c, sam);
      if (!inScope(e.dn, config.groupOUs)) throw new AdError(404, `Group "${sam}" is outside the OUs this portal manages.`);
      const g = shapeGroup(e);
      const members = await search(c, config.ldap.baseDn, `(memberOf=${escapeFilter(e.dn)})`,
        ['distinguishedName', 'sAMAccountName', 'displayName', 'cn', 'objectClass', 'userAccountControl']);
      g.members = members.map((m) => {
        const classes = arr(m.objectClass).map((x) => String(x).toLowerCase());
        const kind = classes.includes('group') ? 'group' : classes.includes('computer') ? 'computer' : 'user';
        return {
          dn: m.dn,
          sam: one(m.sAMAccountName),
          name: one(m.displayName) || one(m.cn) || rdnValue(m.dn),
          kind,
          enabled: kind === 'group' ? true : !(Number(one(m.userAccountControl) || 0) & UAC.ACCOUNTDISABLE),
          inScope: inScope(m.dn, kind === 'group' ? config.groupOUs : config.userOUs),
        };
      }).sort((a, b) => a.name.localeCompare(b.name));
      return g;
    });
  },

  async createGroup(d) {
    assertOu(d.ou, config.groupOUs, 'group');
    return withService(async (c) => {
      if (await samTaken(c, d.name)) throw new AdError(409, `"${d.name}" already exists in the domain.`);
      const dn = `CN=${escapeDnValue(d.name)},${d.ou}`;
      const entry = {
        objectClass: ['top', 'group'],
        cn: d.name,
        sAMAccountName: d.name,
        groupType: String(groupTypeValue(d.scope, d.type)),
      };
      if (d.description) entry.description = d.description;
      if (d.info) entry.info = d.info;
      if (d.mail) entry.mail = d.mail;
      await c.add(dn, entry);
      return { sam: d.name, dn };
    });
  },

  async updateGroup(sam, fields) {
    return withService(async (c) => {
      const e = await findGroup(c, sam);
      assertWritableGroup(e);
      const changes = [];
      const before = {};
      for (const k of ['description', 'info', 'mail']) {
        if (fields[k] === undefined) continue;
        const old = one(e[k]) || '';
        if (old === fields[k]) continue;
        before[k] = old;
        changes.push(replace(k, fields[k] ? fields[k] : []));
      }
      if (changes.length) await c.modify(e.dn, changes);
      return { changed: Object.keys(before), before };
    });
  },

  async deleteGroup(sam) {
    return withService(async (c) => {
      const e = await findGroup(c, sam);
      assertWritableGroup(e);
      await c.del(e.dn);
      return { dn: e.dn };
    });
  },

  async addMember(groupSam, memberSam) {
    return withService(async (c) => {
      const g = await findGroup(c, groupSam);
      assertWritableGroup(g);
      const f = `(&(|(&${USER_CLASS})(objectClass=group))(sAMAccountName=${escapeFilter(memberSam)}))`;
      const m = (await search(c, config.ldap.baseDn, f, ['distinguishedName']))[0];
      if (!m) throw new AdError(404, `"${memberSam}" was not found.`);
      if (normDn(m.dn) === normDn(g.dn)) throw new AdError(400, 'A group cannot be a member of itself.');
      try {
        await c.modify(g.dn, [addVal('member', m.dn)]);
      } catch (err) {
        if (err?.code === 68) throw new AdError(409, `"${memberSam}" is already a member of ${groupSam}.`);
        throw err;
      }
      return { group: g.dn, member: m.dn };
    });
  },

  async removeMember(groupSam, memberSam) {
    return withService(async (c) => {
      const g = await findGroup(c, groupSam);
      assertWritableGroup(g);
      const m = (await search(c, config.ldap.baseDn, `(sAMAccountName=${escapeFilter(memberSam)})`, ['distinguishedName']))[0];
      if (!m) throw new AdError(404, `"${memberSam}" was not found.`);
      try {
        await c.modify(g.dn, [delVal('member', m.dn)]);
      } catch (err) {
        if (err?.code === 53 || err?.code === 16) throw new AdError(400, `"${memberSam}" is not a direct member of ${groupSam}.`);
        throw err;
      }
      return { group: g.dn, member: m.dn };
    });
  },

  // Used by the setup screen: test a connection that is not saved yet and
  // discover the domain, OUs, groups and UPN suffixes for the pickers.
  async probe(conn, { checkMember } = {}) {
    const c = newClient(conn);
    const result = { steps: [] };
    try {
      try {
        await c.bind(conn.bindDn, conn.bindPassword);
      } catch (e) {
        const m = String(e?.message || '');
        if (e?.code === 49) {
          if (/data 775/.test(m)) throw new AdError(400, 'Service account is locked out.');
          if (/data 533/.test(m)) throw new AdError(400, 'Service account is disabled.');
          if (/data 532|data 773/.test(m)) throw new AdError(400, 'Service account password has expired or must be changed.');
          throw new AdError(400, 'Connected over LDAPS, but the service account sign-in failed: wrong username or password. Use user@domain or the full DN.');
        }
        throw mapError(e);
      }
      result.steps.push('Connected over LDAPS (encrypted) and signed in as the service account');

      const root = (await search(c, '', '(objectClass=*)',
        ['defaultNamingContext', 'configurationNamingContext', 'dnsHostName', 'domainFunctionality'], { scope: 'base' }))[0] || {};
      result.server = one(root.dnsHostName) || '';
      result.defaultNamingContext = one(root.defaultNamingContext) || '';
      const baseDn = conn.baseDn || result.defaultNamingContext;
      if (!baseDn) throw new AdError(400, 'Could not detect the base DN. Enter it manually (e.g. DC=corp,DC=local).');
      try {
        await search(c, baseDn, '(objectClass=*)', ['distinguishedName'], { scope: 'base' });
      } catch (e) {
        if (e?.code === 32) throw new AdError(400, `Base DN "${baseDn}" does not exist in this directory.`);
        throw e;
      }
      result.baseDn = baseDn;
      result.domain = baseDn.split(',').filter((p) => /^DC=/i.test(p.trim())).map((p) => p.trim().slice(3)).join('.');
      result.steps.push(`Domain ${result.domain} found on ${result.server || 'the domain controller'}`);

      const ous = await search(c, baseDn,
        '(|(objectClass=organizationalUnit)(&(objectClass=container)(cn=Users)))', ['distinguishedName']);
      result.ous = [baseDn, ...ous.map((e) => e.dn).filter((dn) => normDn(dn) !== normDn(baseDn))].sort((a, b) => a.split(',').reverse().join(',').localeCompare(b.split(',').reverse().join(',')));

      const groups = await search(c, baseDn, '(objectClass=group)', ['sAMAccountName', 'cn', 'description']);
      result.groups = groups.map((e) => ({ dn: e.dn, sam: one(e.sAMAccountName), description: one(e.description) || '' }))
        .sort((a, b) => String(a.sam).localeCompare(String(b.sam))).slice(0, 5000);
      result.steps.push(`Found ${result.ous.length} OUs and ${groups.length} groups`);

      result.upnSuffixes = [result.domain];
      const configNc = one(root.configurationNamingContext);
      if (configNc) {
        try {
          const p = (await search(c, `CN=Partitions,${configNc}`, '(objectClass=*)', ['uPNSuffixes'], { scope: 'base' }))[0];
          for (const s of arr(p?.uPNSuffixes)) if (!result.upnSuffixes.includes(s)) result.upnSuffixes.push(s);
        } catch { /* not readable: fine */ }
      }

      if (checkMember?.userDn && checkMember?.groupDn) {
        const f = `(member:1.2.840.113556.1.4.1941:=${escapeFilter(checkMember.userDn)})`;
        const hit = await search(c, checkMember.groupDn, f, ['distinguishedName'], { scope: 'base' }).catch(() => []);
        result.currentUserIsAdmin = hit.length > 0;
      }
      return result;
    } catch (e) {
      throw mapError(e);
    } finally {
      await c.unbind().catch(() => {});
    }
  },

  async ping() {
    return withService(async (c) => {
      await search(c, config.ldap.baseDn, '(objectClass=*)', ['distinguishedName'], { scope: 'base' });
      return true;
    });
  },
};
