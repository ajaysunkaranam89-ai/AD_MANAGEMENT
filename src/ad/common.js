// Helpers shared by the real LDAP directory and the mock directory.

export class AdError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export const UAC = {
  ACCOUNTDISABLE: 0x2,
  NORMAL_ACCOUNT: 0x200,
  DONT_EXPIRE_PASSWORD: 0x10000,
  LOCKOUT: 0x10, // in msDS-User-Account-Control-Computed
  PASSWORD_EXPIRED: 0x800000, // in msDS-User-Account-Control-Computed
};

export const GROUP_SCOPES = { global: 0x2, domainlocal: 0x4, universal: 0x8 };
const SECURITY_ENABLED = 0x80000000;

export function groupTypeValue(scope, type) {
  const s = GROUP_SCOPES[scope];
  if (!s) throw new AdError(400, 'Invalid group scope');
  // Bitwise OR gives the signed 32-bit value AD expects (e.g. -2147483646)
  return type === 'security' ? s | SECURITY_ENABLED : s;
}

export function describeGroupType(gt) {
  const n = Number(gt);
  const scope = n & 0x2 ? 'global' : n & 0x4 ? 'domainlocal' : n & 0x8 ? 'universal' : 'unknown';
  return { scope, type: n & SECURITY_ENABLED ? 'security' : 'distribution' };
}

// RFC 4515 filter value escaping
export function escapeFilter(v) {
  return String(v).replace(/[\\*()\0]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

// RFC 4514 RDN value escaping
export function escapeDnValue(v) {
  let s = String(v).replace(/[\\,+"<>;=]/g, (c) => '\\' + c);
  if (s.startsWith(' ') || s.startsWith('#')) s = '\\' + s;
  if (s.endsWith(' ')) s = s.slice(0, -1) + '\\ ';
  return s;
}

export const normDn = (dn) => String(dn).toLowerCase().replace(/\s*,\s*/g, ',').replace(/\s*=\s*/g, '=');

export function isUnder(dn, ou) {
  const d = normDn(dn);
  const o = normDn(ou);
  return d === o || d.endsWith(',' + o);
}

export const inScope = (dn, ous) => ous.some((ou) => isUnder(dn, ou));

// First RDN value of a DN, unescaped (CN=Smith\, John,OU=... -> "Smith, John")
export function rdnValue(dn) {
  const m = String(dn).match(/^[^=]+=((?:\\.|[^,])*)/);
  return m ? m[1].replace(/\\(.)/g, '$1') : String(dn);
}

export function parentDn(dn) {
  const m = String(dn).match(/^(?:\\.|[^,])*,(.*)$/);
  return m ? m[1] : '';
}

export const arr = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
export const one = (v) => (Array.isArray(v) ? v[0] : v);

// AD FILETIME (100ns since 1601) -> ISO string, or null
export function fileTimeToIso(v) {
  const s = one(v);
  if (!s || s === '0' || s === '9223372036854775807') return null;
  try {
    const ms = Number(BigInt(s) / 10000n) - 11644473600000;
    return new Date(ms).toISOString();
  } catch {
    return null;
  }
}

// AD GeneralizedTime (20261105103000.0Z) -> ISO string
export function genTimeToIso(v) {
  const s = one(v);
  const m = s && String(s).match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
  return m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])).toISOString() : null;
}

// --- input validation -------------------------------------------------------

const CONTROL = /[\u0000-\u001f\u007f]/;

export function text(v, field, { max = 64, required = false } = {}) {
  const s = v === undefined || v === null ? '' : String(v).trim();
  if (required && !s) throw new AdError(400, `${field} is required`);
  if (s.length > max) throw new AdError(400, `${field} must be at most ${max} characters`);
  if (CONTROL.test(s)) throw new AdError(400, `${field} contains invalid characters`);
  return s;
}

export function userSam(v) {
  const s = text(v, 'Username', { max: 20, required: true });
  if (!/^[A-Za-z0-9._-]+$/.test(s)) throw new AdError(400, 'Username may contain only letters, numbers, dot, dash and underscore');
  return s;
}

export function groupSam(v) {
  const s = text(v, 'Group name', { max: 64, required: true });
  if (!/^[A-Za-z0-9 ._&-]+$/.test(s)) throw new AdError(400, 'Group name may contain only letters, numbers, spaces and . _ - &');
  return s;
}

export function password(v) {
  const s = v === undefined || v === null ? '' : String(v);
  if (!s) throw new AdError(400, 'Password is required');
  if (s.length > 128) throw new AdError(400, 'Password is too long');
  if (CONTROL.test(s)) throw new AdError(400, 'Password contains invalid characters');
  return s;
}

// Editable user attributes: field name in API -> LDAP attribute
export const USER_FIELDS = {
  givenName: 'givenName',
  sn: 'sn',
  displayName: 'displayName',
  mail: 'mail',
  title: 'title',
  department: 'department',
  company: 'company',
  office: 'physicalDeliveryOfficeName',
  telephoneNumber: 'telephoneNumber',
  mobile: 'mobile',
  employeeID: 'employeeID',
  description: 'description',
};

export function cleanUserFields(body) {
  const out = {};
  for (const key of Object.keys(USER_FIELDS)) {
    if (body[key] !== undefined) out[key] = text(body[key], key, { max: key === 'description' ? 256 : 128 });
  }
  if (out.mail && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(out.mail)) throw new AdError(400, 'E-mail address is not valid');
  return out;
}

export const PROTECTED_MSG = 'This is a protected (privileged) AD object. For safety it can only be changed directly on the domain controller.';
