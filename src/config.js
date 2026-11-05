import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

// Resolve .env and relative paths from the app folder, whatever the working directory is
export const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
dotenv.config({ path: path.join(APP_ROOT, '.env') });

export const MOCK = process.argv.includes('--mock') || process.env.MOCK_AD === 'true';
export const DATA_DIR = path.resolve(APP_ROOT, process.env.DATA_DIR || './data');

// DNs contain commas, so lists of DNs in .env are separated with "|"
const dnList = (name) => (process.env[name] || '').split('|').map((s) => s.trim()).filter(Boolean);
const bool = (v, def) => (v === undefined || v === '' ? def : /^(1|true|yes)$/i.test(v));

export const USERNAME_FORMATS = ['first.last', 'firstlast', 'flast', 'first.l', 'first', 'manual'];

// Effective configuration. Starts from .env (optional) and is overwritten by
// the settings saved from the web UI (data/settings.json) via applySettings().
export const config = {
  port: Number(process.env.PORT || 3200),
  httpsCert: process.env.HTTPS_CERT_FILE || '',
  httpsKey: process.env.HTTPS_KEY_FILE || '',
  trustProxy: bool(process.env.TRUST_PROXY, false),
  sessionTimeoutMinutes: Number(process.env.SESSION_TIMEOUT_MINUTES || 30),

  ldap: {
    url: process.env.LDAP_URL || '',
    caCert: process.env.LDAP_CA_CERT || '', // path to PEM file (.env only)
    caPem: '', // PEM text (from the web UI)
    rejectUnauthorized: bool(process.env.LDAP_TLS_REJECT_UNAUTHORIZED, true),
    baseDn: process.env.LDAP_BASE_DN || '',
    bindDn: process.env.LDAP_BIND_DN || '',
    bindPassword: process.env.LDAP_BIND_PASSWORD || '',
  },
  upnSuffix: process.env.AD_UPN_SUFFIX || '',

  userOUs: dnList('MANAGED_USER_OUS'),
  groupOUs: dnList('MANAGED_GROUP_OUS'),

  roleGroups: {
    admin: process.env.ROLE_ADMIN_GROUP || '',
    helpdesk: process.env.ROLE_HELPDESK_GROUP || '',
  },
  helpdeskPermissions: null, // null = defaults from roles.js

  branding: { orgName: process.env.ORG_NAME || '', logo: '' },

  provisioning: {
    upnSuffixes: [],
    emailDomain: '',
    usernameFormat: 'first.last',
    defaultUserOU: '',
    defaultGroups: [],
    mustChangeDefault: true,
    enabledDefault: true,
  },

  auditFile: path.resolve(APP_ROOT, process.env.AUDIT_LOG_FILE || './logs/audit.jsonl'),
};

// Apply settings saved from the web UI (see settings.js for the schema).
export function applySettings(s) {
  const c = s.connection;
  config.ldap.url = `ldaps://${c.host}:${c.port || 636}`;
  config.ldap.caPem = c.caPem || '';
  config.ldap.caCert = '';
  config.ldap.rejectUnauthorized = c.rejectUnauthorized !== false;
  config.ldap.baseDn = c.baseDn;
  config.ldap.bindDn = c.bindUser;
  config.ldap.bindPassword = c.bindPassword;
  config.userOUs = [...s.scope.userOUs];
  config.groupOUs = [...s.scope.groupOUs];
  config.roleGroups = { admin: s.roles.adminGroup, helpdesk: s.roles.helpdeskGroup || '' };
  config.helpdeskPermissions = Array.isArray(s.roles.helpdeskPermissions) ? [...s.roles.helpdeskPermissions] : null;
  config.branding = { orgName: s.branding?.orgName || '', logo: s.branding?.logo || '' };
  config.upnSuffix = s.provisioning.upnSuffix;
  config.provisioning = { ...config.provisioning, ...s.provisioning };
  config.sessionTimeoutMinutes = s.session?.timeoutMinutes || config.sessionTimeoutMinutes;
}

export function isConfigured() {
  if (MOCK) return true;
  const l = config.ldap;
  return !!(l.url && /^ldaps:\/\//i.test(l.url) && l.baseDn && l.bindDn && l.bindPassword
    && config.userOUs.length && config.groupOUs.length && config.roleGroups.admin && config.upnSuffix);
}
