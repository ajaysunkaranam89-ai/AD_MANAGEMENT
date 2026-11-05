// Sign-in protections: per-account throttling, TOTP multi-factor, IP allow-list.
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { config, DATA_DIR, MOCK } from './config.js';
import { encrypt, decrypt } from './settings.js';

// ---------------------------------------------------------------- per-account throttling
// AD locks an account after a few bad passwords (often 3-5). The portal stops trying
// *before* that, so nobody can use the portal to lock other people out of AD.
const failures = new Map(); // account -> { count, first, blockedUntil }
const WINDOW_MS = 15 * 60 * 1000;

export const accountKey = (u) => String(u || '').replace(/^.*\\/, '').replace(/@.*$/, '').trim().toLowerCase();

export function throttleCheck(account) {
  const f = failures.get(account);
  if (!f) return null;
  const now = Date.now();
  if (f.blockedUntil && f.blockedUntil > now) return Math.ceil((f.blockedUntil - now) / 60000);
  if (now - f.first > WINDOW_MS) failures.delete(account);
  return null;
}

export function throttleFail(account) {
  const now = Date.now();
  const f = failures.get(account) && now - failures.get(account).first <= WINDOW_MS ? failures.get(account) : { count: 0, first: now };
  f.count++;
  if (f.count >= config.security.maxFailuresPerUser) f.blockedUntil = now + WINDOW_MS;
  failures.set(account, f);
}

export const throttleReset = (account) => failures.delete(account);

// keep the map small
setInterval(() => {
  const now = Date.now();
  for (const [k, f] of failures) if (now - f.first > WINDOW_MS && (!f.blockedUntil || f.blockedUntil < now)) failures.delete(k);
}, 60000).unref();

// ---------------------------------------------------------------- IP allow-list

export function parseAllowEntry(entry) {
  const s = String(entry).trim();
  const [ip, bits] = s.split('/');
  const type = net.isIP(ip);
  if (!type) return null;
  if (bits !== undefined) {
    const n = Number(bits);
    if (!Number.isInteger(n) || n < 0 || n > (type === 4 ? 32 : 128)) return null;
  }
  return { ip, bits: bits === undefined ? undefined : Number(bits), type: type === 4 ? 'ipv4' : 'ipv6', text: s };
}

function buildList(entries) {
  const bl = new net.BlockList();
  for (const e of entries.map(parseAllowEntry).filter(Boolean)) {
    if (e.bits === undefined) bl.addAddress(e.ip, e.type); else bl.addSubnet(e.ip, e.bits, e.type);
  }
  return bl;
}

const normIp = (ip) => String(ip || '').replace(/^::ffff:/i, '');
const isLoopback = (ip) => ['127.0.0.1', '::1'].includes(normIp(ip)) || normIp(ip).startsWith('127.');

// Loopback is always allowed so the server itself can never be locked out.
export function ipAllowed(ip, entries = config.security.ipAllowlist) {
  if (!entries?.length || isLoopback(ip)) return true;
  const a = normIp(ip);
  return buildList(entries).check(a, net.isIP(a) === 6 ? 'ipv6' : 'ipv4');
}

// ---------------------------------------------------------------- TOTP (RFC 6238)

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const ch of str.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(ch); if (i < 0) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function hotp(secret, counter) {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}
export const newTotpSecret = () => base32Encode(crypto.randomBytes(20));

// Returns the matched time-step (for replay protection) or null. Accepts ±1 step clock drift.
export function verifyTotp(secret, code, lastStep = -1) {
  const c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return null;
  const step = Math.floor(Date.now() / 30000);
  for (const s of [step - 1, step, step + 1]) {
    if (s > lastStep && crypto.timingSafeEqual(Buffer.from(hotp(secret, s)), Buffer.from(c))) return s;
  }
  return null;
}

export const otpauthUrl = (secret, account) => {
  const issuer = (config.branding.orgName || 'AD Admin Portal').replace(/[:]/g, '');
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${account}`)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
};

// ---------------------------------------------------------------- MFA enrolment store (secrets encrypted)

const MFA_FILE = path.join(DATA_DIR, MOCK ? 'mfa-demo.json' : 'mfa.json');
let mfa = {};
try { mfa = JSON.parse(fs.readFileSync(MFA_FILE, 'utf8')); } catch { mfa = {}; }
const saveMfa = () => { fs.writeFileSync(MFA_FILE + '.tmp', JSON.stringify(mfa, null, 2)); fs.renameSync(MFA_FILE + '.tmp', MFA_FILE); };

export function mfaRecord(account) {
  const r = mfa[account];
  return r ? { secret: decrypt(r.secret), lastStep: r.lastStep ?? -1, enrolledAt: r.enrolledAt } : null;
}
export function mfaEnroll(account, secret, step) {
  mfa[account] = { secret: encrypt(secret), enrolledAt: new Date().toISOString(), lastStep: step };
  saveMfa();
}
export function mfaUsed(account, step) {
  if (mfa[account]) { mfa[account].lastStep = step; saveMfa(); }
}
export function mfaReset(account) {
  const had = !!mfa[account];
  delete mfa[account];
  saveMfa();
  return had;
}
export const mfaList = () => Object.entries(mfa).map(([account, r]) => ({ account, enrolledAt: r.enrolledAt })).sort((a, b) => a.account.localeCompare(b.account));
