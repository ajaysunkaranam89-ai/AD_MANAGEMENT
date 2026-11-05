// Append-only audit log: one JSON object per line (JSONL), one file per month.
// Records who did what, to which object, when, from which IP, and whether it succeeded.
// Passwords are never written.
//
// Tamper evidence: every entry carries `hash` = SHA-256(previous hash + entry), so
// editing or deleting a line breaks the chain (see verifyAudit / Audit log → Verify).
// Copies can also be sent to a syslog/SIEM server and the Windows Event Log.
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { execFile } from 'node:child_process';
import { config } from './config.js';

const dir = path.dirname(config.auditFile);
const base = path.basename(config.auditFile, path.extname(config.auditFile));
fs.mkdirSync(dir, { recursive: true });

const fileFor = (d) => path.join(dir, `${base}-${d.toISOString().slice(0, 7)}.jsonl`);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function auditFiles() {
  return fs.readdirSync(dir)
    .filter((f) => f.startsWith(base + '-') && f.endsWith('.jsonl'))
    .sort()
    .map((f) => path.join(dir, f));
}

// last hash of the newest file, so the chain continues across restarts and months
let lastHash = (() => {
  const files = auditFiles();
  for (let i = files.length - 1; i >= 0; i--) {
    const lines = fs.readFileSync(files[i], 'utf8').split('\n').filter(Boolean);
    for (let j = lines.length - 1; j >= 0; j--) {
      try { const e = JSON.parse(lines[j]); if (e.hash) return e.hash; } catch { /* skip */ }
    }
  }
  return '';
})();

export function audit(req, action, target, { result = 'success', details, error, actor } = {}) {
  const now = new Date();
  const entry = {
    time: now.toISOString(),
    actor: actor || req.session?.user?.sam || req.body?.username || 'anonymous',
    actorName: req.session?.user?.displayName || '',
    role: req.session?.user?.role || '',
    ip: String(req.ip || '').replace(/^::ffff:/, ''),
    action,
    target: target || '',
    result,
  };
  if (details && Object.keys(details).length) entry.details = details;
  if (error) entry.error = String(error);
  entry.prev = lastHash;
  entry.hash = sha(lastHash + JSON.stringify(entry));
  try {
    fs.appendFileSync(fileFor(now), JSON.stringify(entry) + '\n', { encoding: 'utf8' });
    lastHash = entry.hash;
  } catch (e) {
    console.error('AUDIT WRITE FAILED', e, entry);
  }
  console.log(`[audit] ${entry.time} ${entry.actor} ${action} ${entry.target} ${result}${error ? ' - ' + error : ''}`);
  forward(entry);
}

// Re-compute the chain over all files. Entries written before sealing was
// introduced (no hash) are counted but cannot be verified.
export async function verifyAudit() {
  let prev = null;
  let sealed = 0;
  let unsealed = 0;
  for (const file of auditFiles()) {
    const rl = readline.createInterface({ input: fs.createReadStream(file, 'utf8'), crlfDelay: Infinity });
    let n = 0;
    for await (const line of rl) {
      n++;
      if (!line.trim()) continue;
      let e;
      try { e = JSON.parse(line); } catch { return { ok: false, file: path.basename(file), line: n, problem: 'Line is not valid JSON (edited?)', sealed, unsealed }; }
      if (!e.hash) { unsealed++; continue; }
      const { hash, ...rest } = e;
      if (prev !== null && e.prev !== prev) return { ok: false, file: path.basename(file), line: n, time: e.time, problem: 'Chain broken: an entry before this one was removed or changed', sealed, unsealed };
      if (sha(e.prev + JSON.stringify(rest)) !== hash) return { ok: false, file: path.basename(file), line: n, time: e.time, problem: 'This entry was modified after it was written', sealed, unsealed };
      prev = hash;
      sealed++;
    }
  }
  return { ok: true, sealed, unsealed };
}

// ---------------------------------------------------------------- forwarding (best effort, never blocks)

const SEVERITY = (e) => (e.result === 'success' ? 6 : 4); // informational / warning
function syslogLine(e) {
  const pri = 10 * 8 + SEVERITY(e); // facility 10 = authpriv
  const msg = JSON.stringify(e);
  return `<${pri}>1 ${e.time} ${os.hostname()} ADAdminPortal ${process.pid} ${e.action} - ${msg}`;
}

function forward(e) {
  const s = config.security || {};
  if (s.syslogHost) {
    const line = syslogLine(e);
    try {
      if (s.syslogProtocol === 'tcp') {
        const sock = net.createConnection({ host: s.syslogHost, port: s.syslogPort || 514 }, () => sock.end(`${Buffer.byteLength(line)} ${line}`));
        sock.on('error', (err) => console.error('syslog:', err.message));
        sock.setTimeout(5000, () => sock.destroy());
      } else {
        const sock = dgram.createSocket(net.isIPv6(s.syslogHost) ? 'udp6' : 'udp4');
        sock.send(Buffer.from(line), s.syslogPort || 514, s.syslogHost, () => sock.close());
      }
    } catch (err) { console.error('syslog:', err.message); }
  }
  if (s.eventLog && process.platform === 'win32') eventLogQueue(e);
}

// Windows Application event log via eventcreate (source "ADAdminPortal").
// The first write registers the source, which needs administrator rights once
// (setup\Install-Portal.ps1 does it). If writing fails it is reported once.
let evBusy = Promise.resolve();
let evWarned = false;
function eventLogQueue(e) {
  evBusy = evBusy.then(() => new Promise((resolve) => {
    const desc = `${e.actor} ${e.action} ${e.target} ${e.result}${e.error ? ': ' + e.error : ''} | ip ${e.ip} | ${e.time}`.slice(0, 30000);
    execFile('eventcreate', ['/L', 'APPLICATION', '/SO', 'ADAdminPortal', '/T', e.result === 'success' ? 'INFORMATION' : 'WARNING', '/ID', e.result === 'success' ? '100' : '200', '/D', desc],
      { windowsHide: true, timeout: 10000 }, (err) => {
        if (err && !evWarned) { evWarned = true; console.error('Windows Event Log write failed (register the source once as administrator):', err.message); }
        resolve();
      });
  }));
}

// ---------------------------------------------------------------- query / export

// Query newest-first with optional filters.
export async function queryAudit({ q = '', actor = '', action = '', result = '', from = '', to = '', limit = 500 } = {}) {
  const ql = q.toLowerCase();
  const fromT = from ? new Date(from).getTime() : 0;
  const toT = to ? new Date(to).getTime() + 86400000 - 1 : Infinity;
  const out = [];
  for (const file of auditFiles().reverse()) {
    const lines = [];
    const rl = readline.createInterface({ input: fs.createReadStream(file, 'utf8'), crlfDelay: Infinity });
    for await (const line of rl) if (line.trim()) lines.push(line);
    for (let i = lines.length - 1; i >= 0; i--) {
      let e;
      try { e = JSON.parse(lines[i]); } catch { continue; }
      const t = new Date(e.time).getTime();
      if (t < fromT || t > toT) continue;
      if (actor && e.actor?.toLowerCase() !== actor.toLowerCase()) continue;
      if (action && e.action !== action) continue;
      if (result && e.result !== result) continue;
      if (ql && !lines[i].toLowerCase().includes(ql)) continue;
      delete e.prev;
      out.push(e);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

export function toCsv(entries) {
  const cols = ['time', 'actor', 'actorName', 'role', 'ip', 'action', 'target', 'result', 'details', 'error', 'hash'];
  const cell = (v) => {
    let s = v === undefined || v === null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (/^[=+\-@]/.test(s)) s = "'" + s; // prevent spreadsheet formula injection
    return `"${s.replace(/"/g, '""')}"`;
  };
  return [cols.join(','), ...entries.map((e) => cols.map((c) => cell(e[c])).join(','))].join('\r\n');
}
