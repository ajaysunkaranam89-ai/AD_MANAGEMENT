// Append-only audit log: one JSON object per line (JSONL), one file per month.
// Records who did what, to which object, when, from which IP, and whether it succeeded.
// Passwords are never written.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { config } from './config.js';

const dir = path.dirname(config.auditFile);
const base = path.basename(config.auditFile, path.extname(config.auditFile));
fs.mkdirSync(dir, { recursive: true });

const fileFor = (d) => path.join(dir, `${base}-${d.toISOString().slice(0, 7)}.jsonl`);

export function audit(req, action, target, { result = 'success', details, error } = {}) {
  const now = new Date();
  const entry = {
    time: now.toISOString(),
    actor: req.session?.user?.sam || req.body?.username || 'anonymous',
    actorName: req.session?.user?.displayName || '',
    role: req.session?.user?.role || '',
    ip: req.ip,
    action,
    target: target || '',
    result,
  };
  if (details && Object.keys(details).length) entry.details = details;
  if (error) entry.error = String(error);
  try {
    fs.appendFileSync(fileFor(now), JSON.stringify(entry) + '\n', { encoding: 'utf8' });
  } catch (e) {
    console.error('AUDIT WRITE FAILED', e, entry);
  }
  console.log(`[audit] ${entry.time} ${entry.actor} ${action} ${entry.target} ${result}${error ? ' - ' + error : ''}`);
}

function auditFiles() {
  return fs.readdirSync(dir)
    .filter((f) => f.startsWith(base + '-') && f.endsWith('.jsonl'))
    .sort()
    .reverse()
    .map((f) => path.join(dir, f));
}

// Query newest-first with optional filters.
export async function queryAudit({ q = '', actor = '', action = '', result = '', from = '', to = '', limit = 500 } = {}) {
  const ql = q.toLowerCase();
  const fromT = from ? new Date(from).getTime() : 0;
  const toT = to ? new Date(to).getTime() + 86400000 - 1 : Infinity;
  const out = [];
  for (const file of auditFiles()) {
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
      out.push(e);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

export function toCsv(entries) {
  const cols = ['time', 'actor', 'actorName', 'role', 'ip', 'action', 'target', 'result', 'details', 'error'];
  const cell = (v) => {
    let s = v === undefined || v === null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (/^[=+\-@]/.test(s)) s = "'" + s; // prevent spreadsheet formula injection
    return `"${s.replace(/"/g, '""')}"`;
  };
  return [cols.join(','), ...entries.map((e) => cols.map((c) => cell(e[c])).join(','))].join('\r\n');
}
