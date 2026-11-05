// Four-eyes approval: sensitive actions (Settings → Workflow) are stored as requests
// and only run when a different admin approves them.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR, MOCK } from './config.js';

const FILE = path.join(DATA_DIR, MOCK ? 'approvals-demo.json' : 'approvals.json');
const EXPIRE_MS = 7 * 86400000;
const KEEP_MS = 90 * 86400000;

let list = [];
try { list = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { list = []; }

function save() {
  const now = Date.now();
  list = list.filter((r) => r.status === 'pending' || now - new Date(r.decidedAt || r.createdAt).getTime() < KEEP_MS);
  fs.writeFileSync(FILE + '.tmp', JSON.stringify(list, null, 2));
  fs.renameSync(FILE + '.tmp', FILE);
}

function expire() {
  const now = Date.now();
  let changed = false;
  for (const r of list) {
    if (r.status === 'pending' && now - new Date(r.createdAt).getTime() > EXPIRE_MS) { r.status = 'expired'; r.decidedAt = new Date().toISOString(); changed = true; }
  }
  if (changed) save();
}

export function createRequest({ action, params, target, summary, requestedBy, requestedByName }) {
  const r = {
    id: crypto.randomBytes(6).toString('hex'),
    action, params, target, summary,
    requestedBy, requestedByName,
    createdAt: new Date().toISOString(),
    status: 'pending',
  };
  list.push(r);
  save();
  return r;
}

export function listRequests() {
  expire();
  return [...list].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function getRequest(id) {
  expire();
  return list.find((r) => r.id === id) || null;
}

export function decide(id, fields) {
  const r = list.find((x) => x.id === id);
  if (!r) return null;
  Object.assign(r, fields, { decidedAt: new Date().toISOString() });
  save();
  return r;
}

export const pendingCount = () => listRequests().filter((r) => r.status === 'pending').length;
