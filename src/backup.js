// Daily backup of settings (data/) and the audit trail (logs/) to a folder or share.
// Note: on Windows the settings key is DPAPI-protected for this machine; to restore
// on another server set SETTINGS_KEY or re-enter the service-account password.
import fs from 'node:fs';
import path from 'node:path';
import { config, DATA_DIR } from './config.js';

const STATE = path.join(DATA_DIR, 'backup-state.json');
const readState = () => { try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch { return {}; } };

export function lastBackup() {
  return readState();
}

export function runBackup() {
  const b = config.backup;
  if (!b.folder) throw new Error('No backup folder is configured');
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16);
  const dest = path.join(b.folder, `ADPortal-${stamp}`);
  fs.mkdirSync(dest, { recursive: true });
  fs.cpSync(DATA_DIR, path.join(dest, 'data'), { recursive: true, filter: (src) => !/setup-token\.txt$/.test(src) });
  fs.cpSync(path.dirname(config.auditFile), path.join(dest, 'logs'), { recursive: true });
  // keep only the newest N backups
  const all = fs.readdirSync(b.folder).filter((d) => /^ADPortal-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}$/.test(d)).sort().reverse();
  for (const old of all.slice(b.keep)) fs.rmSync(path.join(b.folder, old), { recursive: true, force: true });
  const state = { at: new Date().toISOString(), dest, ok: true };
  fs.writeFileSync(STATE, JSON.stringify(state));
  return state;
}

// Check every hour; run when enabled and the last good backup is older than 24 h.
export function startBackupSchedule(onResult) {
  const tick = () => {
    if (!config.backup.enabled || !config.backup.folder) return;
    const last = readState();
    if (last.ok && Date.now() - new Date(last.at).getTime() < 24 * 3600000) return;
    try { onResult(null, runBackup()); } catch (e) {
      fs.writeFileSync(STATE, JSON.stringify({ at: new Date().toISOString(), ok: false, error: e.message }));
      onResult(e);
    }
  };
  setTimeout(tick, 60000).unref();
  setInterval(tick, 3600000).unref();
}
