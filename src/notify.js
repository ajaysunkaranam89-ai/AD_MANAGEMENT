// E-mail notifications (Settings → Notifications). Fire-and-forget: a mail problem
// never blocks or fails the AD action. Passwords are never included in e-mails.
import nodemailer from 'nodemailer';
import { config } from './config.js';

export const EVENT_LABELS = {
  'user.create': 'Account created',
  'user.resetPassword': 'Password reset',
  'user.unlock': 'Account unlocked',
  'user.enable': 'Account enabled / disabled',
  'user.offboard': 'Leaver offboarded',
  'user.delete': 'Account deleted',
  'group.addMember': 'Added to group',
  'group.removeMember': 'Removed from group',
  'approval.requested': 'Approval needed',
};

const clean = (s) => String(s ?? '').replace(/[\r\n]+/g, ' ').slice(0, 300);

function transportFor(n) {
  return nodemailer.createTransport({
    host: n.smtpHost,
    port: n.smtpPort,
    secure: !!n.smtpSecure, // true = implicit TLS (465); otherwise STARTTLS when offered
    requireTLS: !n.smtpSecure && n.smtpPort === 587,
    auth: n.smtpUser ? { user: n.smtpUser, pass: n.smtpPassword } : undefined,
    tls: { minVersion: 'TLSv1.2' },
    connectionTimeout: 15000,
  });
}

export async function sendMail(n, { to, subject, text }) {
  await transportFor(n).sendMail({ from: n.from, to, subject: clean(subject), text });
}

export function notify(event, { actor, target, lines = [], managerMail } = {}) {
  const n = config.notifications;
  if (!n?.enabled || !n.events?.includes(event)) return;
  const to = new Set([n.itMailbox]);
  if (n.notifyManager && managerMail && /^[^@\s]+@[^@\s]+$/.test(managerMail)) to.add(managerMail);
  const org = config.branding.orgName ? ` (${config.branding.orgName})` : '';
  const text = [
    `${EVENT_LABELS[event] || event}${org}`,
    '',
    `Account / object: ${clean(target)}`,
    `Done by: ${clean(actor)}`,
    `When: ${new Date().toLocaleString()}`,
    ...lines.map(clean),
    '',
    'This message was sent by the AD Admin Portal. Passwords are never included in e-mails.',
  ].join('\n');
  sendMail(n, { to: [...to].join(', '), subject: `[AD Portal] ${EVENT_LABELS[event] || event}: ${clean(target)}`, text })
    .catch((e) => console.error('notification e-mail failed:', e.message));
}
