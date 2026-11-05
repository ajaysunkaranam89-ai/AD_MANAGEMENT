import { config } from './config.js';

// Every permission the portal knows, with a label for the settings screen.
export const ALL_PERMISSIONS = {
  'user.read': 'View users',
  'group.read': 'View groups',
  'user.resetPassword': 'Reset passwords',
  'user.unlock': 'Unlock accounts',
  'user.enable': 'Enable / disable users',
  'user.create': 'Create users',
  'user.edit': 'Edit user details',
  'user.move': 'Move users between OUs',
  'user.delete': 'Delete users',
  'group.create': 'Create groups',
  'group.edit': 'Edit groups',
  'group.delete': 'Delete groups',
  'group.members': 'Add / remove group members',
  'audit.read': 'View & export audit log',
  'settings.manage': 'Change portal settings',
};

// Helpdesk defaults; each company can change these in Settings.
export const DEFAULT_HELPDESK = ['user.read', 'group.read', 'user.resetPassword', 'user.unlock', 'user.enable'];

// Never grantable to helpdesk (keeps admin-only control of the portal itself).
export const ADMIN_ONLY = ['settings.manage'];

export function permissionsFor(role) {
  if (role === 'admin') return Object.keys(ALL_PERMISSIONS);
  if (role === 'helpdesk') {
    const list = config.helpdeskPermissions || DEFAULT_HELPDESK;
    return list.filter((p) => ALL_PERMISSIONS[p] && !ADMIN_ONLY.includes(p));
  }
  return [];
}

export function can(role, permission) {
  return permissionsFor(role).includes(permission);
}
