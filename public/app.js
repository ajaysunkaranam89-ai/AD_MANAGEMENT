// AD Admin Portal - front end (no build step, no external libraries)

const state = { me: null, info: null, mock: false, ous: null, users: null, userQuery: { q: '', status: 'all' }, groups: null, groupQuery: '', allGroups: null };

// ------------------------------------------------------------------ DOM helpers

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'selected') el.selected = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const ICONS = {
  logo: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8.5" r="3.8" fill="white"/><path d="M4.5 20c1.2-4 4-5.6 7.5-5.6s6.3 1.6 7.5 5.6" fill="white"/></svg>',
  users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5"/><circle cx="17" cy="9" r="2.6"/><path d="M16 14.6c2.7-.3 4.7 1.3 5.5 4.4"/></svg>',
  groups: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="16" rx="3"/><circle cx="9" cy="11" r="2.3"/><circle cx="15" cy="11" r="2.3"/><path d="M5.5 17.5c.8-2 2-3 3.5-3s2.7 1 3.5 3M11.5 17.5c.8-2 2-3 3.5-3s2.7 1 3.5 3"/></svg>',
  audit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 12h6M10 15.5h6M10 19h4"/><path d="M4 6v15h3"/></svg>',
  dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="8" height="9" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/><rect x="13" y="10" width="8" height="11" rx="1.5"/><rect x="3" y="14" width="8" height="7" rx="1.5"/></svg>',
  reports: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>',
  approvals: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 11l3 3 8-8"/><path d="M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
};
const icon = (name) => { const s = h('span', { 'aria-hidden': 'true' }); s.innerHTML = ICONS[name]; return s.firstChild; };

const initials = (name) => String(name || '?').split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join('');
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');
const can = (perm) => !!state.me?.permissions?.includes(perm);
const ouLabel = (dn) => (/^DC=/i.test(String(dn || '')) ? '(domain root)' : String(dn || '').split(/,DC=/i)[0]).split(/,(?=OU=|CN=)/i).map((p) => p.replace(/^(OU|CN)=/i, '')).reverse().join(' › ');

function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

// Words-in-any-order text match used by client-side filters
const matchesWords = (text, q) => {
  const t = String(text || '').toLowerCase();
  return String(q || '').toLowerCase().split(/\s+/).filter(Boolean).every((w) => t.includes(w));
};

// Search-as-you-type picker with a dropdown of results.
// search(q) -> Promise<[{ value, label, sub }]>; onPick(item) runs when one is chosen.
function searchSelect({ placeholder, search, onPick, minChars = 1 }) {
  const input = h('input', { type: 'search', placeholder, autocomplete: 'off', 'aria-autocomplete': 'list' });
  const list = h('div', { class: 'ss-list', role: 'listbox', hidden: true });
  let items = [];
  let active = -1;
  let seq = 0;
  const close = () => { list.hidden = true; active = -1; };
  const message = (text) => { list.replaceChildren(h('div', { class: 'ss-empty' }, text)); list.hidden = false; };
  function draw() {
    if (!items.length) return message('No matches');
    list.replaceChildren(...items.map((it, i) => h('div', {
      class: `ss-item ${i === active ? 'active' : ''}`,
      role: 'option',
      onmousedown: (e) => { e.preventDefault(); pick(it); },
    }, h('div', {}, it.label), it.sub ? h('div', { class: 'sub' }, it.sub) : null)));
    list.hidden = false;
    list.children[active]?.scrollIntoView({ block: 'nearest' });
  }
  async function pick(it) {
    close();
    input.value = '';
    input.disabled = true;
    try { await onPick(it); } finally { input.disabled = false; }
  }
  const run = debounce(async () => {
    const q = input.value.trim();
    if (q.length < minChars) { close(); return; }
    const my = ++seq;
    message('Searching…');
    try {
      const r = await search(q);
      if (my !== seq) return; // a newer search has started
      items = r.slice(0, 50);
      active = items.length ? 0 : -1;
      draw();
    } catch (e) { if (my === seq) message(e.message); }
  }, 250);
  input.addEventListener('input', run);
  input.addEventListener('focus', () => { if (input.value.trim()) run(); });
  input.addEventListener('blur', () => setTimeout(close, 150));
  input.addEventListener('keydown', (e) => {
    if (list.hidden || !items.length) return;
    if (e.key === 'ArrowDown') { active = Math.min(items.length - 1, active + 1); draw(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { active = Math.max(0, active - 1); draw(); e.preventDefault(); }
    else if (e.key === 'Enter') { e.preventDefault(); if (items[active]) pick(items[active]); }
    else if (e.key === 'Escape') close();
  });
  return h('div', { class: 'ss' }, input, list);
}

// ------------------------------------------------------------------ API

async function api(method, url, body, extraHeaders = {}) {
  const res = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers: { 'X-Requested-With': 'ad-portal', ...(body ? { 'Content-Type': 'application/json' } : {}), ...extraHeaders },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty */ }
  if (res.status === 503 && data.setupRequired) {
    state.me = null;
    await loadInfo();
    renderSetup();
    throw new Error(data.error);
  }
  if (res.status === 401 && !url.startsWith('/api/login')) {
    state.me = null;
    renderLogin('Your session has expired. Please sign in again.');
    throw new Error('Session expired');
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ------------------------------------------------------------------ toasts & modals

function toast(msg, kind = 'info') {
  const t = h('div', { class: `toast ${kind}` }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), kind === 'error' ? 7000 : 4000);
}

function modal({ title, body, actions = [], wide = false }) {
  return new Promise((resolve) => {
    const back = h('div', { class: 'modal-back' });
    const errBox = h('div', { class: 'error-box', hidden: true });
    const close = (v) => { back.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
    const onKey = (e) => { if (e.key === 'Escape') close(null); };
    document.addEventListener('keydown', onKey);
    const foot = h('div', { class: 'modal-foot' });
    const ctx = {
      close,
      error(msg) { errBox.textContent = msg; errBox.hidden = !msg; },
      busy(on) { foot.querySelectorAll('button').forEach((b) => { b.disabled = on; }); },
      setActions(list) { foot.replaceChildren(...list.map(mkBtn)); },
    };
    function mkBtn(a) {
      return h('button', {
        class: `btn ${a.kind || ''}`,
        type: 'button',
        async onclick() {
          if (!a.run) return close(a.value ?? null);
          ctx.error('');
          ctx.busy(true);
          try { await a.run(ctx); } catch (e) { ctx.error(e.message); } finally { if (back.isConnected) ctx.busy(false); }
        },
      }, a.label);
    }
    foot.append(...actions.map(mkBtn));
    const m = h('div', { class: `modal ${wide ? 'wide' : ''}`, role: 'dialog', 'aria-modal': 'true' },
      h('div', { class: 'modal-head' }, title),
      h('div', { class: 'modal-body' }, errBox, typeof body === 'function' ? body(ctx) : body),
      foot);
    back.append(m);
    back.addEventListener('mousedown', (e) => { if (e.target === back) close(null); });
    document.body.append(back);
    setTimeout(() => m.querySelector('input:not([type=checkbox]), select, textarea')?.focus(), 30);
  });
}

function confirmAction({ title, message, confirmLabel, danger = true, typeToConfirm, run }) {
  let input;
  return modal({
    title,
    body: h('div', {},
      h('p', { style: 'margin-top:0' }, message),
      typeToConfirm && h('div', { class: 'field' },
        h('label', {}, `Type "${typeToConfirm}" to confirm`),
        input = h('input', { type: 'text', autocomplete: 'off' }))),
    actions: [
      { label: 'Cancel' },
      {
        label: confirmLabel,
        kind: danger ? 'danger solid' : 'primary',
        async run(ctx) {
          if (typeToConfirm && input.value.trim() !== typeToConfirm) throw new Error('The text you typed does not match.');
          await run();
          ctx.close(true);
        },
      },
    ],
  });
}

// ------------------------------------------------------------------ password generator

function generatePassword(len = 14) {
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '@#$%&*!?'];
  const all = sets.join('');
  const rnd = (n) => { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; };
  const chars = sets.map((s) => s[rnd(s.length)]);
  while (chars.length < len) chars.push(all[rnd(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) { const j = rnd(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}

function passwordInput(id) {
  const input = h('input', { type: 'password', id, autocomplete: 'new-password' });
  const show = h('button', { class: 'btn small', type: 'button', onclick() { input.type = input.type === 'password' ? 'text' : 'password'; show.textContent = input.type === 'password' ? 'Show' : 'Hide'; } }, 'Show');
  const gen = h('button', { class: 'btn small', type: 'button', onclick() { input.value = generatePassword(); input.type = 'text'; show.textContent = 'Hide'; } }, 'Generate');
  return { input, row: h('div', { class: 'input-row' }, input, show, gen) };
}

function showPasswordResult(title, who, pwd, mustChange) {
  const copy = h('button', { class: 'btn small', type: 'button', async onclick() { await navigator.clipboard.writeText(pwd).catch(() => {}); copy.textContent = 'Copied'; } }, 'Copy');
  return modal({
    title,
    body: h('div', { class: 'success-box' },
      h('div', {}, `New password for ${who}:`),
      h('div', { class: 'pwd-show' }, pwd),
      copy,
      h('p', { style: 'margin:10px 0 0' }, mustChange ? 'The user must change it at next sign-in. Share it securely (phone / in person), not by e-mail.' : 'Share it securely (phone / in person), not by e-mail.')),
    actions: [{ label: 'Done', kind: 'primary' }],
  });
}

// ------------------------------------------------------------------ branding

const PIERSOFT_LOGO = 'brand/piersoft-logo.png';
const productName = () => 'AD Admin Portal';

// Company logo if the organisation uploaded one, otherwise the Piersoft logo
function brandMark(cls = '') {
  const src = state.info?.logo || PIERSOFT_LOGO;
  return h('img', { class: `brand-logo ${cls}`, src, alt: state.info?.orgName || 'Piersoft' });
}

const poweredBy = () => h('div', { class: 'powered' },
  h('span', {}, 'Powered by'), h('img', { src: PIERSOFT_LOGO, alt: '' }), h('b', {}, 'Piersoft'));

function setTitle() {
  document.title = state.info?.orgName ? `${productName()} · ${state.info.orgName}` : productName();
}

// ------------------------------------------------------------------ boot & login

async function loadInfo() {
  try { state.info = await api('GET', '/api/info'); } catch { state.info = state.info || {}; }
  state.mock = !!state.info.mock;
  setTitle();
}

async function boot() {
  await loadInfo();
  if (state.info.configured === false) return renderSetup();
  try {
    const r = await fetch('/api/me', { credentials: 'same-origin' });
    if (r.ok) { state.me = await r.json(); renderShell(); route(); return; }
  } catch { /* ignore */ }
  renderLogin();
}

function renderLogin(message) {
  const user = h('input', { type: 'text', id: 'username', autocomplete: 'username', placeholder: 'e.g. john.smith' });
  const pass = h('input', { type: 'password', id: 'password', autocomplete: 'current-password' });
  const err = h('div', { class: 'error-box', hidden: !message }, message || '');
  const btn = h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, 'Sign in');
  const form = h('form', {
    async onsubmit(e) {
      e.preventDefault();
      err.hidden = true;
      btn.disabled = true; btn.textContent = 'Signing in…';
      try {
        const r = await api('POST', '/api/login', { username: user.value, password: pass.value });
        if (r.mfa) { pass.value = ''; showMfaStep(r); return; }
        await finishLogin();
      } catch (ex) {
        err.textContent = ex.message; err.hidden = false; pass.value = ''; pass.focus();
      } finally { btn.disabled = false; btn.textContent = 'Sign in'; }
    },
  },
  err,
  h('div', { class: 'field' }, h('label', { for: 'username' }, 'Username'), user),
  h('div', { class: 'field' }, h('label', { for: 'password' }, 'Password'), pass),
  btn);

  // Domain passwords must not cross the network unencrypted
  const insecure = location.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  document.getElementById('app').replaceChildren(h('div', { class: 'login-wrap' },
    h('div', { class: 'login-card' },
      h('div', { class: 'login-brand' }, brandMark('lg')),
      h('h1', {}, productName()),
      h('p', { class: 'sub' }, state.info?.orgName ? `${state.info.orgName} · sign in with your domain account` : 'Sign in with your domain account'),
      insecure && h('div', { class: 'error-box' }, h('b', {}, 'Not secure: '), 'this page is not using HTTPS, so your password would be sent unencrypted. Ask your administrator to enable HTTPS.'),
      form,
      state.mock && h('div', { class: 'hint' }, h('b', {}, 'Demo mode. '), 'No real AD is connected. Sign in as ', h('b', {}, 'portal.admin'), ' (admin) or ', h('b', {}, 'helpdesk'), ' with password ', h('b', {}, 'Demo@1234'), '.')),
    poweredBy()));
  setTimeout(() => user.focus(), 30);

  // Second step: code from an authenticator app (Microsoft / Google Authenticator etc.)
  function showMfaStep(r) {
    const code = h('input', { type: 'text', id: 'mfa-code', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, placeholder: '6-digit code', class: 'mono', style: 'font-size:18px;letter-spacing:.2em;text-align:center' });
    const err2 = h('div', { class: 'error-box', hidden: true });
    const go = h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, r.mfa === 'enroll' ? 'Confirm and sign in' : 'Verify');
    const enroll = r.mfa === 'enroll' && h('div', { class: 'mfa-enroll' },
      h('p', {}, h('b', {}, 'Set up two-step sign-in. '), 'Scan this QR code with an authenticator app (Microsoft Authenticator, Google Authenticator…), then enter the 6-digit code it shows.'),
      h('img', { src: `data:image/svg+xml;base64,${btoa(r.qr)}`, alt: 'QR code for the authenticator app', class: 'mfa-qr' }),
      h('details', {}, h('summary', {}, "Can't scan? Enter this key instead"), h('div', { class: 'mono', style: 'word-break:break-all;margin-top:6px' }, r.secret.replace(/(.{4})/g, '$1 ').trim())));
    form.replaceChildren(
      err2,
      enroll || h('p', { style: 'margin-top:0' }, 'Enter the 6-digit code from your authenticator app.'),
      h('div', { class: 'field' }, h('label', { for: 'mfa-code' }, 'Verification code'), code),
      go,
      h('div', { style: 'text-align:center;margin-top:10px' }, h('a', { href: '#', onclick: (e) => { e.preventDefault(); renderLogin(); } }, 'Start again')));
    form.onsubmit = async (e) => {
      e.preventDefault();
      err2.hidden = true; go.disabled = true;
      try {
        await api('POST', '/api/login/mfa', { code: code.value });
        await finishLogin();
      } catch (ex) {
        if (/start again/i.test(ex.message)) return renderLogin(ex.message);
        err2.textContent = ex.message; err2.hidden = false; code.value = ''; code.focus();
      } finally { go.disabled = false; }
    };
    setTimeout(() => code.focus(), 30);
  }
}

async function finishLogin() {
  state.me = await api('GET', '/api/me');
  renderShell();
  if (!location.hash) location.hash = '#/dashboard'; else route();
}

const SECTION_TITLES = { dashboard: 'Dashboard', users: 'Users', groups: 'Groups', reports: 'Reports', approvals: 'Approvals', audit: 'Audit log', settings: 'Settings' };

function renderShell() {
  const navLink = (n) => h('a', { href: n.href, 'data-nav': n.href }, icon(n.ic), h('span', { class: 'hide-sm' }, n.label), n.badge ? h('span', { class: 'nav-badge' }, String(n.badge)) : null);
  const directory = [
    { href: '#/dashboard', label: 'Dashboard', ic: 'dashboard', show: can('user.read') },
    { href: '#/users', label: 'Users', ic: 'users', show: can('user.read') },
    { href: '#/groups', label: 'Groups', ic: 'groups', show: can('group.read') },
    { href: '#/reports', label: 'Reports', ic: 'reports', show: can('reports.read') },
  ].filter((n) => n.show);
  const admin = [
    { href: '#/approvals', label: 'Approvals', ic: 'approvals', show: can('approvals.approve') || (state.me.approvalActions || []).length > 0, badge: state.me.pendingApprovals },
    { href: '#/audit', label: 'Audit log', ic: 'audit', show: can('audit.read') },
    { href: '#/settings', label: 'Settings', ic: 'settings', show: can('settings.manage') },
  ].filter((n) => n.show);

  document.getElementById('app').replaceChildren(h('div', { class: 'shell' },
    h('aside', { class: 'side' },
      h('div', { class: 'brand' },
        h('div', { class: 'brand-box' }, brandMark()),
        h('div', { class: 'brand-text' }, h('div', {}, productName()), state.info?.orgName && h('div', { class: 'org' }, state.info.orgName))),
      h('nav', { class: 'nav' },
        h('div', { class: 'nav-label' }, 'Directory'), directory.map(navLink),
        admin.length ? [h('div', { class: 'nav-label' }, 'Administration'), admin.map(navLink)] : null),
      h('div', { class: 'side-foot' }, 'AD Admin Portal v1.1', h('br'), 'Powered by ', h('b', {}, 'Piersoft'))),
    h('div', { class: 'content' },
      h('header', { class: 'topbar' },
        h('div', { class: 'crumb' },
          h('span', {}, state.info?.orgName || 'Active Directory'), h('span', {}, '›'), h('b', { id: 'crumb-page' }, ''),
          h('span', { class: `env-badge ${state.me.mock ? 'demo' : ''}` }, state.me.mock ? 'DEMO' : (state.me.upnSuffix || '').toUpperCase())),
        h('div', { class: 'user-chip' },
          h('div', { class: 'who' }, h('div', { class: 'n' }, state.me.displayName), h('div', { class: 'r' }, `${state.me.role} · ${state.me.sam}`)),
          h('div', { class: 'avatar' }, initials(state.me.displayName)),
          h('button', { class: 'btn small', onclick: logout }, 'Sign out'))),
      h('main', { class: 'main' },
        state.me.mock && h('div', { class: 'mock-banner' }, 'Demo mode: working on sample data in memory. Nothing here changes your real Active Directory.'),
        h('div', { id: 'view' })),
      h('footer', { class: 'app-foot' },
        h('span', {}, 'AD Admin Portal v1.1'),
        h('span', {}, 'All changes are recorded in the audit log')))));
}

// ------------------------------------------------------------------ dashboard

async function renderDashboard(view) {
  view.replaceChildren(
    h('div', { class: 'page-head' }, h('div', {}, h('h2', {}, 'Dashboard'), h('p', { class: 'desc' }, 'Overview of the accounts this portal manages'))),
    h('div', { class: 'loading' }, 'Loading directory overview…'));
  let s;
  try { s = await api('GET', '/api/stats'); } catch (e) { view.lastChild.replaceWith(h('div', { class: 'error-box' }, e.message)); return; }
  const kpi = (v, l, cls, href) => h(href ? 'a' : 'div', { class: `kpi ${cls}`, href }, h('div', { class: 'v' }, v.toLocaleString()), h('div', { class: 'l' }, l));

  const lockedRows = s.locked.map((u) => h('tr', {},
    h('td', {}, h('a', { href: `#/users/${encodeURIComponent(u.sam)}` }, u.displayName), h('div', { class: 'sub' }, u.sam)),
    h('td', { class: 'hide-sm' }, h('span', { class: 'sub' }, u.department || ouLabel(u.ou))),
    h('td', { class: 'center' }, can('user.unlock') && h('button', {
      class: 'btn small primary',
      async onclick(e) {
        e.target.disabled = true;
        try { await api('POST', `/api/users/${encodeURIComponent(u.sam)}/unlock`); toast(`${u.displayName} unlocked`, 'success'); renderDashboard(view); } catch (ex) { toast(ex.message, 'error'); e.target.disabled = false; }
      },
    }, 'Unlock'))));

  const activity = h('ul', { class: 'activity' }, h('li', {}, h('span', { class: 'sub' }, 'Loading…')));
  if (can('audit.read')) {
    api('GET', '/api/audit').then((rows) => {
      const recent = rows.filter((e) => !['login', 'logout', 'settings.test'].includes(e.action)).slice(0, 8);
      activity.replaceChildren(...(recent.length ? recent.map((e) => h('li', {},
        h('span', { class: `dot ${e.result === 'success' ? '' : 'fail'}` }),
        h('div', {}, h('div', {}, h('b', {}, e.actor), ' · ', ACTION_LABELS[e.action] || e.action, e.target ? ` · ${e.target}` : ''),
          h('div', { class: 't' }, fmtDate(e.time), e.result === 'success' ? '' : ` · failed: ${e.error || ''}`)))) : [h('li', {}, h('span', { class: 'sub' }, 'No changes recorded yet.'))]));
    }).catch(() => activity.replaceChildren(h('li', {}, h('span', { class: 'sub' }, 'Could not load activity.'))));
  }

  view.replaceChildren(
    h('div', { class: 'page-head' },
      h('div', {}, h('h2', {}, 'Dashboard'), h('p', { class: 'desc' }, 'Overview of the accounts this portal manages')),
      h('button', { class: 'btn', onclick: () => renderDashboard(view) }, 'Refresh')),
    h('div', { class: 'kpis' },
      kpi(s.users, 'Total users', '', '#/users'),
      kpi(s.enabled, 'Enabled', 'ok'),
      kpi(s.disabled, 'Disabled', 'off'),
      kpi(s.locked.length, 'Locked out now', 'danger'),
      kpi(s.inactive90, 'No sign-in for 90+ days', 'warn'),
      kpi(s.groups, 'Groups', 'violet', '#/groups')),
    h('div', { class: 'dash-grid' },
      h('div', { class: 'card card-pad' },
        h('div', { class: 'card-title' }, h('span', {}, `Locked accounts (${s.locked.length})`), h('span', { class: 'sub', style: 'text-transform:none;letter-spacing:0;font-weight:400' }, 'Live status from AD')),
        s.locked.length
          ? h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'User'), h('th', { class: 'hide-sm' }, 'Department / OU'), h('th', { class: 'center' }, 'Action'))), h('tbody', {}, lockedRows))
          : h('div', { class: 'empty' }, 'No accounts are locked out right now.'),
        h('div', { class: 'sub', style: 'margin-top:10px' }, `${s.mustChange.toLocaleString()} must change password · ${s.passwordExpired.toLocaleString()} with expired password`)),
      can('audit.read') && h('div', { class: 'card card-pad' },
        h('div', { class: 'card-title' }, h('span', {}, 'Recent changes'), h('a', { href: '#/audit', style: 'text-transform:none;letter-spacing:0;font-weight:400' }, 'View audit log')),
        activity)));
}

async function logout() {
  try { await api('POST', '/api/logout'); } catch { /* ignore */ }
  state.me = null; state.users = null; state.groups = null; state.allGroups = null; state.ous = null;
  location.hash = '';
  renderLogin();
}

// ------------------------------------------------------------------ router

window.addEventListener('hashchange', route);

function route() {
  if (!state.me) return;
  const [section, id] = location.hash.replace(/^#\/?/, '').split('/').map((p) => decodeURIComponent(p || ''));
  document.querySelectorAll('[data-nav]').forEach((a) => a.classList.toggle('active', a.getAttribute('data-nav') === `#/${section}`));
  const view = document.getElementById('view');
  if (!view) return;
  const crumb = document.getElementById('crumb-page');
  if (crumb) crumb.textContent = SECTION_TITLES[section] || '';
  if (section === 'dashboard' && can('user.read')) return renderDashboard(view);
  if (section === 'groups') {
    if (id === 'new' && can('group.create')) return renderNewGroup(view);
    return renderGroups(view, id);
  }
  if (section === 'audit' && can('audit.read')) return renderAudit(view);
  if (section === 'settings' && can('settings.manage')) return renderSettingsPage(view);
  if (section === 'reports' && can('reports.read')) return renderReports(view);
  if (section === 'approvals') return renderApprovals(view);
  if (section !== 'users') { location.hash = can('user.read') ? '#/dashboard' : '#/users'; return; }
  if (id === 'new' && can('user.create')) return renderNewUser(view);
  if (id === 'import' && can('user.import')) return renderImport(view);
  return renderUsers(view, id);
}

async function loadOUs() {
  if (!state.ous) state.ous = await api('GET', '/api/ous');
  return state.ous;
}

async function loadAllGroups(force) {
  if (!state.allGroups || force) state.allGroups = (await api('GET', '/api/groups?q=')).items;
  return state.allGroups;
}

// ------------------------------------------------------------------ users list

function statusBadges(u) {
  return [
    u.enabled ? h('span', { class: 'badge ok' }, 'Enabled') : h('span', { class: 'badge off' }, 'Disabled'),
    u.locked && h('span', { class: 'badge danger' }, 'Locked'),
    u.passwordExpired && h('span', { class: 'badge warn' }, 'Password expired'),
    u.mustChangePassword && h('span', { class: 'badge warn' }, 'Must change password'),
    u.protected && h('span', { class: 'badge info' }, 'Protected'),
    !u.protected && u.serviceAccount && h('span', { class: 'badge off' }, 'Service'),
    u.accountExpires && new Date(u.accountExpires) <= new Date() && h('span', { class: 'badge danger' }, 'Expired'),
  ];
}

async function renderUsers(view, selected) {
  const search = h('input', { type: 'search', class: 'search', placeholder: 'Search by name, username, e-mail or employee ID…', value: state.userQuery.q });
  const status = h('select', { style: 'width:auto' },
    ['all', 'enabled', 'disabled', 'locked'].map((s) => h('option', { value: s, selected: state.userQuery.status === s }, s[0].toUpperCase() + s.slice(1))));
  const count = h('span', { class: 'count' });
  const listBox = h('div', { class: 'card table-wrap' }, h('div', { class: 'loading' }, 'Loading users…'));
  const detailBox = h('div', {});
  const split = h('div', { class: `split ${selected ? '' : 'no-detail'}` }, listBox, detailBox);
  const picked = new Set(); // selected usernames for bulk actions
  const bulkBar = h('div', { class: 'bulk-bar', hidden: true });

  view.replaceChildren(
    h('div', { class: 'page-head' },
      h('h2', {}, 'Users', count),
      h('div', { class: 'input-row' },
        can('user.import') && can('user.create') && h('a', { class: 'btn', href: '#/users/import' }, 'Import CSV'),
        can('user.create') && h('a', { class: 'btn primary', href: '#/users/new' }, '+ New user'))),
    h('div', { class: 'toolbar' }, search, status,
      h('button', { class: 'btn', onclick: () => load(true) }, 'Refresh')),
    bulkBar,
    split);

  const bulkActions = [
    { kind: 'unlock', label: 'Unlock', perm: 'user.unlock' },
    { kind: 'enable', label: 'Enable', perm: 'user.enable' },
    { kind: 'disable', label: 'Disable', perm: 'user.enable', danger: true },
    { kind: 'move', label: 'Move…', perm: 'user.move' },
    { kind: 'offboard', label: 'Offboard…', perm: 'user.offboard', danger: true },
  ].filter((a) => can(a.perm));

  function drawBulk() {
    bulkBar.hidden = picked.size === 0 || !bulkActions.length;
    bulkBar.replaceChildren(
      h('b', {}, `${picked.size} selected`),
      ...bulkActions.map((a) => h('button', { class: `btn small ${a.danger ? 'danger' : ''}`, onclick: () => bulkDialog(a, [...picked], async () => { picked.clear(); drawBulk(); await load(true); }) }, a.label)),
      h('button', { class: 'btn small ghost', onclick: () => { picked.clear(); drawBulk(); drawList(); } }, 'Clear selection'));
  }

  let seq = 0;
  async function load(force) {
    const q = { q: search.value.trim(), status: status.value };
    if (force || !state.users || q.q !== state.userQuery.q || q.status !== state.userQuery.status) {
      const my = ++seq;
      state.userQuery = q;
      listBox.replaceChildren(h('div', { class: 'loading' }, 'Loading users…'));
      try {
        const r = await api('GET', `/api/users?q=${encodeURIComponent(q.q)}&status=${q.status}`);
        if (my !== seq) return; // a newer search replaced this one
        state.users = r;
      } catch (e) { if (my === seq) listBox.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    }
    drawList();
  }

  function drawList() {
    const { items, total, truncated } = state.users;
    count.textContent = truncated ? `${items.length} of ${total} (refine your search)` : `${total}`;
    if (!items.length) { listBox.replaceChildren(h('div', { class: 'empty' }, 'No users match your search.')); return; }
    const selectable = items.filter((u) => !u.protected);
    const all = h('input', { type: 'checkbox', title: 'Select all shown', checked: selectable.length > 0 && selectable.every((u) => picked.has(u.sam)) });
    all.addEventListener('change', () => { selectable.forEach((u) => (all.checked ? picked.add(u.sam) : picked.delete(u.sam))); drawBulk(); drawList(); });
    listBox.replaceChildren(h('table', {},
      h('thead', {}, h('tr', {}, bulkActions.length ? h('th', { class: 'cb' }, all) : null, h('th', {}, 'Name'), h('th', { class: 'hide-sm' }, 'Title / Department'), h('th', { class: 'hide-sm' }, 'OU'), h('th', {}, 'Status'))),
      h('tbody', {}, items.map((u) => {
        const cb = h('input', { type: 'checkbox', checked: picked.has(u.sam), disabled: u.protected, title: u.protected ? 'Protected account' : 'Select' });
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', () => { cb.checked ? picked.add(u.sam) : picked.delete(u.sam); drawBulk(); });
        return h('tr', {
          class: `clickable ${selected && u.sam.toLowerCase() === selected.toLowerCase() ? 'selected' : ''}`,
          onclick: () => { location.hash = `#/users/${encodeURIComponent(u.sam)}`; },
        },
        bulkActions.length ? h('td', { class: 'cb' }, cb) : null,
        h('td', {}, h('div', {}, u.displayName), h('div', { class: 'sub' }, u.sam)),
        h('td', { class: 'hide-sm' }, h('div', {}, u.title || '—'), h('div', { class: 'sub' }, u.department)),
        h('td', { class: 'hide-sm' }, h('span', { class: 'sub' }, ouLabel(u.ou))),
        h('td', {}, h('div', { class: 'badges' }, statusBadges(u),
          u.locked && can('user.unlock') && h('button', {
            class: 'btn small',
            async onclick(e) {
              e.stopPropagation();
              e.target.disabled = true;
              try { actionDone(await api('POST', `/api/users/${encodeURIComponent(u.sam)}/unlock`), `${u.displayName} unlocked`); await load(true); if (selected) renderUserDetail(detailBox, selected, () => load(true)); } catch (ex) { toast(ex.message, 'error'); e.target.disabled = false; }
            },
          }, 'Unlock'))));
      }))));
  }

  search.addEventListener('input', debounce(() => load(), 300));
  status.addEventListener('change', () => load());
  drawBulk();
  await load();
  if (selected) renderUserDetail(detailBox, selected, () => load(true));
}

// Bulk action dialog: confirm, run on the server, show per-user results
async function bulkDialog(a, sams, done) {
  let ouSel = null;
  if (a.kind === 'move') {
    let ous;
    try { ous = (await loadOUs()).userOUs; } catch (e) { toast(e.message, 'error'); return; }
    ouSel = h('select', {}, ous.map((o) => h('option', { value: o.dn }, ouLabel(o.dn))));
  }
  const typed = (a.danger || a.kind === 'move') ? h('input', { type: 'text', autocomplete: 'off', placeholder: String(sams.length) }) : null;
  const svcBox = h('input', { type: 'checkbox' });
  const results = h('div', {});
  return modal({
    title: `${a.label.replace('…', '')} ${sams.length} user(s)`,
    wide: true,
    body: h('div', {},
      h('p', { style: 'margin-top:0' }, sams.slice(0, 30).join(', '), sams.length > 30 ? ` and ${sams.length - 30} more` : ''),
      a.kind === 'offboard' && h('p', { class: 'sub' }, 'Each account is disabled, removed from its groups, stamped with today\'s date, its password scrambled' + (state.me.leaverOU ? `, and moved to ${ouLabel(state.me.leaverOU)}.` : '.')),
      ouSel && h('div', { class: 'field' }, h('label', {}, 'Move to OU'), ouSel),
      h('label', { class: 'check' }, svcBox, 'Also apply to service accounts in the selection (otherwise they are skipped)'),
      typed && h('div', { class: 'field' }, h('label', {}, `Type the number of users (${sams.length}) to confirm`), typed),
      results),
    actions: [
      { label: 'Close' },
      {
        label: 'Run', kind: a.danger ? 'danger solid' : 'primary',
        async run(ctx) {
          if (typed && typed.value.trim() !== String(sams.length)) throw new Error('The number you typed does not match.');
          const r = await api('POST', '/api/users/bulk', { action: a.kind, sams, ou: ouSel?.value, confirmServiceAccounts: svcBox.checked ? sams : [] });
          const ok = r.results.filter((x) => x.ok);
          const pend = ok.filter((x) => x.status === 'pending').length;
          results.replaceChildren(
            h('div', { class: ok.length === r.results.length ? 'success-box' : 'error-box' },
              `${ok.length - pend} done${pend ? `, ${pend} sent for approval` : ''}, ${r.results.length - ok.length} failed.`),
            h('ul', { class: 'list', style: 'max-height:240px;overflow:auto' }, r.results.map((x) => h('li', {},
              h('span', { class: `badge ${x.ok ? (x.status === 'pending' ? 'warn' : 'ok') : 'danger'}` }, x.ok ? (x.status === 'pending' ? 'Pending' : 'Done') : 'Failed'),
              h('span', { class: 'grow' }, x.sam, x.error ? h('span', { class: 'sub' }, ` – ${x.needsConfirm ? 'service account skipped' : x.error}`) : null)))));
          ctx.setActions([{ label: 'Close', kind: 'primary' }]);
          done();
        },
      },
    ],
  });
}

// ------------------------------------------------------------------ user detail

async function renderUserDetail(box, sam, refreshList) {
  box.replaceChildren(h('div', { class: 'card detail' }, h('div', { class: 'loading' }, 'Loading…')));
  let u;
  try { u = await api('GET', `/api/users/${encodeURIComponent(sam)}`); } catch (e) {
    box.replaceChildren(h('div', { class: 'card detail' }, h('div', { class: 'empty' }, e.message))); return;
  }
  const reload = async () => { await refreshList(); await renderUserDetail(box, u.sam, refreshList); };
  const enc = encodeURIComponent(u.sam);
  const w = !u.protected;
  // service-like accounts need the username typed for risky changes (server enforces it too)
  const svc = u.serviceAccount ? u.sam : undefined;
  const svcNote = u.serviceAccount ? ' This looks like a service account – changing it can break the applications that use it.' : '';

  const actions = [
    w && can('user.resetPassword') && h('button', { class: 'btn primary small', onclick: () => resetPasswordDialog(u, reload) }, 'Reset password'),
    u.locked && can('user.unlock') && h('button', {
      class: 'btn small',
      async onclick() {
        try { actionDone(await api('POST', `/api/users/${enc}/unlock`), `${u.displayName} unlocked`); reload(); } catch (e) { toast(e.message, 'error'); }
      },
    }, 'Unlock'),
    w && can('user.enable') && h('button', {
      class: `btn small ${u.enabled ? 'danger' : ''}`,
      onclick: () => (u.enabled
        ? confirmAction({
          title: 'Disable account', confirmLabel: 'Disable', typeToConfirm: svc,
          message: `${u.displayName} (${u.sam}) will not be able to sign in until the account is enabled again.${svcNote}`,
          run: async () => { actionDone(await api('POST', `/api/users/${enc}/enabled`, { enabled: false, confirmServiceAccount: svc }), `${u.displayName} disabled`); reload(); },
        })
        : api('POST', `/api/users/${enc}/enabled`, { enabled: true }).then((r) => { actionDone(r, `${u.displayName} enabled`); reload(); }, (e) => toast(e.message, 'error'))),
    }, u.enabled ? 'Disable' : 'Enable'),
    w && can('user.edit') && h('button', { class: 'btn small', onclick: () => editUserDialog(u, reload) }, 'Edit'),
    w && can('user.move') && h('button', { class: 'btn small', onclick: () => moveUserDialog(u, reload) }, 'Move'),
    w && can('user.offboard') && h('button', { class: 'btn small danger', onclick: () => offboardDialog(u, reload) }, 'Offboard'),
    w && can('user.delete') && h('button', {
      class: 'btn small danger',
      onclick: () => confirmAction({
        title: 'Delete user', confirmLabel: 'Delete permanently', typeToConfirm: u.sam,
        message: `This permanently deletes ${u.displayName} from Active Directory, including all group memberships. Consider "Offboard" instead, which disables and keeps the account.${svcNote}`,
        run: async () => {
          const r = await api('DELETE', `/api/users/${enc}`, { confirmServiceAccount: u.sam });
          actionDone(r, `${u.displayName} deleted`);
          if (r.status !== 'pending') { location.hash = '#/users'; state.users = null; }
        },
      }),
    }, 'Delete'),
  ].filter(Boolean);

  const kv = (pairs) => h('dl', { class: 'kv' }, pairs.filter(([, v]) => v !== undefined).map(([k, v]) => [h('dt', {}, k), h('dd', {}, v || '—')]));

  const groupItems = u.groups.map((g) => h('li', {},
    h('div', { class: 'grow' }, h('div', {}, g.name), h('div', { class: 'sub' }, g.description || `${g.scope} ${g.type}`)),
    can('group.members') && w && g.manageable && h('button', {
      class: 'icon-btn', title: `Remove from ${g.name}`,
      onclick: () => confirmAction({
        title: 'Remove from group', confirmLabel: 'Remove', message: `Remove ${u.displayName} from ${g.name}?`,
        run: async () => { actionDone(await api('DELETE', `/api/groups/${encodeURIComponent(g.sam)}/members/${enc}`), `Removed from ${g.name}`); reload(); },
      }),
    }, '✕')));

  let addGroup = null;
  if (can('group.members') && w) {
    addGroup = h('div', { style: 'margin-top:10px' }, searchSelect({
      placeholder: 'Add to group – type a group name…',
      async search(q) {
        const gs = await loadAllGroups();
        return gs.filter((g) => g.manageable && !u.groups.some((x) => x.sam === g.sam) && matchesWords(`${g.sam} ${g.name} ${g.description}`, q))
          .map((g) => ({ value: g.sam, label: g.name, sub: g.description || groupTypeLabel(g) }));
      },
      async onPick(it) {
        try { actionDone(await api('POST', `/api/groups/${encodeURIComponent(it.value)}/members`, { member: u.sam }), `Added to ${it.label}`); reload(); } catch (e) { toast(e.message, 'error'); }
      },
    }));
  }

  const manager = u.managerInfo
    ? (u.managerInfo.sam ? h('a', { href: `#/users/${encodeURIComponent(u.managerInfo.sam)}` }, u.managerInfo.name) : u.managerInfo.name)
    : '';
  const expiry = u.accountExpires
    ? h('span', {}, fmtDate(u.accountExpires), ' ', new Date(u.accountExpires) <= new Date() ? h('span', { class: 'badge danger' }, 'Expired') : h('span', { class: 'badge warn' }, 'Contractor / temporary'))
    : 'Never';

  box.replaceChildren(h('div', { class: 'card detail' },
    h('div', { class: 'detail-head' },
      h('div', { class: 'avatar' }, initials(u.displayName)),
      h('div', {},
        h('h3', {}, u.displayName),
        h('div', { class: 'sub' }, `${u.sam} · ${u.upn}`),
        h('div', { class: 'badges' }, statusBadges(u))),
      h('a', { class: 'btn small ghost close', href: '#/users', title: 'Close' }, '✕')),
    u.protected && h('div', { class: 'notice warn' }, 'This is a privileged/protected account (adminCount=1). It can be viewed and unlocked here; other changes must be made on the domain controller.'),
    !u.protected && u.serviceAccount && h('div', { class: 'notice info' }, 'Service account: its password never expires or it has a service principal name. Risky changes ask you to type the username to confirm.'),
    actions.length ? h('div', { class: 'actions' }, actions) : null,
    h('div', { class: 'section' }, h('h4', {}, 'Profile'), kv([
      ['First name', u.givenName], ['Last name', u.sn], ['E-mail', u.mail], ['Job title', u.title], ['Department', u.department],
      ['Manager', manager], ['Company', u.company], ['Office', u.office], ['Phone', u.telephoneNumber], ['Mobile', u.mobile],
      ['Employee ID', u.employeeID], ['Description', u.description],
    ])),
    h('div', { class: 'section' }, h('h4', {}, `Groups (${u.groups.length})`),
      u.groups.length ? h('ul', { class: 'list' }, groupItems) : h('div', { class: 'sub' }, 'Not a member of any group (besides Domain Users).'),
      addGroup),
    h('div', { class: 'section' }, h('h4', {}, 'Account'), kv([
      ['Password set', u.mustChangePassword ? 'Must change at next sign-in' : fmtDate(u.passwordLastSet)],
      ['Password expires', u.passwordNeverExpires ? 'Never' : undefined],
      ['Last sign-in', u.lastLogon ? fmtDate(u.lastLogon) : 'Never / unknown'],
      ['Account expires', expiry],
      ['Created', fmtDate(u.created)], ['Last changed', fmtDate(u.changed)],
      ['OU', ouLabel(u.ou)],
    ]), h('div', { class: 'mono sub', style: 'margin-top:10px;word-break:break-all' }, u.dn))));
}

// Toast for actions that may have been sent for approval instead of run
function actionDone(r, doneMsg) {
  if (r?.status === 'pending') {
    toast(`Sent for approval: ${r.summary}`, 'info');
    if (state.me) state.me.pendingApprovals = (state.me.pendingApprovals || 0);
  } else toast(doneMsg, 'success');
}

// Field asking to type the username for service-like accounts
function serviceConfirmField(u) {
  if (!u.serviceAccount) return { el: null, value: () => undefined, check: () => true };
  const input = h('input', { type: 'text', autocomplete: 'off', placeholder: u.sam });
  return {
    el: h('div', { class: 'field' }, h('div', { class: 'notice warn inline' }, 'This looks like a service account (password never expires or it has a service principal name). Changing it can break applications.'),
      h('label', {}, `Type "${u.sam}" to confirm`), input),
    value: () => input.value.trim(),
    check: () => input.value.trim().toLowerCase() === u.sam.toLowerCase(),
  };
}

function resetPasswordDialog(u, done) {
  const pw = passwordInput('rp-pass');
  const must = h('input', { type: 'checkbox', checked: true });
  const unlock = h('input', { type: 'checkbox', checked: true });
  const sc = serviceConfirmField(u);
  pw.input.value = generatePassword(); pw.input.type = 'text';
  return modal({
    title: `Reset password · ${u.displayName}`,
    body: h('div', {},
      sc.el,
      h('div', { class: 'field' }, h('label', { for: 'rp-pass' }, 'New password'), pw.row,
        h('div', { class: 'help' }, 'Must meet the domain password policy. A strong random password has been generated for you.')),
      h('label', { class: 'check' }, must, 'User must change password at next sign-in'),
      h('label', { class: 'check' }, unlock, 'Unlock the account if it is locked')),
    actions: [
      { label: 'Cancel' },
      {
        label: 'Reset password', kind: 'primary',
        async run(ctx) {
          if (!sc.check()) throw new Error('Type the username to confirm.');
          const password = pw.input.value;
          await api('POST', `/api/users/${encodeURIComponent(u.sam)}/reset-password`, { password, mustChange: must.checked, unlock: unlock.checked, confirmServiceAccount: sc.value() });
          ctx.close(true);
          done();
          showPasswordResult('Password reset', u.displayName, password, must.checked);
        },
      },
    ],
  });
}

function offboardDialog(u, done) {
  const resetPw = h('input', { type: 'checkbox', checked: true });
  const typed = h('input', { type: 'text', autocomplete: 'off', placeholder: u.sam });
  const leaver = state.me.leaverOU;
  const manageable = u.groups.filter((g) => g.manageable);
  return modal({
    title: `Offboard leaver · ${u.displayName}`,
    body: h('div', {},
      h('p', { style: 'margin-top:0' }, 'This will:'),
      h('ul', { class: 'steps-list' },
        h('li', {}, 'Disable the account'),
        h('li', {}, `Remove it from ${manageable.length} group(s)`, u.groups.length > manageable.length ? ` (${u.groups.length - manageable.length} protected group(s) stay)` : ''),
        h('li', {}, 'Stamp the description with today\'s date and your name'),
        h('li', {}, leaver ? `Move it to ${ouLabel(leaver)}` : 'Leave it in its current OU (set a leavers OU in Settings → Workflow to move it automatically)')),
      h('label', { class: 'check' }, resetPw, 'Also change the password to a random value nobody knows'),
      h('p', { class: 'sub' }, 'The account is kept (not deleted), so it can be restored if needed.'),
      h('div', { class: 'field' }, h('label', {}, `Type "${u.sam}" to confirm`), typed)),
    actions: [
      { label: 'Cancel' },
      {
        label: 'Offboard', kind: 'danger solid',
        async run(ctx) {
          if (typed.value.trim().toLowerCase() !== u.sam.toLowerCase()) throw new Error('The text you typed does not match.');
          const r = await api('POST', `/api/users/${encodeURIComponent(u.sam)}/offboard`, { resetPassword: resetPw.checked, confirmServiceAccount: u.sam });
          ctx.close(true);
          if (r.status === 'pending') { actionDone(r); done(); return; }
          done();
          modal({
            title: `${u.displayName} offboarded`,
            body: h('div', { class: 'success-box' }, h('ul', { class: 'steps' }, (r.steps || []).map((s) => h('li', {}, '✓ ', s))),
              r.kept?.length ? h('p', { style: 'margin:8px 0 0;color:var(--warn)' }, `Still a member of: ${r.kept.join(', ')}`) : null),
            actions: [{ label: 'Done', kind: 'primary' }],
          });
        },
      },
    ],
  });
}

const PROFILE_FIELDS = [
  ['givenName', 'First name'], ['sn', 'Last name'], ['displayName', 'Display name'], ['mail', 'E-mail'],
  ['title', 'Job title'], ['department', 'Department'], ['company', 'Company'], ['office', 'Office'],
  ['telephoneNumber', 'Phone'], ['mobile', 'Mobile'], ['employeeID', 'Employee ID'], ['description', 'Description'],
];

// Manager picker (search-as-you-type) used by Edit and New user
function managerPicker(current) {
  let value = current?.sam || '';
  const label = h('span', { class: 'sub' }, current?.name ? `Current: ${current.name}` : 'No manager set');
  const clear = h('button', { class: 'btn small', type: 'button', onclick: () => { value = ''; label.textContent = 'No manager set'; } }, 'Clear');
  const picker = searchSelect({
    placeholder: 'Search for the manager by name…',
    minChars: 2,
    async search(q) {
      const r = await api('GET', `/api/users?q=${encodeURIComponent(q)}&status=enabled`);
      return r.items.slice(0, 20).map((x) => ({ value: x.sam, label: x.displayName, sub: `${x.sam}${x.title ? ' · ' + x.title : ''}` }));
    },
    onPick(it) { value = it.value; label.textContent = `Selected: ${it.label}`; },
  });
  return { el: h('div', {}, picker, h('div', { class: 'input-row', style: 'margin-top:6px;align-items:center' }, label, clear)), value: () => value };
}

const isoToDate = (iso) => (iso ? new Date(new Date(iso).getTime() - 86400000).toISOString().slice(0, 10) : ''); // last working day

function editUserDialog(u, done) {
  const inputs = {};
  const fields = PROFILE_FIELDS.map(([k, label]) => h('div', { class: 'field' },
    h('label', { for: `eu-${k}` }, label),
    inputs[k] = h('input', { type: k === 'mail' ? 'email' : 'text', id: `eu-${k}`, value: u[k] || '' })));
  const mgr = managerPicker(u.managerInfo);
  const origExp = isoToDate(u.accountExpires);
  const exp = h('input', { type: 'date', id: 'eu-exp', value: origExp });
  return modal({
    title: `Edit · ${u.displayName}`,
    wide: true,
    body: h('div', {},
      h('div', { class: 'grid2' }, fields),
      h('div', { class: 'form-section' }, 'Manager & contract'),
      h('div', { class: 'grid2' },
        h('div', { class: 'field' }, h('label', {}, 'Manager'), mgr.el),
        h('div', { class: 'field' }, h('label', { for: 'eu-exp' }, 'Account expires after (last working day)'), exp,
          h('div', { class: 'help' }, 'Leave empty for permanent staff. The account stops working at midnight after this date.')))),
    actions: [
      { label: 'Cancel' },
      {
        label: 'Save changes', kind: 'primary',
        async run(ctx) {
          const body = {};
          for (const [k] of PROFILE_FIELDS) if ((u[k] || '') !== inputs[k].value.trim()) body[k] = inputs[k].value.trim();
          if ((u.managerInfo?.sam || '') !== mgr.value()) body.manager = mgr.value();
          if (origExp !== exp.value) body.accountExpires = exp.value;
          if (!Object.keys(body).length) { ctx.close(); return; }
          await api('PATCH', `/api/users/${encodeURIComponent(u.sam)}`, body);
          toast('Changes saved', 'success');
          ctx.close(true);
          done();
        },
      },
    ],
  });
}

async function moveUserDialog(u, done) {
  let ous;
  try { ous = (await loadOUs()).userOUs; } catch (e) { toast(e.message, 'error'); return; }
  const sel = h('select', { id: 'mv-ou' }, ous.map((o) => h('option', { value: o.dn, selected: o.dn.toLowerCase() === u.ou.toLowerCase() }, ouLabel(o.dn))));
  const sc = serviceConfirmField(u);
  return modal({
    title: `Move · ${u.displayName}`,
    body: h('div', {},
      sc.el,
      h('p', { style: 'margin-top:0' }, `Current OU: ${ouLabel(u.ou)}`),
      h('div', { class: 'field' }, h('label', { for: 'mv-ou' }, 'Move to OU'), sel),
      h('div', { class: 'help' }, 'Group Policies linked to the new OU will apply to this user.')),
    actions: [
      { label: 'Cancel' },
      {
        label: 'Move', kind: 'primary',
        async run(ctx) {
          if (!sc.check()) throw new Error('Type the username to confirm.');
          actionDone(await api('POST', `/api/users/${encodeURIComponent(u.sam)}/move`, { ou: sel.value, confirmServiceAccount: sc.value() }), `Moved to ${ouLabel(sel.value)}`);
          ctx.close(true);
          done();
        },
      },
    ],
  });
}

// ------------------------------------------------------------------ new user

async function renderNewUser(view) {
  view.replaceChildren(h('div', { class: 'loading' }, 'Loading…'));
  let ous, groups;
  try { [ous, groups] = await Promise.all([loadOUs(), loadAllGroups(true)]); } catch (e) { view.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }

  const f = {};
  const inp = (k, label, opts = {}) => h('div', { class: 'field' },
    h('label', { for: `nu-${k}` }, label, opts.required ? ' *' : ''),
    f[k] = h('input', { type: opts.type || 'text', id: `nu-${k}`, maxlength: opts.max || 128, placeholder: opts.placeholder || '' }),
    opts.help && h('div', { class: 'help' }, opts.help));

  const pw = passwordInput('nu-password');
  pw.input.value = generatePassword(); pw.input.type = 'text';
  const prov = state.me.provisioning || {};
  const ouSel = h('select', { id: 'nu-ou' }, ous.userOUs.map((o) => h('option', { value: o.dn, selected: !!prov.defaultUserOU && o.dn.toLowerCase() === prov.defaultUserOU.toLowerCase() }, ouLabel(o.dn))));
  const must = h('input', { type: 'checkbox', checked: prov.mustChangeDefault !== false });
  const enabled = h('input', { type: 'checkbox', checked: prov.enabledDefault !== false });
  const suffixes = prov.upnSuffixes?.length ? prov.upnSuffixes : [state.me.upnSuffix];
  const upnSel = h('select', { id: 'nu-upn', style: 'width:auto', hidden: suffixes.length < 2 }, suffixes.map((x) => h('option', { value: x }, '@' + x)));
  const err = h('div', { class: 'error-box', hidden: true });
  const upnPreview = h('div', { class: 'help' });

  const manageable = groups.filter((g) => g.manageable);
  const manageableSams = new Set(manageable.map((g) => g.sam.toLowerCase()));
  const groupPick = pickList({
    items: manageable.map((g) => ({ value: g.sam, label: g.name, sub: g.description ? `— ${g.description}` : '' })),
    selected: (prov.defaultGroups || []).filter((x) => manageableSams.has(x.toLowerCase())),
    placeholder: 'Search groups…',
    empty: 'No manageable groups.',
    height: 260,
    alwaysFilter: true,
  });
  const mgrNew = managerPicker(null);
  const expNew = h('input', { type: 'date', id: 'nu-exp' });

  let samEdited = false, dispEdited = false, mailEdited = false;
  const clean = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const makeSam = (gn, sn) => {
    const g = clean(gn), s = clean(sn);
    switch (prov.usernameFormat) {
      case 'manual': return null;
      case 'firstlast': return g + s;
      case 'flast': return (g[0] || '') + s;
      case 'first.l': return [g, s[0]].filter(Boolean).join('.');
      case 'first': return g;
      default: return [g, s].filter(Boolean).join('.');
    }
  };
  const suggest = () => {
    const gn = f.givenName.value.trim(), sn = f.sn.value.trim();
    if (!dispEdited) f.displayName.value = `${gn} ${sn}`.trim();
    const sam = makeSam(gn, sn);
    if (!samEdited && sam !== null) f.sam.value = sam.slice(0, 20);
    if (!mailEdited && prov.emailDomain) f.mail.value = f.sam.value ? `${f.sam.value}@${prov.emailDomain}` : '';
    upnPreview.textContent = f.sam.value ? `Sign-in name: ${f.sam.value}@${upnSel.value}` : '';
  };

  const submit = h('button', { class: 'btn primary', type: 'submit' }, 'Create user');
  const form = h('form', {
    class: 'card card-pad form-card',
    async onsubmit(e) {
      e.preventDefault();
      err.hidden = true;
      const body = { ou: ouSel.value, sam: f.sam.value.trim(), password: pw.input.value, upnSuffix: upnSel.value, mustChange: must.checked, enabled: enabled.checked,
        groups: groupPick.value(), manager: mgrNew.value(), accountExpires: expNew.value };
      for (const [k] of PROFILE_FIELDS) body[k] = f[k].value.trim();
      submit.disabled = true; submit.textContent = 'Creating…';
      try {
        const r = await api('POST', '/api/users', body);
        state.users = null; state.allGroups = null;
        (r.warnings || []).forEach((w) => toast(w, 'error'));
        location.hash = `#/users/${encodeURIComponent(r.sam)}`;
        showPasswordResult('User created', `${body.displayName || body.sam} (${r.sam})`, body.password, body.mustChange);
      } catch (ex) {
        err.textContent = ex.message; err.hidden = false; window.scrollTo({ top: 0, behavior: 'smooth' });
      } finally { submit.disabled = false; submit.textContent = 'Create user'; }
    },
  },
  err,
  h('div', { class: 'form-section' }, 'Name & sign-in'),
  h('div', { class: 'grid3' }, inp('givenName', 'First name', { required: true }), inp('sn', 'Last name'), inp('displayName', 'Display name', { required: true })),
  h('div', { class: 'grid2' },
    h('div', {}, inp('sam', 'Username (sAMAccountName)', { required: true, max: 20, help: 'Max 20 characters: letters, numbers, . _ -' }), h('div', { class: 'input-row', style: 'align-items:center' }, upnPreview, upnSel)),
    h('div', { class: 'field' }, h('label', { for: 'nu-ou' }, 'Organizational unit *'), ouSel)),
  h('div', { class: 'form-section' }, 'Password'),
  h('div', { class: 'field' }, h('label', { for: 'nu-password' }, 'Initial password *'), pw.row),
  h('label', { class: 'check' }, must, 'User must change password at next sign-in'),
  h('label', { class: 'check' }, enabled, 'Enable the account now'),
  h('div', { class: 'form-section' }, 'Profile'),
  h('div', { class: 'grid3' },
    inp('mail', 'E-mail', { type: 'email' }), inp('title', 'Job title'), inp('department', 'Department'),
    inp('company', 'Company'), inp('office', 'Office'), inp('employeeID', 'Employee ID'),
    inp('telephoneNumber', 'Phone'), inp('mobile', 'Mobile'), inp('description', 'Description')),
  h('div', { class: 'form-section' }, 'Manager & contract'),
  h('div', { class: 'grid2' },
    h('div', { class: 'field' }, h('label', {}, 'Manager'), mgrNew.el),
    h('div', { class: 'field' }, h('label', { for: 'nu-exp' }, 'Account expires after (contractors / temporary staff)'), expNew,
      h('div', { class: 'help' }, 'Leave empty for permanent staff. The account stops working at midnight after this date.'))),
  h('div', { class: 'form-section' }, 'Groups'),
  groupPick.el,
  h('div', { class: 'form-actions' }, h('a', { class: 'btn', href: '#/users' }, 'Cancel'), submit));

  f.givenName.addEventListener('input', suggest);
  f.sn.addEventListener('input', suggest);
  f.displayName.addEventListener('input', () => { dispEdited = true; });
  f.sam.addEventListener('input', () => { samEdited = true; suggest(); });
  f.mail.addEventListener('input', () => { mailEdited = true; });
  upnSel.addEventListener('change', suggest);

  view.replaceChildren(h('div', { class: 'page-head' }, h('h2', {}, 'New user')), form);
  f.givenName.focus();
}

// ------------------------------------------------------------------ groups

const groupTypeLabel = (g) => `${{ global: 'Global', domainlocal: 'Domain local', universal: 'Universal' }[g.scope] || g.scope} · ${g.type === 'security' ? 'Security' : 'Distribution'}`;

async function renderGroups(view, selected) {
  const search = h('input', { type: 'search', class: 'search', placeholder: 'Search groups by name or description…', value: state.groupQuery });
  const count = h('span', { class: 'count' });
  const listBox = h('div', { class: 'card table-wrap' }, h('div', { class: 'loading' }, 'Loading groups…'));
  const detailBox = h('div', {});
  view.replaceChildren(
    h('div', { class: 'page-head' }, h('h2', {}, 'Groups', count),
      can('group.create') && h('a', { class: 'btn primary', href: '#/groups/new' }, '+ New group')),
    h('div', { class: 'toolbar' }, search, h('button', { class: 'btn', onclick: () => load(true) }, 'Refresh')),
    h('div', { class: `split ${selected ? '' : 'no-detail'}` }, listBox, detailBox));

  let seq = 0;
  async function load(force) {
    const q = search.value.trim();
    if (force || !state.groups || q !== state.groupQuery) {
      const my = ++seq;
      state.groupQuery = q;
      listBox.replaceChildren(h('div', { class: 'loading' }, 'Loading groups…'));
      try {
        const r = await api('GET', `/api/groups?q=${encodeURIComponent(q)}`);
        if (my !== seq) return; // a newer search replaced this one
        state.groups = r;
      } catch (e) { if (my === seq) listBox.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    }
    const { items, total } = state.groups;
    count.textContent = String(total);
    if (!items.length) { listBox.replaceChildren(h('div', { class: 'empty' }, 'No groups match your search.')); return; }
    listBox.replaceChildren(h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Group'), h('th', { class: 'hide-sm' }, 'Type'), h('th', { class: 'hide-sm' }, 'OU'))),
      h('tbody', {}, items.map((g) => h('tr', {
        class: `clickable ${selected && g.sam.toLowerCase() === selected.toLowerCase() ? 'selected' : ''}`,
        onclick: () => { location.hash = `#/groups/${encodeURIComponent(g.sam)}`; },
      },
      h('td', {}, h('div', {}, g.name, g.protected ? ' ' : '', g.protected && h('span', { class: 'badge info' }, 'Protected')), h('div', { class: 'sub' }, g.description)),
      h('td', { class: 'hide-sm' }, h('span', { class: `badge ${g.type === 'security' ? 'info' : 'off'}` }, groupTypeLabel(g))),
      h('td', { class: 'hide-sm' }, h('span', { class: 'sub' }, ouLabel(g.ou))))))));
  }

  search.addEventListener('input', debounce(() => load(), 300));
  await load();
  if (selected) renderGroupDetail(detailBox, selected, () => load(true));
}

async function renderGroupDetail(box, sam, refreshList) {
  box.replaceChildren(h('div', { class: 'card detail' }, h('div', { class: 'loading' }, 'Loading…')));
  let g;
  try { g = await api('GET', `/api/groups/${encodeURIComponent(sam)}`); } catch (e) {
    box.replaceChildren(h('div', { class: 'card detail' }, h('div', { class: 'empty' }, e.message))); return;
  }
  const enc = encodeURIComponent(g.sam);
  const w = g.manageable;
  const reload = async () => { state.allGroups = null; await refreshList(); await renderGroupDetail(box, g.sam, refreshList); };

  const actions = [
    w && can('group.edit') && h('button', { class: 'btn small', onclick: () => editGroupDialog(g, reload) }, 'Edit'),
    w && can('group.delete') && h('button', {
      class: 'btn small danger',
      onclick: () => confirmAction({
        title: 'Delete group', confirmLabel: 'Delete permanently', typeToConfirm: g.sam,
        message: `This permanently deletes the group ${g.name} (${g.members.length} members). Members' accounts are not deleted, but they lose any access granted through this group.`,
        run: async () => { const r = await api('DELETE', `/api/groups/${enc}`); actionDone(r, `${g.name} deleted`); if (r.status !== 'pending') { state.groups = null; state.allGroups = null; location.hash = '#/groups'; } },
      }),
    }, 'Delete'),
  ].filter(Boolean);

  let addMember = null;
  if (w && can('group.members')) {
    const isMember = (sam) => g.members.some((m) => String(m.sam).toLowerCase() === String(sam).toLowerCase());
    addMember = h('div', { style: 'margin-bottom:10px' }, searchSelect({
      placeholder: 'Add member – type a name, username or group…',
      minChars: 2,
      async search(q) {
        const [users, groups] = await Promise.all([
          api('GET', `/api/users?q=${encodeURIComponent(q)}&status=all`),
          api('GET', `/api/groups?q=${encodeURIComponent(q)}`),
        ]);
        const us = users.items.filter((x) => !isMember(x.sam)).slice(0, 30)
          .map((x) => ({ value: x.sam, label: x.displayName, sub: `${x.sam} · user${x.enabled ? '' : ' · disabled'}${x.department ? ' · ' + x.department : ''}` }));
        const gs = groups.items.filter((x) => x.sam !== g.sam && !isMember(x.sam)).slice(0, 15)
          .map((x) => ({ value: x.sam, label: x.name, sub: 'group' + (x.description ? ' · ' + x.description : '') }));
        return [...us, ...gs];
      },
      async onPick(it) {
        try { actionDone(await api('POST', `/api/groups/${enc}/members`, { member: it.value }), `${it.label} added to ${g.name}`); reload(); } catch (e) { toast(e.message, 'error'); }
      },
    }));
  }

  const members = g.members.map((m) => h('li', {},
    h('div', { class: 'grow' },
      m.kind === 'user' && m.inScope ? h('a', { href: `#/users/${encodeURIComponent(m.sam)}` }, m.name)
        : m.kind === 'group' && m.inScope ? h('a', { href: `#/groups/${encodeURIComponent(m.sam)}` }, m.name) : h('span', {}, m.name),
      h('div', { class: 'sub' }, `${m.sam || ''} · ${m.kind}${m.enabled ? '' : ' · disabled'}`)),
    w && can('group.members') && h('button', {
      class: 'icon-btn', title: `Remove ${m.name}`,
      onclick: () => confirmAction({
        title: 'Remove member', confirmLabel: 'Remove', message: `Remove ${m.name} from ${g.name}?`,
        run: async () => { actionDone(await api('DELETE', `/api/groups/${enc}/members/${encodeURIComponent(m.sam)}`), `${m.name} removed`); reload(); },
      }),
    }, '✕')));

  box.replaceChildren(h('div', { class: 'card detail' },
    h('div', { class: 'detail-head' },
      h('div', { class: 'avatar group' }, initials(g.name)),
      h('div', {},
        h('h3', {}, g.name),
        h('div', { class: 'sub' }, g.description || 'No description'),
        h('div', { class: 'badges' }, h('span', { class: `badge ${g.type === 'security' ? 'info' : 'off'}` }, groupTypeLabel(g)), g.protected && h('span', { class: 'badge info' }, 'Protected'))),
      h('a', { class: 'btn small ghost close', href: '#/groups', title: 'Close' }, '✕')),
    !w && h('div', { class: 'notice warn' }, 'This group is protected or outside the managed OUs. It is read-only here.'),
    actions.length ? h('div', { class: 'actions' }, actions) : null,
    h('div', { class: 'section' }, h('h4', {}, `Members (${g.members.length})`), addMember,
      g.members.length ? h('ul', { class: 'list' }, members) : h('div', { class: 'sub' }, 'This group has no members.')),
    h('div', { class: 'section' }, h('h4', {}, 'Details'), h('dl', { class: 'kv' },
      h('dt', {}, 'Name'), h('dd', {}, g.sam),
      h('dt', {}, 'E-mail'), h('dd', {}, g.mail || '—'),
      h('dt', {}, 'Notes'), h('dd', {}, g.info || '—'),
      h('dt', {}, 'OU'), h('dd', {}, ouLabel(g.ou)),
      h('dt', {}, 'Created'), h('dd', {}, fmtDate(g.created)),
      h('dt', {}, 'Last changed'), h('dd', {}, fmtDate(g.changed))),
    h('div', { class: 'mono sub', style: 'margin-top:10px;word-break:break-all' }, g.dn))));
}

function editGroupDialog(g, done) {
  const desc = h('input', { type: 'text', id: 'eg-desc', value: g.description, maxlength: 256 });
  const mail = h('input', { type: 'email', id: 'eg-mail', value: g.mail, maxlength: 128 });
  const info = h('textarea', { id: 'eg-info', maxlength: 1024 }, g.info);
  return modal({
    title: `Edit group · ${g.name}`,
    body: h('div', {},
      h('div', { class: 'field' }, h('label', { for: 'eg-desc' }, 'Description'), desc),
      h('div', { class: 'field' }, h('label', { for: 'eg-mail' }, 'E-mail'), mail),
      h('div', { class: 'field' }, h('label', { for: 'eg-info' }, 'Notes'), info)),
    actions: [
      { label: 'Cancel' },
      {
        label: 'Save changes', kind: 'primary',
        async run(ctx) {
          await api('PATCH', `/api/groups/${encodeURIComponent(g.sam)}`, { description: desc.value.trim(), mail: mail.value.trim(), info: info.value.trim() });
          toast('Changes saved', 'success');
          ctx.close(true);
          done();
        },
      },
    ],
  });
}

async function renderNewGroup(view) {
  view.replaceChildren(h('div', { class: 'loading' }, 'Loading…'));
  let ous;
  try { ous = await loadOUs(); } catch (e) { view.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
  const name = h('input', { type: 'text', id: 'ng-name', maxlength: 64 });
  const ou = h('select', { id: 'ng-ou' }, ous.groupOUs.map((o) => h('option', { value: o.dn }, ouLabel(o.dn))));
  const scope = h('select', { id: 'ng-scope' }, h('option', { value: 'global' }, 'Global'), h('option', { value: 'domainlocal' }, 'Domain local'), h('option', { value: 'universal' }, 'Universal'));
  const type = h('select', { id: 'ng-type' }, h('option', { value: 'security' }, 'Security'), h('option', { value: 'distribution' }, 'Distribution'));
  const desc = h('input', { type: 'text', id: 'ng-desc', maxlength: 256 });
  const mail = h('input', { type: 'email', id: 'ng-mail', maxlength: 128 });
  const info = h('textarea', { id: 'ng-info', maxlength: 1024 });
  const err = h('div', { class: 'error-box', hidden: true });
  const submit = h('button', { class: 'btn primary', type: 'submit' }, 'Create group');
  const fld = (id, label, el, help) => h('div', { class: 'field' }, h('label', { for: id }, label), el, help && h('div', { class: 'help' }, help));

  view.replaceChildren(h('div', { class: 'page-head' }, h('h2', {}, 'New group')), h('form', {
    class: 'card card-pad form-card',
    async onsubmit(e) {
      e.preventDefault();
      err.hidden = true; submit.disabled = true;
      try {
        const r = await api('POST', '/api/groups', { name: name.value.trim(), ou: ou.value, scope: scope.value, type: type.value, description: desc.value.trim(), mail: mail.value.trim(), info: info.value.trim() });
        toast(`Group ${r.sam} created`, 'success');
        state.groups = null; state.allGroups = null;
        location.hash = `#/groups/${encodeURIComponent(r.sam)}`;
      } catch (ex) { err.textContent = ex.message; err.hidden = false; } finally { submit.disabled = false; }
    },
  },
  err,
  h('div', { class: 'grid2' },
    fld('ng-name', 'Group name *', name, 'Letters, numbers, spaces and . _ - &'),
    fld('ng-ou', 'Organizational unit *', ou),
    fld('ng-scope', 'Group scope', scope, 'Global is right for most permission groups.'),
    fld('ng-type', 'Group type', type, 'Security groups can grant access; distribution groups are for e-mail only.'),
    fld('ng-desc', 'Description', desc),
    fld('ng-mail', 'E-mail (optional)', mail)),
  fld('ng-info', 'Notes', info),
  h('div', { class: 'form-actions' }, h('a', { class: 'btn', href: '#/groups' }, 'Cancel'), submit)));
  name.focus();
}

// ------------------------------------------------------------------ shared: CSV + downloads

function parseCsv(textIn) {
  const text = textIn.replace(/^﻿/, '');
  const firstLine = text.split(/\r?\n/, 1)[0] || '';
  const delim = (firstLine.match(/;/g) || []).length > (firstLine.match(/,/g) || []).length ? ';' : ',';
  const rows = [];
  let row = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (ch === '"') quoted = false; else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === delim) { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); cell = '';
      if (row.some((c) => c.trim())) rows.push(row);
      row = [];
    } else cell += ch;
  }
  row.push(cell);
  if (row.some((c) => c.trim())) rows.push(row);
  return rows;
}

function toCsvText(columns, rows) {
  const cell = (v) => {
    let s = v === undefined || v === null ? '' : String(v);
    if (/^[=+\-@]/.test(s)) s = "'" + s; // no spreadsheet formulas
    return `"${s.replace(/"/g, '""')}"`;
  };
  return '﻿' + [columns.map((c) => cell(c.label)).join(','), ...rows.map((r) => columns.map((c) => cell(typeof c.value === 'function' ? c.value(r) : r[c.key])).join(','))].join('\r\n');
}

function downloadText(filename, content, type = 'text/csv;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = h('a', { href: url, download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// Username from first/last name using the format chosen in Settings
function suggestSam(gn, sn) {
  const clean = (s) => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const g = clean(gn), s = clean(sn);
  switch (state.me?.provisioning?.usernameFormat) {
    case 'firstlast': return (g + s).slice(0, 20);
    case 'flast': return ((g[0] || '') + s).slice(0, 20);
    case 'first.l': return [g, s[0]].filter(Boolean).join('.').slice(0, 20);
    case 'first': return g.slice(0, 20);
    case 'manual': return '';
    default: return [g, s].filter(Boolean).join('.').slice(0, 20);
  }
}

// ------------------------------------------------------------------ bulk import

const IMPORT_COLUMNS = {
  givenName: ['firstname', 'givenname', 'first name', 'first'],
  sn: ['lastname', 'sn', 'surname', 'last name', 'last'],
  sam: ['username', 'sam', 'samaccountname', 'login', 'user name', 'userid'],
  displayName: ['displayname', 'display name', 'fullname', 'full name', 'name'],
  mail: ['email', 'mail', 'e-mail', 'emailaddress'],
  title: ['title', 'jobtitle', 'job title', 'designation'],
  department: ['department', 'dept'],
  company: ['company'],
  office: ['office', 'location'],
  telephoneNumber: ['phone', 'telephone', 'telephonenumber'],
  mobile: ['mobile', 'cell'],
  employeeID: ['employeeid', 'employee id', 'empid', 'emp id', 'employee no', 'employeenumber'],
  description: ['description', 'notes'],
  ou: ['ou', 'organizationalunit'],
  groups: ['groups', 'group', 'memberof'],
  manager: ['manager', 'managerusername', 'manager username'],
  accountExpires: ['accountexpires', 'expires', 'expiry', 'expirydate', 'enddate', 'end date', 'last working day'],
};

const normDate = (v) => {
  const s = String(v || '').trim();
  if (!s) return '';
  let y, mo, d;
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (m) [, y, mo, d] = m.map(Number);
  else if ((m = s.match(/^(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})$/))) [, d, mo, y] = m.map(Number); // DD/MM/YYYY
  else return 'invalid';
  const dt = new Date(Date.UTC(y, mo - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return 'invalid'; // e.g. month 13, 31 June
  return `${y}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
};

async function renderImport(view) {
  view.replaceChildren(h('div', { class: 'loading' }, 'Loading…'));
  let ous, groups;
  try { [ous, groups] = await Promise.all([loadOUs(), loadAllGroups(true)]); } catch (e) { view.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
  const prov = state.me.provisioning || {};
  const ouSel = h('select', {}, ous.userOUs.map((o) => h('option', { value: o.dn, selected: !!prov.defaultUserOU && o.dn.toLowerCase() === prov.defaultUserOU.toLowerCase() }, ouLabel(o.dn))));
  const manageable = groups.filter((g) => g.manageable);
  const gp = pickList({ items: manageable.map((g) => ({ value: g.sam, label: g.name, sub: g.description ? `— ${g.description}` : '' })), selected: (prov.defaultGroups || []), placeholder: 'Search groups…', height: 180, alwaysFilter: true });
  const must = h('input', { type: 'checkbox', checked: prov.mustChangeDefault !== false });
  const enabled = h('input', { type: 'checkbox', checked: prov.enabledDefault !== false });
  const file = h('input', { type: 'file', accept: '.csv,text/csv' });
  const preview = h('div', {});
  let rows = [];

  const template = () => downloadText('ad-portal-import-template.csv', toCsvText(
    ['First name', 'Last name', 'Username', 'E-mail', 'Job title', 'Department', 'Employee ID', 'Mobile', 'Manager', 'Expires', 'Groups', 'OU'].map((l) => ({ label: l })),
    [{}]).replace(/\r\n""(,"")*$/, ''));

  file.addEventListener('change', async () => {
    const f = file.files[0];
    if (!f) return;
    if (f.size > 2 * 1024 * 1024) { toast('File is too large (max 2 MB)', 'error'); return; }
    const table = parseCsv(await f.text());
    if (table.length < 2) { preview.replaceChildren(h('div', { class: 'error-box' }, 'The file needs a header row and at least one user.')); return; }
    const header = table[0].map((x) => x.trim().toLowerCase().replace(/[_]/g, ' '));
    const colOf = {};
    for (const [key, names] of Object.entries(IMPORT_COLUMNS)) {
      const i = header.findIndex((hd) => names.includes(hd) || names.includes(hd.replace(/\s/g, '')));
      if (i >= 0) colOf[key] = i;
    }
    if (colOf.givenName === undefined && colOf.sn === undefined && colOf.displayName === undefined) {
      preview.replaceChildren(h('div', { class: 'error-box' }, 'Could not find name columns. Use the template (First name, Last name, …).'));
      return;
    }
    const seen = new Set();
    rows = table.slice(1, 501).map((r, i) => {
      const row = {};
      for (const [key, idx] of Object.entries(colOf)) row[key] = String(r[idx] ?? '').trim();
      if (!row.sam) row.sam = suggestSam(row.givenName, row.sn);
      if (!row.mail && prov.emailDomain && row.sam) row.mail = `${row.sam}@${prov.emailDomain}`;
      if (row.accountExpires) row.accountExpires = normDate(row.accountExpires);
      const problems = [];
      if (!row.givenName && !row.sn && !row.displayName) problems.push('no name');
      if (!/^[A-Za-z0-9._-]{1,20}$/.test(row.sam || '')) problems.push('username missing/invalid');
      if (seen.has((row.sam || '').toLowerCase())) problems.push('duplicate username in file');
      seen.add((row.sam || '').toLowerCase());
      if (row.accountExpires === 'invalid') problems.push('expiry date not understood (use YYYY-MM-DD)');
      return { line: i + 2, row, problems };
    });
    drawPreview(table.length - 1 > 500);
  });

  function drawPreview(cut) {
    const okRows = rows.filter((r) => !r.problems.length);
    const go = h('button', { class: 'btn primary', disabled: !okRows.length }, `Create ${okRows.length} user(s)`);
    go.addEventListener('click', () => runImport(okRows, go));
    preview.replaceChildren(
      h('div', { class: 'card card-pad', style: 'margin-top:14px' },
        h('div', { class: 'card-title' }, h('span', {}, `Preview – ${rows.length} row(s)`), h('span', {}, okRows.length < rows.length ? h('span', { class: 'badge danger' }, `${rows.length - okRows.length} with problems (will be skipped)`) : h('span', { class: 'badge ok' }, 'All rows look good'))),
        cut && h('div', { class: 'notice warn inline' }, 'Only the first 500 rows are imported at a time.'),
        h('div', { class: 'table-wrap', style: 'max-height:380px' }, h('table', {},
          h('thead', {}, h('tr', {}, ['Line', 'Name', 'Username', 'E-mail', 'Department', 'Manager', 'Expires', 'Groups', 'Check'].map((x) => h('th', {}, x)))),
          h('tbody', {}, rows.map((r) => h('tr', {},
            h('td', {}, r.line),
            h('td', {}, r.row.displayName || `${r.row.givenName || ''} ${r.row.sn || ''}`.trim()),
            h('td', { class: 'mono' }, r.row.sam),
            h('td', {}, r.row.mail || ''),
            h('td', {}, r.row.department || ''),
            h('td', {}, r.row.manager || ''),
            h('td', {}, r.row.accountExpires || ''),
            h('td', {}, r.row.groups || ''),
            h('td', {}, r.problems.length ? h('span', { class: 'badge danger' }, r.problems.join(', ')) : h('span', { class: 'badge ok' }, 'OK'))))))),
        h('div', { class: 'form-actions' }, go)));
  }

  async function runImport(okRows, btn) {
    btn.disabled = true; btn.textContent = `Creating ${okRows.length} user(s)…`;
    try {
      const r = await api('POST', '/api/users/import', {
        rows: okRows.map((x) => x.row),
        defaults: { ou: ouSel.value, groups: gp.value(), mustChange: must.checked, enabled: enabled.checked },
      });
      state.users = null;
      const ok = r.results.filter((x) => x.ok);
      const save = () => downloadText(`new-accounts-${new Date().toISOString().slice(0, 10)}.csv`, toCsvText(
        [{ label: 'Username', key: 'sam' }, { label: 'Initial password', key: 'password' }, { label: 'Result', value: (x) => (x.ok ? 'created' : `failed: ${x.error}`) }, { label: 'Warnings', value: (x) => (x.warnings || []).join('; ') }],
        r.results));
      preview.replaceChildren(h('div', { class: 'card card-pad', style: 'margin-top:14px' },
        h('div', { class: ok.length === r.results.length ? 'success-box' : 'error-box' }, `${ok.length} created, ${r.results.length - ok.length} failed.`),
        h('div', { class: 'notice warn inline', style: 'margin-top:12px' }, h('b', {}, 'Download the initial passwords now. '), 'They are shown only once and are not stored anywhere. Hand them over securely and delete the file afterwards.'),
        h('div', { class: 'input-row', style: 'margin-bottom:12px' }, h('button', { class: 'btn primary', onclick: save }, 'Download passwords (CSV)')),
        h('div', { class: 'table-wrap', style: 'max-height:380px' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Row'), h('th', {}, 'Username'), h('th', {}, 'Result'))),
          h('tbody', {}, r.results.map((x) => h('tr', {},
            h('td', {}, x.row), h('td', { class: 'mono' }, x.sam),
            h('td', {}, x.ok ? h('span', { class: 'badge ok' }, 'Created') : h('span', { class: 'badge danger' }, x.error),
              (x.warnings || []).length ? h('div', { class: 'sub' }, x.warnings.join('; ')) : null))))))));
    } catch (e) { toast(e.message, 'error'); btn.disabled = false; btn.textContent = 'Try again'; }
  }

  view.replaceChildren(
    h('div', { class: 'page-head' }, h('div', {}, h('h2', {}, 'Import users from CSV'), h('p', { class: 'desc' }, 'Create many accounts at once – e.g. a batch of new joiners from HR.')),
      h('a', { class: 'btn', href: '#/users' }, 'Back to users')),
    h('div', { class: 'card card-pad form-card' },
      h('div', { class: 'form-section' }, '1. Get the file ready'),
      h('p', { style: 'margin-top:0' }, 'Use one row per person. Required: first and/or last name. Username, e-mail and other columns are optional – a username is suggested from the name using your format (', h('b', {}, state.me.provisioning?.usernameFormat || 'first.last'), '). Separate several groups with ";". Dates as YYYY-MM-DD.'),
      h('button', { class: 'btn small', onclick: template }, 'Download template'),
      h('div', { class: 'form-section' }, '2. Defaults for every row'),
      h('div', { class: 'grid2' },
        h('div', { class: 'field' }, h('label', {}, 'OU (unless the file has an OU column)'), ouSel),
        h('div', {}, h('label', { class: 'check' }, must, 'Users must change password at first sign-in'), h('label', { class: 'check' }, enabled, 'Enable the accounts now'))),
      h('div', { class: 'field' }, h('label', {}, 'Add everyone to these groups'), gp.el),
      h('div', { class: 'form-section' }, '3. Choose the file'),
      file),
    preview);
}

// ------------------------------------------------------------------ reports

async function renderReports(view) {
  view.replaceChildren(h('div', { class: 'loading' }, 'Loading…'));
  let list;
  try { list = await api('GET', '/api/reports'); } catch (e) { view.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
  const sel = h('select', {}, list.map((r) => h('option', { value: r.id }, r.title)), h('option', { value: 'group-members' }, 'Members of a group'));
  const days = h('input', { type: 'text', inputmode: 'numeric', style: 'width:90px' });
  const daysWrap = h('label', { class: 'input-row', style: 'align-items:center;gap:6px' }, 'N =', days, 'days');
  let groupSam = '';
  const groupWrap = h('div', { style: 'min-width:260px', hidden: true }, searchSelect({
    placeholder: 'Choose a group…',
    async search(q) { const gs = await loadAllGroups(); return gs.filter((g) => matchesWords(`${g.sam} ${g.description}`, q)).map((g) => ({ value: g.sam, label: g.name, sub: g.description })); },
    onPick(it) { groupSam = it.value; groupLabel.textContent = it.label; run(); },
  }));
  const groupLabel = h('b', {});
  const out = h('div', {});
  let last = null;

  const cols = [
    { label: 'Username', key: 'sam' }, { label: 'Name', key: 'displayName' }, { label: 'Department', key: 'department' },
    { label: 'Title', key: 'title' }, { label: 'E-mail', key: 'mail' }, { label: 'Enabled', value: (r) => (r.enabled ? 'yes' : 'no') },
    { label: 'Last sign-in', value: (r) => (r.lastLogon ? r.lastLogon.slice(0, 10) : 'never') },
    { label: 'Password set', value: (r) => (r.passwordLastSet ? r.passwordLastSet.slice(0, 10) : '') },
    { label: 'Expires', value: (r) => (r.accountExpires ? r.accountExpires.slice(0, 10) : '') },
    { label: 'OU', value: (r) => ouLabel(r.ou) },
  ];
  const groupCols = [{ label: 'Username', key: 'sam' }, { label: 'Name', key: 'displayName' }, { label: 'Type', key: 'kind' }, { label: 'Enabled', value: (r) => (r.enabled ? 'yes' : 'no') }];

  function syncControls() {
    const meta = list.find((r) => r.id === sel.value);
    daysWrap.hidden = !meta?.days;
    if (meta?.days && !days.value) days.value = meta.days;
    groupWrap.hidden = sel.value !== 'group-members';
  }

  async function run() {
    syncControls();
    if (sel.value === 'group-members' && !groupSam) { out.replaceChildren(h('div', { class: 'empty' }, 'Choose a group.')); return; }
    out.replaceChildren(h('div', { class: 'loading' }, 'Running report…'));
    try {
      const q = sel.value === 'group-members' ? `?group=${encodeURIComponent(groupSam)}` : (daysWrap.hidden ? '' : `?days=${encodeURIComponent(days.value)}`);
      last = await api('GET', `/api/reports/${sel.value}${q}`);
      const c = sel.value === 'group-members' ? groupCols : cols;
      out.replaceChildren(h('div', { class: 'card' },
        h('div', { class: 'card-pad', style: 'display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap' },
          h('div', {}, h('b', {}, last.title), h('span', { class: 'count' }, `${last.rows.length} account(s)`)),
          h('button', { class: 'btn', disabled: !last.rows.length, onclick: () => downloadText(`report-${sel.value}-${new Date().toISOString().slice(0, 10)}.csv`, toCsvText(c, last.rows)) }, 'Export CSV (Excel)')),
        last.rows.length ? h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, c.map((x) => h('th', {}, x.label)))),
          h('tbody', {}, last.rows.map((r) => h('tr', { class: 'clickable', onclick: () => { if (r.sam && (!r.kind || r.kind === 'user')) location.hash = `#/users/${encodeURIComponent(r.sam)}`; } },
            c.map((x) => h('td', {}, typeof x.value === 'function' ? x.value(r) : (r[x.key] ?? '')))))))) : h('div', { class: 'empty' }, 'Nothing found – good news.'),
        h('div', { class: 'card-pad sub' }, 'Last sign-in comes from AD\'s replicated lastLogonTimestamp, which can lag by up to 14 days.')));
    } catch (e) { out.replaceChildren(h('div', { class: 'error-box' }, e.message)); }
  }

  sel.addEventListener('change', () => { days.value = ''; run(); });
  days.addEventListener('change', run);
  view.replaceChildren(
    h('div', { class: 'page-head' }, h('div', {}, h('h2', {}, 'Reports'), h('p', { class: 'desc' }, 'Account hygiene and audit reports – export to Excel with one click.'))),
    h('div', { class: 'toolbar', style: 'align-items:center' }, sel, daysWrap, groupWrap, groupLabel, h('button', { class: 'btn primary', onclick: run }, 'Run')),
    out);
  run();
}

// ------------------------------------------------------------------ approvals

const STATUS_BADGE = { pending: 'warn', approved: 'ok', rejected: 'danger', failed: 'danger', cancelled: 'off', expired: 'off' };

async function renderApprovals(view) {
  view.replaceChildren(h('div', { class: 'loading' }, 'Loading…'));
  let list;
  try { list = await api('GET', '/api/approvals'); } catch (e) { view.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
  const me = state.me.sam.toLowerCase();
  const canApprove = can('approvals.approve');
  const pending = list.filter((r) => r.status === 'pending');
  const done = list.filter((r) => r.status !== 'pending');
  state.me.pendingApprovals = canApprove ? pending.length : 0;
  document.querySelectorAll('.nav a[data-nav="#/approvals"] .nav-badge').forEach((b) => { b.textContent = String(pending.length); b.hidden = !pending.length; });

  const decideBtn = (r, decision, label, kind) => h('button', {
    class: `btn small ${kind}`,
    onclick: () => {
      const note = h('input', { type: 'text', placeholder: 'Optional note' });
      modal({
        title: `${label} request`,
        body: h('div', {}, h('p', { style: 'margin-top:0' }, h('b', {}, r.summary), h('br'), `Requested by ${r.requestedByName || r.requestedBy} on ${fmtDate(r.createdAt)}`),
          decision !== 'cancel' && h('div', { class: 'field' }, h('label', {}, 'Note'), note),
          decision === 'approve' && h('div', { class: 'notice warn inline' }, 'Approving runs the action immediately in Active Directory.')),
        actions: [{ label: 'Back' }, {
          label, kind: kind.includes('danger') ? 'danger solid' : 'primary',
          async run(ctx) {
            const out = await api('POST', `/api/approvals/${r.id}/${decision}`, { note: note.value });
            ctx.close(true);
            toast(decision === 'approve' ? `Approved and done${out.steps ? ': ' + out.steps.join('; ') : ''}` : `Request ${decision === 'reject' ? 'rejected' : 'cancelled'}`, 'success');
            state.users = null; state.groups = null;
            renderApprovals(view);
          },
        }],
      });
    },
  }, label);

  const row = (r, actions) => h('tr', {},
    h('td', { class: 'nowrap' }, fmtDate(r.createdAt)),
    h('td', {}, h('div', {}, r.summary), h('div', { class: 'sub' }, r.action)),
    h('td', {}, r.requestedByName || r.requestedBy, h('div', { class: 'sub' }, r.requestedBy)),
    h('td', {}, h('span', { class: `badge ${STATUS_BADGE[r.status] || 'off'}` }, r.status),
      r.decidedBy ? h('div', { class: 'sub' }, `by ${r.decidedBy}${r.note ? ' – ' + r.note : ''}`) : null,
      r.result && r.status !== 'approved' ? h('div', { class: 'sub' }, r.result) : null),
    actions ? h('td', {}, h('div', { class: 'input-row' }, actions)) : null);

  view.replaceChildren(
    h('div', { class: 'page-head' }, h('div', {}, h('h2', {}, 'Approvals'),
      h('p', { class: 'desc' }, (state.me.approvalActions || []).length
        ? 'These actions need a second admin: ' + state.me.approvalActions.map((a) => ACTION_LABELS[a] || a).join(', ') + '. Change this in Settings → Workflow.'
        : 'No actions currently need approval. Turn this on in Settings → Workflow.')),
      h('button', { class: 'btn', onclick: () => renderApprovals(view) }, 'Refresh')),
    h('div', { class: 'card', style: 'margin-bottom:16px' },
      h('div', { class: 'card-pad card-title' }, `Waiting (${pending.length})`),
      pending.length ? h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Requested'), h('th', {}, 'What'), h('th', {}, 'By'), h('th', {}, 'Status'), h('th', {}, ''))),
        h('tbody', {}, pending.map((r) => row(r, [
          canApprove && r.requestedBy.toLowerCase() !== me && decideBtn(r, 'approve', 'Approve', 'primary'),
          canApprove && r.requestedBy.toLowerCase() !== me && decideBtn(r, 'reject', 'Reject', 'danger'),
          r.requestedBy.toLowerCase() === me && decideBtn(r, 'cancel', 'Cancel', ''),
          canApprove && r.requestedBy.toLowerCase() === me && h('span', { class: 'sub' }, 'Another admin must approve'),
        ].filter(Boolean)))))) : h('div', { class: 'empty' }, 'Nothing is waiting for approval.')),
    h('div', { class: 'card' },
      h('div', { class: 'card-pad card-title' }, 'History (last 90 days)'),
      done.length ? h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'Requested'), h('th', {}, 'What'), h('th', {}, 'By'), h('th', {}, 'Outcome'))),
        h('tbody', {}, done.map((r) => row(r))))) : h('div', { class: 'empty' }, 'No decisions yet.')));
}

// ------------------------------------------------------------------ audit log

const ACTION_LABELS = {
  login: 'Signed in', logout: 'Signed out',
  'user.create': 'Created user', 'user.update': 'Edited user', 'user.resetPassword': 'Reset password', 'user.unlock': 'Unlocked user',
  'user.enable': 'Enabled / disabled user', 'user.move': 'Moved user', 'user.delete': 'Deleted user',
  'group.create': 'Created group', 'group.update': 'Edited group', 'group.delete': 'Deleted group',
  'group.addMember': 'Added group member', 'group.removeMember': 'Removed group member', 'audit.export': 'Exported audit log',
  'settings.setup': 'Initial setup', 'settings.update': 'Changed settings', 'settings.test': 'Tested AD connection', 'settings.setupToken': 'Wrong setup token',
  'user.offboard': 'Offboarded leaver', 'login.mfa': 'Two-step code', 'mfa.enroll': 'Set up two-step sign-in', 'mfa.reset': 'Reset two-step sign-in',
  'approval.requested': 'Asked for approval', 'approval.approved': 'Approved request', 'approval.rejected': 'Rejected request', 'approval.cancelled': 'Cancelled request',
  'report.view': 'Ran report', 'audit.verify': 'Verified audit log', 'audit.maintenance': 'Audit log maintenance', 'backup.run': 'Backup',
  'settings.testEmail': 'Sent test e-mail',
};

function describe(e) {
  const d = e.details || {};
  switch (e.action) {
    case 'user.enable': return d.enabled === undefined ? '' : d.enabled ? 'Enabled' : 'Disabled';
    case 'user.resetPassword': return [d.mustChange && 'must change at next sign-in', d.unlock && 'unlocked'].filter(Boolean).join(', ');
    case 'user.update': case 'group.update': return d.changed?.length ? `Changed: ${d.changed.join(', ')}` : 'No changes';
    case 'user.move': return d.to ? `→ ${ouLabel(parentDnOf(d.to))}` : '';
    case 'group.addMember': return d.member ? `Added ${d.member}` : '';
    case 'group.removeMember': return d.member ? `Removed ${d.member}` : '';
    case 'user.create': return [d.ou && `in ${ouLabel(d.ou)}`, d.groups?.length && `groups: ${d.groups.join(', ')}`].filter(Boolean).join('; ');
    case 'audit.export': return d.rows !== undefined ? `${d.rows} rows` : '';
    case 'settings.setup': case 'settings.update': return [d.server, d.baseDn, d.passwordChanged && 'service account password changed'].filter(Boolean).join(' · ');
    case 'settings.test': return d.server || d.baseDn || '';
    default: return '';
  }
}
const parentDnOf = (dn) => String(dn).replace(/^(?:\\.|[^,])*,/, '');

async function renderAudit(view) {
  const f = {
    q: h('input', { type: 'search', id: 'af-q', placeholder: 'Any text…' }),
    actor: h('input', { type: 'text', id: 'af-actor', placeholder: 'Username' }),
    action: h('select', { id: 'af-action' }, h('option', { value: '' }, 'All actions'), Object.entries(ACTION_LABELS).map(([k, v]) => h('option', { value: k }, v))),
    result: h('select', { id: 'af-result' }, h('option', { value: '' }, 'All results'), h('option', { value: 'success' }, 'Success'), h('option', { value: 'failure' }, 'Failure')),
    from: h('input', { type: 'date', id: 'af-from' }),
    to: h('input', { type: 'date', id: 'af-to' }),
  };
  const params = () => new URLSearchParams(Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value.trim()]).filter(([, v]) => v))).toString();
  const box = h('div', { class: 'card table-wrap' }, h('div', { class: 'loading' }, 'Loading…'));
  const count = h('span', { class: 'count' });
  const fld = (id, label, el) => h('div', { class: 'field' }, h('label', { for: id }, label), el);

  view.replaceChildren(
    h('div', { class: 'page-head' }, h('h2', {}, 'Audit log', count),
      h('div', { class: 'input-row' },
        h('button', {
          class: 'btn',
          async onclick(e) {
            e.target.disabled = true;
            try {
              const r = await api('GET', '/api/audit/verify');
              modal({
                title: 'Audit log integrity',
                body: r.ok
                  ? h('div', { class: 'success-box' }, `✓ Intact. ${r.sealed.toLocaleString()} sealed entries verified – nothing was changed or removed.`, r.unsealed ? h('div', { class: 'sub', style: 'margin-top:6px' }, `${r.unsealed} older entries were written before sealing was switched on and cannot be verified.`) : null)
                  : h('div', { class: 'error-box' }, h('b', {}, 'Problem found: '), r.problem, h('div', {}, `File ${r.file}, line ${r.line}${r.time ? ` (${fmtDate(r.time)})` : ''}.`)),
                actions: [{ label: 'Close', kind: 'primary' }],
              });
            } catch (ex) { toast(ex.message, 'error'); } finally { e.target.disabled = false; }
          },
        }, 'Verify integrity'),
        h('button', { class: 'btn', onclick: () => { window.location.href = `/api/audit.csv?${params()}`; } }, 'Export CSV'))),
    h('form', { class: 'audit-filters', onsubmit: (e) => { e.preventDefault(); load(); } },
      fld('af-q', 'Search', f.q), fld('af-actor', 'Done by', f.actor), fld('af-action', 'Action', f.action),
      fld('af-result', 'Result', f.result), fld('af-from', 'From', f.from), fld('af-to', 'To', f.to),
      h('button', { class: 'btn primary', type: 'submit' }, 'Apply')),
    box);

  async function load() {
    box.replaceChildren(h('div', { class: 'loading' }, 'Loading…'));
    let rows;
    try { rows = await api('GET', `/api/audit?${params()}`); } catch (e) { box.replaceChildren(h('div', { class: 'empty' }, e.message)); return; }
    count.textContent = rows.length >= 1000 ? 'latest 1000' : String(rows.length);
    if (!rows.length) { box.replaceChildren(h('div', { class: 'empty' }, 'No audit entries match these filters.')); return; }
    box.replaceChildren(h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Who'), h('th', {}, 'Action'), h('th', {}, 'Target'), h('th', {}, 'Result'), h('th', { class: 'hide-sm' }, 'Details'), h('th', { class: 'hide-sm' }, 'IP'))),
      h('tbody', {}, rows.map((e) => h('tr', {},
        h('td', { class: 'nowrap' }, fmtDate(e.time)),
        h('td', {}, h('div', {}, e.actor), e.role && h('div', { class: 'sub' }, e.role)),
        h('td', {}, ACTION_LABELS[e.action] || e.action),
        h('td', {}, e.target || '—'),
        h('td', {}, e.result === 'success' ? h('span', { class: 'badge ok' }, 'Success') : h('span', { class: 'badge danger' }, 'Failed')),
        h('td', { class: 'hide-sm' },
          h('div', {}, e.error || describe(e)),
          e.details && h('details', { class: 'raw' }, h('summary', {}, 'Full details'), h('pre', {}, JSON.stringify(e.details, null, 2)))),
        h('td', { class: 'hide-sm mono' }, e.ip))))));
  }
  load();
}

// ------------------------------------------------------------------ settings & first-run setup

const USERNAME_EXAMPLES = {
  'first.last': 'john.smith', firstlast: 'johnsmith', flast: 'jsmith', 'first.l': 'john.s', first: 'john', manual: 'typed by hand',
};
const ndn = (dn) => String(dn || '').toLowerCase().replace(/\s*,\s*/g, ',');
const under = (dn, ou) => ndn(dn) === ndn(ou) || ndn(dn).endsWith(',' + ndn(ou));

// Filterable checkbox / radio list
function pickList({ items, multiple = true, selected = [], allowNone = false, placeholder = 'Filter…', empty = 'Nothing to show', height = 220, missing = '(saved – not found)', alwaysFilter = false, onChange }) {
  const list = [...items];
  for (const v of selected) {
    if (v && !list.some((i) => ndn(i.value) === ndn(v))) list.unshift({ value: v, label: ouLabel(v) || v, sub: missing });
  }
  const sel = new Set(selected.map(ndn));
  // currently selected entries first, so they are visible without scrolling
  list.sort((a, b) => (sel.has(ndn(b.value)) ? 1 : 0) - (sel.has(ndn(a.value)) ? 1 : 0));
  if (allowNone) list.unshift({ value: '', label: '— None —' });
  const name = 'pl' + Math.random().toString(36).slice(2);
  const filter = h('input', { type: 'search', placeholder, style: 'margin-bottom:6px' });
  const box = h('div', { class: 'picker', style: `max-height:${height}px` });
  const rows = list.map((it) => {
    const inp = h('input', { type: multiple ? 'checkbox' : 'radio', name, checked: it.value ? sel.has(ndn(it.value)) : (allowNone && !selected.some(Boolean)) });
    inp.addEventListener('change', () => onChange?.(value()));
    const row = h('label', { class: 'check', 'data-k': `${it.label} ${it.sub || ''}`.toLowerCase() },
      inp, h('span', {}, it.label, it.sub ? h('span', { class: 'sub' }, ' ', it.sub) : null));
    return { it, inp, row };
  });
  box.append(...rows.map((r) => r.row));
  if (!rows.length) box.append(h('div', { class: 'sub' }, empty));
  const noMatch = h('div', { class: 'sub', hidden: true }, 'No matches.');
  box.append(noMatch);
  filter.addEventListener('input', () => {
    const q = filter.value.trim();
    let matched = 0;
    rows.forEach((r) => {
      const hit = !!r.it.value && matchesWords(r.row.getAttribute('data-k'), q);
      if (hit) matched++;
      r.row.hidden = !(!q || hit || !r.it.value || r.inp.checked); // keep None + current choices visible
    });
    noMatch.hidden = !q || matched > 0;
  });
  function value() {
    return multiple ? rows.filter((r) => r.inp.checked).map((r) => r.it.value) : (rows.find((r) => r.inp.checked)?.it.value || '');
  }
  return { el: h('div', {}, (alwaysFilter || list.length > 8) ? filter : null, box), value };
}

function readFile(file, as) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error('Could not read the file'));
    if (as === 'dataurl') r.readAsDataURL(file); else r.readAsText(file);
  });
}

async function renderSettingsForm(container, { mode, token, onSaved }) {
  const hdrs = token ? { 'X-Setup-Token': token } : {};
  container.replaceChildren(h('div', { class: 'loading' }, 'Loading settings…'));
  let data;
  try { data = await api('GET', '/api/settings', null, hdrs); } catch (e) { container.replaceChildren(h('div', { class: 'error-box' }, e.message)); return; }

  const s = data.settings;
  const m = { // working model
    branding: { orgName: s.branding?.orgName || '', logo: s.branding?.logo || '' },
    scope: { userOUs: [...(s.scope.userOUs || [])], groupOUs: [...(s.scope.groupOUs || [])] },
    roles: { adminGroup: s.roles.adminGroup || '', helpdeskGroup: s.roles.helpdeskGroup || '', helpdeskPermissions: [...(s.roles.helpdeskPermissions || data.defaultHelpdesk)] },
    provisioning: { ...s.provisioning, upnSuffixes: [...(s.provisioning.upnSuffixes || [])], defaultGroups: [...(s.provisioning.defaultGroups || [])] },
    security: { ...(s.security || {}), excludedOUs: [...(s.security?.excludedOUs || [])], ipAllowlist: [...(s.security?.ipAllowlist || [])] },
    notifications: { ...(s.notifications || {}), events: [...(s.notifications?.events || [])] },
    workflow: { leaverOU: s.workflow?.leaverOU || '', approvalActions: [...(s.workflow?.approvalActions || [])] },
    backup: { ...(s.backup || {}) },
  };
  let disc = null; // discovery result (OUs, groups, suffixes)

  const fld = (label, el, help, id) => h('div', { class: 'field' }, h('label', id ? { for: id } : {}, label), el, help && h('div', { class: 'help' }, help));
  const card = (num, title, desc, ...body) => h('section', { class: 'card card-pad set-card' },
    h('div', { class: 'set-head' }, h('span', { class: 'step-num' }, num), h('div', {}, h('h3', {}, title), desc && h('p', { class: 'sub' }, desc))),
    ...body);

  // ---- 1. Organization
  const orgName = h('input', { type: 'text', id: 'st-org', maxlength: 80, value: m.branding.orgName, placeholder: 'Your company name' });
  const logoPreview = h('div', { class: 'logo-preview' });
  const drawLogo = () => logoPreview.replaceChildren(m.branding.logo
    ? h('img', { src: m.branding.logo, alt: 'Company logo' })
    : h('div', { class: 'sub' }, 'No company logo – the Piersoft logo is shown.'));
  drawLogo();
  const logoFile = h('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,image/svg+xml', hidden: true });
  logoFile.addEventListener('change', async () => {
    const f = logoFile.files[0];
    if (!f) return;
    if (f.size > 300 * 1024) { toast('Logo must be smaller than 300 KB', 'error'); return; }
    m.branding.logo = await readFile(f, 'dataurl');
    drawLogo();
  });
  const sec1 = card('1', 'Organization', 'Shown on the sign-in page and in the menu.',
    h('div', { class: 'grid2' },
      fld('Organization name', orgName, null, 'st-org'),
      fld('Company logo', h('div', {}, logoPreview, h('div', { class: 'input-row' },
        logoFile,
        h('button', { class: 'btn small', type: 'button', onclick: () => logoFile.click() }, 'Upload logo'),
        h('button', { class: 'btn small', type: 'button', onclick: () => { m.branding.logo = ''; drawLogo(); } }, 'Remove'))),
      'PNG, JPG, WebP or SVG, max 300 KB')));

  // ---- 2. Connection
  const c = s.connection;
  const host = h('input', { type: 'text', id: 'st-host', value: c.host || '', placeholder: 'dc01.corp.local' });
  const port = h('input', { type: 'text', id: 'st-port', value: String(c.port || 636), inputmode: 'numeric' });
  const bindUser = h('input', { type: 'text', id: 'st-user', value: c.bindUser || '', placeholder: 'svc-adportal@corp.local', autocomplete: 'off' });
  const bindPw = h('input', { type: 'password', id: 'st-pass', autocomplete: 'new-password', placeholder: c.passwordSet ? 'Saved – leave blank to keep' : '' });
  const baseDn = h('input', { type: 'text', id: 'st-base', value: c.baseDn || '', placeholder: 'Detected automatically, e.g. DC=corp,DC=local' });
  const caPem = h('textarea', { id: 'st-ca', rows: 4, class: 'mono', placeholder: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----' }, c.caPem || '');
  const caFile = h('input', { type: 'file', accept: '.cer,.crt,.pem', hidden: true });
  caFile.addEventListener('change', async () => {
    const f = caFile.files[0];
    if (!f) return;
    const t = await readFile(f, 'text');
    if (!t.includes('-----BEGIN CERTIFICATE-----')) { toast('This certificate is in binary (DER) format. Export it again as "Base-64 encoded X.509 (.CER)".', 'error'); return; }
    caPem.value = t.trim();
  });
  const verify = h('input', { type: 'checkbox', checked: c.rejectUnauthorized !== false });
  const verifyWarn = h('div', { class: 'notice warn inline', hidden: verify.checked }, 'Certificate checking is off. Use this only for a first test – anyone on the network could impersonate your DC.');
  verify.addEventListener('change', () => { verifyWarn.hidden = verify.checked; });
  const testOut = h('div', {});
  const testBtn = h('button', { class: 'btn primary', type: 'button', onclick: () => testConnection() }, 'Test connection & load OUs');

  const conn = () => ({
    host: host.value.trim(), port: Number(port.value.trim() || 636), bindUser: bindUser.value.trim(), bindPassword: bindPw.value,
    baseDn: baseDn.value.trim(), caPem: caPem.value.trim(), rejectUnauthorized: verify.checked,
  });

  async function testConnection(silent) {
    testBtn.disabled = true; testBtn.textContent = 'Testing…';
    testOut.replaceChildren(h('div', { class: 'sub' }, 'Connecting to the domain controller…'));
    try {
      const r = await api('POST', '/api/settings/test', { connection: conn() }, hdrs);
      disc = r;
      if (!baseDn.value.trim()) baseDn.value = r.baseDn;
      const dropped = adoptDomain(r);
      testOut.replaceChildren(h('div', { class: 'success-box' }, h('ul', { class: 'steps' }, r.steps.map((x) => h('li', {}, '✓ ', x)),
        dropped.length ? h('li', {}, `ℹ Cleared ${dropped.length} earlier selection(s) that are not in ${r.domain}: ${dropped.map((d) => ouLabel(d) || d).join(', ')}`) : null)));
      drawDynamic();
    } catch (e) {
      testOut.replaceChildren(h('div', { class: 'error-box' }, e.message));
      if (!silent) toast('Connection test failed', 'error');
    } finally { testBtn.disabled = false; testBtn.textContent = 'Test connection & load OUs'; }
  }

  const sec2 = card('2', 'Connect to Active Directory',
    'The portal connects to a domain controller over LDAPS (port 636) with a service account that has delegated rights – not a Domain Admin.',
    state.mock && h('div', { class: 'notice warn inline' }, 'Demo mode uses sample data. You can still test a real connection here, but it will only be used when the portal runs normally (npm start).'),
    h('div', { class: 'grid3' },
      fld('Domain controller', host, 'Full DNS name, matching the DC certificate', 'st-host'),
      fld('LDAPS port', port, 'Normally 636 (3269 for Global Catalog)', 'st-port'),
      fld('Base DN', baseDn, 'Leave blank to detect', 'st-base')),
    h('div', { class: 'grid2' },
      fld('Service account', bindUser, 'user@domain or full DN', 'st-user'),
      fld('Service account password', bindPw, 'Stored encrypted on the server', 'st-pass')),
    fld('Root CA certificate (optional)', h('div', {}, caPem, h('div', { class: 'input-row', style: 'margin-top:6px' }, caFile,
      h('button', { class: 'btn small', type: 'button', onclick: () => caFile.click() }, 'Upload .cer / .pem'),
      h('button', { class: 'btn small', type: 'button', onclick: () => { caPem.value = ''; } }, 'Clear'))),
    "Needed when this server doesn't already trust your DC's certificate. Export your root CA as Base-64.", 'st-ca'),
    h('label', { class: 'check' }, verify, 'Verify the domain controller certificate (recommended)'),
    verifyWarn,
    h('div', { class: 'input-row', style: 'margin-top:10px' }, testBtn),
    testOut);

  // ---- dynamic sections (need discovery data)
  const sec3 = card('3', 'What the portal manages', 'Users and groups outside these OUs are hidden or read-only. Privileged accounts are always read-only.');
  const sec4 = card('4', 'Who can use the portal', 'Sign-in is allowed only for members of these AD groups (nested membership works).');
  const sec5 = card('5', 'New-user defaults', 'Pre-filled values on the New user form.');
  let pick = {};

  function ouItems() {
    return (disc?.ous || []).map((dn) => (disc.baseDn && ndn(dn) === ndn(disc.baseDn)
      ? { value: dn, label: `Entire domain (${disc.domain || dn})`, sub: '– all users and groups' }
      : { value: dn, label: ouLabel(dn) }));
  }
  function groupItems(filterOUs) {
    return (disc?.groups || []).filter((g) => !filterOUs || filterOUs.some((ou) => under(g.dn, ou)))
      .map((g) => ({ value: filterOUs ? g.sam : g.dn, label: g.sam, sub: g.description }));
  }
  const needTest = () => h('div', { class: 'notice info inline' }, state.mock ? 'Loading demo directory…' : 'Click "Test connection & load OUs" above to load the OUs and groups from your AD.');

  // After connecting to a (possibly different) domain, drop selections that don't
  // exist there - e.g. demo OUs or OUs from a previously configured domain.
  function adoptDomain(r) {
    flushPicks();
    const dropped = [];
    const keepDn = (dn) => { if (!dn) return true; const ok = under(dn, r.baseDn); if (!ok) dropped.push(dn); return ok; };
    m.scope.userOUs = m.scope.userOUs.filter(keepDn);
    m.scope.groupOUs = m.scope.groupOUs.filter(keepDn);
    if (!keepDn(m.roles.adminGroup)) m.roles.adminGroup = '';
    if (!keepDn(m.roles.helpdeskGroup)) m.roles.helpdeskGroup = '';
    if (!keepDn(m.provisioning.defaultUserOU)) m.provisioning.defaultUserOU = '';
    const sams = new Set(r.groups.map((g) => String(g.sam).toLowerCase()));
    m.provisioning.defaultGroups = m.provisioning.defaultGroups.filter((g) => { const ok = sams.has(g.toLowerCase()); if (!ok) dropped.push(g); return ok; });
    const suffixes = r.upnSuffixes.map((x) => x.toLowerCase());
    if (!m.provisioning.upnSuffix || !suffixes.includes(m.provisioning.upnSuffix.toLowerCase())) m.provisioning.upnSuffix = r.domain;
    m.provisioning.upnSuffixes = m.provisioning.upnSuffixes.filter((x) => suffixes.includes(x.toLowerCase()));
    // forget the old pickers so their stale values aren't read back
    pick = {}; extraSuffix = null; defOu.replaceChildren(); upnSel.replaceChildren();
    return dropped;
  }

  function flushPicks() {
    if (pick.excluded) m.security.excludedOUs = pick.excluded.value();
    if (pick.userOUs) m.scope.userOUs = pick.userOUs.value();
    if (pick.groupOUs) m.scope.groupOUs = pick.groupOUs.value();
    if (pick.admin) m.roles.adminGroup = pick.admin.value();
    if (pick.helpdesk) m.roles.helpdeskGroup = pick.helpdesk.value();
    if (pick.defaultGroups) m.provisioning.defaultGroups = pick.defaultGroups.value();
    if (extraSuffix) m.provisioning.upnSuffixes = extraSuffix.value();
    if (defOu.options.length) m.provisioning.defaultUserOU = defOu.value;
    if (upnSel.options.length && upnSel.value) m.provisioning.upnSuffix = upnSel.value;
  }

  function drawDynamic() {
    // capture current values before rebuilding
    if (pick.excluded) m.security.excludedOUs = pick.excluded.value();
    if (pick.userOUs) m.scope.userOUs = pick.userOUs.value();
    if (pick.groupOUs) m.scope.groupOUs = pick.groupOUs.value();
    if (pick.admin) m.roles.adminGroup = pick.admin.value();
    if (pick.helpdesk) m.roles.helpdeskGroup = pick.helpdesk.value();
    if (pick.defaultGroups) m.provisioning.defaultGroups = pick.defaultGroups.value();
    const head = (sec) => sec.firstChild;

    // 3. scope
    if (!disc) {
      sec3.replaceChildren(head(sec3), needTest());
    } else {
      pick.userOUs = pickList({ items: ouItems(), selected: m.scope.userOUs, placeholder: 'Filter OUs…', onChange: (v) => { m.scope.userOUs = v; drawDefaults(); } });
      pick.groupOUs = pickList({ items: ouItems(), selected: m.scope.groupOUs, placeholder: 'Filter OUs…', onChange: (v) => { m.scope.groupOUs = v; drawDefaults(); } });
      pick.excluded = pickList({ items: ouItems().filter((x) => !(disc.baseDn && ndn(x.value) === ndn(disc.baseDn))), selected: m.security.excludedOUs, placeholder: 'Filter OUs…', height: 180, onChange: (v) => { m.security.excludedOUs = v; } });
      sec3.replaceChildren(head(sec3), h('div', { class: 'grid2' },
        fld('User OUs (sub-OUs included)', pick.userOUs.el),
        fld('Group OUs (sub-OUs included)', pick.groupOUs.el)),
        fld('Excluded OUs – never managed, even inside the OUs above', pick.excluded.el, 'Use this for service accounts, admin accounts, servers or anything the portal must not touch (e.g. "Administration Accounts").'));
    }

    // 4. access
    const permBoxes = Object.entries(data.permissions).filter(([p]) => !data.adminOnly.includes(p)).map(([p, label]) => {
      const box = h('input', { type: 'checkbox', checked: m.roles.helpdeskPermissions.includes(p) });
      box.addEventListener('change', () => {
        m.roles.helpdeskPermissions = box.checked ? [...new Set([...m.roles.helpdeskPermissions, p])] : m.roles.helpdeskPermissions.filter((x) => x !== p);
      });
      return h('tr', {}, h('td', {}, label), h('td', { class: 'center' }, h('input', { type: 'checkbox', checked: true, disabled: true })), h('td', { class: 'center' }, box));
    });
    const matrix = h('table', { class: 'perm-table' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Permission'), h('th', { class: 'center' }, 'Admin'), h('th', { class: 'center' }, 'Helpdesk'))),
      h('tbody', {}, permBoxes,
        h('tr', {}, h('td', {}, data.permissions['settings.manage']), h('td', { class: 'center' }, h('input', { type: 'checkbox', checked: true, disabled: true })), h('td', { class: 'center sub' }, 'admin only'))));
    if (!disc) {
      sec4.replaceChildren(head(sec4), needTest(), h('div', { class: 'form-section' }, 'Role permissions'), matrix);
    } else {
      pick.admin = pickList({ items: groupItems(), multiple: false, selected: [m.roles.adminGroup], placeholder: 'Search groups…', height: 180 });
      pick.helpdesk = pickList({ items: groupItems(), multiple: false, allowNone: true, selected: [m.roles.helpdeskGroup], placeholder: 'Search groups…', height: 180 });
      sec4.replaceChildren(head(sec4),
        h('div', { class: 'grid2' },
          fld('Admin group (full access)', pick.admin.el, 'Tip: create a group such as "ADPortal-Admins".'),
          fld('Helpdesk group (optional)', pick.helpdesk.el, 'Tip: create a group such as "ADPortal-Helpdesk".')),
        h('div', { class: 'form-section' }, 'Role permissions'), matrix);
    }
    drawDefaults();
  }

  const upnSel = h('select', { id: 'st-upn' });
  const emailDomain = h('input', { type: 'text', id: 'st-mail', value: m.provisioning.emailDomain || '', placeholder: 'company.com (optional)' });
  const fmtSel = h('select', { id: 'st-fmt' }, data.usernameFormats.map((f) => h('option', { value: f, selected: m.provisioning.usernameFormat === f }, `${f}  (e.g. ${USERNAME_EXAMPLES[f]})`)));
  const defOu = h('select', { id: 'st-defou' });
  const mustChg = h('input', { type: 'checkbox', checked: m.provisioning.mustChangeDefault !== false });
  const enabledDef = h('input', { type: 'checkbox', checked: m.provisioning.enabledDefault !== false });
  const timeout = h('input', { type: 'text', id: 'st-timeout', inputmode: 'numeric', value: String(s.session?.timeoutMinutes || 30) });
  let extraSuffix = null;

  function drawDefaults() {
    if (pick.defaultGroups) m.provisioning.defaultGroups = pick.defaultGroups.value();
    if (extraSuffix) m.provisioning.upnSuffixes = extraSuffix.value();
    if (defOu.options.length) m.provisioning.defaultUserOU = defOu.value;
    if (upnSel.options.length) m.provisioning.upnSuffix = upnSel.value;

    const suffixes = [...new Set([m.provisioning.upnSuffix, ...(disc?.upnSuffixes || []), ...m.provisioning.upnSuffixes].filter(Boolean))];
    upnSel.replaceChildren(...suffixes.map((x) => h('option', { value: x, selected: x === m.provisioning.upnSuffix }, x)));
    if (!suffixes.length) upnSel.append(h('option', { value: '' }, 'Test the connection first'));
    extraSuffix = suffixes.length > 1
      ? pickList({ items: suffixes.map((x) => ({ value: x, label: x })), selected: m.provisioning.upnSuffixes, height: 120 })
      : null;

    const ous = (disc?.ous || []).filter((dn) => m.scope.userOUs.some((ou) => under(dn, ou)));
    defOu.replaceChildren(h('option', { value: '' }, '— First managed OU —'),
      ...ous.map((dn) => h('option', { value: dn, selected: ndn(dn) === ndn(m.provisioning.defaultUserOU) }, ouLabel(dn))));

    pick.defaultGroups = pickList({ items: groupItems(m.scope.groupOUs), selected: m.provisioning.defaultGroups, placeholder: 'Filter groups…', height: 160, empty: 'Select group OUs above first.', missing: '(not in the selected group OUs)' });

    sec5.replaceChildren(sec5.firstChild,
      h('div', { class: 'grid3' },
        fld('Default UPN suffix', upnSel, 'Sign-in name = username@suffix', 'st-upn'),
        fld('E-mail domain', emailDomain, 'Auto-fills e-mail as username@domain', 'st-mail'),
        fld('Username format', fmtSel, 'Suggested from first + last name', 'st-fmt')),
      h('div', { class: 'grid2' },
        fld('Default OU for new users', defOu, null, 'st-defou'),
        extraSuffix ? fld('UPN suffixes users may choose', extraSuffix.el) : h('div', {})),
      fld('Groups every new user is added to', pick.defaultGroups.el),
      h('label', { class: 'check' }, mustChg, 'New users must change password at first sign-in'),
      h('label', { class: 'check' }, enabledDef, 'New accounts are enabled immediately'));
    drawLeaver();
  }

  // ---- 6. Security
  const sec = m.security;
  const numIn = (id, v) => h('input', { type: 'text', id, inputmode: 'numeric', value: String(v ?? '') });
  const maxFails = numIn('st-maxfail', sec.maxFailuresPerUser ?? 2);
  const maxHours = numIn('st-maxhours', sec.sessionMaxHours ?? 8);
  const recheck = numIn('st-recheck', sec.roleRecheckMinutes ?? 5);
  const requireMfa = h('input', { type: 'checkbox', checked: !!sec.requireMfa });
  const reauth = h('input', { type: 'checkbox', checked: sec.reauthForSettings !== false });
  const ipList = h('textarea', { id: 'st-ips', rows: 3, class: 'mono', placeholder: 'One per line, e.g.\n10.0.4.0/24\n192.168.10.25' }, (sec.ipAllowlist || []).join('\n'));
  const syslogHost = h('input', { type: 'text', id: 'st-syslog', value: sec.syslogHost || '', placeholder: 'siem.company.local (optional)' });
  const syslogPort = numIn('st-syslogport', sec.syslogPort ?? 514);
  const syslogProto = h('select', { id: 'st-syslogproto' }, ['udp', 'tcp'].map((p) => h('option', { value: p, selected: (sec.syslogProtocol || 'udp') === p }, p.toUpperCase())));
  const eventLog = h('input', { type: 'checkbox', checked: !!sec.eventLog });
  const mfaWarn = h('div', { class: 'notice warn inline', hidden: !!sec.requireMfa || mode === 'setup' }, 'When you save with two-step sign-in switched on, everyone (including you) signs in again and sets up an authenticator app on first sign-in.');
  requireMfa.addEventListener('change', () => { mfaWarn.hidden = !requireMfa.checked || !!sec.requireMfa; });
  const mfaListBox = h('div', {});
  async function drawMfaList() {
    if (mode === 'setup') return;
    try {
      const list = await api('GET', '/api/mfa');
      mfaListBox.replaceChildren(
        h('div', { class: 'form-section' }, `Authenticator apps set up (${list.length})`),
        list.length ? h('ul', { class: 'list mfa-list' }, list.map((x) => h('li', {},
          h('span', { class: 'grow' }, h('b', {}, x.account), h('span', { class: 'sub' }, ` – since ${fmtDate(x.enrolledAt)}`)),
          h('button', {
            class: 'btn small', type: 'button',
            onclick: () => confirmAction({
              title: 'Reset two-step sign-in', confirmLabel: 'Reset', danger: true,
              message: `${x.account} will set up their authenticator app again at next sign-in (e.g. after losing a phone).`,
              run: async () => { await api('DELETE', `/api/mfa/${encodeURIComponent(x.account)}`); toast('Reset', 'success'); drawMfaList(); },
            }),
          }, 'Reset')))) : h('div', { class: 'sub' }, 'Nobody has set up an authenticator app yet.'));
    } catch { /* not allowed or not configured */ }
  }
  const sec6 = card('6', 'Security', 'Sign-in protection, sessions and where audit events are sent.',
    h('div', { class: 'grid3' },
      fld('Sign out after inactivity (minutes)', timeout, '5 – 480', 'st-timeout'),
      fld('Maximum session length (hours)', maxHours, 'Sign in again after this, even if active (1 – 24)', 'st-maxhours'),
      fld('Re-check group membership every (minutes)', recheck, 'Removed admins lose access within this time', 'st-recheck')),
    h('div', { class: 'grid3' },
      fld('Pause an account after failed sign-ins', maxFails, 'Keep this BELOW your AD lockout threshold so the portal can never lock people out', 'st-maxfail'),
      h('div', { style: 'grid-column: span 2' },
        h('label', { class: 'check' }, requireMfa, h('span', {}, h('b', {}, 'Require two-step sign-in'), ' (authenticator app code after the password)')),
        mfaWarn,
        h('label', { class: 'check' }, reauth, 'Ask for the admin\'s password again before saving Settings'))),
    fld('Allow access only from these IP addresses / ranges', ipList, 'Leave empty to allow any address. The server itself is always allowed. Saving refuses a list that would lock you out.', 'st-ips'),
    h('div', { class: 'form-section' }, 'Copy audit events to'),
    h('div', { class: 'grid3' },
      fld('Syslog / SIEM server', syslogHost, null, 'st-syslog'),
      fld('Port', syslogPort, null, 'st-syslogport'),
      fld('Protocol', syslogProto, null, 'st-syslogproto')),
    h('label', { class: 'check' }, eventLog, 'Also write audit events to the Windows Application event log (source "ADAdminPortal")'),
    mfaListBox);
  drawMfaList();

  // ---- 7. Notifications
  const nt = m.notifications;
  const ntEnabled = h('input', { type: 'checkbox', checked: !!nt.enabled });
  const smtpHost = h('input', { type: 'text', id: 'st-smtp', value: nt.smtpHost || '', placeholder: 'smtp.office365.com / mail.company.local' });
  const smtpPort = numIn('st-smtpport', nt.smtpPort ?? 587);
  const smtpSecure = h('input', { type: 'checkbox', checked: !!nt.smtpSecure });
  const smtpUser = h('input', { type: 'text', id: 'st-smtpuser', value: nt.smtpUser || '', autocomplete: 'off', placeholder: 'optional' });
  const smtpPass = h('input', { type: 'password', id: 'st-smtppass', autocomplete: 'new-password', placeholder: nt.smtpPasswordSet ? 'Saved – leave blank to keep' : 'optional' });
  const mailFrom = h('input', { type: 'email', id: 'st-from', value: nt.from || '', placeholder: 'adportal@company.com' });
  const itMailbox = h('input', { type: 'email', id: 'st-itmail', value: nt.itMailbox || '', placeholder: 'it-team@company.com' });
  const notifyMgr = h('input', { type: 'checkbox', checked: nt.notifyManager !== false });
  const EVENTS = [['user.create', 'Account created'], ['user.resetPassword', 'Password reset'], ['user.unlock', 'Account unlocked'], ['user.enable', 'Enabled / disabled'], ['user.offboard', 'Leaver offboarded'], ['user.delete', 'Account deleted'], ['group.addMember', 'Added to group'], ['group.removeMember', 'Removed from group'], ['approval.requested', 'Approval needed']];
  const evBoxes = EVENTS.map(([k, label]) => ({ k, box: h('input', { type: 'checkbox', checked: nt.events.includes(k) }), label }));
  const ntFields = () => ({
    enabled: ntEnabled.checked, smtpHost: smtpHost.value.trim(), smtpPort: Number(smtpPort.value.trim() || 587), smtpSecure: smtpSecure.checked,
    smtpUser: smtpUser.value.trim(), smtpPassword: smtpPass.value, from: mailFrom.value.trim(), itMailbox: itMailbox.value.trim(),
    notifyManager: notifyMgr.checked, events: evBoxes.filter((x) => x.box.checked).map((x) => x.k),
  });
  const testMail = h('button', {
    class: 'btn small', type: 'button',
    async onclick() {
      testMail.disabled = true;
      try { await api('POST', '/api/settings/test-email', { notifications: ntFields() }); toast(`Test e-mail sent to ${itMailbox.value}`, 'success'); } catch (e) { toast(e.message, 'error'); } finally { testMail.disabled = false; }
    },
  }, 'Send test e-mail');
  const sec7 = card('7', 'E-mail notifications', 'Tell the IT mailbox (and the user\'s manager) when accounts change. Passwords are never e-mailed.',
    h('label', { class: 'check' }, ntEnabled, h('b', {}, 'Send notification e-mails')),
    h('div', { class: 'grid3' },
      fld('SMTP server', smtpHost, null, 'st-smtp'),
      fld('Port', smtpPort, '587 = STARTTLS, 465 = TLS, 25 = relay', 'st-smtpport'),
      h('div', { class: 'field' }, h('label', {}, ' '), h('label', { class: 'check' }, smtpSecure, 'Use TLS from the start (port 465)'))),
    h('div', { class: 'grid2' },
      fld('SMTP user', smtpUser, null, 'st-smtpuser'),
      fld('SMTP password', smtpPass, 'Stored encrypted', 'st-smtppass')),
    h('div', { class: 'grid2' },
      fld('From address', mailFrom, null, 'st-from'),
      fld('IT mailbox (receives every notification)', itMailbox, null, 'st-itmail')),
    h('label', { class: 'check' }, notifyMgr, 'Also e-mail the user\'s manager (when a manager is set in AD)'),
    h('div', { class: 'form-section' }, 'Send an e-mail when'),
    h('div', { class: 'grid3' }, evBoxes.map((x) => h('label', { class: 'check' }, x.box, x.label))),
    mode === 'setup' ? null : h('div', { class: 'input-row' }, testMail));

  // ---- 8. Workflow
  const leaverSel = h('select', { id: 'st-leaver' });
  const APPROVALS = [['user.delete', 'Delete a user'], ['group.delete', 'Delete a group'], ['user.offboard', 'Offboard a leaver'], ['user.move', 'Move a user to another OU'], ['group.addMember', 'Add someone to a group']];
  const apBoxes = APPROVALS.map(([k, label]) => ({ k, box: h('input', { type: 'checkbox', checked: m.workflow.approvalActions.includes(k) }), label }));
  function drawLeaver() {
    if (leaverSel.options.length) m.workflow.leaverOU = leaverSel.value;
    const ous = (disc?.ous || []).filter((dn) => m.scope.userOUs.some((ou) => under(dn, ou)) && !(disc.baseDn && ndn(dn) === ndn(disc.baseDn)));
    if (m.workflow.leaverOU && !ous.some((dn) => ndn(dn) === ndn(m.workflow.leaverOU))) ous.unshift(m.workflow.leaverOU);
    leaverSel.replaceChildren(h('option', { value: '' }, '— Keep in current OU —'),
      ...ous.map((dn) => h('option', { value: dn, selected: ndn(dn) === ndn(m.workflow.leaverOU) }, ouLabel(dn))));
  }
  const sec8 = card('8', 'Workflow', 'Leaver handling and four-eyes approval for risky actions.',
    h('div', { class: 'grid2' },
      fld('Leavers OU (Offboard moves accounts here)', leaverSel, 'e.g. "Disabled Users"', 'st-leaver'),
      h('div', {})),
    h('div', { class: 'form-section' }, 'Need approval by a second admin'),
    h('div', { class: 'grid3' }, apBoxes.map((x) => h('label', { class: 'check' }, x.box, x.label))),
    h('div', { class: 'help' }, 'The request appears under Approvals; a different admin must approve it before it runs.'));

  // ---- 9. Backup
  const bk = m.backup;
  const bkEnabled = h('input', { type: 'checkbox', checked: !!bk.enabled });
  const bkFolder = h('input', { type: 'text', id: 'st-bkfolder', value: bk.folder || '', placeholder: 'D:\\Backups\\ADPortal  or  \\\\fileserver\\backups\\ADPortal' });
  const bkKeep = numIn('st-bkkeep', bk.keep ?? 14);
  const bkStatus = h('div', { class: 'sub' });
  const bkNow = h('button', {
    class: 'btn small', type: 'button',
    async onclick() {
      bkNow.disabled = true;
      try { const r = await api('POST', '/api/settings/backup'); toast(`Backup saved to ${r.dest}`, 'success'); drawBkStatus(); } catch (e) { toast(e.message, 'error'); } finally { bkNow.disabled = false; }
    },
  }, 'Back up now');
  async function drawBkStatus() {
    if (mode === 'setup') return;
    try {
      const r = await api('GET', '/api/settings/backup');
      bkStatus.textContent = r.at ? `Last backup: ${fmtDate(r.at)} – ${r.ok ? r.dest : 'FAILED: ' + r.error}` : 'No backup yet.';
    } catch { /* ignore */ }
  }
  const sec9 = card('9', 'Backup', 'Daily copy of the settings and the audit trail.',
    h('label', { class: 'check' }, bkEnabled, h('b', {}, 'Back up every day')),
    h('div', { class: 'grid2' },
      fld('Backup folder (local or network share)', bkFolder, 'The portal\'s service account needs write access to it.', 'st-bkfolder'),
      fld('Keep the newest', bkKeep, 'backups (older ones are deleted)', 'st-bkkeep')),
    mode === 'setup' ? null : h('div', { class: 'input-row', style: 'align-items:center' }, bkNow, bkStatus),
    h('div', { class: 'help' }, 'Note: the encryption key is tied to this server (Windows DPAPI). When restoring on another server, re-enter the service-account password in Settings.'));
  drawBkStatus();

  const collectExtras = () => {
    if (pick.excluded) m.security.excludedOUs = pick.excluded.value();
    drawLeaver();
    return {
      security: {
        maxFailuresPerUser: Number(maxFails.value.trim()), sessionMaxHours: Number(maxHours.value.trim()), roleRecheckMinutes: Number(recheck.value.trim()),
        requireMfa: requireMfa.checked, reauthForSettings: reauth.checked,
        ipAllowlist: ipList.value.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean),
        excludedOUs: m.security.excludedOUs,
        syslogHost: syslogHost.value.trim(), syslogPort: Number(syslogPort.value.trim() || 514), syslogProtocol: syslogProto.value, eventLog: eventLog.checked,
      },
      notifications: ntFields(),
      workflow: { leaverOU: m.workflow.leaverOU, approvalActions: apBoxes.filter((x) => x.box.checked).map((x) => x.k) },
      backup: { enabled: bkEnabled.checked, folder: bkFolder.value.trim(), keep: Number(bkKeep.value.trim() || 14) },
    };
  };

  // Ask for the current password before saving (Settings → Security)
  const askPassword = () => new Promise((resolve) => {
    const pw = h('input', { type: 'password', autocomplete: 'current-password' });
    modal({
      title: 'Confirm it\'s you',
      body: h('div', {}, h('p', { style: 'margin-top:0' }, `Enter the password for ${state.me.sam} to save the settings.`), h('div', { class: 'field' }, pw)),
      actions: [{ label: 'Cancel', run: (ctx) => { ctx.close(); resolve(null); } }, { label: 'Save', kind: 'primary', run: (ctx) => { ctx.close(); resolve(pw.value); } }],
    }).then((v) => { if (v === null) resolve(null); });
    setTimeout(() => pw.focus(), 50);
    pw.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); pw.closest('.modal').querySelector('.modal-foot .btn.primary').click(); } });
  });

  // ---- save
  const saveErr = h('div', { class: 'error-box', hidden: true });
  const saveBtn = h('button', { class: 'btn primary', type: 'button' }, mode === 'setup' ? 'Finish setup' : 'Save settings');
  saveBtn.addEventListener('click', async () => {
    saveErr.hidden = true;
    drawDefaults(); // flush pickers into the model
    if (pick.userOUs) m.scope.userOUs = pick.userOUs.value();
    if (pick.groupOUs) m.scope.groupOUs = pick.groupOUs.value();
    if (pick.admin) m.roles.adminGroup = pick.admin.value();
    if (pick.helpdesk) m.roles.helpdeskGroup = pick.helpdesk.value();
    const settings = {
      branding: { orgName: orgName.value.trim(), logo: m.branding.logo },
      connection: conn(),
      scope: m.scope,
      roles: m.roles,
      provisioning: { ...m.provisioning, emailDomain: emailDomain.value.trim(), usernameFormat: fmtSel.value, mustChangeDefault: mustChg.checked, enabledDefault: enabledDef.checked },
      session: { timeoutMinutes: Number(timeout.value.trim()) },
      ...collectExtras(),
    };
    let currentPassword;
    if (mode !== 'setup' && state.me?.reauthForSettings) {
      currentPassword = await askPassword();
      if (currentPassword === null) return;
    }
    saveBtn.disabled = true; saveBtn.textContent = 'Checking & saving…';
    try {
      const r = await api('POST', '/api/settings', { settings, currentPassword }, hdrs);
      onSaved?.(r);
    } catch (e) {
      saveErr.textContent = e.message; saveErr.hidden = false;
    } finally { saveBtn.disabled = false; saveBtn.textContent = mode === 'setup' ? 'Finish setup' : 'Save settings'; }
  });

  container.replaceChildren(...[
    data.source === 'env' && h('div', { class: 'notice info', style: 'margin:0' }, 'These settings currently come from the .env file. Saving here stores them in data/settings.json, which then takes priority.'),
    data.source === 'demo-draft' && h('div', { class: 'notice warn', style: 'margin:0' }, 'Pre-filled from the settings you entered in demo mode. Review every section (especially the admin and helpdesk groups), then click Finish setup.'),
    sec1, sec2, sec3, sec4, sec5, sec6, sec7, sec8, sec9,
    h('div', { class: 'save-bar card' }, saveErr, h('div', { class: 'save-row' },
      h('span', { class: 'sub' }, state.mock ? 'Demo mode: organization, permissions and new-user defaults are applied. AD settings are saved for later.' : 'The connection, OUs and groups are verified against AD before saving.'),
      saveBtn)),
  ].filter(Boolean));
  drawDynamic();

  // Pre-load discovery so the pickers are filled
  if (state.mock && data.configured) {
    try {
      const [ous, groups] = await Promise.all([api('GET', '/api/ous'), api('GET', '/api/groups?q=')]);
      disc = {
        ous: [...new Set([...ous.userOUs, ...ous.groupOUs].map((o) => o.dn))],
        groups: groups.items.map((g) => ({ dn: g.dn, sam: g.sam, description: g.description })),
        upnSuffixes: ['corp.local', 'example.com'],
      };
      if (!m.scope.userOUs.length) m.scope.userOUs = ous.userOUs.slice(0, 1).map((o) => o.dn);
      if (!m.scope.groupOUs.length) m.scope.groupOUs = ous.groupOUs.slice(0, 1).map((o) => o.dn);
      drawDynamic();
    } catch { /* ignore */ }
  } else if (c.host && c.passwordSet) {
    testConnection(true);
  }
}

async function renderSettingsPage(view) {
  const body = h('div', { class: 'settings-wrap' });
  view.replaceChildren(h('div', { class: 'page-head' }, h('h2', {}, 'Settings')), body);
  renderSettingsForm(body, {
    mode: 'settings',
    async onSaved() {
      toast('Settings saved', 'success');
      await loadInfo();
      state.me = await api('GET', '/api/me');
      state.ous = null; state.allGroups = null; state.users = null; state.groups = null;
      renderShell();
      route();
    },
  });
}

function renderSetup() {
  const app = document.getElementById('app');
  const tokenIn = h('input', { type: 'text', id: 'setup-token', autocomplete: 'off', placeholder: 'Paste the setup token', class: 'mono' });
  const err = h('div', { class: 'error-box', hidden: true });
  const go = h('button', { class: 'btn primary', type: 'submit' }, 'Continue');
  const body = h('div', { class: 'settings-wrap' });

  const page = h('div', { class: 'setup-page' },
    h('header', { class: 'setup-top' }, h('div', { class: 'brand-box' }, brandMark()), h('div', {}, h('b', {}, `${productName()} – first-time setup`), h('div', { class: 'sub' }, 'Connect the portal to your Active Directory'))),
    h('div', { class: 'setup-body' },
      h('form', {
        class: 'card card-pad setup-token',
        async onsubmit(e) {
          e.preventDefault();
          err.hidden = true; go.disabled = true;
          const token = tokenIn.value.trim();
          try {
            await api('GET', '/api/settings', null, { 'X-Setup-Token': token });
            e.target.remove();
            renderSettingsForm(body, {
              mode: 'setup',
              token,
              async onSaved() {
                await loadInfo();
                body.replaceChildren(h('div', { class: 'card card-pad setup-done' },
                  h('div', { class: 'big-check' }, '✓'),
                  h('h2', {}, 'Setup complete'),
                  h('p', {}, 'Sign in with a domain account that is a member of the admin group you selected. You can change everything later under Settings.'),
                  h('button', { class: 'btn primary', onclick: () => { location.hash = '#/users'; boot(); } }, 'Go to sign-in')));
                window.scrollTo({ top: 0 });
              },
            });
          } catch (ex) { err.textContent = ex.message; err.hidden = false; } finally { go.disabled = false; }
        },
      },
      h('h2', {}, 'Welcome'),
      h('p', {}, 'To protect this page, enter the one-time setup token. It is shown in the server console when the portal starts, and saved in ', h('code', {}, 'data/setup-token.txt'), ' on the server.'),
      err,
      h('div', { class: 'field' }, h('label', { for: 'setup-token' }, 'Setup token'), tokenIn),
      h('div', { class: 'form-actions' }, go),
      h('div', { class: 'checklist' },
        h('b', {}, 'Before you start, have ready:'),
        h('ul', {},
          h('li', {}, 'The DNS name of a domain controller with LDAPS (port 636) enabled'),
          h('li', {}, 'A service account with delegated rights on your user and group OUs (see setup/Setup-ADPortalDelegation.ps1)'),
          h('li', {}, 'Two AD groups for portal access, e.g. ADPortal-Admins and ADPortal-Helpdesk'),
          h('li', {}, "Your root CA certificate (Base-64) if this server doesn't trust the DC certificate")))),
      body),
    poweredBy());
  app.replaceChildren(page);
  setTimeout(() => tokenIn.focus(), 30);
}

boot();
