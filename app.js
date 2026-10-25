'use strict';
// Finora: single-user budget app. All data is encrypted on the device with a
// key derived from the passphrase; only ciphertext is stored locally or on GitHub.
// DOM is only ever written with textContent / element APIs, never innerHTML.

(() => {
  if (window.top !== window.self) { document.documentElement.textContent = ''; return; } // no framing

  const KDF_ITER = 600000;
  const LOCK_AFTER_MS = 5 * 60 * 1000;
  const DATA_PATH = 'finora.json';
  const LS_VAULT = 'finora.vault';
  const LS_CFG = 'finora.cfg';
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const $ = (id) => document.getElementById(id);

  // ---------- crypto ----------
  // Chunked so large vaults don't exceed the engine's argument limit.
  const b64 = (buf) => {
    const a = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode(...a.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveKey(pass, salt, iter) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function seal(obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, S.key, enc.encode(JSON.stringify(obj)));
    return JSON.stringify({ v: 1, kdf: 'PBKDF2-SHA256', iter: S.iter, salt: b64(S.salt), iv: b64(iv), ct: b64(ct) });
  }

  // Opens a sealed blob. Derives a new key if the blob uses a different salt
  // (e.g. it was created on another device) and returns that key with the data.
  async function open(text, pass) {
    const box = JSON.parse(text);
    if (box.v !== 1 || box.kdf !== 'PBKDF2-SHA256') throw new Error('Unknown format');
    const iter = Number(box.iter);
    if (!Number.isInteger(iter) || iter < KDF_ITER || iter > 10000000) throw new Error('Bad KDF settings');
    const salt = unb64(box.salt);
    const sameKey = S.key && S.salt && b64(S.salt) === box.salt && S.iter === iter;
    const key = sameKey ? S.key : await deriveKey(pass, salt, iter);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct));
    return { data: JSON.parse(dec.decode(pt)), key, salt, iter };
  }

  // ---------- state ----------
  // S.data.items: { [id]: item }, each item has id, type, updatedAt and may be
  // a tombstone ({deleted:true}) so deletes sync across devices.
  const S = { key: null, salt: null, iter: KDF_ITER, pass: null, data: null, cfg: null, month: null, syncing: false, again: false };

  const emptyData = () => ({ v: 1, currency: 'EUR', currencyAt: 0, items: {} });
  const uid = () => b64(crypto.getRandomValues(new Uint8Array(12))).replace(/[+/=]/g, (c) => ({ '+': '-', '/': '_', '=': '' }[c]));
  const live = (type) => Object.values(S.data.items).filter((i) => !i.deleted && i.type === type);

  function put(item) {
    item.updatedAt = Date.now();
    S.data.items[item.id] = item;
    persist();
  }
  function remove(id) {
    S.data.items[id] = { id, deleted: true, updatedAt: Date.now() };
    persist();
  }

  async function persist() {
    try {
      localStorage.setItem(LS_VAULT, await seal(S.data));
      render();
      scheduleSync();
    } catch (e) { toast('Could not save: ' + e.message); }
  }

  async function saveCfg() { localStorage.setItem(LS_CFG, await seal(S.cfg)); }

  // ---------- validation ----------
  const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
  function toCents(s) {
    const m = /^(\d{1,9})(?:[.,](\d{1,2}))?$/.exec(String(s).trim());
    if (!m) return null;
    return Number(m[1]) * 100 + Number((m[2] || '0').padEnd(2, '0'));
  }
  const isDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + 'T00:00:00Z'));

  function validItem(i) {
    if (!i || typeof i !== 'object' || typeof i.id !== 'string' || !/^[A-Za-z0-9_-]{1,40}$/.test(i.id)) return false;
    if (!Number.isFinite(i.updatedAt)) return false;
    if (i.deleted) return true;
    if (!Number.isInteger(i.amount) || i.amount < 0 || i.amount > 1e11) return false;
    if (typeof i.category !== 'string' || i.category.length > 40) return false;
    if (i.type === 'budget') return true;
    if (!['income', 'expense'].includes(i.kind) || !isDate(i.date)) return false;
    if (typeof i.note !== 'string' || i.note.length > 100) return false;
    if (i.type === 'tx') return true;
    if (i.type === 'rec') return ['weekly', 'monthly'].includes(i.freq) && (i.end == null || isDate(i.end));
    return false;
  }
  function sanitize(d) {
    const out = emptyData();
    if (d && typeof d === 'object') {
      if (/^[A-Z]{3}$/.test(d.currency)) { out.currency = d.currency; out.currencyAt = Number(d.currencyAt) || 0; }
      for (const i of Object.values(d.items || {})) if (validItem(i)) out.items[i.id] = i;
    }
    return out;
  }

  // Newest edit per item wins.
  function merge(a, b) {
    const out = { ...a, items: { ...a.items } };
    for (const [id, item] of Object.entries(b.items)) {
      if (!out.items[id] || out.items[id].updatedAt < item.updatedAt) out.items[id] = item;
    }
    if (b.currencyAt > a.currencyAt) { out.currency = b.currency; out.currencyAt = b.currencyAt; }
    return out;
  }

  // ---------- GitHub sync ----------
  async function gh(method, body) {
    const [owner, repo] = S.cfg.repo.split('/');
    const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${DATA_PATH}`;
    const res = await fetch(url, {
      method,
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${S.cfg.token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    return res;
  }

  let syncTimer = null;
  function scheduleSync() {
    if (!S.cfg?.token) return;
    clearTimeout(syncTimer);
    syncTimer = setTimeout(sync, 1500);
  }

  async function sync() {
    if (!S.cfg?.token || !S.cfg?.repo) return;
    if (S.syncing) { S.again = true; return; } // run once more when the current sync ends
    S.syncing = true;
    status('Syncing…');
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        const res = await gh('GET');
        let sha;
        if (res.status === 200) {
          const file = await res.json();
          sha = file.sha;
          const remote = await open(atob(file.content.replace(/\n/g, '')), S.pass);
          // Adopt the remote key so all devices converge on one salt.
          if (remote.key !== S.key) { S.key = remote.key; S.salt = remote.salt; S.iter = remote.iter; await saveCfg(); }
          S.data = merge(S.data, sanitize(remote.data));
        } else if (res.status !== 404) {
          throw new Error(res.status === 401 ? 'token rejected' : `GitHub error ${res.status}`);
        }
        const content = btoa(await seal(S.data));
        const w = await gh('PUT', { message: 'update', content, ...(sha ? { sha } : {}) });
        if (w.status === 200 || w.status === 201) {
          localStorage.setItem(LS_VAULT, await seal(S.data));
          S.cfg.lastSync = Date.now();
          await saveCfg();
          status('Synced ' + new Date(S.cfg.lastSync).toLocaleString());
          render();
          return;
        }
        if (w.status !== 409 && w.status !== 422) throw new Error(`GitHub error ${w.status}`);
        // Someone else wrote in between: loop, re-merge and retry.
      }
      throw new Error('conflict, try again');
    } catch (e) {
      status('Sync failed: ' + (e.name === 'OperationError' ? 'remote data uses a different passphrase' : e.message));
    } finally {
      S.syncing = false;
      if (S.again) { S.again = false; sync(); }
    }
  }

  // ---------- money / dates ----------
  const money = (c) => new Intl.NumberFormat(undefined, { style: 'currency', currency: S.data.currency }).format(c / 100);
  const ym = (d) => d.slice(0, 7);
  const today = () => new Date().toLocaleDateString('sv-SE'); // YYYY-MM-DD in local time
  const daysIn = (y, m) => new Date(Date.UTC(y, m, 0)).getUTCDate();

  // All dates in the month on which a recurring item falls.
  function occurrences(r, month) {
    const [y, m] = month.split('-').map(Number);
    const first = `${month}-01`, last = `${month}-${String(daysIn(y, m)).padStart(2, '0')}`;
    if (r.date > last || (r.end && r.end < first)) return [];
    const out = [];
    if (r.freq === 'monthly') {
      const day = Math.min(Number(r.date.slice(8)), daysIn(y, m));
      out.push(`${month}-${String(day).padStart(2, '0')}`);
    } else {
      const start = Date.parse(r.date + 'T00:00:00Z');
      let t = Math.max(start, Date.parse(first + 'T00:00:00Z'));
      const off = ((t - start) / 864e5) % 7;
      if (off) t += (7 - off) * 864e5;
      for (; t <= Date.parse(last + 'T00:00:00Z'); t += 7 * 864e5) out.push(new Date(t).toISOString().slice(0, 10));
    }
    return out.filter((d) => d >= r.date && (!r.end || d <= r.end));
  }

  function monthEntries(month) {
    const list = live('tx').filter((t) => ym(t.date) === month).map((t) => ({ ...t, recurring: false }));
    for (const r of live('rec')) for (const d of occurrences(r, month)) list.push({ ...r, date: d, recurring: true });
    return list.sort((a, b) => b.date.localeCompare(a.date));
  }

  // ---------- rendering ----------
  function el(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
    }
    for (const k of kids) n.append(k);
    return n;
  }
  const empty = (text) => el('li', { class: 'muted', text });

  function render() {
    if (!S.data) return;
    const month = S.month;
    const [y, m] = month.split('-').map(Number);
    $('month-title').textContent = new Date(y, m - 1, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });

    const entries = monthEntries(month);
    const inn = entries.filter((e) => e.kind === 'income').reduce((s, e) => s + e.amount, 0);
    const out = entries.filter((e) => e.kind === 'expense').reduce((s, e) => s + e.amount, 0);
    $('sum-in').textContent = money(inn);
    $('sum-out').textContent = money(out);
    $('sum-net').textContent = money(inn - out);
    $('sum-net').className = inn - out < 0 ? 'neg' : 'pos';

    const spent = new Map();
    for (const e of entries) if (e.kind === 'expense') spent.set(e.category, (spent.get(e.category) || 0) + e.amount);
    const budgets = live('budget').sort((a, b) => a.category.localeCompare(b.category));
    $('budget-progress').replaceChildren(...(budgets.length ? budgets.map((b) => {
      const s = spent.get(b.category) || 0;
      const pct = b.amount ? Math.min(100, Math.round((s / b.amount) * 100)) : 100;
      return el('li', { class: 'budget' },
        el('div', { class: 'row-between' }, el('span', { text: b.category }), el('span', { class: s > b.amount ? 'neg' : '', text: `${money(s)} / ${money(b.amount)}` })),
        el('progress', { max: '100', value: String(pct), class: s > b.amount ? 'over' : '' }));
    }) : [empty('No budgets yet. Add them in Budgets.')]));

    $('tx-list').replaceChildren(...(entries.length ? entries.map((e) => el('li', { class: 'row-between' },
      el('div', {}, el('div', { text: e.category + (e.recurring ? ' ↻' : '') }), el('small', { class: 'muted', text: e.date + (e.note ? ' · ' + e.note : '') })),
      el('div', { class: 'right' },
        el('b', { class: e.kind === 'income' ? 'pos' : 'neg', text: (e.kind === 'income' ? '+' : '−') + money(e.amount) }),
        e.recurring ? '' : el('button', { class: 'link', 'aria-label': 'Delete', text: '✕', onclick: () => confirm('Delete this entry?') && remove(e.id) }))))
      : [empty('Nothing this month.')]));

    $('rec-list').replaceChildren(...(live('rec').length ? live('rec').sort((a, b) => a.category.localeCompare(b.category)).map((r) => el('li', { class: 'row-between' },
      el('div', {}, el('div', { text: `${r.category} · ${r.freq}` }), el('small', { class: 'muted', text: `from ${r.date}` + (r.end ? ` to ${r.end}` : '') + (r.note ? ' · ' + r.note : '') })),
      el('div', { class: 'right' },
        el('b', { class: r.kind === 'income' ? 'pos' : 'neg', text: money(r.amount) }),
        r.end ? '' : el('button', { class: 'link', text: 'Stop', onclick: () => { if (confirm('Stop from today? Past months keep it.')) put({ ...r, end: today() }); } }),
        el('button', { class: 'link', 'aria-label': 'Delete', text: '✕', onclick: () => confirm('Delete everywhere, including past months?') && remove(r.id) }))))
      : [empty('No recurring items. Add one and pick "Every week" or "Every month".')]));

    $('budget-list').replaceChildren(...budgets.map((b) => el('li', { class: 'row-between' },
      el('span', { text: b.category }),
      el('div', { class: 'right' }, el('b', { text: money(b.amount) }), el('button', { class: 'link', 'aria-label': 'Delete', text: '✕', onclick: () => remove(b.id) })))));

    const cats = new Set([...live('tx'), ...live('rec'), ...live('budget')].map((i) => i.category));
    $('cats').replaceChildren(...[...cats].sort().map((c) => el('option', { value: c })));
    $('currency-form').currency.value = S.data.currency;
    $('sync-form').repo.value = S.cfg.repo || '';
    if (!S.syncing) status(S.cfg.token ? (S.cfg.lastSync ? 'Last synced ' + new Date(S.cfg.lastSync).toLocaleString() : 'Not synced yet') : 'Sync is off. Only this device has your data.');
  }

  const status = (t) => { $('sync-status').textContent = t; };
  const toast = (t) => { $('add-msg').textContent = t; };

  // ---------- lock / unlock ----------
  async function unlock(e) {
    e.preventDefault();
    const pass = $('pass').value;
    const isNew = !localStorage.getItem(LS_VAULT);
    $('lock-err').textContent = '';
    if (pass.length < 12) { $('lock-err').textContent = 'Use at least 12 characters.'; return; }
    if (isNew && pass !== $('pass2').value) { $('lock-err').textContent = 'Passphrases do not match.'; return; }
    $('lock-btn').disabled = true;
    $('lock-btn').textContent = 'Working…';
    try {
      S.pass = pass;
      if (isNew) {
        S.salt = crypto.getRandomValues(new Uint8Array(16));
        S.key = await deriveKey(pass, S.salt, S.iter);
        S.data = emptyData();
        S.cfg = {};
        await saveCfg();
        localStorage.setItem(LS_VAULT, await seal(S.data));
      } else {
        const v = await open(localStorage.getItem(LS_VAULT), pass);
        Object.assign(S, { key: v.key, salt: v.salt, iter: v.iter, data: sanitize(v.data) });
        const cfgText = localStorage.getItem(LS_CFG);
        S.cfg = cfgText ? (await open(cfgText, pass)).data : {};
      }
      $('pass').value = $('pass2').value = '';
      $('lock').hidden = true;
      $('app').hidden = false;
      S.month = ym(today());
      $('add-form').date.value = today();
      render();
      sync();
      armLock();
    } catch {
      S.pass = S.key = null;
      $('lock-err').textContent = 'Wrong passphrase.';
      await new Promise((r) => setTimeout(r, 1000));
    } finally {
      $('lock-btn').disabled = false;
      $('lock-btn').textContent = isNew ? 'Create' : 'Unlock';
    }
  }

  // Reloading drops the key, passphrase and decrypted data from memory.
  const lock = () => location.reload();

  let lockTimer = null, hiddenAt = 0;
  function armLock() {
    const reset = () => { clearTimeout(lockTimer); lockTimer = setTimeout(lock, LOCK_AFTER_MS); };
    ['pointerdown', 'keydown', 'touchstart'].forEach((ev) => document.addEventListener(ev, reset, { passive: true }));
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) hiddenAt = Date.now();
      else if (Date.now() - hiddenAt > LOCK_AFTER_MS) lock();
      else sync();
    });
    reset();
  }

  function showLock() {
    const isNew = !localStorage.getItem(LS_VAULT);
    $('lock').hidden = false;
    $('pass2-wrap').hidden = !isNew;
    $('pass2').required = isNew;
    $('pass').autocomplete = isNew ? 'new-password' : 'current-password';
    $('lock-btn').textContent = isNew ? 'Create' : 'Unlock';
    $('lock-hint').textContent = isNew
      ? 'Choose a passphrase (12+ characters). It encrypts all your data. Use the same one on every device. If you forget it, the data cannot be recovered.'
      : 'Enter your passphrase.';
    $('lock-form').addEventListener('submit', unlock);
    $('pass').focus();
  }

  // ---------- UI wiring ----------
  function wire() {
    document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => {
      document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('on', x === b));
      document.querySelectorAll('.view').forEach((v) => { v.hidden = v.id !== 'view-' + b.dataset.view; });
      $('add-msg').textContent = '';
    }));
    const shift = (n) => {
      const [y, m] = S.month.split('-').map(Number);
      const d = new Date(y, m - 1 + n, 1);
      S.month = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      render();
    };
    $('prev').addEventListener('click', () => shift(-1));
    $('next').addEventListener('click', () => shift(1));

    $('add-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const f = e.target;
      const amount = toCents(f.amount.value);
      const category = clean(f.category.value, 40);
      if (amount === null || !category || !isDate(f.date.value)) { toast('Check amount, category and date.'); return; }
      const base = { id: uid(), kind: f.kind.value === 'income' ? 'income' : 'expense', amount, category, note: clean(f.note.value, 100), date: f.date.value };
      if (f.freq.value === 'once') put({ ...base, type: 'tx' });
      else put({ ...base, type: 'rec', freq: f.freq.value === 'weekly' ? 'weekly' : 'monthly', end: null });
      f.amount.value = f.note.value = '';
      toast('Saved.');
    });

    $('budget-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const f = e.target;
      const amount = toCents(f.amount.value);
      const category = clean(f.category.value, 40);
      if (amount === null || !category) return;
      const existing = live('budget').find((b) => b.category.toLowerCase() === category.toLowerCase());
      put({ id: existing?.id || uid(), type: 'budget', category, amount });
      f.reset();
    });

    $('currency-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const c = e.target.currency.value.trim().toUpperCase();
      try { new Intl.NumberFormat(undefined, { style: 'currency', currency: c }); } catch { return; }
      S.data.currency = c;
      S.data.currencyAt = Date.now();
      persist();
    });

    $('sync-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.target;
      const repo = f.repo.value.trim();
      const token = f.token.value.trim();
      if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(repo)) { status('Repository must look like owner/name.'); return; }
      if (token && !/^[A-Za-z0-9_]{20,255}$/.test(token)) { status('That does not look like a GitHub token.'); return; }
      S.cfg.repo = repo;
      if (token) S.cfg.token = token;
      f.token.value = '';
      await saveCfg();
      sync();
    });
    $('sync-now').addEventListener('click', sync);

    $('export').addEventListener('click', () => {
      if (!confirm('The exported file is NOT encrypted. Keep it somewhere safe. Continue?')) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(S.data, null, 2)], { type: 'application/json' }));
      const a = el('a', { href: url, download: `finora-${today()}.json` });
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    $('lock-now').addEventListener('click', lock);
    $('wipe').addEventListener('click', () => {
      if (!confirm('Remove all Finora data and the token from this device? Synced data on GitHub stays.')) return;
      localStorage.removeItem(LS_VAULT);
      localStorage.removeItem(LS_CFG);
      lock();
    });
  }

  document.addEventListener('DOMContentLoaded', () => { wire(); showLock(); });
})();
