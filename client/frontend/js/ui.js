// DOM rendering only — no state held here, that's vault.js.
// TODO: edit form, new-item dialog, password strength meter, favicons, keyboard nav.

import { filteredItems, selectItem, getSelected } from './vault.js';
import { api } from './api.js';

const $itemList   = document.getElementById('item-list');
const $detailPane = document.getElementById('detail-pane');
const $paneTitle  = document.getElementById('pane-title');
const $toastCont  = (() => {
  const el = document.createElement('div');
  el.id = 'toast-container';
  document.body.appendChild(el);
  return el;
})();

export function renderItemList(items, selectedId) {
  if (items.length === 0) {
    $itemList.innerHTML = `
      <li class="empty-state">
        <span class="empty-state-text">No items found</span>
      </li>`;
    return;
  }

  $itemList.innerHTML = '';
  const frag = document.createDocumentFragment();

  items.forEach(item => {
    const li = document.createElement('li');
    li.className = 'item-row' + (item.id === selectedId ? ' selected' : '');
    li.dataset.id = item.id;
    li.setAttribute('role', 'button');
    li.setAttribute('tabindex', '0');

    const icon    = itemIcon(item);
    const name    = esc(item.name ?? 'Untitled');
    const meta    = itemMeta(item);

    li.innerHTML = `
      <span class="item-icon" aria-hidden="true">${icon}</span>
      <span class="item-info">
        <span class="item-name">${name}</span>
        <span class="item-meta">${esc(meta)}</span>
      </span>`;

    li.addEventListener('click', () => selectItem(item.id));
    li.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') selectItem(item.id); });

    frag.appendChild(li);
  });

  $itemList.appendChild(frag);
}

export function renderDetail(item) {
  if (!item) {
    $detailPane.hidden = true;
    $detailPane.innerHTML = '';
    return;
  }

  $detailPane.hidden = false;

  const login = item.kind?.type === 'Login' ? item.kind : null;

  $detailPane.innerHTML = `
    <div class="detail-header">
      <h2 class="detail-title">${esc(item.name)}</h2>
      <div class="detail-actions">
        <button data-variant="secondary" id="detail-edit">Edit</button>
        <button data-variant="danger" id="detail-delete">Delete</button>
      </div>
    </div>

    ${login ? renderLoginFields(login) : ''}
    ${item.notes ? renderField('Notes', item.notes, false) : ''}

    ${item.fields?.length ? renderCustomFields(item.fields) : ''}

    <div style="margin-top:auto; padding-top: 16px; font-size:11px; color:var(--color-text-muted);">
      Updated ${timeAgo(item.updated_at)}
    </div>`;

  $detailPane.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const val = btn.dataset.copy;
      await navigator.clipboard.writeText(val);
      toast('Copied!');
    });
  });

  // autofill button
  const autofillBtn = $detailPane.querySelector('#detail-autofill');
  if (autofillBtn) {
    autofillBtn.addEventListener('click', async () => {
      try {
        await api.triggerAutofill(item.id);
        toast('Autofill sent');
      } catch (e) {
        toast(e.message ?? 'Autofill failed', true);
      }
    });
  }

  // delete
  document.getElementById('detail-delete')?.addEventListener('click', async () => {
    if (!confirm(`Delete "${item.name}"?`)) return;
    try {
      await api.deleteItem(item.id);
      toast('Item deleted');
      // TODO: optimistic remove from local state instead of waiting for next sync
    } catch (e) {
      toast(e.message ?? 'Delete failed', true);
    }
  });

  document.getElementById('detail-edit')?.addEventListener('click', () => {
    toast('Edit form — TODO', false);
  });
}

function renderLoginFields(login) {
  const uriStr = login.uris?.[0]?.uri ?? '';
  return `
    ${login.username ? renderField('Username', login.username, true) : ''}
    ${login.password ? renderField('Password', login.password, true, true) : ''}
    ${uriStr ? `
      <div class="field-display">
        <label>Website</label>
        <div class="copy-row">
          <span class="val">${esc(uriStr)}</span>
          <button data-variant="secondary" data-copy="${esc(uriStr)}">Copy</button>
          <a href="${esc(uriStr)}" target="_blank" rel="noopener noreferrer" data-variant="ghost">Open ↗</a>
        </div>
      </div>` : ''}
    ${login.totp ? `
      <div class="field-display">
        <label>TOTP</label>
        <div class="copy-row">
          <span class="val" id="totp-code">···</span>
          <button data-variant="secondary" id="detail-autofill">Autofill</button>
        </div>
      </div>` : ''}`;
}

function renderField(label, value, copyable = true, masked = false) {
  const display = masked ? '••••••••••••' : esc(value);
  const rawVal  = typeof value === 'string' ? value : (value?.expose?.() ?? '');

  return `
    <div class="field-display">
      <label>${esc(label)}</label>
      <div class="copy-row">
        <span class="val${masked ? ' masked' : ''}">${display}</span>
        ${masked ? `<button data-variant="ghost" onclick="this.previousElementSibling.textContent = this.previousElementSibling.textContent === '••••••••••••' ? '${esc(rawVal)}' : '••••••••••••'; this.textContent = this.textContent === 'Show' ? 'Hide' : 'Show'">Show</button>` : ''}
        ${copyable ? `<button data-variant="secondary" data-copy="${esc(rawVal)}">Copy</button>` : ''}
      </div>
    </div>`;
}

function renderCustomFields(fields) {
  return fields.map(f => {
    if (f.value?.type === 'Hidden') return renderField(f.name, f.value.value, true, true);
    if (f.value?.type === 'Boolean') return renderField(f.name, f.value.value ? 'Yes' : 'No', false);
    return renderField(f.name, f.value?.value ?? '', true);
  }).join('');
}

export function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id)?.classList.add('active');
}

export function toast(message, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.textContent = message;
  $toastCont.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

const $folderList = document.getElementById('folder-list');

export function renderFolderList(folders, onSelect) {
  if (!folders || folders.length === 0) {
    $folderList.innerHTML = '';
    return;
  }
  $folderList.innerHTML = '';
  const frag = document.createDocumentFragment();
  folders.forEach(f => {
    const btn = document.createElement('button');
    btn.className = 'nav-item';
    btn.textContent = f.name;
    btn.addEventListener('click', () => onSelect(f.id));
    frag.appendChild(btn);
  });
  $folderList.appendChild(frag);
}

const $autofillPicker = document.getElementById('autofill-picker');
const $autofillList = document.getElementById('autofill-picker-list');

export function renderAutofillPicker(candidates, onPick, onDismiss) {
  if (!candidates) {
    $autofillPicker.hidden = true;
    return;
  }

  $autofillPicker.hidden = false;
  $autofillList.innerHTML = '';

  if (candidates.length === 0) {
    $autofillList.innerHTML = '<li style="color:var(--color-text-muted)">No matching credentials</li>';
  } else {
    candidates.forEach(c => {
      const li = document.createElement('li');
      li.textContent = c.name;
      li.addEventListener('click', () => onPick(c.id));
      $autofillList.appendChild(li);
    });
  }

  document.getElementById('btn-autofill-dismiss').onclick = onDismiss;
}

let totpInterval = null;

// Login's fields are flattened onto item.kind (internally-tagged serde), not
// nested under item.kind.Login - that's why itemKind checks read item.kind.type directly.
export function startTotpRefresh(itemId, api) {
  stopTotpRefresh();
  const el = document.getElementById('totp-code');
  if (!el) return;

  const tick = async () => {
    try {
      const [code, remaining] = await api.getTotpCode(itemId); // Rust (String, u8) tuple -> JSON array
      el.textContent = `${code}  (${remaining}s)`;
    } catch (e) {
      el.textContent = '(no TOTP)';
      stopTotpRefresh();
    }
  };

  tick();
  totpInterval = setInterval(tick, 1000);
}

export function stopTotpRefresh() {
  if (totpInterval) {
    clearInterval(totpInterval);
    totpInterval = null;
  }
}

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const ICON_STROKE = 'fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"';
const ITEM_ICONS = {
  Login: `<svg viewBox="0 0 24 24" ${ICON_STROKE}><circle cx="8" cy="8" r="4"/><path d="M11 11l9 9M17 15l3 3M14 18l2.5 2.5"/></svg>`,
  Card: `<svg viewBox="0 0 24 24" ${ICON_STROKE}><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M3 10h18"/></svg>`,
  Identity: `<svg viewBox="0 0 24 24" ${ICON_STROKE}><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M7 16c.5-1.5 1.8-2 2-2s1.5.5 2 2M14 10h5M14 14h4"/></svg>`,
  SecureNote: `<svg viewBox="0 0 24 24" ${ICON_STROKE}><path d="M6 3h9l3 3v15H6z"/><path d="M15 3v3h3M9 12h6M9 16h6"/></svg>`,
};
const ITEM_ICON_DEFAULT = `<svg viewBox="0 0 24 24" ${ICON_STROKE}><rect x="3.5" y="3.5" width="17" height="17" rx="3"/></svg>`;

function itemIcon(item) {
  const kind = item.kind?.type ?? '';
  return ITEM_ICONS[kind] ?? ITEM_ICON_DEFAULT;
}

function itemMeta(item) {
  const login = item.kind?.type === 'Login' ? item.kind : null;
  if (login?.username) return login.username;
  const uri = login?.uris?.[0]?.uri;
  if (uri) {
    try { return new URL(uri).hostname; } catch {}
  }
  return '';
}

function timeAgo(unixSecs) {
  if (!unixSecs) return 'unknown';
  const diff = Math.floor(Date.now() / 1000) - unixSecs;
  if (diff < 60)   return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
