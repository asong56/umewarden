// Event wiring + init. TODO: new/edit item form, password generator UI (backend commands exist).

import { api } from './api.js';
import * as vault from './vault.js';
import {
  renderItemList, renderDetail, renderFolderList, renderAutofillPicker,
  startTotpRefresh, stopTotpRefresh, showScreen, toast,
} from './ui.js';

vault.subscribe(state => {
  if (state.locked) {
    showScreen('screen-unlock');
    document.getElementById('field-2fa').hidden = !state.twoFactorRequired;
    const errEl = document.getElementById('unlock-error');
    errEl.hidden = !state.unlockError;
    errEl.textContent = state.unlockError ?? '';
  } else {
    showScreen('screen-main');
    renderItemList(vault.filteredItems(), state.selectedId);
    renderFolderList(state.folders, id => { /* TODO: filter by folder, only type filter exists today */ });

    const selected = vault.getSelected();
    renderDetail(selected);
    stopTotpRefresh();
    if (selected?.kind?.totp) {
      startTotpRefresh(selected.id, api);
    }
  }

  renderAutofillPicker(
    state.autofillCandidates,
    async (itemId) => {
      vault.dismissAutofillCandidates();
      try {
        await api.triggerAutofill(itemId);
      } catch (e) {
        toast(e.message ?? 'Autofill failed', true);
      }
    },
    () => vault.dismissAutofillCandidates(),
  );
});

const formUnlock  = document.getElementById('form-unlock');
const inputPw     = document.getElementById('input-password');
const input2fa    = document.getElementById('input-2fa');
const btnUnlock   = document.getElementById('btn-unlock');
const btnTogglePw = document.getElementById('btn-toggle-pw');

formUnlock.addEventListener('submit', async e => {
  e.preventDefault();
  const pw = inputPw.value;
  if (!pw) return;

  const twoFactorCode = input2fa.hidden ? null : (input2fa.value.trim() || null);

  btnUnlock.disabled = true;
  btnUnlock.textContent = 'Unlocking…';

  try {
    await vault.unlock(pw, twoFactorCode); // result arrives async via vault:unlocked/unlock_failed events
  } catch (err) {
    toast(err?.message ?? 'Failed to send unlock request', true); // only rejects if the daemon channel itself is down
  } finally {
    btnUnlock.disabled = false;
    btnUnlock.textContent = 'Unlock';
  }
});

btnTogglePw.addEventListener('click', () => {
  const showing = inputPw.type === 'password';
  inputPw.type = showing ? 'text' : 'password';
  btnTogglePw.textContent = showing ? 'Hide' : 'Show';
});

document.getElementById('btn-lock').addEventListener('click', async () => {
  try { await vault.lock(); }
  catch (e) { toast(e.message ?? 'Lock failed', true); }
});

document.querySelectorAll('.nav-item[data-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const filter = btn.dataset.filter;
    vault.setFilter(filter);

    const labels = { all: 'All items', login: 'Logins', card: 'Cards', note: 'Notes', identity: 'Identities' };
    document.getElementById('pane-title').textContent = labels[filter] ?? filter;
  });
});

document.getElementById('search').addEventListener('input', e => {
  vault.setSearch(e.target.value);
});

document.getElementById('btn-sync').addEventListener('click', async () => {
  try {
    await api.syncNow();
    toast('Sync started');
  } catch (e) {
    toast(e.message ?? 'Sync failed', true);
  }
});

document.getElementById('btn-settings').addEventListener('click', () => {
  showScreen('screen-settings');
  loadSettingsValues();
});

document.getElementById('btn-new-item').addEventListener('click', () => {
  toast('New item form — TODO');
});

document.getElementById('btn-setup').addEventListener('click', () => {
  showScreen('screen-settings');
});

document.getElementById('btn-back-settings').addEventListener('click', () => {
  showScreen('screen-unlock');
});

document.getElementById('btn-save-vw').addEventListener('click', async () => {
  const url   = document.getElementById('cfg-server-url').value.trim();
  const email = document.getElementById('cfg-email').value.trim();

  if (!url || !email) { toast('Server URL and email are required', true); return; }

  try {
    await api.setVaultwardenServer(url, email);
    toast('Server configured. Enter your master password to unlock.');
    showScreen('screen-unlock');
    document.getElementById('unlock-subtitle').textContent = `Connecting to ${new URL(url).hostname}`;
  } catch (e) {
    toast(e.message ?? 'Failed to configure server', true);
  }
});

document.getElementById('btn-browse-kdbx').addEventListener('click', async () => {
  try {
    const path = await api.pickKdbxFile();
    if (!path) return;
    await api.openKdbxFile(path);
    document.getElementById('cfg-kdbx-path').value = path;
    toast('Vault file set. Enter your master password to unlock.');
    showScreen('screen-unlock');
  } catch (e) {
    toast(e.message ?? 'Failed to open file', true);
  }
});

document.getElementById('btn-create-kdbx').addEventListener('click', async () => {
  const password = document.getElementById('new-kdbx-password').value;
  if (!password || password.length < 8) {
    toast('Choose a password with at least 8 characters', true);
    return;
  }

  try {
    const savePath = await api.pickSaveKdbxPath();
    if (!savePath) return;
    await api.createKdbxFile(savePath, password);
    document.getElementById('cfg-kdbx-path').value = savePath;
    toast('New vault created. Unlock with the password you just set.');
    showScreen('screen-unlock');
  } catch (e) {
    toast(e.message ?? 'Failed to create vault', true);
  }
});

async function loadSettingsValues() {
  try {
    const cfg = await api.getConfig();
    if (cfg.backend?.kind === 'Vaultwarden') {
      document.getElementById('cfg-server-url').value = cfg.backend.server_url ?? '';
      document.getElementById('cfg-email').value      = cfg.backend.email ?? '';
    } else if (cfg.backend?.kind === 'Kdbx') {
      document.getElementById('cfg-kdbx-path').value  = cfg.backend.file_path ?? '';
    }
    document.getElementById('cfg-lock-timeout').value = String((cfg.auto_lock_secs ?? 300) / 60);
  } catch (e) {
    console.warn('Failed to load config:', e);
  }
}

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    document.getElementById('search')?.focus();
  }
  if (e.key === 'Escape') {
    vault.selectItem(null);
    vault.dismissAutofillCandidates();
  }
});

(async function init() {
  try {
    const cfg = await api.getConfig();
    if (!cfg.backend || cfg.backend.kind === 'None') {
      showScreen('screen-settings');
      return;
    }
    showScreen('screen-unlock');
  } catch {
    showScreen('screen-unlock');
  }
})();
