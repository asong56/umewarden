// Minimal pub/sub state container, no framework. TODO: sorting, favorite toggle.

import {
  api, onVaultLocked, onVaultUnlocked, onVaultUnlockFailed,
  onTwoFactorRequired, onVaultSynced, onVaultSyncFailed, onAutofillCandidates,
} from './api.js';

const state = {
  locked:      true,
  items:       [],
  folders:     [],
  selectedId:  null,
  filter:      'all', // 'all' | 'login' | 'card' | 'note' | 'identity'
  searchQuery: '',
  syncStatus:  null,

  unlockError:        null,
  twoFactorRequired:  false,
  twoFactorProviders: [],

  autofillCandidates: null, // null = hidden, array = showing (possibly empty)
};

const listeners = new Set();

function notify() {
  listeners.forEach(fn => fn(state));
}

export function subscribe(fn) {
  listeners.add(fn);
  fn(state);
  return () => listeners.delete(fn);
}

export function filteredItems() {
  const q = state.searchQuery.toLowerCase().trim();
  return state.items.filter(item => {
    if (state.filter !== 'all') {
      const kind = item.kind?.type?.toLowerCase() ?? '';
      if (!kind.startsWith(state.filter)) return false;
    }
    if (q) {
      const name     = item.name?.toLowerCase() ?? '';
      const username = item.kind?.username?.toLowerCase() ?? '';
      const uri      = item.kind?.uris?.[0]?.uri?.toLowerCase() ?? '';
      return name.includes(q) || username.includes(q) || uri.includes(q);
    }
    return true;
  });
}

export async function unlock(password, twoFactorCode = null) {
  state.unlockError = null;
  notify();
  try {
    await api.unlock(password, twoFactorCode); // resolves once the daemon has the message, not once unlock is done
  } catch (e) {
    state.unlockError = e?.message ?? String(e);
    notify();
    throw e;
  }
}

export async function lock() {
  await api.lock();
}

export async function loadItems() {
  state.items = await api.listItems();
  notify();
}

export function setFilter(filter) {
  state.filter = filter;
  notify();
}

export function setSearch(query) {
  state.searchQuery = query;
  notify();
}

export function selectItem(id) {
  state.selectedId = id;
  notify();
}

export function getSelected() {
  return state.items.find(i => i.id === state.selectedId) ?? null;
}

export function dismissAutofillCandidates() {
  state.autofillCandidates = null;
  notify();
}

onVaultLocked(() => {
  state.locked = true;
  state.items  = [];
  state.selectedId = null;
  state.twoFactorRequired = false;
  notify();
});

onVaultUnlocked(async () => {
  state.locked = false;
  state.unlockError = null;
  state.twoFactorRequired = false;
  await loadItems();
});

onVaultUnlockFailed(({ payload }) => {
  state.unlockError = typeof payload === 'string' ? payload : JSON.stringify(payload);
  state.twoFactorRequired = false;
  notify();
});

onTwoFactorRequired(({ payload }) => {
  state.twoFactorRequired = true;
  state.twoFactorProviders = payload ?? [];
  state.unlockError = null;
  notify();
});

onVaultSynced(async ({ payload }) => {
  state.syncStatus = payload;
  await loadItems();
});

onVaultSyncFailed(({ payload }) => {
  console.warn('sync failed:', payload);
});

onAutofillCandidates(({ payload }) => {
  state.autofillCandidates = payload ?? [];
  notify();
});
