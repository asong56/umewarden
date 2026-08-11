/**
 * vault.js — 前端 vault 状态
 *
 * 极简的响应式状态容器，不引入任何框架。
 * 使用发布-订阅模式通知 UI 层更新。
 *
 * TODO:
 *   - 排序（按名称 / 最近使用 / 收藏）
 *   - 收藏标记的读写
 */

import {
  api, onVaultLocked, onVaultUnlocked, onVaultUnlockFailed,
  onTwoFactorRequired, onVaultSynced, onVaultSyncFailed, onAutofillCandidates,
} from './api.js';

// ─── 状态 ─────────────────────────────────────────────────────────────────────

const state = {
  locked:      true,
  items:       [],    // VaultItem[]
  folders:     [],
  selectedId:  null,
  filter:      'all',   // 'all' | 'login' | 'card' | 'note' | 'identity'
  searchQuery: '',
  syncStatus:  null,

  // 解锁相关
  unlockError:        null,   // 上次解锁失败的错误信息
  twoFactorRequired:  false,  // 是否需要输入 2FA 验证码
  twoFactorProviders: [],

  // autofill 候选列表（热键触发后弹出的选择框用）
  autofillCandidates: null,   // null = 不显示；[] 或 [{id,name}] = 显示
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

// ─── 派生数据 ─────────────────────────────────────────────────────────────────

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

// ─── Actions ──────────────────────────────────────────────────────────────────

export async function unlock(password, twoFactorCode = null) {
  state.unlockError = null;
  notify();
  try {
    await api.unlock(password, twoFactorCode);
    // 成功与否都通过 vault:unlocked / vault:unlock_failed / vault:two_factor_required 事件反馈，
    // 这里的 await 只是确认消息成功送到了 daemon channel，不代表解锁已经完成
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

// ─── Tauri events → 状态同步 ──────────────────────────────────────────────────

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
