// VaultError shape: { kind, message }. TwoFactorRequired's message is
// { providers: string[] }, not a string - check err.kind before reading it.

const { invoke } = window.__TAURI__.core;

export const api = {
  unlock(password, twoFactorCode = null) { return invoke('unlock', { password, twoFactorCode }); },
  lock()                        { return invoke('lock'); },
  listItems(folderId = null)    { return invoke('list_items',   { folderId }); },
  getItem(id)                   { return invoke('get_item',     { id }); },
  getTotpCode(id)                { return invoke('get_totp_code', { id }); },
  createItem(item)              { return invoke('create_item',  { item }); },
  updateItem(item)              { return invoke('update_item',  { item }); },
  deleteItem(id)                { return invoke('delete_item',  { id }); },

  getConfig()                            { return invoke('get_config'); },
  setVaultwardenServer(serverUrl, email) { return invoke('set_vaultwarden_server', { serverUrl, email }); },
  openKdbxFile(filePath)                 { return invoke('open_kdbx_file', { filePath }); },
  createKdbxFile(filePath, password)     { return invoke('create_kdbx_file', { filePath, password }); },

  generatePassword(opts)    { return invoke('generate_password',   { opts }); },
  generatePassphrase(opts)  { return invoke('generate_passphrase', { opts }); },

  triggerAutofill(itemId)   { return invoke('trigger_autofill', { itemId }); },

  syncNow()                 { return invoke('sync_now'); },
  getSyncStatus()           { return invoke('get_sync_status'); },

  // No npm/bundler here, so this calls tauri-plugin-dialog's raw invoke channel
  // ("plugin:{name}|{command}") instead of its JS wrapper. Param names (filters/
  // multiple) aren't pinned to a specific plugin version - if the filter silently
  // no-ops, check that against the installed tauri-plugin-dialog version.
  async pickKdbxFile() {
    const selected = await invoke('plugin:dialog|open', {
      multiple: false,
      directory: false,
      filters: [{ name: 'KeePass Database', extensions: ['kdbx'] }],
    });
    if (!selected) return null; // return shape varies by plugin version: string | {path} | array
    if (typeof selected === 'string') return selected;
    if (Array.isArray(selected)) return selected[0] ?? null;
    return selected.path ?? null;
  },

  async pickSaveKdbxPath() {
    const selected = await invoke('plugin:dialog|save', {
      filters: [{ name: 'KeePass Database', extensions: ['kdbx'] }],
      defaultPath: 'vault.kdbx',
    });
    return selected ?? null;
  },
};

const { listen } = window.__TAURI__.event;

export function onVaultLocked(cb)   { return listen('vault:locked',   cb); }
export function onVaultUnlocked(cb) { return listen('vault:unlocked', cb); }
export function onVaultUnlockFailed(cb) { return listen('vault:unlock_failed', cb); }
export function onTwoFactorRequired(cb) { return listen('vault:two_factor_required', cb); }
export function onVaultSynced(cb)   { return listen('vault:synced',   cb); }
export function onVaultSyncFailed(cb) { return listen('vault:sync_failed', cb); }
export function onAutofillCandidates(cb) { return listen('autofill:candidates', cb); }
