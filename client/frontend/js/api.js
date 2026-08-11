/**
 * api.js — Tauri IPC 封装层
 *
 * 所有与 Rust 后端的通信通过此模块进行。
 * 使用 Tauri v2 的 `window.__TAURI__.core.invoke`。
 *
 * 错误格式：后端返回 VaultError，序列化为 { kind: string, message: string | object }
 * 注意 TwoFactorRequired 的 message 是个对象 { providers: string[] }，不是字符串——
 * 用之前先检查 err.kind。
 */

const { invoke } = window.__TAURI__.core;

export const api = {
  // ─── Vault ───────────────────────────────────────────────────────────────
  // twoFactorCode: 收到 vault:two_factor_required 事件后，带着用户输入的验证码重新调用
  unlock(password, twoFactorCode = null) { return invoke('unlock', { password, twoFactorCode }); },
  lock()                        { return invoke('lock'); },
  listItems(folderId = null)    { return invoke('list_items',   { folderId }); },
  getItem(id)                   { return invoke('get_item',     { id }); },
  getTotpCode(id)                { return invoke('get_totp_code', { id }); },
  createItem(item)              { return invoke('create_item',  { item }); },
  updateItem(item)              { return invoke('update_item',  { item }); },
  deleteItem(id)                { return invoke('delete_item',  { id }); },

  // ─── Config ──────────────────────────────────────────────────────────────
  getConfig()                            { return invoke('get_config'); },
  setVaultwardenServer(serverUrl, email) { return invoke('set_vaultwarden_server', { serverUrl, email }); },
  // 只记录路径，不再传密码——密码统一走 unlock()
  openKdbxFile(filePath)                 { return invoke('open_kdbx_file', { filePath }); },
  createKdbxFile(filePath, password)     { return invoke('create_kdbx_file', { filePath, password }); },

  // ─── Generator ───────────────────────────────────────────────────────────
  generatePassword(opts)    { return invoke('generate_password',   { opts }); },
  generatePassphrase(opts)  { return invoke('generate_passphrase', { opts }); },

  // ─── Autofill ────────────────────────────────────────────────────────────
  triggerAutofill(itemId)   { return invoke('trigger_autofill', { itemId }); },

  // ─── Sync ─────────────────────────────────────────────────────────────────
  syncNow()                 { return invoke('sync_now'); },
  getSyncStatus()           { return invoke('get_sync_status'); },

  // ─── 原生文件对话框（tauri-plugin-dialog）─────────────────────────────────
  // 没有用官方 JS 包（vanilla 环境没有 npm/bundler），直接调用插件的底层 invoke
  // 通道：Tauri 插件命令名格式固定是 "plugin:{name}|{command}"。
  // 参数字段名（filters/multiple 等）未 100% 核实版本一致性，如果调起对话框但
  // 参数不生效（比如过滤器没起作用），对照当前 tauri-plugin-dialog 版本的文档确认。
  async pickKdbxFile() {
    const selected = await invoke('plugin:dialog|open', {
      multiple: false,
      directory: false,
      filters: [{ name: 'KeePass Database', extensions: ['kdbx'] }],
    });
    // 有的版本返回字符串，有的版本返回 { path } 对象或数组，做个宽松处理
    if (!selected) return null;
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

// ─── Tauri event listeners ───────────────────────────────────────────────────

const { listen } = window.__TAURI__.event;

/** vault:locked — 服务端锁定（超时自动锁）时触发 */
export function onVaultLocked(cb)   { return listen('vault:locked',   cb); }
/** vault:unlocked — 解锁成功时触发 */
export function onVaultUnlocked(cb) { return listen('vault:unlocked', cb); }
/** vault:unlock_failed — 解锁失败（密码错/网络错），payload 是错误描述字符串 */
export function onVaultUnlockFailed(cb) { return listen('vault:unlock_failed', cb); }
/** vault:two_factor_required — 需要 2FA 验证码，payload 是 provider 类型数组，如 ["0"] */
export function onTwoFactorRequired(cb) { return listen('vault:two_factor_required', cb); }
/** vault:synced — 同步完成时触发，payload: { timestamp: number } */
export function onVaultSynced(cb)   { return listen('vault:synced',   cb); }
export function onVaultSyncFailed(cb) { return listen('vault:sync_failed', cb); }
/** autofill:candidates — 热键触发后，匹配到的候选凭据列表，payload: [{id, name}] */
export function onAutofillCandidates(cb) { return listen('autofill:candidates', cb); }
