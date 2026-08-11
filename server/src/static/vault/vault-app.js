/*!
 * umewarden vault-app.js
 *
 * UI glue: login screen <-> vault screen, decrypting/rendering the vault,
 * and a single item dialog used for viewing, creating, and editing items.
 *
 * Scope, by design ("just enough to talk to the server"):
 *   - Login (personal vault only - no SSO, no API-key login)
 *   - TOTP-based 2FA only (webauthn/Duo/email 2FA are not implemented here;
 *     accounts using only those must sign in with an official client)
 *   - Full create/edit/delete for Login and Secure Note items
 *   - Read-only listing for other item types (Card/Identity/SSH key/...)
 *   - Organization (shared) items are intentionally never decrypted here -
 *     that requires unwrapping org keys via the account's RSA keypair, which
 *     is out of scope for this minimal UI - they're hidden from the list.
 *   - No attachments, sends, folders, or trash management.
 *
 * Session state lives in memory only (not localStorage/sessionStorage) -
 * closing or reloading the tab requires unlocking again. This is a
 * deliberate, conservative default for a password manager UI.
 */
(function () {
  'use strict';

  const Crypto = window.umewardenCrypto;
  const Api = window.umewardenApi;

  const CIPHER_TYPE = { LOGIN: 1, SECURE_NOTE: 2, CARD: 3, IDENTITY: 4, SSH_KEY: 5, BANK_ACCOUNT: 6 };
  const TYPE_LABELS = {
    1: 'Login',
    2: 'Secure note',
    3: 'Card',
    4: 'Identity',
    5: 'SSH key',
    6: 'Bank account',
  };

  /** @type {{accessToken: string, userKey: {encKey: Uint8Array, macKey: Uint8Array}, email: string} | null} */
  let session = null;

  /** Decrypted, in-memory copy of the vault. Cleared on logout. */
  let vaultItems = []; // [{ id, type, name, notes, login, raw, decryptFailed }]
  let orgItemsHiddenCount = 0;

  // ---- small DOM helpers -------------------------------------------------

  const $ = (sel) => document.querySelector(sel);
  const el = (tag, props = {}, children = []) => {
    const node = document.createElement(tag);
    Object.entries(props).forEach(([k, v]) => {
      if (k === 'class') node.className = v;
      else if (k === 'dataset') Object.entries(v).forEach(([dk, dv]) => (node.dataset[dk] = dv));
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else if (v !== null && v !== undefined) node.setAttribute(k, v);
    });
    (Array.isArray(children) ? children : [children]).forEach((c) => {
      if (c == null) return;
      node.append(c.nodeType ? c : document.createTextNode(String(c)));
    });
    return node;
  };

  function showBanner(target, message, type = 'error') {
    target.hidden = false;
    target.dataset.type = type;
    target.textContent = message;
  }
  function hideBanner(target) {
    target.hidden = true;
    target.textContent = '';
  }

  async function copyToClipboard(text, button) {
    try {
      await navigator.clipboard.writeText(text ?? '');
      if (button) flashButton(button, 'Copied');
    } catch (e) {
      if (button) flashButton(button, 'Copy failed');
    }
  }

  function flashButton(button, label) {
    const original = button.textContent;
    button.textContent = label;
    button.setAttribute('data-success', 'true');
    setTimeout(() => {
      button.textContent = original;
      button.removeAttribute('data-success');
    }, 1200);
  }

  // ---- login flow ---------------------------------------------------------

  const loginForm = $('#login-form');
  const loginBanner = $('#login-banner');
  const twofactorField = $('#twofactor-field');
  const loginSubmit = $('#login-submit');

  let pendingTwoFactorProviders = null;
  let pendingLoginContext = null; // { email, masterKey, masterPasswordHashB64 }

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanner(loginBanner);
    loginSubmit.setAttribute('aria-busy', 'true');
    try {
      const email = $('#login-email').value.trim();
      const password = $('#login-password').value;

      if (!pendingTwoFactorProviders) {
        const kdfInfo = await Api.prelogin(email);
        const masterKey = await Crypto.makeMasterKey(email, password, kdfInfo);
        const masterPasswordHashB64 = await Crypto.hashMasterKeyForServer(masterKey, password);
        pendingLoginContext = { email, masterKey, masterPasswordHashB64 };
      }

      const twoFactorProvider = pendingTwoFactorProviders ? 0 : undefined;
      const twoFactorToken = pendingTwoFactorProviders ? $('#login-2fa').value.trim() : undefined;

      if (pendingTwoFactorProviders && !pendingTwoFactorProviders.includes(0)) {
        showBanner(
          loginBanner,
          'This account requires a two-step verification method (WebAuthn, Duo, or email code) ' +
            'that umewarden does not support. Please use an official Bitwarden app to sign in.'
        );
        return;
      }

      const result = await Api.login({
        email: pendingLoginContext.email,
        masterPasswordHashB64: pendingLoginContext.masterPasswordHashB64,
        twoFactorProvider,
        twoFactorToken,
      });

      if (!result.ok) {
        pendingTwoFactorProviders = result.twoFactorProviders;
        twofactorField.hidden = false;
        $('#login-2fa').focus();
        showBanner(loginBanner, 'Enter the 6-digit code from your authenticator app.', 'warning');
        return;
      }

      const { encKey: stretchedEnc, macKey: stretchedMac } = await Crypto.stretchKey(pendingLoginContext.masterKey);
      const userKey = await Crypto.decryptUserKey(result.account.encryptedUserKey, stretchedEnc, stretchedMac);

      session = { accessToken: result.tokens.accessToken, userKey, email: pendingLoginContext.email };
      pendingTwoFactorProviders = null;
      pendingLoginContext = null;
      $('#login-password').value = '';

      await loadVault();
      enterVaultScreen();
    } catch (err) {
      console.error(err);
      const message =
        err instanceof Api.ApiError
          ? err.message
          : err instanceof DOMException || /MAC verification|Unexpected user key length/.test(err.message || '')
            ? 'Could not unlock the vault with that password (or this account uses an unsupported KDF setup).'
            : err.message || 'Something went wrong while signing in.';
      showBanner(loginBanner, message);
    } finally {
      loginSubmit.removeAttribute('aria-busy');
    }
  });

  function enterVaultScreen() {
    $('#login-screen').hidden = true;
    $('#vault-screen').hidden = false;
    $('#login-email-display') && ($('#login-email-display').textContent = session.email);
    renderList();
  }

  $('#logout-btn').addEventListener('click', () => {
    session = null;
    vaultItems = [];
    pendingTwoFactorProviders = null;
    pendingLoginContext = null;
    twofactorField.hidden = true;
    $('#login-2fa').value = '';
    loginForm.reset();
    hideBanner(loginBanner);
    $('#vault-screen').hidden = true;
    $('#login-screen').hidden = false;
    renderList();
  });

  // ---- vault loading / decryption -----------------------------------------

  async function loadVault() {
    const data = await Api.sync(session.accessToken);
    const ciphers = (data.ciphers || []).filter((c) => !c.deletedDate);

    orgItemsHiddenCount = ciphers.filter((c) => c.organizationId).length;
    const personal = ciphers.filter((c) => !c.organizationId);

    vaultItems = await Promise.all(personal.map((c) => decryptCipher(c)));
  }

  async function decryptCipher(cipher) {
    try {
      const itemKey = cipher.key ? await Crypto.decryptCipherKey(cipher.key, session.userKey) : session.userKey;

      const name = await Crypto.decryptString(cipher.name, itemKey.encKey, itemKey.macKey);
      const notes = cipher.notes ? await Crypto.decryptString(cipher.notes, itemKey.encKey, itemKey.macKey) : '';

      let login = null;
      if (cipher.type === CIPHER_TYPE.LOGIN && cipher.login) {
        const username = cipher.login.username
          ? await Crypto.decryptString(cipher.login.username, itemKey.encKey, itemKey.macKey)
          : '';
        const password = cipher.login.password
          ? await Crypto.decryptString(cipher.login.password, itemKey.encKey, itemKey.macKey)
          : '';
        let uri = '';
        if (Array.isArray(cipher.login.uris) && cipher.login.uris[0]?.uri) {
          uri = await Crypto.decryptString(cipher.login.uris[0].uri, itemKey.encKey, itemKey.macKey);
        }
        login = { username, password, uri };
      }

      return { id: cipher.id, type: cipher.type, name, notes, login, raw: cipher, decryptFailed: false };
    } catch (e) {
      console.error('Failed to decrypt cipher', cipher.id, e);
      return { id: cipher.id, type: cipher.type, name: '(could not decrypt)', notes: '', login: null, raw: cipher, decryptFailed: true };
    }
  }

  // ---- list rendering -------------------------------------------------------

  const listEl = $('#vault-list');
  const emptyEl = $('#vault-empty');
  const searchInput = $('#vault-search');

  function renderList() {
    const query = searchInput.value.trim().toLowerCase();
    listEl.innerHTML = '';

    const filtered = vaultItems.filter((item) => {
      if (!query) return true;
      return (
        item.name.toLowerCase().includes(query) ||
        (item.login?.username || '').toLowerCase().includes(query) ||
        (item.login?.uri || '').toLowerCase().includes(query)
      );
    });

    filtered
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach((item) => listEl.append(renderRow(item)));

    let notice = document.getElementById('org-hidden-notice');
    if (orgItemsHiddenCount > 0) {
      if (!notice) {
        notice = el('li', { id: 'org-hidden-notice', class: 'banner', 'data-type': 'warning' });
        listEl.before(notice);
      }
      notice.textContent = `${orgItemsHiddenCount} organization item(s) are hidden - open them in an official Bitwarden app.`;
    } else if (notice) {
      notice.remove();
    }

    emptyEl.hidden = vaultItems.length !== 0;
    listEl.hidden = vaultItems.length === 0;
  }

  function renderRow(item) {
    const subtitle = item.type === CIPHER_TYPE.LOGIN ? item.login?.username || '' : TYPE_LABELS[item.type] || '';
    return el(
      'li',
      { class: 'card is-interactive item-row', onclick: () => openItemDialog(item) },
      [
        el('div', { class: 'item-row-main' }, [
          el('strong', {}, item.name || '(no name)'),
          el('div', { class: 'item-row-subtitle text-muted' }, subtitle),
        ]),
        el('span', { class: 'badge' }, TYPE_LABELS[item.type] || 'Item'),
      ]
    );
  }

  searchInput.addEventListener('input', renderList);

  // ---- item dialog: view / edit / create ------------------------------------

  const dialog = $('#item-dialog');
  const dialogBody = $('#item-dialog-body');
  const dialogTitle = $('#item-dialog-title');

  $('#add-item-btn').addEventListener('click', () => openItemDialog(null));

  function openItemDialog(item) {
    const isNew = item == null;
    const type = item?.type ?? CIPHER_TYPE.LOGIN;
    dialogTitle.textContent = isNew ? 'New item' : item.name || '(no name)';
    dialogBody.innerHTML = '';
    dialogBody.append(buildItemForm(item, isNew, type));
    dialog.showModal();
  }

  function buildItemForm(item, isNew, initialType) {
    const banner = el('div', { class: 'banner', 'data-type': 'error', hidden: '' });
    const nameInput = el('input', { type: 'text', value: item?.name || '', required: '', placeholder: 'Item name' });

    const typeSelect = el(
      'select',
      { disabled: isNew ? null : 'true' },
      [CIPHER_TYPE.LOGIN, CIPHER_TYPE.SECURE_NOTE].map((t) =>
        el('option', { value: t, selected: t === initialType ? 'true' : null }, TYPE_LABELS[t])
      )
    );

    const notesInput = el('textarea', { rows: '3', placeholder: 'Notes' }, item?.notes || '');

    let usernameInput, passwordInput, uriInput, revealBtn;
    const loginFields = el('div', { class: 'login-fields' });

    function renderTypeSpecificFields() {
      loginFields.innerHTML = '';
      const currentType = Number(typeSelect.value);
      if (currentType === CIPHER_TYPE.LOGIN) {
        usernameInput = el('input', { type: 'text', autocomplete: 'off', value: item?.login?.username || '', placeholder: 'Username' });
        passwordInput = el('input', { type: 'password', autocomplete: 'off', value: item?.login?.password || '', placeholder: 'Password' });
        uriInput = el('input', { type: 'text', value: item?.login?.uri || '', placeholder: 'https://example.com' });
        revealBtn = el('button', { type: 'button', class: 'icon-only', 'data-variant': 'ghost', 'aria-label': 'Show password' }, '👁');
        revealBtn.addEventListener('click', () => {
          passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
        });
        const copyUserBtn = el('button', { type: 'button', 'data-variant': 'ghost' }, 'Copy');
        copyUserBtn.addEventListener('click', () => copyToClipboard(usernameInput.value, copyUserBtn));
        const copyPassBtn = el('button', { type: 'button', 'data-variant': 'ghost' }, 'Copy');
        copyPassBtn.addEventListener('click', () => copyToClipboard(passwordInput.value, copyPassBtn));

        loginFields.append(
          el('label', {}, ['Username', el('div', { class: 'input-row' }, [usernameInput, copyUserBtn])]),
          el('label', {}, ['Password', el('div', { class: 'input-row' }, [passwordInput, revealBtn, copyPassBtn])]),
          el('label', {}, ['Website', uriInput])
        );
      }
    }
    typeSelect.addEventListener('change', renderTypeSpecificFields);
    renderTypeSpecificFields();

    const saveBtn = el('button', { type: 'submit', 'data-variant': 'primary' }, isNew ? 'Create' : 'Save');
    const deleteBtn = !isNew ? el('button', { type: 'button', 'data-variant': 'ghost' }, 'Delete') : null;
    const cancelBtn = el('button', { type: 'button', 'data-variant': 'ghost' }, 'Close');
    cancelBtn.addEventListener('click', () => dialog.close());

    if (deleteBtn) {
      deleteBtn.addEventListener('click', async () => {
        if (!confirm(`Delete "${item.name}"? It will be moved to the trash.`)) return;
        try {
          await Api.softDeleteCipher(session.accessToken, item.id);
          vaultItems = vaultItems.filter((v) => v.id !== item.id);
          renderList();
          dialog.close();
        } catch (e) {
          showBanner(banner, e.message || 'Failed to delete item.');
        }
      });
    }

    const readOnlyNotice =
      initialType !== CIPHER_TYPE.LOGIN && initialType !== CIPHER_TYPE.SECURE_NOTE
        ? el(
            'div',
            { class: 'banner', 'data-type': 'warning' },
            `${TYPE_LABELS[initialType] || 'This item type'} isn't editable in umewarden yet - open it in an official Bitwarden app.`
          )
        : null;

    const form = el('form', { id: 'item-form' }, [
      banner,
      readOnlyNotice,
      el('label', {}, ['Name', nameInput]),
      isNew ? el('label', {}, ['Type', typeSelect]) : null,
      loginFields,
      el('label', {}, ['Notes', notesInput]),
      el('footer', { class: 'form-actions' }, [deleteBtn, cancelBtn, readOnlyNotice ? null : saveBtn].filter(Boolean)),
    ]);

    if (readOnlyNotice) {
      // Still viewable/deletable, just not editable through this minimal UI.
      nameInput.disabled = true;
      notesInput.disabled = true;
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (readOnlyNotice) return;
      hideBanner(banner);
      saveBtn.setAttribute('aria-busy', 'true');
      try {
        const currentType = Number(typeSelect.value);
        const { encKey, macKey } = session.userKey;

        const cipherData = {
          type: currentType,
          name: await Crypto.encryptString(nameInput.value, encKey, macKey),
          notes: notesInput.value ? await Crypto.encryptString(notesInput.value, encKey, macKey) : null,
          // Preserve everything this minimal UI doesn't understand, unchanged.
          folderId: item?.raw?.folderId ?? null,
          organizationId: null,
          favorite: item?.raw?.favorite ?? false,
          reprompt: item?.raw?.reprompt ?? 0,
          fields: item?.raw?.fields ?? null,
          passwordHistory: item?.raw?.passwordHistory ?? null,
          key: item?.raw?.key ?? null,
          id: item?.id,
        };

        if (currentType === CIPHER_TYPE.LOGIN) {
          cipherData.login = {
            username: usernameInput.value ? await Crypto.encryptString(usernameInput.value, encKey, macKey) : null,
            password: passwordInput.value ? await Crypto.encryptString(passwordInput.value, encKey, macKey) : null,
            uris: uriInput.value
              ? [{ uri: await Crypto.encryptString(uriInput.value, encKey, macKey), match: null }]
              : item?.raw?.login?.uris ?? [],
            totp: item?.raw?.login?.totp ?? null,
            passwordRevisionDate: item?.raw?.login?.passwordRevisionDate ?? null,
          };
        } else if (currentType === CIPHER_TYPE.SECURE_NOTE) {
          cipherData.secureNote = item?.raw?.secureNote ?? { type: 0 };
        }

        let saved;
        if (isNew) {
          saved = await Api.createCipher(session.accessToken, cipherData);
        } else {
          saved = await Api.updateCipher(session.accessToken, item.id, cipherData);
        }

        const decrypted = await decryptCipher(saved);
        vaultItems = vaultItems.filter((v) => v.id !== decrypted.id);
        vaultItems.push(decrypted);
        renderList();
        dialog.close();
      } catch (err) {
        showBanner(banner, err.message || 'Failed to save item.');
      } finally {
        saveBtn.removeAttribute('aria-busy');
      }
    });

    return form;
  }

  $('#item-dialog-close').addEventListener('click', () => dialog.close());
})();
