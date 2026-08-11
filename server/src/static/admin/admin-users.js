"use strict";
/* eslint-env es2017, browser */
/* global _post:readable, _delete:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

function deleteUser(event) {
  event.preventDefault();
  const cell = event.target.closest("[data-vw-user-uuid]");
  const id = cell.dataset.vwUserUuid;
  const email = cell.dataset.vwUserEmail;
  const input_email = prompt(`To delete user "${email}", please type the email below`);
  if (input_email != null) {
    if (input_email === email) {
      _post(`${BASE_URL}/admin/users/${id}/delete`, "User deleted correctly", "Error deleting user");
    } else {
      alert("Wrong email, please try again");
    }
  }
}

function remove2fa(event) {
  event.preventDefault();
  const cell = event.target.closest("[data-vw-user-uuid]");
  const id = cell.dataset.vwUserUuid;
  const email = cell.dataset.vwUserEmail;
  if (confirm(`Are you sure you want to remove 2FA for "${email}"?`)) {
    _post(`${BASE_URL}/admin/users/${id}/remove-2fa`, "2FA removed correctly", "Error removing 2FA");
  }
}

function deauthUser(event) {
  event.preventDefault();
  const cell = event.target.closest("[data-vw-user-uuid]");
  const id = cell.dataset.vwUserUuid;
  const email = cell.dataset.vwUserEmail;
  if (confirm(`Are you sure you want to deauthorize sessions for "${email}"?`)) {
    _post(`${BASE_URL}/admin/users/${id}/deauth`, "Sessions deauthorized correctly", "Error deauthorizing sessions");
  }
}

function disableUser(event) {
  event.preventDefault();
  const cell = event.target.closest("[data-vw-user-uuid]");
  const id = cell.dataset.vwUserUuid;
  const email = cell.dataset.vwUserEmail;
  if (confirm(`Are you sure you want to disable user "${email}"? This will also deauthorize their sessions.`)) {
    _post(`${BASE_URL}/admin/users/${id}/disable`, "User disabled successfully", "Error disabling user");
  }
}

function enableUser(event) {
  event.preventDefault();
  const cell = event.target.closest("[data-vw-user-uuid]");
  const id = cell.dataset.vwUserUuid;
  const email = cell.dataset.vwUserEmail;
  if (confirm(`Are you sure you want to enable user "${email}"?`)) {
    _post(`${BASE_URL}/admin/users/${id}/enable`, "User enabled successfully", "Error enabling user");
  }
}

function resendUserInvite(event) {
  event.preventDefault();
  const cell = event.target.closest("[data-vw-user-uuid]");
  const id = cell.dataset.vwUserUuid;
  const email = cell.dataset.vwUserEmail;
  if (confirm(`Are you sure you want to resend invitation for "${email}"?`)) {
    _post(`${BASE_URL}/admin/users/${id}/invite/resend`, "Invite sent successfully", "Error resending invite");
  }
}

function updateRevisions(event) {
  event.preventDefault();
  _post(`${BASE_URL}/admin/users/update_revision`, "Success, clients will sync next time they connect", "Error forcing clients to sync");
}

function inviteUser(event) {
  event.preventDefault();
  const email = document.getElementById("inviteEmail");
  const data = JSON.stringify({ email: email.value });
  email.value = "";
  _post(`${BASE_URL}/admin/invite`, "User invited correctly", "Error inviting user", data);
}

function initUserTable() {
  document.querySelectorAll("button[vw-remove2fa]").forEach((btn) => btn.addEventListener("click", remove2fa));
  document.querySelectorAll("button[vw-deauth-user]").forEach((btn) => btn.addEventListener("click", deauthUser));
  document.querySelectorAll("button[vw-delete-user]").forEach((btn) => btn.addEventListener("click", deleteUser));
  document.querySelectorAll("button[vw-disable-user]").forEach((btn) => btn.addEventListener("click", disableUser));
  document.querySelectorAll("button[vw-enable-user]").forEach((btn) => btn.addEventListener("click", enableUser));
  document.querySelectorAll("button[vw-resend-user-invite]").forEach((btn) => btn.addEventListener("click", resendUserInvite));

  if (typeof jdenticon !== "undefined") jdenticon();
}

// ---- Lightweight vanilla replacement for DataTables: click-to-sort + search ----
function initSortAndSearch() {
  const table = document.getElementById("users-table");
  const tbody = table.querySelector("tbody");
  const rows = Array.from(tbody.querySelectorAll("tr"));

  document.querySelectorAll("th[data-sortable]").forEach((th) => {
    let dir = 1;
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      rows.sort((a, b) => {
        const av = a.dataset[key] || "";
        const bv = b.dataset[key] || "";
        const an = parseFloat(av);
        const bn = parseFloat(bv);
        const cmp = !isNaN(an) && !isNaN(bn) ? an - bn : av.localeCompare(bv);
        return cmp * dir;
      });
      dir *= -1;
      rows.forEach((r) => tbody.append(r));
    });
  });

  const search = document.getElementById("users-search");
  if (search) {
    search.addEventListener("input", () => {
      const q = search.value.trim().toLowerCase();
      rows.forEach((r) => {
        r.hidden = q && !(r.dataset.name || "").toLowerCase().includes(q);
      });
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initUserTable();
  initSortAndSearch();

  document.getElementById("updateRevisions")?.addEventListener("click", updateRevisions);
  document.getElementById("reload")?.addEventListener("click", reload);
  document.getElementById("inviteUserForm")?.addEventListener("submit", inviteUser);
});
