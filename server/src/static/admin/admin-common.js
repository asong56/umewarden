"use strict";
/* eslint-env es2017, browser */
/* exported BASE_URL, _post, _delete, showToast */

function getBaseUrl() {
  const pathname = window.location.pathname;
  const adminPos = pathname.indexOf("/admin");
  const newPathname = pathname.substring(0, adminPos !== -1 ? adminPos : pathname.length);
  return `${window.location.origin}${newPathname}`;
}
const BASE_URL = getBaseUrl();

function reload() {
  window.location = window.location.href;
}

// A small, non-blocking toast in the corner instead of a blocking alert() -
// styled with acdn's .banner, not a Bootstrap toast component.
function showToast(text, type = "success") {
  if (!text) return;
  let host = document.getElementById("admin-toast-host");
  if (!host) {
    host = document.createElement("div");
    host.id = "admin-toast-host";
    host.style.cssText = "position:fixed;bottom:24px;right:24px;z-index:1000;max-width:360px;";
    document.body.append(host);
  }
  const toast = document.createElement("div");
  toast.className = "banner";
  toast.dataset.type = type;
  toast.style.marginTop = "8px";
  toast.textContent = text;
  host.append(toast);
  setTimeout(() => toast.remove(), 4000);
}

function msg(text, reload_page = true) {
  if (text) showToast(text, /error/i.test(text) ? "error" : "success");
  if (reload_page) setTimeout(reload, 600);
}

function _fetch(method, url, successMsg, errMsg, body, reload_page = true) {
  let respStatus;
  let respStatusText;
  return fetch(url, {
    method: method,
    body: body,
    mode: "same-origin",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
  })
    .then((resp) => {
      if (resp.ok) {
        msg(successMsg, reload_page);
        return Promise.reject({ error: false });
      }
      respStatus = resp.status;
      respStatusText = resp.statusText;
      return resp.text();
    })
    .then((respText) => {
      try {
        const respJson = JSON.parse(respText);
        if (respJson.errorModel && respJson.errorModel.message) {
          return respJson.errorModel.message;
        } else if (respJson.message) {
          return respJson.message;
        }
        return Promise.reject({ body: `${respStatus} - ${respStatusText}\n\nUnknown error`, error: true });
      } catch (e) {
        return Promise.reject({ body: `${respStatus} - ${respStatusText}\n\n[Catch] ${e}`, error: true });
      }
    })
    .then((apiMsg) => {
      msg(`${errMsg}: ${apiMsg}`, reload_page);
    })
    .catch((e) => {
      if (e.error === false) return true;
      msg(`${errMsg}: ${e.body}`, reload_page);
      return false;
    });
}

function _post(url, successMsg, errMsg, body, reload_page = true) {
  return _fetch("POST", url, successMsg, errMsg, body, reload_page);
}

function _delete(url, successMsg, errMsg, body, reload_page = true) {
  return _fetch("DELETE", url, successMsg, errMsg, body, reload_page);
}

// Highlight the current page in the nav (acdn nav-links, see base.hbs).
document.addEventListener("DOMContentLoaded", () => {
  const pathname = window.location.pathname;
  document.querySelectorAll(".nav-links a").forEach((a) => {
    if (a.getAttribute("href") === pathname) {
      a.setAttribute("aria-current", "page");
    }
  });
});
