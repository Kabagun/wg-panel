/* Navigation and ordinary forms work without JS; instant settings and search require it. */
"use strict";
document.documentElement.classList.add("js");

const menuToggle = document.querySelector(".menu-toggle");
const sidebar = document.getElementById("navigation");
function closeMenu() {
  document.documentElement.classList.remove("menu-open");
  menuToggle?.setAttribute("aria-expanded", "false");
}
menuToggle?.addEventListener("click", () => {
  const opened = document.documentElement.classList.toggle("menu-open");
  menuToggle.setAttribute("aria-expanded", String(opened));
  if (opened) sidebar?.querySelector(".nav-link.active, .nav-link")?.focus();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.documentElement.classList.contains("menu-open")) {
    closeMenu();
    menuToggle?.focus();
  }
});
window.matchMedia("(min-width: 761px)").addEventListener("change", closeMenu);

document.querySelectorAll("[data-history-trigger]").forEach((button) => {
  const popover = document.getElementById(button.getAttribute("popovertarget"));
  popover.addEventListener("toggle", (event) => {
    const opened = event.newState === "open";
    button.setAttribute("aria-expanded", String(opened));
    if (!opened) return;
    const anchor = button.getBoundingClientRect();
    const panel = popover.getBoundingClientRect();
    const edge = 12;
    const viewport = document.documentElement;
    const left = Math.max(edge, Math.min(anchor.right - panel.width, viewport.clientWidth - panel.width - edge));
    const below = anchor.bottom + 8;
    const top = below + panel.height <= viewport.clientHeight - edge
      ? below : Math.max(edge, anchor.top - panel.height - 8);
    Object.assign(popover.style, {left: `${left}px`, top: `${top}px`, right: "auto", bottom: "auto", margin: "0"});
  });
});
function closeHistory() {
  document.querySelectorAll(".history-popover:popover-open").forEach((popover) => popover.hidePopover());
}
window.addEventListener("resize", closeHistory);
document.addEventListener("scroll", (event) => {
  if (!(event.target instanceof Element) || !event.target.closest(".history-popover")) closeHistory();
}, {capture: true, passive: true});

document.querySelectorAll("[data-filter-scope]").forEach((scope) => {
  const input = scope.querySelector("[data-search]");
  input?.addEventListener("input", () => {
    const query = input.value.trim().toLocaleLowerCase();
    let matches = 0;
    const items = scope.querySelectorAll("[data-search-item]");
    items.forEach((item) => {
      const visible = item.dataset.searchItem.toLocaleLowerCase().includes(query);
      item.hidden = !visible;
      if (visible) matches += 1;
    });
    const empty = scope.querySelector("[data-search-empty]");
    if (empty) empty.hidden = matches > 0 || !query;
    const add = scope.querySelector(".add-device-card");
    if (add) add.hidden = Boolean(query);
  });
});

document.querySelectorAll("[data-password-target]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.passwordTarget);
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.setAttribute("aria-pressed", String(visible));
    button.setAttribute("aria-label", visible ? button.dataset.hideLabel : button.dataset.showLabel);
  });
});

document.querySelectorAll("[data-auto-submit]").forEach((form) => {
  const toggle = form.querySelector("[data-auto-toggle]");
  toggle.disabled = false;
  toggle.addEventListener("change", () => form.requestSubmit());
  form.addEventListener("submit", (event) => {
    if (form.dataset.saving === "true") {
      event.preventDefault();
      return;
    }
    // Snapshot the choice before disabling the switch; disabled inputs are not submitted.
    if (toggle.checked) {
      const value = document.createElement("input");
      value.type = "hidden";
      value.name = toggle.name;
      value.value = toggle.value;
      value.dataset.toggleSnapshot = "";
      form.append(value);
    }
    toggle.disabled = true;
    form.dataset.saving = "true";
    form.setAttribute("aria-busy", "true");
    form.querySelector('[role="status"]').textContent = form.dataset.savingLabel;
  });
});
// A back/forward cache restore must reconcile state instead of showing an old switch/config.
window.addEventListener("pageshow", (event) => {
  if (event.persisted && document.querySelector("[data-auto-submit]")) window.location.reload();
});

function copyFallback(text) {
  const field = document.createElement("textarea");
  field.value = text;
  field.className = "clipboard-buffer";
  field.readOnly = true;
  document.body.append(field);
  field.select();
  try {
    return document.execCommand("copy");
  } finally {
    field.remove();
  }
}

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copyTarget);
    const status = button.closest("section").querySelector("[data-copy-status]");
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(source.textContent);
      status.textContent = button.dataset.copySuccess;
    } catch {
      let copied = false;
      try { copied = copyFallback(source.textContent); } catch { /* Show the download alternative. */ }
      status.textContent = copied ? button.dataset.copySuccess : button.dataset.copyError;
      button.focus();
    }
  });
});

const confirmation = document.getElementById("confirm-dialog");
let pendingForm = null;
let pendingSubmitter = null;
let dialogOpener = null;
document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (form.dataset.confirmed === "true") return;
    if (!confirmation?.showModal) {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
      return;
    }
    event.preventDefault();
    pendingForm = form;
    pendingSubmitter = event.submitter;
    dialogOpener = document.activeElement;
    document.getElementById("confirm-description").textContent = form.dataset.confirm;
    confirmation.showModal();
    confirmation.querySelector("[data-dialog-cancel]").focus();
  });
});
confirmation?.querySelector("[data-dialog-cancel]").addEventListener("click", () => confirmation.close());
confirmation?.querySelector("[data-dialog-confirm]").addEventListener("click", () => {
  if (!pendingForm) return;
  const form = pendingForm;
  const submitter = pendingSubmitter;
  form.dataset.confirmed = "true";
  confirmation.close();
  form.requestSubmit(submitter || undefined);
  delete form.dataset.confirmed;
});
confirmation?.addEventListener("close", () => {
  pendingForm = null;
  pendingSubmitter = null;
  if (dialogOpener?.isConnected) dialogOpener.focus();
});
