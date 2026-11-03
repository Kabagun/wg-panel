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

document.querySelectorAll("[data-traffic-scope]").forEach((scope) => {
  const table = scope.querySelector("[data-traffic-table]");
  const body = table.tBodies[0];
  // Move whole rows so history popovers and device links stay with their data.
  const rows = Array.from(body.children).filter((row) => row.hasAttribute("data-traffic-download"));
  const originalOrder = new Map(rows.map((row, index) => [row, index]));
  const buttons = scope.querySelectorAll("[data-traffic-sort]");
  let selected = null;
  let direction = "descending";
  buttons.forEach((button) => button.addEventListener("click", () => {
    const key = button.dataset.trafficSort;
    direction = selected === key && direction === "descending" ? "ascending" : "descending";
    selected = key;
    const field = key === "download" ? "trafficDownload" : "trafficUpload";
    const sign = direction === "descending" ? -1 : 1;
    rows.sort((a, b) => sign * (Number(a.dataset[field]) - Number(b.dataset[field]))
      || originalOrder.get(a) - originalOrder.get(b));
    rows.forEach((row) => body.append(row));
    scope.querySelectorAll("[data-traffic-heading]").forEach((heading) => {
      heading.setAttribute("aria-sort", heading.dataset.trafficHeading === key ? direction : "none");
    });
    buttons.forEach((control) => {
      const active = control.dataset.trafficSort === key;
      control.setAttribute("aria-pressed", String(active));
      control.querySelector(".sort-indicator").textContent = active ? (direction === "descending" ? "↓" : "↑") : "↕";
      const next = active && direction === "descending" ? scope.dataset.sortAscending : scope.dataset.sortDescending;
      control.setAttribute("aria-label", `${control.dataset.sortLabel}: ${next}`);
    });
    const current = direction === "descending" ? scope.dataset.sortDescending : scope.dataset.sortAscending;
    scope.querySelector("[data-traffic-sort-status]").textContent = `${button.dataset.sortLabel}: ${current}`;
  }));
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

function confirmSafeInternet(message) {
  const dialog = document.getElementById("safe-internet-dialog");
  if (!dialog?.showModal) return Promise.resolve(window.confirm(message));
  return new Promise((resolve) => {
    dialog.returnValue = "";
    dialog.querySelector("[data-safe-cancel]").onclick = () => dialog.close("cancel");
    dialog.querySelector("[data-safe-accept]").onclick = () => dialog.close("confirm");
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), {once: true});
    dialog.showModal();
    dialog.querySelector("[data-safe-cancel]").focus();
  });
}

document.querySelectorAll("[data-auto-submit]").forEach((form) => {
  const toggle = form.querySelector("[data-auto-toggle]");
  const lockButton = form.querySelector("[data-safe-lock]");
  const savedEnabled = toggle.checked;
  toggle.disabled = false;
  if (lockButton) {
    lockButton.disabled = false;
    lockButton.addEventListener("click", () => { toggle.checked = true; });
  }
  toggle.addEventListener("change", () => form.requestSubmit());
  form.addEventListener("submit", (event) => {
    if (form.dataset.saving === "true") {
      event.preventDefault();
      return;
    }
    const consent = form.querySelector('[name="safe_internet_confirmed"]');
    if (toggle.checked && form.dataset.safeConfirmation && consent?.value !== "on") {
      event.preventDefault();
      if (form.dataset.confirming === "true") return;
      form.dataset.confirming = "true";
      toggle.disabled = true;
      if (lockButton) lockButton.disabled = true;
      confirmSafeInternet(form.dataset.safeConfirmation).then((accepted) => {
        delete form.dataset.confirming;
        toggle.disabled = false;
        if (lockButton) lockButton.disabled = false;
        toggle.checked = accepted || savedEnabled;
        if (accepted) {
          consent.value = "on";
          form.requestSubmit();
        } else {
          consent.value = "";
          toggle.focus();
        }
      });
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
    if (lockButton) lockButton.disabled = true;
    form.dataset.saving = "true";
    form.setAttribute("aria-busy", "true");
    form.querySelector('[role="status"]').textContent = form.dataset.savingLabel;
  });
});
// A back/forward cache restore must reconcile state instead of showing an old switch/config.
window.addEventListener("pageshow", (event) => {
  if (event.persisted && document.querySelector("[data-device-policy]")) window.location.reload();
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

function setupDeviceDeletion(workspace, dialog = null) {
  workspace.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    event.preventDefault();
    if (dialog) dialog.close();
    else workspace.querySelector("[data-delete-cancel]")?.click();
  });
  if (dialog) workspace.querySelectorAll("[data-delete-cancel]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      dialog.close();
    });
  });
  const field = workspace.querySelector("[data-delete-exact-name]");
  if (!field) return;
  const status = workspace.querySelector("[data-delete-input-status]");
  const submit = workspace.querySelector("[data-delete-submit]");
  let lastTypedValue = "";
  let manualInputPending = false;
  let composing = false;
  const validate = () => {
    const matches = field.value === field.dataset.deleteExactName;
    field.setCustomValidity(matches ? "" : field.dataset.mismatchMessage);
    submit.disabled = !matches;
  };
  const blockTransfer = (event) => {
    event.preventDefault();
    status.textContent = status.dataset.pasteMessage;
    field.focus();
  };
  field.addEventListener("paste", blockTransfer);
  field.addEventListener("drop", blockTransfer);
  field.addEventListener("dragover", (event) => event.preventDefault());
  field.addEventListener("compositionstart", () => { composing = true; });
  field.addEventListener("compositionend", () => { composing = false; });
  field.addEventListener("beforeinput", (event) => {
    manualInputPending = /^(insertText|insertCompositionText|delete.*|historyUndo|historyRedo)$/.test(event.inputType || "");
    if (!manualInputPending || event.dataTransfer) {
      manualInputPending = false;
      blockTransfer(event);
    }
  });
  field.addEventListener("input", (event) => {
    // Some autofill engines emit input without a cancelable beforeinput. Keep
    // only changes preceded by ordinary typing, deletion or IME composition.
    if ((!manualInputPending && !composing) || event.inputType === "insertReplacementText") {
      field.value = lastTypedValue;
      status.textContent = status.dataset.pasteMessage;
    } else {
      lastTypedValue = field.value;
      status.textContent = "";
    }
    manualInputPending = false;
    validate();
  });
  field.value = "";
  validate();
}

document.querySelectorAll("[data-device-deletion]").forEach((workspace) => setupDeviceDeletion(workspace));

document.querySelectorAll("[data-delete-open]").forEach((opener) => {
  opener.addEventListener("click", async (event) => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey
        || !window.HTMLDialogElement?.prototype.showModal || !window.fetch) return;
    event.preventDefault();
    if (opener.getAttribute("aria-busy") === "true") return;
    opener.setAttribute("aria-busy", "true");
    try {
      const response = await fetch(opener.href, {credentials: "same-origin", headers: {Accept: "text/html"}});
      if (!response.ok || response.redirected) throw new Error("Confirmation unavailable");
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      const content = page.querySelector("[data-device-deletion]");
      if (!content) throw new Error("Confirmation unavailable");
      const dialog = document.createElement("dialog");
      dialog.className = "device-delete-dialog";
      dialog.setAttribute("aria-labelledby", "deletion-title");
      dialog.setAttribute("aria-describedby", "deletion-description deletion-device-name");
      const workspace = document.importNode(content, true);
      dialog.append(workspace);
      document.body.append(dialog);
      setupDeviceDeletion(workspace, dialog);
      dialog.addEventListener("close", () => {
        dialog.remove();
        if (opener.isConnected) opener.focus();
      }, {once: true});
      dialog.showModal();
      workspace.querySelector("[data-delete-cancel]").focus();
    } catch {
      window.location.assign(opener.href);
    } finally {
      opener.removeAttribute("aria-busy");
    }
  });
});
