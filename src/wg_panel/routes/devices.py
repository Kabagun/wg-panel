from flask import Response, flash, redirect, render_template_string, request, session, url_for
from markupsafe import escape

from ..auth import approved_required
from ..core import _lang, _now, app, load_users
from ..i18n import t
from ..security import csrf_input
from ..telegram import send_telegram
from ..ui import CSS, flash_html, nav_bar, page_head
from ..wireguard import (
    client_name,
    create_device,
    delete_device,
    get_config,
    get_device,
    get_user_devices,
    qr_svg_b64,
    set_device_safe_internet,
)


@app.route("/dashboard")
@approved_required
def dashboard():
    username = session["user"]
    user = load_users().get(username, {})
    is_admin = user.get("role") == "admin"
    devices = get_user_devices(username)
    max_devices = user.get("max_devices", 3)
    used = len(devices)
    can_add = max_devices == -1 or used < max_devices
    lang = _lang()
    limit_text = t("dash_unlim", lang) if max_devices == -1 else str(max_devices)
    rows = ""
    for device in devices:
        wg_name = client_name(username, device)
        rows += f"""<tr>
          <td><span class="mono device-name">{escape(device)}</span></td>
          <td><div class="table-actions"><a href="/device/{escape(wg_name)}" class="btn b">{t("dash_view_qr", lang)}</a>
              <form method="POST" action="/device/{escape(wg_name)}/delete"
                    onsubmit="return confirm('{escape(device)}?')">
                {csrf_input()}
                <button class="btn r">{t("dash_remove", lang)}</button>
              </form></div></td>
        </tr>"""

    empty = (
        f'<tr><td colspan="2" class="empty-state">{t("dash_empty", lang)}</td></tr>'
        if not rows
        else ""
    )
    add_button = (
        f'<a href="/add" class="btn g">{t("dash_add_btn", lang)}</a>'
        if can_add
        else f'<span class="field-help">{t("dash_limit", lang).format(n=max_devices)}</span>'
    )

    html = page_head(t("dash_title", lang)) + CSS + f"""
<div class="wide">
  {nav_bar(is_admin)}
  <div class="card">
    <div class="page-heading">
      <div><h1 class="page-title">{t("dash_title", lang)}</h1>
      <p class="sub">{t("dash_logged", lang)} <b>{escape(username)}</b> &nbsp;·&nbsp;
         {used} / {escape(limit_text)} {t("dash_used", lang)}</p></div>
    </div>
    {flash_html()}
    <div class="tbl-wrap">
    <table class="compact-table"><thead><tr><th>{t("dash_col_dev", lang)}</th><th>{t("dash_col_act", lang)}</th></tr></thead>
    <tbody>{rows}{empty}</tbody></table>
    </div>
    <hr>
    <div class="actions">{add_button}</div>
  </div>
</div>"""
    return render_template_string(html)


@app.route("/add", methods=["GET", "POST"])
@approved_required
def add_device():
    username = session["user"]
    user = load_users().get(username, {})
    is_admin = user.get("role") == "admin"
    max_devices = user.get("max_devices", 3)

    if request.method == "POST":
        device = request.form.get("device", "").strip().lower()
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        if (
            not 1 <= len(device) <= 64
            or not all(character in allowed for character in device)
            or device[0] in "-_"
            or device[-1] in "-_"
        ):
            flash(t("flash_add_invalid", _lang()), "error")
        else:
            ok, wg_name, error = create_device(username, device)
            if ok:
                send_telegram(
                    "📱 *Device added*\n\n"
                    f"👤 User: `{username}`\n"
                    f"🔌 Device: `{device}`\n"
                    f"🕐 Time: {_now()}",
                    silent=True,
                )
                return redirect(url_for("view_device", wg_name=wg_name))
            if error == "Device limit reached":
                flash(t("flash_add_limit", _lang()).format(n=max_devices), "error")
            else:
                flash(f"Failed to create device: {error}", "error")

    lang = _lang()
    html = page_head("Add Device") + CSS + f"""
<div class="wrap">
  {nav_bar(is_admin)}
  <div class="card">
    <div class="page-heading"><div><h1 class="page-title">➕ Add Device</h1></div></div>
    <p class="sub">{t("add_sub", lang)}</p>
    {flash_html()}
    <form method="POST" class="stack">
      {csrf_input()}
      <label for="device">{t("add_label", lang)}</label>
      <input type="text" id="device" name="device" pattern="[a-z0-9][a-z0-9_-]*[a-z0-9]|[a-z0-9]"
             maxlength="64" placeholder="phone, pipyao-router, my_laptop" required autofocus>
      <button class="btn g btn-full" type="submit">{t("add_btn", lang)}</button>
    </form>
    <p class="field-help field-help-spaced">{t("add_tip", lang)}</p>
  </div>
</div>"""
    return render_template_string(html)


def _authorized_device(wg_name):
    username = session["user"]
    user = load_users().get(username, {})
    device = get_device(wg_name)
    if not device:
        return None, user
    if user.get("role") != "admin" and device["owner"] != username:
        return None, user
    return device, user


@app.route("/device/<wg_name>")
@approved_required
def view_device(wg_name):
    device, user = _authorized_device(wg_name)
    if not device:
        flash("Device not found or access denied.", "error")
        return redirect(url_for("dashboard"))
    config = get_config(wg_name)
    if not config:
        flash("Device not found.", "error")
        return redirect(url_for("dashboard"))

    qr = qr_svg_b64(wg_name)
    lang = _lang()
    display_name = device["device"]
    qr_alt = "QR-код конфигурации WireGuard" if lang == "ru" else "WireGuard configuration QR code"
    copy_label = "Скопировать конфигурацию" if lang == "ru" else "Copy configuration"
    qr_block = (
        f'<div class="qr"><img src="{qr}" alt="{qr_alt}"></div>'
        if qr
        else '<p class="empty-state">QR unavailable</p>'
    )
    config_hint = (
        "WireGuard → + → Сканировать QR код"
        if lang == "ru"
        else "WireGuard app → + → Scan from QR code"
    )
    remove_label = "🗑️ Удалить устройство" if lang == "ru" else "🗑️ Remove this device"
    sub_text = (
        f"Конфигурация VPN для <b>{escape(display_name)}</b>"
        if lang == "ru"
        else f"VPN config for <b>{escape(display_name)}</b>"
    )
    config_title = "Текст конфига" if lang == "ru" else "Config Text"
    qr_heading = "QR-код" if lang == "ru" else "QR Code"
    copied = "✅ Скопировано!" if lang == "ru" else "✅ Copied!"
    safe_checked = " checked" if device["safe_internet"] else ""
    safe_status_key = "safe_status_on" if device["safe_internet"] else "safe_status_off"
    safe_status_class = "tag-ok" if device["safe_internet"] else "tag-pend"

    html = page_head(display_name) + CSS + f"""
<div class="wrap">
  {nav_bar(user.get("role") == "admin")}
  <div class="card">
    <div class="page-heading"><div><h1 class="page-title">📱 {escape(display_name)}</h1></div></div>
    <p class="sub">{sub_text}</p>
    {flash_html()}
    <form method="POST" action="/device/{escape(wg_name)}/safe-internet"
          class="safe-card"
          aria-labelledby="safe-internet-title"
          >
      {csrf_input()}
      <div class="safe-card-head">
        <div>
          <h2 id="safe-internet-title" class="safe-card-title">{t("safe_title", lang)}</h2>
          <span class="tag {safe_status_class}" role="status" aria-live="polite">{t(safe_status_key, lang)}</span>
        </div>
        <label for="safe-internet" class="safe-toggle">
          <input id="safe-internet" type="checkbox" name="safe_internet"{safe_checked}
                 aria-describedby="safe-internet-help">
          <span>{t("safe_toggle", lang)}</span>
        </label>
      </div>
      <p id="safe-internet-help" class="safe-help">{t("safe_help", lang)}</p>
      <button class="btn b" type="submit">{t("safe_save", lang)}</button>
    </form>
    <h2>{qr_heading}</h2>
    <p class="field-help section-hint">{config_hint}</p>
    <div class="actions section-actions">
      <a href="https://apps.apple.com/app/wireguard/id1441195209" target="_blank" rel="noopener" class="btn b">📱 iOS / macOS</a>
      <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener" class="btn b">💻 Install WireGuard</a>
    </div>
    {qr_block}
    <hr>
    <h2>{config_title}</h2>
    <div class="conf" id="conf-block" role="button" tabindex="0" aria-label="{copy_label}"
         onclick="copyConf(this)" onkeydown="copyConfKey(event, this)">{escape(config)}</div>
    <div id="copy-toast" class="copy-toast">{copied}</div>
    <a href="/device/{escape(wg_name)}/download" class="btn b btn-full download-btn">⬇️ Download / Open</a>
    <form method="POST" action="/device/{escape(wg_name)}/delete"
          onsubmit="return confirm('Remove {escape(display_name)}? This cannot be undone.')">
      {csrf_input()}
      <button class="btn r btn-full" type="submit">{remove_label}</button>
    </form>
  </div>
</div>
<script>
function copyConf(el) {{
  const text = el.innerText;
  const showToast = () => {{
    const toast = document.getElementById('copy-toast');
    toast.style.display = 'block'; setTimeout(() => toast.style.display = 'none', 2000);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(showToast);
  }}
}}
function copyConfKey(event, el) {{
  if (event.key === 'Enter' || event.key === ' ') {{
    event.preventDefault(); copyConf(el);
  }}
}}
</script>"""
    return render_template_string(html)


@app.route("/device/<wg_name>/safe-internet", methods=["POST"])
@approved_required
def update_device_safe_internet(wg_name):
    device, _user = _authorized_device(wg_name)
    if not device:
        flash("Device not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    enabled = request.form.get("safe_internet") == "on"
    if set_device_safe_internet(wg_name, enabled):
        flash(t("flash_safe_on" if enabled else "flash_safe_off", _lang()), "ok")
    else:
        flash(t("flash_safe_error", _lang()), "error")
    return redirect(url_for("view_device", wg_name=wg_name))


@app.route("/device/<wg_name>/download")
@approved_required
def download_device(wg_name):
    device, _user = _authorized_device(wg_name)
    if not device:
        return "Access denied", 403
    config = get_config(wg_name)
    if not config:
        return "Device not found", 404
    response = Response(config, mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = f'inline; filename="{device["device"]}.conf"'
    return response


@app.route("/device/<wg_name>/delete", methods=["POST"])
@approved_required
def delete_device_route(wg_name):
    device, user = _authorized_device(wg_name)
    if not device:
        flash("Device not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    ok, error = delete_device(wg_name)
    if not ok:
        flash(f"Failed to remove device: {error}", "error")
    else:
        send_telegram(
            "🗑️ *Device removed*\n\n"
            f"👤 By: `{session['user']}`\n"
            f"🔌 Device: `{device['device']}`\n"
            f"🕐 Time: {_now()}",
            silent=True,
        )
        flash(f"Device '{device['device']}' removed.", "ok")

    if user.get("role") == "admin" and request.form.get("return_to") == "admin":
        return redirect(url_for("admin_devices"))
    return redirect(url_for("dashboard"))
