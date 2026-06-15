from flask import Response, flash, redirect, render_template_string, request, session, url_for

from ..auth import approved_required
from ..core import app, _lang, _now, load_users
from ..i18n import t
from ..telegram import send_telegram
from ..ui import CSS, flash_html, nav_bar, page_head
from ..wireguard import client_name, create_device, delete_device, get_config, get_user_devices, qr_svg_b64

@app.route("/dashboard")
@approved_required
def dashboard():
    u = session["user"]
    users = load_users()
    usr = users.get(u, {})
    is_admin = usr.get("role") == "admin"
    devices = get_user_devices(u)
    max_d = usr.get("max_devices", 3)
    limit_str = "unlimited" if max_d == -1 else str(max_d)
    used = len(devices)
    can_add = max_d == -1 or used < max_d
    lang = _lang()
    limit_str = t("dash_unlim", lang) if max_d == -1 else str(max_d)

    rows = ""
    for d in devices:
        wg = client_name(u, d)
        rows += f"""<tr>
          <td><span style="font-family:monospace;color:#58a6ff">{d}</span></td>
          <td><a href="/device/{wg}" class="btn b" style="padding:4px 10px;font-size:12px">{t("dash_view_qr", lang)}</a>
              <a href="/device/{wg}/delete" class="btn r" style="padding:4px 10px;font-size:12px"
                 onclick="return confirm('{d}?')">{t("dash_remove", lang)}</a></td>
        </tr>"""

    empty = f'<tr><td colspan="2" style="color:#8b949e;padding:16px">{t("dash_empty", lang)}</td></tr>' if not rows else ""
    add_btn = f'<a href="/add" class="btn g">{t("dash_add_btn", lang)}</a>' if can_add else \
              f'<span style="color:#8b949e;font-size:13px">{t("dash_limit", lang).format(n=max_d)}</span>'

    html = page_head(t("dash_title", lang)) + CSS + f"""
<div class="wide">
  {nav_bar(is_admin)}
  <div class="card">
    <h1>{t("dash_title", lang)}</h1>
    <p class="sub">{t("dash_logged", lang)} <b>{u}</b> &nbsp;·&nbsp;
       {used} / {limit_str} {t("dash_used", lang)}</p>
    {flash_html()}
    <div class="tbl-wrap">
    <table><thead><tr><th>{t("dash_col_dev", lang)}</th><th>{t("dash_col_act", lang)}</th></tr></thead>
    <tbody>{rows}{empty}</tbody></table>
    </div>
    <hr>
    {add_btn}
  </div>
</div>"""
    return render_template_string(html)

@app.route("/add", methods=["GET", "POST"])
@approved_required
def add_device():
    u = session["user"]
    users = load_users()
    usr = users.get(u, {})
    is_admin = usr.get("role") == "admin"
    max_d = usr.get("max_devices", 3)

    if request.method == "POST":
        device = request.form.get("device", "").strip().lower()
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        if not device or not all(c in allowed for c in device) or device[0] in "-_" or device[-1] in "-_":
            flash(t("flash_add_invalid", _lang()), "error")
        else:
            devices = get_user_devices(u)
            if max_d != -1 and len(devices) >= max_d:
                flash(t("flash_add_limit", _lang()).format(n=max_d), "error")
            elif device in devices:
                return redirect(url_for("view_device", wg_name=client_name(u, device)))
            else:
                wg = client_name(u, device)
                ok, err = create_device(wg)
                if ok:
                    send_telegram(
                        f"📱 *Device added*\n\n"
                        f"👤 User: `{u}`\n"
                        f"🔌 Device: `{device}`\n"
                        f"🕐 Time: {_now()}",
                        silent=True
                    )
                    return redirect(url_for("view_device", wg_name=wg))
                else:
                    flash(f"Failed to create device: {err}", "error")

    lang = _lang()
    html = page_head("Add Device") + CSS + f"""
<div class="wrap">
  {nav_bar(is_admin)}
  <div class="card">
    <h1>➕ Add Device</h1>
    <p class="sub">{t("add_sub", lang)}</p>
    {flash_html()}
    <form method="POST">
      <label>{t("add_label", lang)}</label>
      <input type="text" name="device" pattern="[a-z0-9][a-z0-9_-]*[a-z0-9]|[a-z0-9]"
             placeholder="phone, pipyao-router, my_laptop" title="Lowercase letters, numbers, dashes and underscores" required autofocus>
      <button class="btn g btn-full" type="submit">{t("add_btn", lang)}</button>
    </form>
    <p style="color:var(--text2);font-size:12px;margin-top:12px">
      {t("add_tip", lang)}
    </p>
  </div>
</div>"""
    return render_template_string(html)

@app.route("/device/<wg_name>")
@approved_required
def view_device(wg_name):
    u = session["user"]
    users = load_users()
    is_admin = users.get(u, {}).get("role") == "admin"

    # Users can only see their own devices (admin can see all)
    if not is_admin and not wg_name.startswith(f"{u}-"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    config = get_config(wg_name)
    if not config:
        flash("Device not found.", "error")
        return redirect(url_for("dashboard"))

    qr = qr_svg_b64(wg_name)
    lang = _lang()
    display_name = wg_name.split("-", 1)[1] if "-" in wg_name else wg_name
    qr_block = f'<div class="qr"><img src="{qr}" alt="QR"></div>' if qr else \
               '<p style="color:#8b949e">QR unavailable</p>'

    type_badge = ""
    app_hint = ""
    app_links = """<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      <a href="https://apps.apple.com/app/wireguard/id1441195209" target="_blank" rel="noopener"
         class="btn b" style="font-size:12px;padding:5px 12px;text-decoration:none">
        📱 iOS / macOS
      </a>
      <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener"
         class="btn b" style="font-size:12px;padding:5px 12px;text-decoration:none">
        💻 Windows / Linux / macOS
      </a>
    </div>"""
    config_hint = ("WireGuard → + → Сканировать QR код" if lang == "ru"
                   else "WireGuard app → + → Scan from QR code")
    ios_tip = ("💡 <b>iOS:</b> Откройте WireGuard → ➕ → <b>Сканировать QR</b> — без скачивания!"
               if lang == "ru" else
               "💡 <b>iOS:</b> Open WireGuard → ➕ → <b>Scan from QR code</b> — no download needed!")
    dl_btn_text = ("⬇️ Скачать или открыть в WireGuard (iOS · macOS)"
                   if lang == "ru" else "⬇️ Download or Open in WireGuard (iOS · macOS)")

    conf_section_title = "Текст конфига" if lang == "ru" else "Config Text"
    conf_section_hint  = ("Скопируйте и вставьте в приложение → Добавить туннель"
                          if lang == "ru" else "Copy and paste into the app → Add Tunnel → Add empty tunnel")
    remove_label   = "🗑️ Удалить устройство" if lang == "ru" else "🗑️ Remove this device"
    remove_confirm = "Удалить {d}? Это действие необратимо.".format(d=display_name) if lang == "ru" else f"Remove {display_name}? This cannot be undone."
    sub_text       = f"Конфигурация VPN для <b>{display_name}</b>" if lang == "ru" else f"VPN config for <b>{display_name}</b>"
    qr_heading     = "QR-код" if lang == "ru" else "QR Code"
    copy_hint      = "👆 Нажмите, чтобы скопировать" if lang == "ru" else "👆 Click to copy"
    copied_msg     = "✅ Скопировано!" if lang == "ru" else "✅ Copied!"

    html = page_head(display_name) + CSS + f"""
<div class="wrap">
  {nav_bar(is_admin)}
  <div class="card">
    <h1>📱 {display_name}{type_badge}</h1>
    <p class="sub">{sub_text}</p>
    {flash_html()}
    <h2>{qr_heading}</h2>
    {app_hint}
    <p style="color:#8b949e;font-size:12px;margin-bottom:4px">{config_hint}</p>
    <p style="color:#58a6ff;font-size:12px;margin-bottom:8px">{ios_tip}</p>
    {app_links}
    {qr_block}
    <hr>
    <h2>{conf_section_title}</h2>
    <p style="color:#8b949e;font-size:12px;margin-bottom:4px">{conf_section_hint}</p>
    <p style="color:#58a6ff;font-size:12px;margin-bottom:8px">{copy_hint}</p>
    <div class="conf" id="conf-block" onclick="copyConf(this)" title="{copy_hint}"
         style="cursor:pointer;position:relative;user-select:all">{config}</div>
    <div id="copy-toast" style="display:none;color:#3fb950;font-size:13px;margin:4px 0 8px">{copied_msg}</div>
    <a href="/device/{wg_name}/download" class="btn b btn-full" style="margin-bottom:8px">
       {dl_btn_text}
    </a>
    <a href="/device/{wg_name}/delete" class="btn r btn-full"
       onclick="return confirm('{remove_confirm}')">
       {remove_label}
    </a>
  </div>
</div>
<script>
function copyConf(el) {{
  const text = el.innerText;
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(showToast, fallback);
  }} else {{ fallback(); }}
  function fallback() {{
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    showToast();
  }}
  function showToast() {{
    const t = document.getElementById('copy-toast');
    t.style.display = 'block';
    setTimeout(() => t.style.display = 'none', 2000);
  }}
}}
</script>"""
    return render_template_string(html)

@app.route("/device/<wg_name>/download")
@approved_required
def download_device(wg_name):
    u = session["user"]
    users = load_users()
    is_admin = users.get(u, {}).get("role") == "admin"
    if not is_admin and not wg_name.startswith(f"{u}-"):
        return "Access denied", 403
    config = get_config(wg_name)
    if not config:
        return "Device not found", 404
    display_name = wg_name.split("-", 1)[1] if "-" in wg_name else wg_name
    return Response(
        config,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'inline; filename="{display_name}.conf"'}
    )

@app.route("/device/<wg_name>/delete")
@approved_required
def delete_device_route(wg_name):
    u = session["user"]
    users = load_users()
    is_admin = users.get(u, {}).get("role") == "admin"

    if not is_admin and not wg_name.startswith(f"{u}-"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    delete_device(wg_name)
    send_telegram(
        f"🗑️ *Device removed*\n\n"
        f"👤 By: `{u}`\n"
        f"🔌 Device: `{wg_name}`\n"
        f"🕐 Time: {_now()}",
        silent=True
    )
    flash(f"Device '{wg_name}' removed.", "ok")

    if is_admin and request.referrer and "/admin" in request.referrer:
        return redirect(url_for("admin_devices"))
    return redirect(url_for("dashboard"))
