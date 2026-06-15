from datetime import datetime, timezone

from flask import flash, redirect, render_template_string, request, url_for

from ..auth import admin_required
from ..core import app, _lang, load_users, save_users
from ..i18n import t
from ..traffic import collect_traffic, fmt_bytes, load_traffic
from ..ui import CSS, flash_html, nav_bar, page_head
from ..wireguard import client_name, delete_device, get_all_devices, get_user_devices

@app.route("/traffic")
@admin_required
def traffic_page():
    try:
        collect_traffic()
    except Exception:
        pass
    traffic = load_traffic()
    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    all_devices = get_all_devices()
    lang = _lang()
    # First pass: totals only
    total_rx = total_tx = 0
    for owner, device, wg_name in all_devices:
        curr = traffic.get(wg_name, {}).get("monthly", {}).get(month_key, {"rx": 0, "tx": 0})
        total_rx += curr["rx"]
        total_tx += curr["tx"]
    nodata_label = f'<span style="color:#8b949e;font-size:11px">{t("tr_nodata", lang)}</span>'
    rows = ""
    for owner, device, wg_name in all_devices:
        entry = traffic.get(wg_name, {})
        monthly = entry.get("monthly", {})
        curr = monthly.get(month_key, {"rx": 0, "tx": 0})
        history = ""
        for mk in sorted(monthly.keys(), reverse=True)[:3]:
            m = monthly[mk]
            history += f'<span style="color:#8b949e;font-size:11px">{mk}: ↓{fmt_bytes(m["tx"])} ↑{fmt_bytes(m["rx"])}</span><br>'
        rows += f"""<tr>
          <td><span style="font-family:monospace;color:#8b949e">{owner}</span></td>
          <td><span style="font-family:monospace;color:#58a6ff">{device}</span></td>
          <td style="color:#3fb950">↓ {fmt_bytes(curr["tx"])}</td>
          <td style="color:#f78166">↑ {fmt_bytes(curr["rx"])}</td>
          <td>{history if history else nodata_label}</td>
        </tr>"""
    empty = f'<tr><td colspan="5" style="color:#8b949e;padding:16px">{t("tr_nodiv", lang)}</td></tr>' if not rows else ""
    html = page_head(f"Traffic {month_key}") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>📊 Traffic — {month_key}</h1>
    <p class="sub">{t("tr_sub", lang)}</p>
    <div style="display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap">
      <div class="stat-box"><div class="stat-num" style="color:#3fb950">{fmt_bytes(total_tx)}</div><div class="stat-lbl">{t("tr_total_dl", lang)}</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#f78166">{fmt_bytes(total_rx)}</div><div class="stat-lbl">{t("tr_total_ul", lang)}</div></div>
      <div class="stat-box"><div class="stat-num">{fmt_bytes(total_rx + total_tx)}</div><div class="stat-lbl">{t("tr_combined", lang)}</div></div>
    </div>
    <div class="tbl-wrap">
    <table><thead><tr><th>{t("tr_col_owner", lang)}</th><th>{t("tr_col_dev", lang)}</th><th>{t("tr_col_dl", lang)}</th><th>{t("tr_col_ul", lang)}</th><th>{t("tr_col_hist", lang)}</th></tr></thead>
    <tbody>{rows}{empty}</tbody></table>
    </div>
    <p style="color:#8b949e;font-size:12px;margin-top:12px">{t("tr_warn", lang)}</p>
  </div>
</div>"""
    return render_template_string(html)

# ─── Routes: Admin────────────────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin_panel():
    users = load_users()
    pending = [u for u, d in users.items() if not d["approved"] and d["role"] != "admin"]
    all_devices = get_all_devices()

    pending_rows = ""
    for u in pending:
        pending_rows += f"""<tr>
          <td><span style="font-family:monospace">{u}</span></td>
          <td>{users[u]['created_at']}</td>
          <td>
            <form method="POST" action="/admin/users/{u}/approve" style="display:inline">
              <input type="number" name="max_devices" value="3" min="1" max="50"
                     style="width:60px;margin:0 4px 0 0;padding:4px">
              <button class="btn g" style="padding:4px 10px;font-size:12px">Approve</button>
            </form>
            <a href="/admin/users/{u}/delete" class="btn r"
               style="padding:4px 10px;font-size:12px"
               onclick="return confirm('Delete user {u}?')">Delete</a>
          </td>
        </tr>"""

    html = page_head("Admin") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>⚙️ Admin Panel</h1>
    <p class="sub">Overview</p>
    <div class="row" style="gap:12px;margin-bottom:0">
      <div class="stat-box">
        <div class="stat-num" style="color:var(--accent)">{len(users)}</div>
        <div class="stat-lbl">Total users</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:var(--pend)">{len(pending)}</div>
        <div class="stat-lbl">Pending</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:var(--ok)">{len(all_devices)}</div>
        <div class="stat-lbl">Total devices</div>
      </div>
    </div>
  </div>

  {"" if not pending else f'''
  <div class="card">
    <h2>⏳ Pending Approvals ({len(pending)})</h2>
    <div class="tbl-wrap">
    <table><thead><tr><th>Username</th><th>Registered</th><th>Actions</th></tr></thead>
    <tbody>{pending_rows}</tbody></table>
    </div>
  </div>'''}

  <div class="card">
    <div class="row">
      <a href="/admin/users" class="btn b">👥 Manage Users</a>
      <a href="/admin/devices" class="btn b">📱 All Devices</a>
    </div>
  </div>
</div>"""
    return render_template_string(html)

@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    rows = ""
    for u, d in sorted(users.items()):
        devices = get_user_devices(u)
        max_d = d.get("max_devices", 3)
        limit = "∞" if max_d == -1 else str(max_d)
        amount = "∞ / ∞" if d["role"] == "admin" else f"{len(devices)} / {limit}"
        role_tag = '<span class="tag tag-admin">admin</span>' if d["role"] == "admin" \
                   else ('<span class="tag tag-ok">active</span>' if d["approved"]
                         else '<span class="tag tag-pend">pending</span>')
        edit_btn = "" if d["role"] == "admin" else f"""
          <form method="POST" action="/admin/users/{u}/edit" style="display:inline;gap:4px">
            <input type="number" name="max_devices" value="{max_d if max_d != -1 else ''}"
                   placeholder="∞" min="1" max="100"
                   style="width:55px;margin:0 4px 0 0;padding:3px 6px;font-size:12px">
            <button class="btn y" style="padding:4px 8px;font-size:11px">Save</button>
          </form>"""
        del_btn = "" if d["role"] == "admin" else \
            f'<a href="/admin/users/{u}/delete" class="btn r" style="padding:4px 8px;font-size:11px" onclick="return confirm(\'Delete {u} and all their devices?\')">Delete</a>'
        approve_btn = "" if d["approved"] else \
            f'<form method="POST" action="/admin/users/{u}/approve" style="display:inline"><input type="hidden" name="max_devices" value="3"><button class="btn g" style="padding:4px 8px;font-size:11px">Approve</button></form>'

        rows += f"""<tr>
          <td><span style="font-family:monospace">{u}</span></td>
          <td>{role_tag}</td>
          <td>{amount}</td>
          <td>{d['created_at']}</td>
          <td>{approve_btn} {edit_btn} {del_btn}</td>
        </tr>"""

    html = page_head("Users") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>👥 Users</h1>
    <p class="sub">Manage accounts and device limits</p>
    {flash_html()}
    <div class="tbl-wrap">
    <table>
      <thead><tr><th>Username</th><th>Status</th><th>Amount</th>
             <th>Registered</th><th>Actions</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>
  </div>
</div>"""
    return render_template_string(html)

@app.route("/admin/users/<username>/approve", methods=["POST"])
@admin_required
def admin_approve(username):
    users = load_users()
    if username in users and users[username]["role"] != "admin":
        try:
            max_d = int(request.form.get("max_devices", 3))
        except ValueError:
            max_d = 3
        users[username]["approved"] = True
        users[username]["max_devices"] = max_d
        save_users(users)
        flash(f"User '{username}' approved with {max_d} device limit.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/edit", methods=["POST"])
@admin_required
def admin_edit(username):
    users = load_users()
    if username in users and users[username]["role"] != "admin":
        val = request.form.get("max_devices", "").strip()
        try:
            users[username]["max_devices"] = -1 if not val else int(val)
        except ValueError:
            flash("Invalid device limit value.", "error")
            return redirect(url_for("admin_users"))
        save_users(users)
        flash(f"User '{username}' updated.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/delete")
@admin_required
def admin_delete_user(username):
    users = load_users()
    if username in users and users[username]["role"] != "admin":
        # Delete all their devices
        for device in get_user_devices(username):
            delete_device(client_name(username, device))
        del users[username]
        save_users(users)
        flash(f"User '{username}' and all their devices deleted.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/devices")
@admin_required
def admin_devices():
    all_devices = get_all_devices()
    rows = ""
    for owner, device, wg_name in all_devices:
        rows += f"""<tr>
          <td><span style="font-family:monospace;color:#8b949e">{owner}</span></td>
          <td><span style="font-family:monospace;color:#58a6ff">{device}</span></td>
          <td>
            <a href="/device/{wg_name}" class="btn b" style="padding:4px 10px;font-size:12px">View</a>
            <a href="/device/{wg_name}/delete" class="btn r" style="padding:4px 10px;font-size:12px"
               onclick="return confirm('Remove {wg_name}?')">Remove</a>
          </td>
        </tr>"""
    empty = '<tr><td colspan="3" style="color:#8b949e;padding:16px">No devices.</td></tr>' if not rows else ""

    html = page_head("All Devices") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>📱 All Devices ({len(all_devices)})</h1>
    <p class="sub">Every WireGuard client across all users</p>
    {flash_html()}
    <div class="tbl-wrap">
    <table><thead><tr><th>Owner</th><th>Device</th><th>Actions</th></tr></thead>
    <tbody>{rows}{empty}</tbody></table>
    </div>
  </div>
</div>"""
    return render_template_string(html)
