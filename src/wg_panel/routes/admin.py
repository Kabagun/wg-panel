from datetime import UTC, datetime

from flask import flash, redirect, render_template_string, request, url_for
from markupsafe import escape

from ..auth import admin_required
from ..core import _lang, app, load_users, mutate_users
from ..i18n import t
from ..payments import (
    effective_due_date,
    next_effective_due_date,
    normalize_telegram_username,
    payment_price,
    payment_today,
)
from ..security import csrf_input
from ..traffic import collect_traffic, fmt_bytes, load_traffic
from ..ui import CSS, flash_html, nav_bar, page_head
from ..wireguard import delete_device, get_all_devices, get_user_devices


@app.route("/traffic")
@admin_required
def traffic_page():
    try:
        collect_traffic()
    except (OSError, ValueError):
        pass
    traffic = load_traffic()
    month_key = datetime.now(UTC).strftime("%Y-%m")
    all_devices = get_all_devices()
    lang = _lang()
    total_rx = total_tx = 0
    for _owner, _device, wg_name in all_devices:
        current = traffic.get(wg_name, {}).get("monthly", {}).get(month_key, {"rx": 0, "tx": 0})
        total_rx += current["rx"]
        total_tx += current["tx"]

    rows = ""
    for owner, device, wg_name in all_devices:
        monthly = traffic.get(wg_name, {}).get("monthly", {})
        current = monthly.get(month_key, {"rx": 0, "tx": 0})
        history = "".join(
            f'<span class="history">{escape(key)}: '
            f'↓{fmt_bytes(monthly[key]["tx"])} ↑{fmt_bytes(monthly[key]["rx"])}</span><br>'
            for key in sorted(monthly, reverse=True)[:3]
        )
        if not history:
            history = f'<span class="history">{t("tr_nodata", lang)}</span>'
        rows += f"""<tr>
          <td><span class="mono owner">{escape(owner)}</span></td>
          <td><span class="mono device-name">{escape(device)}</span></td>
          <td class="cell-down">↓ {fmt_bytes(current['tx'])}</td>
          <td class="cell-up">↑ {fmt_bytes(current['rx'])}</td>
          <td>{history}</td>
        </tr>"""
    if not rows:
        rows = f'<tr><td colspan="5" class="empty-state">{t("tr_nodiv", lang)}</td></tr>'

    html = page_head(f"Traffic {month_key}") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <div class="page-heading"><div><h1 class="page-title">📊 Traffic — {month_key}</h1>
    <p class="sub">{t("tr_sub", lang)}</p></div></div>
    <div class="metric-grid">
      <div class="stat-box"><div class="stat-num cell-down">{fmt_bytes(total_tx)}</div><div class="stat-lbl">{t("tr_total_dl", lang)}</div></div>
      <div class="stat-box"><div class="stat-num cell-up">{fmt_bytes(total_rx)}</div><div class="stat-lbl">{t("tr_total_ul", lang)}</div></div>
      <div class="stat-box"><div class="stat-num">{fmt_bytes(total_rx + total_tx)}</div><div class="stat-lbl">{t("tr_combined", lang)}</div></div>
    </div>
    <div class="tbl-wrap"><table><thead><tr><th>{t("tr_col_owner", lang)}</th><th>{t("tr_col_dev", lang)}</th><th>{t("tr_col_dl", lang)}</th><th>{t("tr_col_ul", lang)}</th><th>{t("tr_col_hist", lang)}</th></tr></thead>
    <tbody>{rows}</tbody></table></div>
  </div>
</div>"""
    return render_template_string(html)


@app.route("/admin")
@admin_required
def admin_panel():
    users = load_users()
    pending = [
        username
        for username, user in users.items()
        if not user.get("approved") and user.get("role") != "admin"
    ]
    all_devices = get_all_devices()
    pending_rows = ""
    for username in pending:
        user = users[username]
        telegram_username = normalize_telegram_username(user.get("telegram_username"))
        telegram = (
            f'<a href="https://t.me/{telegram_username}" target="_blank" rel="noopener">@{escape(telegram_username)}</a>'
            if telegram_username
            else "—"
        )
        pending_rows += f"""<tr>
          <td><span class="mono">{escape(username)}</span></td>
          <td>{telegram}</td><td>{escape(user.get('created_at', ''))}</td>
          <td>
            <div class="table-actions">
            <form method="POST" action="/admin/users/{escape(username)}/approve" class="inline">
              {csrf_input()}
              <input class="compact-input" type="number" name="max_devices" value="3" min="1" max="5" aria-label="Device limit">
              <button class="btn g">Approve</button>
            </form>
            <form method="POST" action="/admin/users/{escape(username)}/delete" class="inline" onsubmit="return confirm('Delete user?')">
              {csrf_input()}<button class="btn r">Delete</button>
            </form>
            </div>
          </td>
        </tr>"""

    pending_block = ""
    if pending:
        pending_block = f"""<div class="card"><h2>⏳ Pending Approvals ({len(pending)})</h2>
        <div class="tbl-wrap"><table><thead><tr><th>Username</th><th>Telegram</th><th>Registered</th><th>Actions</th></tr></thead>
        <tbody>{pending_rows}</tbody></table></div></div>"""

    html = page_head("Admin") + CSS + f"""
<div class="wide">{nav_bar(True)}
  <div class="card"><div class="page-heading"><div><h1 class="page-title">⚙️ Admin Panel</h1><p class="sub">Overview</p></div></div>
    <div class="metric-grid">
      <div class="stat-box"><div class="stat-num">{len(users)}</div><div class="stat-lbl">Total users</div></div>
      <div class="stat-box"><div class="stat-num">{len(pending)}</div><div class="stat-lbl">Pending</div></div>
      <div class="stat-box"><div class="stat-num">{len(all_devices)}</div><div class="stat-lbl">Total devices</div></div>
    </div>
  </div>
  {pending_block}
  <div class="card"><div class="actions">
    <a href="/admin/users" class="btn b">👥 Manage Users</a>
    <a href="/admin/devices" class="btn b">📱 All Devices</a>
  </div></div>
</div>"""
    return render_template_string(html)


@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    rows = ""
    for username, user in sorted(users.items()):
        devices = get_user_devices(username)
        max_devices = user.get("max_devices", 3)
        limit = "∞" if max_devices == -1 else str(max_devices)
        amount = "∞ / ∞" if user.get("role") == "admin" else f"{len(devices)} / {limit}"
        if user.get("role") == "admin":
            role_tag = '<span class="tag tag-admin">admin</span>'
        elif user.get("approved"):
            role_tag = '<span class="tag tag-ok">active</span>'
        else:
            role_tag = '<span class="tag tag-pend">pending</span>'

        telegram_username = normalize_telegram_username(user.get("telegram_username"))
        telegram = (
            f'<a href="https://t.me/{telegram_username}" target="_blank" rel="noopener">@{escape(telegram_username)}</a>'
            if telegram_username
            else "—"
        )
        price = payment_price(max_devices)
        payment = "—"
        if user.get("payment_enabled"):
            payment = f'<span class="tag tag-ok">{price} BYN · day {user.get("payment_day")}</span>'
        elif user.get("role") != "admin":
            payment = '<span class="tag tag-pend">disabled</span>'

        actions = ""
        if user.get("role") != "admin":
            approve = ""
            if not user.get("approved"):
                approve = f"""<form method="POST" action="/admin/users/{escape(username)}/approve" class="inline">
                    {csrf_input()}<input type="hidden" name="max_devices" value="3">
                    <button class="btn g">Approve</button></form>"""
            actions = f"""{approve}
              <a href="/admin/users/{escape(username)}/edit" class="btn y">Edit</a>
              <form method="POST" action="/admin/users/{escape(username)}/delete" class="inline" onsubmit="return confirm('Delete user and all devices?')">
                {csrf_input()}<button class="btn r">Delete</button>
              </form>"""
            actions = f'<div class="table-actions">{actions}</div>'

        rows += f"""<tr><td><span class="mono">{escape(username)}</span></td>
          <td>{role_tag}</td><td>{amount}</td><td>{telegram}</td><td>{payment}</td>
          <td>{escape(user.get('created_at', ''))}</td><td>{actions}</td></tr>"""

    html = page_head("Users") + CSS + f"""
<div class="wide">{nav_bar(True)}<div class="card">
  <div class="page-heading"><div><h1 class="page-title">👥 Users</h1><p class="sub">Manage accounts, device limits and payment reminders</p></div></div>
  {flash_html()}<div class="tbl-wrap"><table>
  <thead><tr><th>Username</th><th>Status</th><th>Devices</th><th>Telegram</th><th>Payment</th><th>Registered</th><th>Actions</th></tr></thead>
  <tbody>{rows}</tbody></table></div>
</div></div>"""
    return render_template_string(html)


def _limit_from_form():
    raw = request.form.get("max_devices", "").strip()
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value in {1, 2, 3, 4, 5, -1} else None


@app.route("/admin/users/<username>/approve", methods=["POST"])
@admin_required
def admin_approve(username):
    max_devices = _limit_from_form()
    if max_devices is None:
        flash("Invalid device limit. Use 1–5 or unlimited.", "error")
        return redirect(url_for("admin_users"))

    def approve(users):
        user = users.get(username)
        if not user or user.get("role") == "admin":
            return False
        user["approved"] = True
        user["max_devices"] = max_devices
        user.pop("approval_token", None)
        return True

    if mutate_users(approve):
        limit = "unlimited" if max_devices == -1 else str(max_devices)
        flash(f"User '{username}' approved with {limit} device limit.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<username>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit(username):
    user = load_users().get(username)
    if not user or user.get("role") == "admin":
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        max_devices = _limit_from_form()
        telegram_username = normalize_telegram_username(request.form.get("telegram_username"))
        enabled = bool(request.form.get("payment_enabled"))
        try:
            payment_day = int(request.form.get("payment_day", ""))
        except ValueError:
            payment_day = 0
        if max_devices is None:
            flash("Device limit must be 1–5 or unlimited.", "error")
        elif request.form.get("telegram_username") and not telegram_username:
            flash("Telegram username must contain 5–32 letters, digits or underscores.", "error")
        elif enabled and not telegram_username:
            flash("Telegram username is required before enabling payments.", "error")
        elif enabled and not 1 <= payment_day <= 31:
            flash("Payment day must be between 1 and 31.", "error")
        elif enabled and payment_price(max_devices) is None:
            flash("This device limit has no configured payment price.", "error")
        else:
            def update(users):
                current = users.get(username)
                if not current or current.get("role") == "admin":
                    return False
                current["max_devices"] = max_devices
                current["telegram_username"] = telegram_username
                current["payment_enabled"] = enabled
                current["payment_day"] = payment_day if enabled else None
                if not enabled:
                    current["payment_delivery"] = {"month": "", "parts": []}
                return True

            if mutate_users(update):
                flash(f"User '{username}' updated.", "ok")
                return redirect(url_for("admin_users"))

    user = load_users().get(username, user)
    max_devices = user.get("max_devices", 3)
    telegram_username = user.get("telegram_username", "")
    payment_day = user.get("payment_day") or 1
    price = payment_price(max_devices)
    today = payment_today()
    if user.get("payment_enabled") and user.get("payment_last_notified_month") != today.strftime("%Y-%m"):
        preview = effective_due_date(today.year, today.month, payment_day)
    else:
        preview = next_effective_due_date(payment_day, today)
    limit_options = "".join(
        f'<option value="{value}" {"selected" if value == max_devices else ""}>{"Unlimited" if value == -1 else value}</option>'
        for value in (1, 2, 3, 4, 5, -1)
    )
    checked = "checked" if user.get("payment_enabled") else ""
    html = page_head(f"Edit {username}") + CSS + f"""
<div class="wrap">{nav_bar(True)}<div class="card">
  <div class="page-heading"><div><h1 class="page-title">👤 {escape(username)}</h1><p class="sub">Admin-only account and payment settings</p></div></div>
  {flash_html()}
  <form method="POST" class="stack">
    {csrf_input()}
    <label for="telegram_username">Telegram username</label>
    <input type="text" id="telegram_username" name="telegram_username" value="{escape(telegram_username)}" pattern="@?[A-Za-z0-9_]{{5,32}}" maxlength="33" placeholder="@username">
    <label for="max_devices">Device limit</label><select id="max_devices" name="max_devices">{limit_options}</select>
    <label for="payment_day">Monthly payment day</label>
    <input type="number" id="payment_day" name="payment_day" min="1" max="31" value="{payment_day}">
    <label class="check-row" for="payment_enabled">
      <input type="checkbox" id="payment_enabled" name="payment_enabled" {checked}> <span>Enable monthly payment reminders</span>
    </label>
    <div class="stat-box price-preview">
      <div class="stat-num">{price if price is not None else '—'} BYN</div>
      <div class="stat-lbl">Calculated price · next effective date {preview.strftime('%d.%m.%Y')}</div>
    </div>
    <button class="btn g btn-full" type="submit">Save</button>
  </form>
</div></div>"""
    return render_template_string(html)


@app.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def admin_delete_user(username):
    user = load_users().get(username)
    if not user or user.get("role") == "admin":
        return redirect(url_for("admin_users"))
    failures = []
    for owner, device, wg_name in get_all_devices():
        if owner != username:
            continue
        ok, error = delete_device(wg_name)
        if not ok:
            failures.append(f"{device}: {error}")
    if failures:
        flash("Account retained because device revocation failed: " + "; ".join(failures), "error")
        return redirect(url_for("admin_users"))

    removed = mutate_users(
        lambda users: bool(users.pop(username, None))
        if users.get(username, {}).get("role") != "admin"
        else False
    )
    if removed:
        flash(f"User '{username}' and all devices deleted.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/devices")
@admin_required
def admin_devices():
    all_devices = get_all_devices()
    rows = ""
    for owner, device, wg_name in all_devices:
        rows += f"""<tr><td><span class="mono owner">{escape(owner)}</span></td>
          <td><span class="mono device-name">{escape(device)}</span></td><td>
            <div class="table-actions"><a href="/device/{escape(wg_name)}" class="btn b">View</a>
            <form method="POST" action="/device/{escape(wg_name)}/delete" class="inline" onsubmit="return confirm('Remove device?')">
              {csrf_input()}<input type="hidden" name="return_to" value="admin">
              <button class="btn r">Remove</button>
            </form></div></td></tr>"""
    if not rows:
        rows = '<tr><td colspan="3" class="empty-state">No devices.</td></tr>'
    html = page_head("All Devices") + CSS + f"""
<div class="wide">{nav_bar(True)}<div class="card"><div class="page-heading"><div><h1 class="page-title">📱 All Devices ({len(all_devices)})</h1>
  <p class="sub">Every WireGuard client across all users</p></div></div>{flash_html()}
  <div class="tbl-wrap"><table><thead><tr><th>Owner</th><th>Device</th><th>Actions</th></tr></thead>
  <tbody>{rows}</tbody></table></div></div></div>"""
    return render_template_string(html)
