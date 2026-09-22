from datetime import UTC, datetime

from flask import flash, redirect, request, url_for

from ..access import access_status, set_user_paused
from ..auth import admin_required
from ..core import _lang, _wireguard_lock, app, load_users, mutate_users
from ..i18n import t
from ..payments import (
    effective_due_date,
    next_effective_due_date,
    normalize_telegram_username,
    payment_price,
    payment_today,
)
from ..traffic import collect_traffic, load_traffic
from ..ui import render_page
from ..wireguard import delete_user, get_all_devices, get_user_devices


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
    rows = []
    total_rx = total_tx = 0
    for owner, device, wg_name in all_devices:
        monthly = traffic.get(wg_name, {}).get("monthly", {})
        current = monthly.get(month_key, {"rx": 0, "tx": 0})
        total_rx += current["rx"]
        total_tx += current["tx"]
        rows.append({
            "owner": owner, "device": device, "wg_name": wg_name,
            "rx": current["rx"], "tx": current["tx"],
            "history": [
                {"month": key, **monthly[key]}
                for key in sorted(monthly, reverse=True)[:3]
            ],
        })
    total = total_rx + total_tx
    for row in rows:
        row["share"] = round((row["rx"] + row["tx"]) / total * 100, 1) if total else 0
    return render_page(
        "traffic.html", "ui_traffic", rows=rows, month=month_key,
        total_rx=total_rx, total_tx=total_tx,
    )


@app.route("/admin")
@admin_required
def admin_panel():
    users = load_users()
    pending = [
        {
            "username": username,
            "telegram_username": normalize_telegram_username(user.get("telegram_username")),
            "created_at": user.get("created_at", ""),
        }
        for username, user in users.items()
        if access_status(user) == "pending"
    ]
    return render_page(
        "admin.html", "ui_overview", pending=pending,
        total_users=len(users), total_devices=len(get_all_devices()),
    )


@app.route("/admin/users")
@admin_required
def admin_users():
    users = []
    for username, user in sorted(load_users().items()):
        limit = user.get("max_devices", 3)
        users.append({
            "username": username, "role": user.get("role", "user"),
            "approved": bool(user.get("approved")), "max_devices": limit,
            "status": access_status(user),
            "paused": bool(user.get("paused")),
            "pause_pending": bool(user.get("pause_pending")),
            "revoking": bool(user.get("revoking")),
            "device_count": len(get_user_devices(username)),
            "telegram_username": normalize_telegram_username(user.get("telegram_username")),
            "payment_enabled": bool(user.get("payment_enabled")),
            "payment_day": user.get("payment_day"), "price": payment_price(limit),
            "created_at": user.get("created_at", ""),
        })
    counts = {key: sum(user["status"] == key for user in users)
              for key in ("active", "paused", "pending", "attention", "revoking")}
    selected = request.args.get("status", "all")
    if selected not in {"all", *counts}:
        selected = "all"
    visible = users if selected == "all" else [user for user in users if user["status"] == selected]
    return render_page(
        "users.html", "ui_users", users=visible, total_users=len(users),
        status_counts=counts, selected_status=selected,
    )


@app.route("/admin/users/<username>/pause", methods=["POST"])
@admin_required
def admin_pause_user(username):
    """Suspend every device belonging to an approved non-admin account."""
    ok, _error = set_user_paused(username, True)
    flash(t("ui_pause_success" if ok else "ui_pause_failed", _lang()).format(user=username),
          "ok" if ok else "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<username>/resume", methods=["POST"])
@admin_required
def admin_resume_user(username):
    """Restore the account's original peer keys and reserved tunnel addresses."""
    ok, _error = set_user_paused(username, False)
    flash(t("ui_resume_success" if ok else "ui_resume_failed", _lang()).format(user=username),
          "ok" if ok else "error")
    return redirect(url_for("admin_users"))


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
        if not user or user.get("role") == "admin" or user.get("revoking"):
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
    form = {
        "telegram_username": telegram_username, "max_devices": max_devices,
        "payment_day": payment_day, "payment_enabled": bool(user.get("payment_enabled")),
    }
    if request.method == "POST":
        form.update({
            "telegram_username": request.form.get("telegram_username", ""),
            "max_devices": request.form.get("max_devices", ""),
            "payment_day": request.form.get("payment_day", ""),
            "payment_enabled": bool(request.form.get("payment_enabled")),
        })
    return render_page(
        "edit_user.html", "ui_account", username=username, form=form, price=price,
        preview=preview.strftime("%d.%m.%Y"),
        reminders_enabled=bool(user.get("payment_enabled")),
    )


@app.route("/admin/users/<username>/delete", methods=["POST"])
@admin_required
def admin_delete_user(username):
    removed, error = delete_user(username)
    if removed:
        flash(f"User '{username}' and all devices deleted.", "ok")
    else:
        flash("Account retained because device revocation failed: " + error, "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/devices")
@admin_required
def admin_devices():
    with _wireguard_lock:
        return render_page(
            "all_devices.html", "ui_all_devices", devices=get_all_devices(),
            owner_status={name: access_status(user) for name, user in load_users().items()},
        )
