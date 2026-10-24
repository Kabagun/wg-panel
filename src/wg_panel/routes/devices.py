from flask import Response, flash, redirect, request, session, url_for

from ..account_policy import account_safe_internet_locked
from ..auth import approved_required
from ..core import _lang, _now, app, load_users
from ..i18n import t
from ..telegram import send_telegram
from ..ui import render_page
from ..wireguard import (
    client_name,
    create_device,
    delete_device,
    get_config,
    get_device,
    get_user_devices,
    qr_svg_b64,
    set_account_safe_internet,
)


@app.route("/dashboard")
@approved_required
def dashboard():
    username = session["user"]
    user = load_users().get(username, {})
    account_locked = account_safe_internet_locked(username)
    device_names = get_user_devices(username)
    max_devices = user.get("max_devices", 3)
    devices = []
    for name in device_names:
        wg_name = client_name(username, name)
        metadata = get_device(wg_name) or {}
        devices.append({
            "device": name,
            "wg_name": wg_name,
            "safe_internet": bool(metadata.get("safe_internet")) or account_locked,
        })
    used = len(devices)
    return render_page(
        "dashboard.html", "ui_devices", devices=devices,
        max_devices=max_devices,
        limit_text=t("dash_unlim", _lang()) if max_devices == -1 else str(max_devices),
        available="∞" if max_devices == -1 else max(0, max_devices - used),
        can_add=not user.get("paused") and (max_devices == -1 or used < max_devices),
        paused=bool(user.get("paused")), pause_pending=bool(user.get("pause_pending")),
        protected_count=sum(device["safe_internet"] for device in devices),
        account_locked=account_locked,
    )


@app.route("/add", methods=["GET", "POST"])
@approved_required
def add_device():
    username = session["user"]
    user = load_users().get(username, {})
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

    return render_page("add_device.html", "ui_add")


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
    device, _user = _authorized_device(wg_name)
    if not device:
        flash("Device not found or access denied.", "error")
        return redirect(url_for("dashboard"))
    config = get_config(wg_name)
    if not config:
        flash("Device not found.", "error")
        return redirect(url_for("dashboard"))

    return render_page(
        "device.html", "ui_devices", device=device, wg_name=wg_name,
        config=config, qr=qr_svg_b64(wg_name),
        owner_paused=bool(load_users().get(device["owner"], {}).get("paused")),
        owner_pause_pending=bool(load_users().get(device["owner"], {}).get("pause_pending")),
    )


@app.route("/device/<wg_name>/safe-internet", methods=["POST"])
@approved_required
def update_device_safe_internet(wg_name):
    device, _user = _authorized_device(wg_name)
    if not device:
        flash("Device not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    _update_account_safe_internet(device["owner"])
    return redirect(url_for("view_device", wg_name=wg_name))


def _update_account_safe_internet(owner):
    """Both entry points activate owner policy; neither accepts an override."""
    enabled = request.form.get("safe_internet") == "on"
    confirmed = request.form.get("safe_internet_confirmed") == "on"
    if not enabled:
        flash(t("flash_safe_locked", _lang()), "error")
    elif not account_safe_internet_locked(owner) and not confirmed:
        flash(t("flash_safe_confirmation", _lang()), "error")
    elif set_account_safe_internet(owner, confirmed=confirmed):
        flash(t("flash_safe_account_on", _lang()), "ok")
    else:
        flash(t("flash_safe_error", _lang()), "error")


@app.route("/account/safe-internet", methods=["POST"])
@approved_required
def update_account_safe_internet():
    _update_account_safe_internet(session["user"])
    return redirect(url_for("dashboard"))


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
