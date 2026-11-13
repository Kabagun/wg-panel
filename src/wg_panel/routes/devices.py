import secrets

from flask import Response, flash, redirect, request, session, url_for

from .. import happ_pilot
from ..account_policy import account_safe_internet_locked
from ..auth import approved_required
from ..connection_config import connection_details
from ..core import _lang, _now, app, load_users
from ..i18n import t
from ..security import csrf_token
from ..telegram import send_telegram
from ..ui import render_page
from ..wireguard import (
    begin_device_deletion,
    client_name,
    create_device,
    delete_device_confirmed,
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
        if metadata.get('happ_transport_internal'):
            continue
        devices.append({
            "device": name,
            "wg_name": wg_name,
            "safe_internet": bool(metadata.get("safe_internet")) or account_locked,
            "deletion_protected": bool(metadata.get("deletion_protected")),
            "connection": connection_details(get_config(wg_name)),
            "happ_pilot": (metadata.get('happ_pilot') is True
                           and happ_pilot.available_for_user(user)),
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
    values = (request.form.getlist('client_app') if request.method == 'POST'
              else request.args.getlist('client_app'))
    if len(values) > 1:
        return 'Invalid client', 400
    selected_client = values[0] if values else ('wireguard' if request.method == 'POST' else None)
    if selected_client not in {None, 'wireguard', 'happ'}:
        return 'Invalid client', 400
    if selected_client == 'happ' and not happ_pilot.available_for_user(user):
        return 'Access denied', 403

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
            client_app = selected_client
            if client_app == 'happ':
                ok, wg_name, error = happ_pilot.create_pilot_device(username, device)
            elif client_app == 'wireguard':
                ok, wg_name, error = create_device(username, device)
            else:
                return 'Invalid client', 400
            if ok:
                send_telegram(
                    "📱 *Device added*\n\n"
                    f"👤 User: `{username}`\n"
                    f"🔌 Device: `{device}`\n"
                    f"🕐 Time: {_now()}",
                    silent=True,
                )
                return redirect(url_for('view_happ_device' if client_app == 'happ'
                                        else 'view_device', wg_name=wg_name))
            if error == "Device limit reached":
                flash(t("flash_add_limit", _lang()).format(n=max_devices), "error")
            else:
                flash(f"Failed to create device: {error}", "error")

    return render_page("add_device.html", "ui_add", selected_client=selected_client,
                       account_locked=account_safe_internet_locked(username))


def _authorized_device(wg_name):
    username = session["user"]
    user = load_users().get(username, {})
    device = get_device(wg_name)
    if not device or device.get('happ_transport_internal'):
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
    if (device.get('happ_pilot') is True and device['owner'] == session['user']
            and happ_pilot.available_for_user(_user)):
        return redirect(url_for('view_happ_device', wg_name=wg_name))
    config = get_config(wg_name)
    if not config:
        flash("Device not found.", "error")
        return redirect(url_for("dashboard"))

    return render_page(
        "device.html", "ui_devices", device=device, wg_name=wg_name,
        config=config, qr=qr_svg_b64(wg_name),
        connection=connection_details(config, include_public_key=True),
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
    response.headers.set("Content-Disposition", "attachment", filename=f"{device['device']}.conf")
    return response


def _deletion_actor():
    # This session-specific random value also separates browser sessions for
    # the same account. Authentication and CSRF rotations invalidate consent.
    if not session.get("_device_delete_session"):
        session["_device_delete_session"] = secrets.token_urlsafe(32)
    return (
        session["user"], session.get("account_id"), session.get("session_version"),
        csrf_token(), session["_device_delete_session"],
    )


def _delete_return_to(user):
    source = request.form if request.method == "POST" else request.args
    return "admin" if user.get("role") == "admin" and source.get("return_to") == "admin" else ""


@app.route("/device/<wg_name>/delete/confirm")
@approved_required
def confirm_device_deletion(wg_name):
    device, user = _authorized_device(wg_name)
    if not device:
        flash("Device not found or access denied.", "error")
        return redirect(url_for("dashboard"))
    return_to = _delete_return_to(user)
    nonce = begin_device_deletion(wg_name, _deletion_actor())
    if not nonce:
        flash(t("delete_confirmation_invalid", _lang()), "error")
        return redirect(url_for("dashboard"))
    cancel_url = (
        url_for("admin_devices") if return_to == "admin"
        else url_for("view_device", wg_name=wg_name)
    )
    return render_page(
        "delete_device.html", "delete_title", device=device, wg_name=wg_name,
        challenge=nonce, return_to=return_to, cancel_url=cancel_url,
    )


@app.route("/device/<wg_name>/delete", methods=["POST"])
@approved_required
def delete_device_route(wg_name):
    device, user = _authorized_device(wg_name)
    if not device:
        flash("Device not found or access denied.", "error")
        return redirect(url_for("dashboard"))

    ok, error = delete_device_confirmed(
        wg_name, _deletion_actor(), request.form.get("challenge", ""),
        confirmed=request.form.get("confirmed") == "on",
        typed_name=request.form.get("typed_name", ""),
    )
    if not ok:
        if error == "Deletion confirmation is invalid or expired":
            flash(t("delete_confirmation_invalid", _lang()), "error")
        else:
            flash(t("delete_failed", _lang()), "error")
        return redirect(url_for("confirm_device_deletion", wg_name=wg_name,
                                return_to=_delete_return_to(user)), code=303)
    else:
        send_telegram(
            "🗑️ *Device removed*\n\n"
            f"👤 By: `{session['user']}`\n"
            f"🔌 Device: `{device['device']}`\n"
            f"🕐 Time: {_now()}",
            silent=True,
        )
        flash(t("delete_success", _lang()).format(device=device["device"]), "ok")

    if user.get("role") == "admin" and request.form.get("return_to") == "admin":
        return redirect(url_for("admin_devices"))
    return redirect(url_for("dashboard"))
