import secrets
from datetime import datetime, timedelta, timezone

from flask import flash, redirect, render_template_string, request, session, url_for

from ..client_context import build_registration_notification
from ..core import DOMAIN, app, _check, _hash, _lang, _now, load_users, save_users
from ..i18n import t
from ..telegram import send_telegram, send_telegram_buttons
from ..ui import flash_html, forgot_page, login_page, register_page, reset_page

@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/healthz")
def healthz():
    return {"status": "ok", "time": _now()}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("u", "").strip().lower()
        p = request.form.get("p", "")
        users = load_users()
        usr = users.get(u)
        if usr and _check(p, usr["password_hash"]):
            session["user"] = u
            session["role"] = usr["role"]
            return redirect(url_for("dashboard"))
        flash(t("flash_login_err", _lang()), "error")
    lang = _lang()
    tmpl = login_page(lang).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("u", "").strip().lower()
        p  = request.form.get("p", "")
        p2 = request.form.get("p2", "")
        users = load_users()
        if not request.form.get("agree"):
            flash(t("flash_reg_agree", _lang()), "error")
        elif not u or not all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in u):
            flash(t("flash_reg_user", _lang()), "error")
        elif len(p) < 8:
            flash(t("flash_reg_pass_len", _lang()), "error")
        elif p != p2:
            flash(t("flash_reg_pass_match", _lang()), "error")
        elif u in users:
            flash(t("flash_reg_taken", _lang()), "error")
        else:
            users[u] = {
                "password_hash": _hash(p),
                "role": "user",
                "approved": False,
                "max_devices": 3,
                "created_at": _now()
            }
            save_users(users)
            reg_time = _now()
            send_telegram_buttons(
                build_registration_notification(u, reg_time, request),
                [
                    [
                        {"text": "\u2705 Approve 3 devices", "callback_data": f"approve:{u}:3"},
                        {"text": "\u274c Reject", "callback_data": f"reject:{u}"}
                    ],
                    [
                        {"text": "\u2705 Approve 5 devices", "callback_data": f"approve:{u}:5"},
                        {"text": "\u2705 Approve unlimited", "callback_data": f"approve:{u}:-1"}
                    ]
                ]
            )
            flash(t("flash_reg_ok", _lang()), "ok")
            return redirect(url_for("login"))
    lang = _lang()
    tmpl = register_page(lang).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        u = request.form.get("u", "").strip().lower()
        users = load_users()
        usr = users.get(u)
        if usr and usr.get("role") != "admin":
            token = secrets.token_urlsafe(32)
            expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            users[u]["reset_token"] = token
            users[u]["reset_token_expiry"] = expiry
            save_users(users)
            reset_url = f"https://{DOMAIN}/reset/{token}"
            send_telegram(
                f"🔑 *Password reset request*\n\n"
                f"👤 Username: `{u}`\n"
                f"🕐 Requested: {_now()}\n"
                f"⏰ Expires in: 1 hour\n\n"
                f"Forward this link to the user:\n{reset_url}"
            )
        # Always show success to prevent username enumeration
        flash("If that username exists, the admin has been notified via Telegram and will send you a reset link.", "ok")
        return redirect(url_for("login"))
    tmpl = forgot_page(_lang()).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    users = load_users()
    # Find user with this token
    matched = None
    for u, d in users.items():
        if d.get("reset_token") == token:
            expiry = d.get("reset_token_expiry", "")
            try:
                if datetime.fromisoformat(expiry) > datetime.now(timezone.utc):
                    matched = u
            except Exception:
                pass
            break

    if not matched:
        flash("Reset link is invalid or has expired.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        p  = request.form.get("p", "")
        p2 = request.form.get("p2", "")
        if len(p) < 8:
            flash(t("flash_reset_len", _lang()), "error")
        elif p != p2:
            flash(t("flash_reset_match", _lang()), "error")
        else:
            users[matched]["password_hash"] = _hash(p)
            users[matched].pop("reset_token", None)
            users[matched].pop("reset_token_expiry", None)
            save_users(users)
            send_telegram(f"✅ Password successfully reset for user: `{matched}`")
            flash(t("flash_reset_ok", _lang()), "ok")
            return redirect(url_for("login"))

    tmpl = reset_page(_lang(), matched).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)
