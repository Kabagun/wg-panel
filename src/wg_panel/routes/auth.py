import secrets
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from flask import flash, redirect, request, session, url_for

from ..client_context import build_registration_notification
from ..core import DOMAIN, _hash, _lang, _now, app, load_users, mutate_users, verify_password
from ..i18n import t
from ..payments import normalize_telegram_username
from ..security import (
    client_ip,
    login_failure_limiter,
    login_request_limiter,
    public_rate_limiter,
    rate_limited_response,
)
from ..telegram import send_telegram, send_telegram_sync, submit_background
from ..ui import forgot_page, login_page, register_page, reset_page


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
        allowed, retry_after = login_request_limiter.consume("login", client_ip(), 30, 60)
        if not allowed:
            return rate_limited_response(retry_after)
        username = request.form.get("u", "").strip().lower()[:32]
        password = request.form.get("p", "")[:256]
        rate_key = f"{client_ip()}|{username}"
        allowed, retry_after = login_failure_limiter.check(rate_key)
        if not allowed:
            return rate_limited_response(retry_after)

        user = load_users().get(username)
        if user and "account_id" not in user:
            # Persist a legacy account identity before verifying credentials;
            # subsequent checks must refer to exactly this incarnation.
            user = mutate_users(lambda users: dict(users[username]) if username in users else None)
        valid, needs_upgrade = verify_password(password, user.get("password_hash") if user else "")
        if valid and user:
            def authenticate(users):
                current = users.get(username)
                if (
                    not current
                    or current.get("revoking")
                    or any(current.get(key) != user.get(key) for key in (
                        "account_id", "password_hash", "session_version"
                    ))
                ):
                    return None
                if needs_upgrade:
                    current["password_hash"] = _hash(password)
                return dict(current)

            authenticated = mutate_users(authenticate)
        else:
            authenticated = None
        if authenticated:
            login_failure_limiter.reset(rate_key)
            session.clear()
            session["user"] = username
            session["account_id"] = authenticated["account_id"]
            session["session_version"] = authenticated["session_version"]
            return redirect(url_for("dashboard"))

        login_failure_limiter.record_failure(rate_key)
        flash(t("flash_login_err", _lang()), "error")

    lang = _lang()
    return login_page(lang)


def _registration_notification(username, telegram_username, registered_at, remote_addr, user_agent, token):
    snapshot = SimpleNamespace(
        remote_addr=remote_addr,
        headers={},
        user_agent=SimpleNamespace(string=user_agent),
    )
    text = build_registration_notification(username, registered_at, snapshot)
    text += f"\n✈️ Telegram: `@{telegram_username}`"
    buttons = [
        [
            {"text": "✅ Approve 3 devices", "callback_data": f"approve:{token}:3"},
            {"text": "❌ Reject", "callback_data": f"reject:{token}"},
        ],
        [
            {"text": "✅ Approve 5 devices", "callback_data": f"approve:{token}:5"},
            {"text": "✅ Approve unlimited", "callback_data": f"approve:{token}:-1"},
        ],
        [{"text": f"✈️ Написать @{telegram_username}", "url": f"https://t.me/{telegram_username}"}],
    ]
    send_telegram_sync(text, False, "Markdown", buttons)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        allowed, retry_after = public_rate_limiter.consume("register", client_ip(), 3, 3600)
        if not allowed:
            return rate_limited_response(retry_after)

        username = request.form.get("u", "").strip().lower()
        password = request.form.get("p", "")
        confirmation = request.form.get("p2", "")
        telegram_username = normalize_telegram_username(request.form.get("telegram_username"))
        error = None
        if not request.form.get("agree"):
            error = t("flash_reg_agree", _lang())
        elif not 3 <= len(username) <= 32 or not all(
            character in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in username
        ):
            error = t("flash_reg_user", _lang())
        elif not telegram_username:
            error = "Укажите корректное публичное имя пользователя Telegram."
        elif not 8 <= len(password) <= 256:
            error = t("flash_reg_pass_len", _lang())
        elif password != confirmation:
            error = t("flash_reg_pass_match", _lang())
        if error:
            flash(error, "error")
        else:
            approval_token = secrets.token_urlsafe(12)

            def create(users):
                if username in users:
                    return "taken"
                pending_count = sum(
                    1
                    for user in users.values()
                    if user.get("role") != "admin" and not user.get("approved")
                )
                if pending_count >= 100:
                    return "capacity"
                users[username] = {
                    "password_hash": _hash(password),
                    "role": "user",
                    "approved": False,
                    "max_devices": 3,
                    "created_at": _now(),
                    "telegram_username": telegram_username,
                    "payment_enabled": False,
                    "payment_day": None,
                    "payment_last_notified_month": "",
                    "payment_delivery": {"month": "", "parts": []},
                    "session_version": 1,
                    "approval_token": approval_token,
                }
                return "created"

            result = mutate_users(create)
            if result == "taken":
                flash(t("flash_reg_taken", _lang()), "error")
            elif result == "capacity":
                flash("Registration is temporarily unavailable. Please contact the administrator.", "error")
            else:
                remote_addr = client_ip()
                user_agent = request.user_agent.string or ""
                queued = submit_background(
                    _registration_notification,
                    username,
                    telegram_username,
                    _now(),
                    remote_addr,
                    user_agent,
                    approval_token,
                )
                if not queued:
                    def rollback(users):
                        current = users.get(username)
                        if current and current.get("approval_token") == approval_token:
                            del users[username]

                    mutate_users(rollback)
                    return "Server is busy. Please retry in a moment.", 503, {"Retry-After": "5"}
                flash(t("flash_reg_ok", _lang()), "ok")
                return redirect(url_for("login"))

    lang = _lang()
    return register_page(lang)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        username = request.form.get("u", "").strip().lower()[:32]
        allowed, retry_after = public_rate_limiter.consume(
            "forgot", f"{client_ip()}|{username}", 3, 3600
        )
        if not allowed:
            return rate_limited_response(retry_after)

        token = secrets.token_urlsafe(32)
        expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

        def create_reset(users):
            user = users.get(username)
            if not user or user.get("role") == "admin":
                return False
            user["reset_token"] = token
            user["reset_token_expiry"] = expiry
            return True

        if mutate_users(create_reset):
            reset_url = f"https://{DOMAIN}/reset/{token}"
            send_telegram(
                "🔑 *Password reset request*\n\n"
                f"👤 Username: `{username}`\n"
                f"🕐 Requested: {_now()}\n"
                "⏰ Expires in: 1 hour\n\n"
                f"Forward this link to the user:\n{reset_url}"
            )
        flash(
            "If that username exists, the admin has been notified via Telegram and will send you a reset link.",
            "ok",
        )
        return redirect(url_for("login"))

    return forgot_page(_lang())


def _find_reset_user(token):
    now = datetime.now(UTC)
    for username, user in load_users().items():
        if not secrets.compare_digest(str(user.get("reset_token", "")), token):
            continue
        try:
            if datetime.fromisoformat(user.get("reset_token_expiry", "")) > now:
                return username
        except (TypeError, ValueError):
            return None
    return None


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    if len(token) > 128:
        return redirect(url_for("login"))
    matched = _find_reset_user(token)
    if not matched:
        flash("Reset link is invalid or has expired.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("p", "")
        confirmation = request.form.get("p2", "")
        if not 8 <= len(password) <= 256:
            flash(t("flash_reset_len", _lang()), "error")
        elif password != confirmation:
            flash(t("flash_reset_match", _lang()), "error")
        else:
            now = datetime.now(UTC)

            def apply_reset(users):
                user = users.get(matched)
                if not user or not secrets.compare_digest(str(user.get("reset_token", "")), token):
                    return False
                try:
                    if datetime.fromisoformat(user.get("reset_token_expiry", "")) <= now:
                        return False
                except (TypeError, ValueError):
                    return False
                user["password_hash"] = _hash(password)
                user["session_version"] = int(user.get("session_version", 1)) + 1
                user.pop("reset_token", None)
                user.pop("reset_token_expiry", None)
                return True

            if mutate_users(apply_reset):
                send_telegram(f"✅ Password successfully reset for user: `{matched}`")
                flash(t("flash_reset_ok", _lang()), "ok")
                return redirect(url_for("login"))
            flash("Reset link is invalid or has expired.", "error")
            return redirect(url_for("login"))

    return reset_page(_lang(), matched)
