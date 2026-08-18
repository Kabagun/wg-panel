import hashlib

from flask import session

from wg_panel import app, core, security
from wg_panel import auth as auth_helpers
from wg_panel import telegram as telegram_client
from wg_panel.routes import telegram as telegram_route
from wg_panel.ui import flash_html


def test_password_hashing_is_scrypt_and_legacy_is_detected():
    password = "correct horse battery staple"
    first = core._hash(password)
    second = core._hash(password)
    assert first.startswith("scrypt:")
    assert first != second
    assert core.verify_password(password, first) == (True, False)
    legacy = hashlib.sha256(password.encode()).hexdigest()
    assert core.verify_password(password, legacy) == (True, True)
    assert core.verify_password("wrong", legacy) == (False, False)


def test_login_failure_limiter_enters_and_exits_cooldown():
    now = [1000.0]
    limiter = security.LoginFailureLimiter(clock=lambda: now[0])
    for _ in range(5):
        assert limiter.check("ip|user")[0]
        limiter.record_failure("ip|user")
    allowed, retry = limiter.check("ip|user")
    assert not allowed
    assert retry == 900
    now[0] += 901
    assert limiter.check("ip|user")[0]


def test_public_window_limiter_bounds_requests():
    now = [10.0]
    limiter = security.WindowRateLimiter(clock=lambda: now[0])
    assert limiter.consume("register", "ip", 2, 60)[0]
    assert limiter.consume("register", "ip", 2, 60)[0]
    allowed, retry = limiter.consume("register", "ip", 2, 60)
    assert not allowed and retry == 60
    now[0] += 61
    assert limiter.consume("register", "ip", 2, 60)[0]


def test_csrf_is_required_and_security_headers_are_present():
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    assert response.headers["Cache-Control"].startswith("no-store")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert client.post("/login", data={"u": "x", "p": "y"}).status_code == 400


def test_oversize_request_body_is_rejected():
    client = app.test_client()
    assert client.post("/login", data={"payload": "x" * (17 * 1024)}).status_code == 413


def test_flash_messages_are_html_escaped():
    with app.test_request_context("/"):
        session["_flashes"] = [("error", '<img src=x onerror="alert(1)">')]
        rendered = flash_html()
    assert "<img" not in rendered
    assert "&lt;img" in rendered


def test_session_version_revokes_existing_session(monkeypatch):
    monkeypatch.setattr(
        auth_helpers,
        "load_users",
        lambda: {"alice": {"approved": True, "role": "user", "session_version": 2}},
    )
    with app.test_request_context("/"):
        session["user"] = "alice"
        session["session_version"] = 1
        username, user = auth_helpers._current_user()
        assert username is None and user is None
        assert "user" not in session


def test_webhook_requires_secret_private_chat_sender_and_one_time_token(monkeypatch):
    state = {
        "alice": {
            "role": "user",
            "approved": False,
            "approval_token": "one-time-token",
            "max_devices": 3,
        }
    }

    def mutate(mutator):
        return mutator(state)

    monkeypatch.setattr(telegram_route, "TG_WEBHOOK_SECRET", "secret")
    monkeypatch.setattr(telegram_route, "TG_CHAT_ID", "42")
    monkeypatch.setattr(telegram_route, "mutate_users", mutate)
    monkeypatch.setattr(telegram_route, "answer_callback", lambda *_args: True)
    monkeypatch.setattr(telegram_route, "edit_tg_message", lambda *_args: True)
    payload = {
        "callback_query": {
            "id": "cb",
            "from": {"id": 42},
            "data": "approve:one-time-token:5",
            "message": {"message_id": 10, "chat": {"id": 42}},
        }
    }
    client = app.test_client()
    assert client.post("/tg_webhook", json=payload).status_code == 403
    headers = {"X-Telegram-Bot-Api-Secret-Token": "secret"}

    wrong_actor = dict(payload)
    wrong_actor["callback_query"] = dict(payload["callback_query"], **{"from": {"id": 41}})
    assert client.post("/tg_webhook", json=wrong_actor, headers=headers).status_code == 403

    assert client.post("/tg_webhook", json=payload, headers=headers).status_code == 200
    assert state["alice"]["approved"] is True
    assert state["alice"]["max_devices"] == 5
    assert "approval_token" not in state["alice"]

    assert client.post("/tg_webhook", json=payload, headers=headers).status_code == 200
    assert state["alice"]["max_devices"] == 5


def test_webhook_registration_includes_secret(monkeypatch):
    calls = []
    monkeypatch.setattr(telegram_client, "TG_TOKEN", "token")
    monkeypatch.setattr(telegram_client, "TG_CHAT_ID", "42")
    monkeypatch.setattr(telegram_client, "TG_WEBHOOK_SECRET", "secret")
    monkeypatch.setattr(telegram_client, "DOMAIN", "vpn.example.com")
    monkeypatch.setattr(
        telegram_client,
        "_telegram_api",
        lambda method, payload, timeout=10: calls.append((method, payload, timeout)) or True,
    )
    assert telegram_client.set_tg_webhook()
    assert calls[0][0] == "setWebhook"
    assert calls[0][1]["secret_token"] == "secret"
    assert calls[0][1]["allowed_updates"] == ["callback_query"]
