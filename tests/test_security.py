import hashlib

import pytest
from flask import session

from wg_panel import app, core, security
from wg_panel import auth as auth_helpers
from wg_panel import telegram as telegram_client
from wg_panel.routes import telegram as telegram_route


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


def test_login_cooldown_survives_key_churn_and_failure_window_expiry():
    now = [1000.0]
    limiter = security.LoginFailureLimiter(max_keys=3, clock=lambda: now[0])
    for _ in range(5):
        limiter.record_failure("ip|admin")
    for offset in range(20):
        limiter.record_failure(f"ip|unknown-{offset}")
    assert limiter.check("ip|admin") == (False, 900)
    assert len(limiter._failures) == 3
    assert not limiter.check("another-ip|new")[0]
    now[0] += 301
    for offset in range(20):
        limiter.record_failure(f"ip|later-{offset}")
    assert limiter.check("ip|admin") == (False, 599)
    now[0] += 600
    assert limiter.check("ip|admin")[0]


def test_window_capacity_preserves_limits_and_recovers_after_expiry():
    now = [1000.0]
    limiter = security.WindowRateLimiter(max_keys=2, clock=lambda: now[0])
    assert limiter.consume("login", "ip1", 1, 60)[0]
    assert limiter.consume("login", "ip2", 1, 60)[0]
    for offset in range(20):
        assert not limiter.consume("login", f"new-{offset}", 1, 60)[0]
    assert not limiter.consume("login", "ip1", 1, 60)[0]
    assert len(limiter._events) == 2
    now[0] += 61
    assert limiter.consume("login", "new", 1, 60)[0]


@pytest.mark.parametrize("action", ["approve:one-time-token:3", "reject:one-time-token"])
def test_webhook_cannot_reactivate_or_drop_revoking_account(monkeypatch, action):
    state = {"alice": {
        "role": "user", "approved": False, "revoking": True,
        "approval_token": "one-time-token",
    }}
    monkeypatch.setattr(telegram_route, "TG_WEBHOOK_SECRET", "secret")
    monkeypatch.setattr(telegram_route, "TG_CHAT_ID", "42")
    monkeypatch.setattr(telegram_route, "mutate_users", lambda callback: callback(state))
    monkeypatch.setattr(telegram_route, "answer_callback", lambda *_args: True)
    monkeypatch.setattr(telegram_route, "edit_tg_message", lambda *_args: True)
    response = app.test_client().post("/tg_webhook", json={"callback_query": {
        "id": "cb", "from": {"id": 42}, "data": action,
        "message": {"message_id": 10, "chat": {"id": 42}},
    }}, headers={"X-Telegram-Bot-Api-Secret-Token": "secret"})
    assert response.status_code == 200
    assert state["alice"]["revoking"] and not state["alice"]["approved"]


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


def test_flash_messages_are_html_escaped_by_single_pass_page_renderer():
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session["_flashes"] = [("error", '<img src=x onerror="alert(1)">')]

    response = client.get("/login")
    rendered = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "<img src=x" not in rendered
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in rendered


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
