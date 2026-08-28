import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from wg_panel import app, core, traffic, wireguard
from wg_panel.routes import auth as auth_routes


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "USERS_FILE", str(data / "users.json"))
    monkeypatch.setattr(core, "DEVICE_META_FILE", str(data / "device_meta.json"))
    monkeypatch.setattr(core, "TRAFFIC_FILE", str(data / "traffic.json"))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(data / "device_meta.json"))
    monkeypatch.setattr(traffic, "TRAFFIC_FILE", str(data / "traffic.json"))
    monkeypatch.setattr(traffic, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(tmp_path / "wireguard"))
    app.config.update(TESTING=True)
    return data, clients


def user_record(password_hash=None, role="user", approved=True, limit=3):
    return {
        "password_hash": password_hash or core._hash("password123"),
        "role": role,
        "approved": approved,
        "max_devices": limit,
        "created_at": "2026-08-18 00:00 UTC",
        "session_version": 1,
        "telegram_username": "",
        "payment_enabled": False,
        "payment_day": None,
        "payment_last_notified_month": "",
        "payment_delivery": {"month": "", "parts": []},
    }


def csrf_session(client, username=None, version=1):
    with client.session_transaction() as browser_session:
        browser_session["_csrf_token"] = "csrf-test-token"
        if username:
            browser_session["user"] = username
            browser_session["session_version"] = version
    return "csrf-test-token"


def test_registration_requires_telegram_and_defaults_payments_disabled(runtime, monkeypatch):
    core.save_users({})
    monkeypatch.setattr(auth_routes, "submit_background", lambda *_args, **_kwargs: True)
    client = app.test_client()
    token = csrf_session(client)
    base = {
        "csrf_token": token,
        "u": "newperson",
        "p": "password123",
        "p2": "password123",
        "agree": "on",
    }
    response = client.post("/register", data=base, environ_base={"REMOTE_ADDR": "198.51.100.10"})
    assert response.status_code == 200
    assert "Telegram" in response.get_data(as_text=True)
    assert "newperson" not in core.load_users()

    response = client.post(
        "/register",
        data={**base, "telegram_username": "@Working_User"},
        environ_base={"REMOTE_ADDR": "198.51.100.11"},
    )
    assert response.status_code == 302
    created = core.load_users()["newperson"]
    assert created["telegram_username"] == "working_user"
    assert created["payment_enabled"] is False
    assert created["payment_day"] is None
    assert created["approval_token"]


def test_registration_notification_has_clickable_telegram_contact(monkeypatch):
    sent = []
    monkeypatch.setattr(auth_routes, "build_registration_notification", lambda *_args: "registration")
    monkeypatch.setattr(
        auth_routes,
        "send_telegram_sync",
        lambda *args: sent.append(args) or True,
    )
    auth_routes._registration_notification(
        "alice", "working_user", "now", "8.8.8.8", "browser", "approval-token"
    )
    buttons = sent[0][3]
    assert buttons[-1][0]["url"] == "https://t.me/working_user"
    assert buttons[0][0]["callback_data"] == "approve:approval-token:3"


def test_legacy_login_rehashes_password_and_stores_session_version(runtime):
    legacy = hashlib.sha256(b"password123").hexdigest()
    core.save_users({"alice": user_record(legacy)})
    client = app.test_client()
    token = csrf_session(client)
    response = client.post(
        "/login",
        data={"csrf_token": token, "u": "alice", "p": "password123"},
        environ_base={"REMOTE_ADDR": "198.51.100.20"},
    )
    assert response.status_code == 302
    assert core.load_users()["alice"]["password_hash"].startswith("scrypt:")
    with client.session_transaction() as browser_session:
        assert browser_session["user"] == "alice"
        assert browser_session["session_version"] == 1


def test_password_reset_revokes_existing_sessions(runtime):
    alice = user_record()
    alice["reset_token"] = "valid-reset-token"
    alice["reset_token_expiry"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    core.save_users({"alice": alice})
    client = app.test_client()
    token = csrf_session(client)
    response = client.post(
        "/reset/valid-reset-token",
        data={"csrf_token": token, "p": "new-password-123", "p2": "new-password-123"},
    )
    assert response.status_code == 302
    updated = core.load_users()["alice"]
    assert updated["session_version"] == 2
    assert "reset_token" not in updated
    assert core.verify_password("new-password-123", updated["password_hash"])[0]


def test_admin_can_enable_priced_payment_settings(runtime):
    core.save_users(
        {
            "admin": user_record(role="admin", limit=-1),
            "alice": user_record(limit=3),
        }
    )
    client = app.test_client()
    token = csrf_session(client, "admin")
    response = client.post(
        "/admin/users/alice/edit",
        data={
            "csrf_token": token,
            "telegram_username": "@Working_User",
            "max_devices": "5",
            "payment_day": "31",
            "payment_enabled": "on",
        },
    )
    assert response.status_code == 302
    alice = core.load_users()["alice"]
    assert alice["max_devices"] == 5
    assert alice["telegram_username"] == "working_user"
    assert alice["payment_enabled"] is True
    assert alice["payment_day"] == 31


def test_invalid_finite_limit_cannot_enable_payments(runtime):
    core.save_users(
        {
            "admin": user_record(role="admin", limit=-1),
            "legacy": user_record(limit=3),
        }
    )
    client = app.test_client()
    token = csrf_session(client, "admin")
    response = client.post(
        "/admin/users/legacy/edit",
        data={
            "csrf_token": token,
            "telegram_username": "working_user",
            "max_devices": "6",
            "payment_day": "15",
            "payment_enabled": "on",
        },
    )
    assert response.status_code == 200
    assert core.load_users()["legacy"]["payment_enabled"] is False


def test_payment_settings_are_not_exposed_to_customer_dashboard(runtime):
    alice = user_record()
    alice.update(
        {
            "telegram_username": "private_handle",
            "payment_enabled": True,
            "payment_day": 15,
        }
    )
    core.save_users({"alice": alice})
    client = app.test_client()
    csrf_session(client, "alice")
    body = client.get("/dashboard").get_data(as_text=True)
    assert "private_handle" not in body
    assert "payment_day" not in body
    assert "5 BYN" not in body


def test_exact_device_authorization_get_delete_rejection_and_no_store(runtime):
    _data, clients = runtime
    core.save_users({"alice": user_record(), "ali": user_record()})
    config = clients / "alice-phone.conf"
    config.write_text("[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n", encoding="utf-8")
    traffic.save_device_meta(
        {"alice-phone": {"owner": "alice", "device": "phone", "vpn_type": "wireguard"}}
    )

    attacker = app.test_client()
    attacker_token = csrf_session(attacker, "ali")
    assert attacker.get("/device/alice-phone/download").status_code == 403
    assert attacker.get("/device/alice-phone/delete").status_code == 405
    response = attacker.post(
        "/device/alice-phone/safe-internet",
        data={"csrf_token": attacker_token, "safe_internet": "on"},
    )
    assert response.status_code == 302
    assert traffic.load_device_meta()["alice-phone"].get("safe_internet") is not True

    owner = app.test_client()
    csrf_session(owner, "alice")
    response = owner.get("/device/alice-phone/download")
    assert response.status_code == 200
    assert response.headers["Cache-Control"].startswith("no-store")
    assert "PrivateKey = secret" in response.get_data(as_text=True)


def test_device_safe_internet_toggle_updates_existing_config_download(runtime):
    _data, clients = runtime
    core.save_users({"alice": user_record()})
    config = clients / "alice-phone.conf"
    config.write_text(
        "[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n"
        "DNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\nPublicKey = server\n",
        encoding="utf-8",
    )
    traffic.save_device_meta(
        {"alice-phone": {"owner": "alice", "device": "phone", "vpn_type": "wireguard"}}
    )
    client = app.test_client()
    token = csrf_session(client, "alice")

    response = client.post(
        "/device/alice-phone/safe-internet",
        data={"csrf_token": token, "safe_internet": "on"},
    )
    assert response.status_code == 302
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"] is True
    assert 'name="safe_internet" checked' in client.get(
        "/device/alice-phone"
    ).get_data(as_text=True)
    enabled_config = client.get("/device/alice-phone/download").get_data(as_text=True)
    assert "DNS = 1.1.1.3, 1.0.0.3" in enabled_config
    assert "DNS = 1.1.1.1, 8.8.8.8" not in enabled_config

    response = client.post(
        "/device/alice-phone/safe-internet",
        data={"csrf_token": token},
    )
    assert response.status_code == 302
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"] is False
    assert 'name="safe_internet" checked' not in client.get(
        "/device/alice-phone"
    ).get_data(as_text=True)
    disabled_config = client.get("/device/alice-phone/download").get_data(as_text=True)
    assert "DNS = 1.1.1.1, 8.8.8.8" in disabled_config


def test_route_map_preserves_public_pages_and_removes_destructive_gets():
    rules = {rule.rule: set(rule.methods) for rule in app.url_map.iter_rules()}
    assert {"/login", "/register", "/dashboard", "/admin", "/tg_webhook", "/healthz"} <= set(
        rules
    )
    assert "GET" not in rules["/device/<wg_name>/delete"]
    assert "GET" not in rules["/admin/users/<username>/delete"]
