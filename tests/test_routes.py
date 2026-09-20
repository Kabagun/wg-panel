import hashlib
import re
import threading
from datetime import UTC, datetime, timedelta

import pytest

from wg_panel import app, core, security, traffic, wireguard
from wg_panel import auth as auth_helpers
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
    monkeypatch.setattr(auth_routes, "login_request_limiter", security.WindowRateLimiter())
    monkeypatch.setattr(auth_routes, "login_failure_limiter", security.LoginFailureLimiter())
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
            browser_session["account_id"] = core.load_users()[username]["account_id"]
    return "csrf-test-token"


def test_recreated_account_rejects_retained_cookie_but_new_login_works(runtime, monkeypatch):
    _data, clients = runtime
    core.save_users({"alice": user_record()})
    old = app.test_client()
    csrf_session(old, "alice")
    old_cookie = old.get_cookie("session").value
    old_id = core.load_users()["alice"]["account_id"]
    assert wireguard.delete_user("alice")[0]
    monkeypatch.setattr(auth_routes, "submit_background", lambda *_args, **_kwargs: True)
    fresh = app.test_client()
    token = csrf_session(fresh)
    assert fresh.post("/register", data={
        "csrf_token": token, "u": "alice", "p": "different123", "p2": "different123",
        "agree": "on", "telegram_username": "alice_contact",
    }, environ_base={"REMOTE_ADDR": "198.51.100.99"}).status_code == 302
    core.mutate_users(lambda users: users["alice"].update(approved=True))
    new_id = core.load_users()["alice"]["account_id"]
    assert new_id != old_id
    assert new_id == core.load_users()["alice"]["account_id"]
    name = "u5-alice-phone"
    (clients / f"{name}.conf").write_text("[Interface]\nPrivateKey = replacement\n")
    traffic.set_device_meta(name, "alice", "phone")
    for path in ("/dashboard", "/add", f"/device/{name}", f"/device/{name}/download"):
        old.set_cookie("session", old_cookie)
        assert old.get(path).status_code == 302
    for path in ("/add", f"/device/{name}/delete", f"/device/{name}/safe-internet"):
        old.set_cookie("session", old_cookie)
        assert old.post(path, data={"csrf_token": "csrf-test-token"}).status_code == 302
    assert traffic.load_device_meta()[name]["owner"] == "alice"
    assert fresh.post("/login", data={
        "csrf_token": token, "u": "alice", "p": "different123",
    }).status_code == 302
    assert fresh.get(f"/device/{name}/download").status_code == 200


@pytest.mark.parametrize("credential_change", ["reset", "recreate"])
def test_legacy_login_conflict_cannot_inherit_new_identity_or_reset_generation(
    runtime, monkeypatch, credential_change,
):
    old = user_record(hashlib.sha256(b"password123").hexdigest())
    old.update(reset_token="racing-reset", reset_token_expiry=(
        datetime.now(UTC) + timedelta(hours=1)
    ).isoformat())
    core.save_users({"alice": old})
    original_verify = auth_routes.verify_password
    monkeypatch.setattr(auth_routes, "send_telegram", lambda *_args, **_kwargs: None)

    def verify_then_change(password, stored):
        result = original_verify(password, stored)
        if credential_change == "reset":
            reset = app.test_client()
            token = csrf_session(reset)
            assert reset.post("/reset/racing-reset", data={
                "csrf_token": token, "p": "new-password123", "p2": "new-password123",
            }).status_code == 302
        else:
            assert wireguard.delete_user("alice")[0]
            core.save_users({"alice": user_record(stored)})
        return result

    monkeypatch.setattr(auth_routes, "verify_password", verify_then_change)
    attacker = app.test_client()
    token = csrf_session(attacker)
    response = attacker.post("/login", data={
        "csrf_token": token, "u": "alice", "p": "password123",
    })
    assert response.status_code == 200
    with attacker.session_transaction() as browser_session:
        assert "user" not in browser_session
    assert attacker.get("/dashboard").status_code == 302


def test_login_ip_throttle_precedes_username_processing(runtime, monkeypatch):
    monkeypatch.setattr(auth_routes, "load_users", dict)
    checks = []
    monkeypatch.setattr(auth_routes, "verify_password", lambda *args: checks.append(args) or (False, False))
    client = app.test_client()
    token = csrf_session(client)
    for index in range(30):
        assert client.post("/login", data={
            "csrf_token": token, "u": f"unknown-{index}", "p": "wrong",
        }).status_code == 200
    assert client.post("/login", data={
        "csrf_token": token, "u": "brand-new-name", "p": "wrong",
    }).status_code == 429
    assert len(checks) == 30


def test_failed_account_revocation_stays_disabled_and_can_be_retried(runtime, monkeypatch):
    _data, clients = runtime
    core.save_users({"admin": user_record(role="admin"), "alice": user_record()})
    config = clients / "u5-alice-phone.conf"
    config.write_text("[Interface]\nAddress = 10.0.0.2/32\n")
    traffic.set_device_meta("u5-alice-phone", "alice", "phone")
    monkeypatch.setattr(wireguard, "_run_script", lambda *_args: (False, "failed revoke"))
    owner = app.test_client()
    csrf_session(owner, "alice")
    admin = app.test_client()
    token = csrf_session(admin, "admin")
    assert admin.post("/admin/users/alice/delete", data={"csrf_token": token}).status_code == 302
    assert core.load_users()["alice"]["revoking"]
    assert not core.load_users()["alice"]["approved"]
    assert "approval_token" not in core.load_users()["alice"]
    assert not wireguard.create_device("alice", "new")[0]
    assert owner.get("/device/u5-alice-phone/download").status_code == 302
    admin.post("/admin/users/alice/approve", data={"csrf_token": token, "max_devices": "3"})
    assert not core.load_users()["alice"]["approved"]

    def remove(*_args):
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    assert admin.post("/admin/users/alice/delete", data={"csrf_token": token}).status_code == 302
    assert "alice" not in core.load_users()
    assert not traffic.load_device_meta()


def test_queued_device_request_rechecks_account_incarnation(runtime, monkeypatch):
    core.save_users({"alice": user_record()})
    client = app.test_client()
    token = csrf_session(client, "alice")
    queued = threading.Event()
    results = []

    class RequestLock:
        def __enter__(self):
            queued.set()
            core._wireguard_lock.acquire()

        def __exit__(self, *_args):
            core._wireguard_lock.release()

    monkeypatch.setattr(auth_helpers, "_wireguard_lock", RequestLock())
    worker = threading.Thread(target=lambda: results.append(client.post("/add", data={
        "csrf_token": token, "device": "phone",
    })))
    with core._wireguard_lock:
        worker.start()
        assert queued.wait(5)
        assert wireguard.delete_user("alice")[0]
        core.save_users({"alice": user_record()})
    worker.join(5)
    assert not worker.is_alive()
    assert results[0].status_code == 302 and results[0].location.endswith("/login")
    assert not traffic.load_device_meta()


def test_legacy_account_identity_is_persisted_before_first_login(runtime):
    import json

    data, _clients = runtime
    data.mkdir(parents=True, exist_ok=True)
    (data / "users.json").write_text(json.dumps({"alice": user_record()}), encoding="utf-8")
    client = app.test_client()
    token = csrf_session(client)
    assert client.post("/login", data={
        "csrf_token": token, "u": "alice", "p": "password123",
    }).status_code == 302
    stored = json.loads((data / "users.json").read_text(encoding="utf-8"))
    with client.session_transaction() as browser_session:
        assert browser_session["account_id"] == stored["alice"]["account_id"]
    assert client.get("/dashboard").status_code == 200


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
    assert 'data-filter-scope' in body
    assert 'href="/admin"' not in body
    assert 'href="/traffic"' not in body


def test_ui_refresh_loads_local_assets_and_accessible_auth_structure():
    client = app.test_client()
    body = client.get("/login").get_data(as_text=True)

    assert '<html lang="en">' in body
    assert '<meta name="color-scheme" content="light">' in body
    assert 'href="/static/panel.css"' in body
    assert 'src="/static/panel.js"' in body
    assert 'class="auth-card"' in body
    assert 'class="button primary button-full"' in body
    assert 'name="csrf_token"' in body
    assert 'class="skip-link" href="#main"' in body

    ru_body = client.get("/login", headers={"Accept-Language": "ru-RU"}).get_data(as_text=True)
    assert '<html lang="ru">' in ru_body
    assert "С возвращением" in ru_body
    assert "Welcome back" not in ru_body


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
    enabled_page = client.get("/device/alice-phone").get_data(as_text=True)
    assert 'name="safe_internet" checked' in enabled_page
    assert '<span class="tag tag-ok" role="status" aria-live="polite">Enabled</span>' in enabled_page
    assert 'aria-describedby="safe-internet-help"' in enabled_page
    assert "VPN server enforces Family DNS immediately" in enabled_page
    assert "newly downloaded configs follow this setting" in enabled_page
    assert "If you disable it after this device imported a Family DNS config" in enabled_page
    assert "Encrypted DNS and proxies may bypass" in enabled_page
    assert '<pre id="conf-block" hidden>' in enabled_page
    assert 'data-copy-target="conf-block"' in enabled_page
    enabled_config = client.get("/device/alice-phone/download").get_data(as_text=True)
    assert "DNS = 1.1.1.3, 1.0.0.3" in enabled_config
    assert "DNS = 1.1.1.1, 8.8.8.8" not in enabled_config

    response = client.post(
        "/device/alice-phone/safe-internet",
        data={"csrf_token": token},
    )
    assert response.status_code == 302
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"] is False
    disabled_page = client.get("/device/alice-phone").get_data(as_text=True)
    assert 'name="safe_internet" checked' not in disabled_page
    assert '<span class="tag tag-pend" role="status" aria-live="polite">Disabled</span>' in disabled_page
    assert "Safe internet disabled on the VPN server" in disabled_page
    assert "previously imported a Family DNS config" in disabled_page
    assert "re-download and re-import the config" in disabled_page
    disabled_config = client.get("/device/alice-phone/download").get_data(as_text=True)
    assert "DNS = 1.1.1.1, 8.8.8.8" in disabled_config


def test_device_safe_internet_copy_is_localized_in_russian(runtime):
    _data, clients = runtime
    core.save_users({"alice": user_record()})
    (clients / "alice-phone.conf").write_text(
        "[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n",
        encoding="utf-8",
    )
    traffic.save_device_meta(
        {"alice-phone": {"owner": "alice", "device": "phone", "vpn_type": "wireguard"}}
    )
    client = app.test_client()
    csrf_session(client, "alice")

    body = client.get(
        "/device/alice-phone", headers={"Accept-Language": "ru-RU,ru;q=0.9"}
    ).get_data(as_text=True)

    assert '<span class="tag tag-pend" role="status" aria-live="polite">Выключен</span>' in body
    assert "VPN-сервер сразу применяет Family DNS" in body
    assert "новые скачанные конфиги учитывают эту настройку" in body
    assert "Если выключить защиту после того, как устройство импортировало конфиг с Family DNS" in body
    assert "скачайте и заново импортируйте конфиг" in body
    assert "Зашифрованный DNS и прокси могут обойти" in body


def test_route_map_preserves_public_pages_and_removes_destructive_gets():
    rules = {rule.rule: set(rule.methods) for rule in app.url_map.iter_rules()}
    assert {"/login", "/register", "/dashboard", "/admin", "/tg_webhook", "/healthz"} <= set(
        rules
    )
    assert "GET" not in rules["/device/<wg_name>/delete"]
    assert "GET" not in rules["/admin/users/<username>/delete"]


def _assert_form_has_csrf(body, action):
    match = re.search(
        rf'<form[^>]+action="{re.escape(action)}"[^>]*>(.*?)</form>',
        body,
        flags=re.DOTALL,
    )
    assert match, f"form action {action!r} was not rendered"
    assert 'name="csrf_token"' in match.group(1)


def test_static_assets_are_served_in_full_by_the_flask_package():
    client = app.test_client()
    expected = {
        "/static/panel.css": ("text/css", 5_000),
        "/static/panel.js": ("text/javascript", 1_000),
        "/static/favicon.svg": ("image/svg+xml", 100),
    }

    for path, (mimetype, minimum_size) in expected.items():
        response = client.get(path)
        assert response.status_code == 200
        assert response.mimetype == mimetype
        assert len(response.data) >= minimum_size


def test_role_navigation_and_customer_payment_privacy(runtime):
    alice = user_record()
    alice.update(
        {
            "telegram_username": "private_handle",
            "payment_enabled": True,
            "payment_day": 15,
        }
    )
    core.save_users(
        {
            "admin": user_record(role="admin", limit=-1),
            "alice": alice,
        }
    )

    customer = app.test_client()
    csrf_session(customer, "alice")
    customer_body = customer.get("/dashboard").get_data(as_text=True)
    assert 'href="/admin"' not in customer_body
    assert 'href="/admin/users"' not in customer_body
    assert 'href="/traffic"' not in customer_body
    assert "private_handle" not in customer_body
    assert "payment_day" not in customer_body
    assert "5 BYN" not in customer_body

    admin = app.test_client()
    csrf_session(admin, "admin")
    admin_body = admin.get("/dashboard").get_data(as_text=True)
    assert 'href="/admin"' in admin_body
    assert 'href="/admin/users"' in admin_body
    assert 'href="/admin/devices"' in admin_body
    assert 'href="/traffic"' in admin_body


def test_device_and_admin_action_forms_keep_csrf_and_post_contracts(runtime):
    _data, clients = runtime
    core.save_users(
        {
            "admin": user_record(role="admin", limit=-1),
            "alice": user_record(),
            "pending": user_record(approved=False),
        }
    )
    (clients / "alice-phone.conf").write_text(
        "[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\n",
        encoding="utf-8",
    )
    traffic.save_device_meta(
        {"alice-phone": {"owner": "alice", "device": "phone", "vpn_type": "wireguard"}}
    )

    owner = app.test_client()
    csrf_session(owner, "alice")
    device_body = owner.get("/device/alice-phone").get_data(as_text=True)
    _assert_form_has_csrf(device_body, "/device/alice-phone/safe-internet")
    _assert_form_has_csrf(device_body, "/device/alice-phone/delete")
    _assert_form_has_csrf(device_body, "/logout")
    assert 'href="/device/alice-phone/download"' in device_body
    assert 'data-confirm=' in device_body

    admin = app.test_client()
    csrf_session(admin, "admin")
    admin_body = admin.get("/admin").get_data(as_text=True)
    _assert_form_has_csrf(admin_body, "/admin/users/pending/approve")
    _assert_form_has_csrf(admin_body, "/admin/users/pending/delete")


def test_english_and_russian_auth_pending_reset_and_app_pages(runtime):
    pending = user_record(approved=False)
    resetting = user_record()
    resetting["reset_token"] = "localized-reset-token"
    resetting["reset_token_expiry"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    core.save_users({"pending": pending, "resetting": resetting})
    client = app.test_client()

    en_login = client.get("/login").get_data(as_text=True)
    ru_login = client.get("/login", headers={"Accept-Language": "ru-RU"}).get_data(as_text=True)
    assert "Welcome back" in en_login
    assert "С возвращением" in ru_login

    csrf_session(client, "pending")
    en_pending = client.get("/dashboard").get_data(as_text=True)
    ru_pending = client.get(
        "/dashboard", headers={"Accept-Language": "ru-RU,ru;q=0.9"}
    ).get_data(as_text=True)
    assert "Pending Approval" in en_pending
    assert "Ожидание одобрения" in ru_pending
    _assert_form_has_csrf(en_pending, "/logout")

    anonymous = app.test_client()
    en_reset = anonymous.get("/reset/localized-reset-token").get_data(as_text=True)
    ru_reset = anonymous.get(
        "/reset/localized-reset-token", headers={"Accept-Language": "ru"}
    ).get_data(as_text=True)
    assert "Set New Password" in en_reset
    assert "Новый пароль" in ru_reset
    assert "resetting" in en_reset
    assert 'name="csrf_token"' in en_reset


def test_user_controlled_device_and_config_are_autoescaped_without_jinja_evaluation(runtime):
    _data, clients = runtime
    core.save_users({"alice": user_record()})
    display_name = "{{ 7 * 7 }}<script>alert(1)</script>"
    config = (
        "[Interface]\nPrivateKey = {{ 8 * 8 }}<img src=x onerror=alert(2)>\n"
        "Address = 10.0.0.2/32\n"
    )
    (clients / "alice-phone.conf").write_text(config, encoding="utf-8")
    traffic.save_device_meta(
        {
            "alice-phone": {
                "owner": "alice",
                "device": display_name,
                "vpn_type": "wireguard",
                "safe_internet": False,
            }
        }
    )
    client = app.test_client()
    csrf_session(client, "alice")

    dashboard = client.get("/dashboard").get_data(as_text=True)
    detail = client.get("/device/alice-phone").get_data(as_text=True)
    assert "{{ 7 * 7 }}" in dashboard
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in dashboard
    assert "<script>alert(1)</script>" not in dashboard
    assert "{{ 8 * 8 }}" in detail
    assert "&lt;img src=x onerror=alert(2)&gt;" in detail
    assert "<img src=x onerror=alert(2)>" not in detail
