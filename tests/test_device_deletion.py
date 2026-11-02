"""Deletion consent must survive neither identity changes nor nonce reuse."""

import re
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from wg_panel import app, core, deletion, traffic, wireguard
from wg_panel.routes import devices as device_routes

CONFIG = "[Interface]\nAddress = 10.0.0.2/32\n\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n"


@pytest.fixture
def deletion_runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "USERS_FILE", str(data / "users.json"))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(data / "device_meta.json"))
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(clients.parent))
    monkeypatch.setattr(device_routes, "qr_svg_b64", lambda _name: None)
    monkeypatch.setattr(device_routes, "send_telegram", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(deletion, "_challenges", {})
    monkeypatch.setitem(app.config, "TESTING", True)
    clock = [1000.0]
    monkeypatch.setattr(deletion.time, "monotonic", lambda: clock[0])
    core.save_users({
        name: {
            "password_hash": "synthetic-test-hash", "role": role, "approved": True,
            "session_version": 1, "max_devices": -1, "payment_enabled": True,
        }
        for name, role in (("admin", "admin"), ("alice", "user"), ("bob", "user"))
    })
    metadata = {}
    for owner, label in (("alice", "phone"), ("alice", "laptop"), ("admin", "home-router")):
        name = f"{owner}-{label}"
        (clients / f"{name}.conf").write_text(CONFIG, encoding="utf-8")
        metadata[name] = {"owner": owner, "device": label, "vpn_type": "wireguard"}
    metadata["admin-home-router"]["deletion_protected"] = True
    traffic.save_device_meta(metadata)
    calls = []

    def remove(script, name, _timeout):
        assert script == "remove-client.sh"
        calls.append(name)
        (clients / f"{name}.conf").unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    return SimpleNamespace(clients=clients, calls=calls, clock=clock)


def browser(username="alice"):
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(
            user=username, session_version=1, account_id=core.load_users()[username]["account_id"],
            _csrf_token="synthetic-csrf-token",
        )
    return client


def confirmation(client, name="alice-phone", **kwargs):
    response = client.get(f"/device/{name}/delete/confirm", **kwargs)
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    match = re.search(r'name="challenge" value="([A-Za-z0-9_-]+)"', body)
    assert match, body
    return match[1], body


def remove(client, nonce, name="alice-phone", **fields):
    return client.post(f"/device/{name}/delete", data={
        "csrf_token": "synthetic-csrf-token", "challenge": nonce, "confirmed": "on", **fields,
    })


def test_ordinary_device_has_one_confirmation_and_no_destructive_get(deletion_runtime):
    client = browser()
    nonce, body = confirmation(client)
    assert '<strong class="deletion-device-name" id="deletion-device-name">phone</strong>' in body
    assert 'action="/device/alice-phone/delete"' in body
    assert 'name="confirmed" value="on"' in body
    assert 'name="typed_name"' not in body
    assert "Confirmation 1 of 2" not in body
    assert deletion_runtime.clients.joinpath("alice-phone.conf").read_text() == CONFIG
    assert client.get("/device/alice-phone/delete").status_code == 405
    assert client.post("/device/alice-phone/delete/confirm", data={
        "csrf_token": "synthetic-csrf-token",
    }).status_code == 405
    assert remove(client, nonce).status_code == 302
    assert deletion_runtime.calls == ["alice-phone"]
    assert not wireguard.get_device("alice-phone")


@pytest.mark.parametrize("fields", [{"challenge": ""}, {"confirmed": ""}])
def test_legacy_or_missing_confirmation_cannot_delete(deletion_runtime, fields):
    client = browser()
    nonce, _body = confirmation(client)
    assert remove(client, nonce, **fields).status_code == 303
    assert not deletion_runtime.calls
    assert wireguard.get_device("alice-phone")


@pytest.mark.parametrize("typed_name", ["", "HOME-router", "home-router ", "phone"])
def test_protected_name_must_match_exactly(deletion_runtime, typed_name):
    client = browser("admin")
    nonce, body = confirmation(client, "admin-home-router")
    assert 'name="typed_name"' in body
    assert 'autocomplete="off"' in body
    assert 'data-delete-exact-name="home-router"' in body
    assert remove(client, nonce, "admin-home-router", typed_name=typed_name).status_code == 303
    assert not deletion_runtime.calls
    assert wireguard.get_device("admin-home-router")
    # A wrong-name attempt consumes consent, so correcting and replaying it fails.
    assert remove(client, nonce, "admin-home-router", typed_name="home-router").status_code == 303
    assert not deletion_runtime.calls


def test_protected_device_can_be_removed_only_through_validated_confirmation(deletion_runtime):
    assert not wireguard.delete_device("admin-home-router")[0]
    client = browser("admin")
    nonce, _body = confirmation(client, "admin-home-router")
    response = remove(client, nonce, "admin-home-router", typed_name="home-router", return_to="admin")
    assert response.status_code == 302
    assert response.location.endswith("/admin/devices")
    assert deletion_runtime.calls == ["admin-home-router"]


def test_csrf_and_ownership_guard_confirmation_and_delete(deletion_runtime):
    owner = browser()
    nonce, _body = confirmation(owner)
    assert owner.post("/device/alice-phone/delete", data={
        "challenge": nonce, "confirmed": "on",
    }).status_code == 400
    attacker = browser("bob")
    assert attacker.get("/device/alice-phone/delete/confirm").status_code == 302
    assert remove(attacker, nonce).status_code == 302
    assert not deletion_runtime.calls
    # An unauthorized request cannot consume the owner's challenge.
    assert remove(owner, nonce).status_code == 302
    assert deletion_runtime.calls == ["alice-phone"]


@pytest.mark.parametrize("state_change", ["paused", "unapproved", "logged_out", "new_account"])
def test_changed_authentication_cannot_use_pending_confirmation(deletion_runtime, state_change):
    client = browser()
    nonce, _body = confirmation(client)
    if state_change == "paused":
        core.mutate_users(lambda users: users["alice"].update(paused=True))
    elif state_change == "unapproved":
        core.mutate_users(lambda users: users["alice"].update(approved=False))
    elif state_change == "new_account":
        core.mutate_users(lambda users: users["alice"].update(account_id="replacement-account"))
    else:
        with client.session_transaction() as state:
            state.pop("user")
    response = remove(client, nonce)
    assert response.status_code in {200, 302}
    assert not deletion_runtime.calls


def test_nonce_is_bound_to_browser_session_and_rotated_csrf(deletion_runtime):
    owner = browser()
    other_session = browser()
    nonce, _body = confirmation(owner)
    assert remove(other_session, nonce).status_code == 303
    assert not deletion_runtime.calls
    nonce, _body = confirmation(owner)
    with owner.session_transaction() as state:
        state["_csrf_token"] = "rotated-token"
    assert remove(owner, nonce, csrf_token="rotated-token").status_code == 303
    assert not deletion_runtime.calls


def test_nonce_expires_and_restart_invalidates_pending_consent(deletion_runtime, monkeypatch):
    client = browser()
    nonce, _body = confirmation(client)
    deletion_runtime.clock[0] += deletion.CHALLENGE_TTL_SECONDS
    assert remove(client, nonce).status_code == 303
    nonce, _body = confirmation(client)
    monkeypatch.setattr(deletion, "_challenges", {})
    assert remove(client, nonce).status_code == 303
    assert not deletion_runtime.calls


@pytest.mark.parametrize("changed", ["config", "owner", "display_name", "protected", "unprotected"])
def test_identity_or_protection_changes_invalidate_consent(deletion_runtime, changed):
    client = browser("admin")
    if changed == "unprotected":
        assert wireguard.set_device_deletion_protected("alice-phone")
    nonce, _body = confirmation(client)
    if changed == "config":
        (deletion_runtime.clients / "alice-phone.conf").write_text(CONFIG + "# recreated\n")
    else:
        field, value = {
            "owner": ("owner", "bob"), "display_name": ("device", "renamed-phone"),
            "protected": ("deletion_protected", True), "unprotected": ("deletion_protected", False),
        }[changed]
        traffic.mutate_device_meta(lambda meta: meta["alice-phone"].update({field: value}))
    assert remove(client, nonce, typed_name="phone").status_code == 303
    assert not deletion_runtime.calls


def test_nonce_cannot_target_another_device_or_replay_after_recreation(deletion_runtime):
    client = browser()
    nonce, _body = confirmation(client)
    assert remove(client, nonce, "alice-laptop").status_code == 303
    assert not deletion_runtime.calls
    nonce, _body = confirmation(client)
    original_meta = traffic.load_device_meta()["alice-phone"]
    assert remove(client, nonce).status_code == 302
    (deletion_runtime.clients / "alice-phone.conf").write_text(CONFIG)
    traffic.mutate_device_meta(lambda meta: meta.update({"alice-phone": original_meta}))
    assert remove(client, nonce).status_code == 303
    assert deletion_runtime.calls == ["alice-phone"]


def test_helper_failure_consumes_nonce_without_losing_device(deletion_runtime, monkeypatch):
    client = browser()
    nonce, _body = confirmation(client)
    monkeypatch.setattr(wireguard, "_run_script", lambda *_args: (False, "synthetic failure"))
    assert remove(client, nonce).status_code == 303
    assert wireguard.get_device("alice-phone")
    assert remove(client, nonce).status_code == 303
    assert not deletion_runtime.calls


def test_concurrent_replay_runs_revocation_once(deletion_runtime):
    actor = ("alice", "synthetic-session")
    nonce = wireguard.begin_device_deletion("alice-phone", actor)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(
            lambda _index: wireguard.delete_device_confirmed(
                "alice-phone", actor, nonce, confirmed=True,
            ), range(2),
        ))
    assert sum(ok for ok, _error in results) == 1
    assert deletion_runtime.calls == ["alice-phone"]


@pytest.mark.parametrize("stale", [False, True])
def test_account_delete_preflight_preserves_every_peer_and_account(deletion_runtime, stale):
    wireguard.set_device_deletion_protected("alice-laptop")
    if stale:
        (deletion_runtime.clients / "alice-laptop.conf").unlink()
    before_users = core.load_users()
    before_meta = traffic.load_device_meta()
    admin = browser("admin")
    response = admin.post("/admin/users/alice/delete", data={
        "csrf_token": "synthetic-csrf-token",
    })
    assert response.status_code == 302
    assert core.load_users() == before_users
    assert traffic.load_device_meta() == before_meta
    assert (deletion_runtime.clients / "alice-phone.conf").exists()
    assert not deletion_runtime.calls
    wireguard.migrate_device_metadata()
    assert traffic.load_device_meta()["alice-laptop"]["deletion_protected"]


def test_protection_is_visible_independent_of_dns_and_cannot_be_overwritten(deletion_runtime):
    admin = browser("admin")
    original = (deletion_runtime.clients / "admin-home-router.conf").read_text()
    for path in ("/dashboard", "/admin/devices", "/device/admin-home-router"):
        body = admin.get(path).get_data(as_text=True)
        assert "home-router" in body
        assert "Deletion protected" in body
    metadata = wireguard.get_device("admin-home-router")
    assert metadata["owner"] == "admin"
    assert not metadata["safe_internet"]
    with pytest.raises(ValueError, match="deletion-protected"):
        traffic.set_device_meta("admin-home-router", "bob", "router")
    assert (deletion_runtime.clients / "admin-home-router.conf").read_text() == original


def test_confirmation_escapes_name_and_localizes_russian(deletion_runtime):
    name = '<script>alert("synthetic")</script>'
    traffic.mutate_device_meta(lambda meta: meta["admin-home-router"].update(device=name))
    _nonce, body = confirmation(browser("admin"), "admin-home-router",
                                headers={"Accept-Language": "ru-RU"})
    assert "Защищено от удаления" in body
    assert "Введите точное имя устройства" in body
    assert name not in body
    assert "&lt;script&gt;" in body
    assert 'name="csrf_token"' in body


def test_challenge_store_is_bounded_and_evicts_expired_entries(deletion_runtime, monkeypatch):
    monkeypatch.setattr(deletion, "MAX_CHALLENGES", 2)
    actor = ("alice", "synthetic-session")
    first = wireguard.begin_device_deletion("alice-phone", actor)
    second = wireguard.begin_device_deletion("alice-phone", actor)
    third = wireguard.begin_device_deletion("alice-phone", actor)
    assert len(deletion._challenges) == 2
    assert first not in deletion._challenges
    assert {second, third} == set(deletion._challenges)
    deletion_runtime.clock[0] += deletion.CHALLENGE_TTL_SECONDS
    wireguard.begin_device_deletion("alice-phone", actor)
    assert len(deletion._challenges) == 1
