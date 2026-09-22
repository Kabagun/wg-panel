import threading

import pytest

from wg_panel import access, app, core, traffic, wireguard


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    monkeypatch.setattr(core, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(core, "USERS_FILE", str(tmp_path / "data" / "users.json"))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(tmp_path / "data" / "devices.json"))
    monkeypatch.setattr(traffic, "TRAFFIC_FILE", str(tmp_path / "data" / "traffic.json"))
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(traffic, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(clients.parent))
    monkeypatch.setattr(traffic, "get_wg_peer_stats", dict)
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda *_args, **_kwargs: ())
    app.config.update(TESTING=True)
    core.save_users({
        "admin": {"role": "admin", "approved": True},
        "alice": {"approved": True, "max_devices": 3, "payment_enabled": True,
                  "payment_day": 15},
        "bob": {"approved": True}, "pending": {"approved": False},
    })
    names = ["u5-alice-phone", "u5-alice-laptop", "u3-bob-phone"]
    for index, name in enumerate(names, 2):
        owner, device = name.split("-", 2)[1:]
        (clients / f"{name}.conf").write_text(
            f"[Interface]\nPrivateKey = private-{name}\nAddress = 10.0.0.{index}/32\n"
            "[Peer]\nPublicKey = server\nPresharedKey = psk\n", encoding="utf-8",
        )
        traffic.set_device_meta(name, owner, device)
    live = set(names)
    calls = []

    def helper(script, name, timeout, *arguments):
        assert script == "set-client-state.sh"
        assert core.load_users()["alice"]["paused"]
        operation, = arguments
        calls.append((name, operation))
        if operation == "pause":
            live.discard(name)
        else:
            live.add(name)
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", helper)
    return clients, live, calls


def login(client, username):
    with client.session_transaction() as browser_session:
        browser_session.update(
            user=username, account_id=core.load_users()[username]["account_id"],
            session_version=1, _csrf_token="test-csrf",
        )
    return {"csrf_token": "test-csrf"}


def test_pause_resume_preserves_identity_configs_history_and_payments(runtime):
    clients, live, calls = runtime
    before = core.load_users()["alice"]
    configs = {path.name: path.read_bytes() for path in clients.iterdir()}
    metadata = traffic.load_device_meta()
    traffic.save_traffic({"u5-alice-phone": {
        "last_rx": 123, "last_tx": 456, "monthly": {"2026-09": {"rx": 123, "tx": 456}},
    }})
    assert access.set_user_paused("alice", True) == (True, "")
    assert live == {"u3-bob-phone"}
    assert core.load_users()["alice"]["paused"]
    assert not core.load_users()["alice"]["pause_pending"]
    assert access.set_user_paused("alice", True)[0]  # idempotent retry
    assert access.set_user_paused("alice", False)[0]
    assert len(live) == 3
    assert core.load_users()["alice"] == before
    assert traffic.load_device_meta() == metadata
    assert {path.name: path.read_bytes() for path in clients.iterdir()} == configs
    stats = traffic.load_traffic()["u5-alice-phone"]
    assert stats["monthly"] == {"2026-09": {"rx": 123, "tx": 456}}
    assert (stats["last_rx"], stats["last_tx"]) == (0, 0)
    assert len(calls) == 6


def test_partial_pause_is_retryable_and_does_not_claim_success(runtime, monkeypatch):
    _clients, live, _calls = runtime
    original = wireguard._run_script

    def failure(script, name, timeout, *arguments):
        if name.endswith("laptop"):
            return False, "simulated failure"
        return original(script, name, timeout, *arguments)

    monkeypatch.setattr(wireguard, "_run_script", failure)
    assert not access.set_user_paused("alice", True)[0]
    assert live == {"u3-bob-phone", "u5-alice-laptop"}
    user = core.load_users()["alice"]
    assert user["paused"] and user["pause_pending"]
    assert access.access_status(user) == "attention"
    assert wireguard.create_device("alice", "new")[2] == "VPN access is paused"
    monkeypatch.setattr(wireguard, "_run_script", original)
    assert access.reconcile_paused_users() == 1
    assert live == {"u3-bob-phone"}
    assert access.access_status(core.load_users()["alice"]) == "paused"


@pytest.mark.parametrize("rollback_fails", [False, True])
def test_resume_failure_repauses_every_peer(runtime, monkeypatch, rollback_fails):
    _clients, live, calls = runtime
    assert access.set_user_paused("alice", True)[0]
    original = wireguard._run_script
    calls.clear()

    def failure(script, name, timeout, *arguments):
        if arguments == ("resume",) and name.endswith("phone"):
            return False, "resume failed"
        if rollback_fails and arguments == ("pause",) and name.endswith("laptop"):
            return False, "rollback failed"
        return original(script, name, timeout, *arguments)

    monkeypatch.setattr(wireguard, "_run_script", failure)
    assert not access.set_user_paused("alice", False)[0]
    user = core.load_users()["alice"]
    assert user["paused"]
    assert user["pause_pending"] == rollback_fails
    assert ("u5-alice-phone", "pause") in calls
    assert ("u5-alice-laptop" in live) == rollback_fails


def test_resume_restores_safe_dns_before_restoring_any_peer(runtime, monkeypatch):
    assert access.set_user_paused("alice", True)[0]
    _clients, live, calls = runtime
    calls.clear()

    def fail_dns(**_kwargs):
        raise wireguard.SafeDnsEnforcementError("simulated DNS failure")

    monkeypatch.setattr(wireguard, "reconcile_safe_dns", fail_dns)
    assert not access.set_user_paused("alice", False)[0]
    assert all(operation == "pause" for _name, operation in calls)
    assert live == {"u3-bob-phone"}


def test_storage_failure_before_pause_does_not_touch_peers(runtime, monkeypatch):
    _clients, live, calls = runtime

    def fail(*_args, **_kwargs):
        raise OSError("read-only storage")

    monkeypatch.setattr(access, "mutate_users", fail)
    assert not access.set_user_paused("alice", True)[0]
    assert len(live) == 3
    assert not calls


def test_resume_confirmation_storage_failure_rolls_back_peers(runtime, monkeypatch):
    _clients, live, _calls = runtime
    assert access.set_user_paused("alice", True)[0]
    original = access._checkpoint

    def fail(username, *, paused, pending):
        if not paused:
            raise OSError("disk full")
        return original(username, paused=paused, pending=pending)

    monkeypatch.setattr(access, "_checkpoint", fail)
    assert not access.set_user_paused("alice", False)[0]
    assert live == {"u3-bob-phone"}
    assert core.load_users()["alice"]["paused"]


@pytest.mark.parametrize("problem", ["missing", "unowned"])
def test_unresolved_ownership_blocks_success_and_startup(runtime, problem):
    clients, _live, _calls = runtime
    if problem == "missing":
        (clients / "u5-alice-phone.conf").unlink()
    else:
        (clients / "unknown.conf").write_text("[Interface]\n")
    assert not access.set_user_paused("alice", True)[0]
    assert core.load_users()["alice"]["pause_pending"]
    with pytest.raises(RuntimeError, match="reconciliation failed"):
        access.reconcile_paused_users()


@pytest.mark.parametrize("username", ["admin", "pending", "missing", "bob"])
def test_protected_accounts_cannot_be_paused(runtime, username):
    core.mutate_users(lambda users: users["bob"].update(revoking=True))
    assert not access.set_user_paused(username, True)[0]
    assert not runtime[2]


def test_pause_excludes_concurrent_provisioning(runtime, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = wireguard._run_script

    def waiting(*args):
        entered.set()
        assert release.wait(3)
        return original(*args)

    monkeypatch.setattr(wireguard, "_run_script", waiting)
    pause_results, create_results = [], []
    pausing = threading.Thread(target=lambda: pause_results.append(access.set_user_paused("alice", True)))
    pausing.start()
    assert entered.wait(2)
    creating = threading.Thread(target=lambda: create_results.append(wireguard.create_device("alice", "new")))
    creating.start()
    release.set()
    pausing.join(5)
    creating.join(5)
    assert pause_results == [(True, "")]
    assert create_results == [(False, "", "VPN access is paused")]


def test_pause_routes_require_admin_post_and_csrf(runtime):
    customer = app.test_client()
    form = login(customer, "alice")
    for operation in ("pause", "resume"):
        url = f"/admin/users/bob/{operation}"
        assert customer.get(url).status_code == 405
        assert customer.post(url, data=form).status_code == 302
    assert not runtime[2]
    admin = app.test_client()
    login(admin, "admin")
    assert admin.post("/admin/users/alice/pause").status_code == 400
    assert not runtime[2]


def test_customer_paused_dashboard_and_configs_remain_readable(runtime):
    clients, _live, _calls = runtime
    assert access.set_user_paused("alice", True)[0]
    customer = app.test_client()
    form = login(customer, "alice")
    page = customer.get("/dashboard", headers={"Accept-Language": "ru"}).get_data(as_text=True)
    assert "Доступ к VPN приостановлен" in page
    assert "Импортировать их заново не нужно" in page
    assert 'href="/add"' not in page
    assert "Можно добавить устройств" not in page
    assert "Сохранён на время паузы" in page
    assert "Device limit reached" not in page
    name = "u5-alice-phone"
    config = customer.get(f"/device/{name}/download")
    assert config.status_code == 200
    assert config.headers["Cache-Control"].startswith("no-store")
    assert "private-" in config.get_data(as_text=True)
    for url in ("/add", f"/device/{name}/delete", f"/device/{name}/safe-internet"):
        assert customer.post(url, data=form).status_code == 302
    assert customer.get("/add").status_code == 302
    assert (clients / f"{name}.conf").exists()
    assert not traffic.load_device_meta()[name]["safe_internet"]


def test_admin_pause_resume_and_filters_reflect_confirmed_state(runtime):
    admin = app.test_client()
    form = login(admin, "admin")
    response = admin.post("/admin/users/alice/pause", data=form, follow_redirects=True)
    assert response.status_code == 200
    assert "VPN paused for alice" in response.get_data(as_text=True)
    body = admin.get("/admin/users?status=paused").get_data(as_text=True)
    assert 'action="/admin/users/alice/resume"' in body
    assert 'action="/admin/users/bob/pause"' not in body
    assert 'name="csrf_token"' in body
    devices = admin.get("/admin/devices").get_data(as_text=True)
    assert 'class="tag access-tag tag-paused"' in devices
    assert admin.post("/admin/users/alice/approve", data={**form, "max_devices": "3"}).status_code == 302
    assert core.load_users()["alice"]["paused"]
    customer = app.test_client()
    login(customer, "alice")
    assert admin.post("/admin/users/alice/resume", data=form).status_code == 302
    assert 'href="/add"' in customer.get("/dashboard").get_data(as_text=True)
    assert not core.load_users()["alice"]["paused"]


def test_partial_pause_ui_is_honest_and_offers_retry(runtime, monkeypatch):
    monkeypatch.setattr(wireguard, "_run_script", lambda *_args: (False, "helper failed"))
    assert not access.set_user_paused("alice", True)[0]
    admin = app.test_client()
    login(admin, "admin")
    body = admin.get("/admin/users?status=attention").get_data(as_text=True)
    assert "Needs attention" in body
    assert "Retry pause: alice" in body
    assert 'action="/admin/users/alice/resume"' not in body
    customer = app.test_client()
    login(customer, "alice")
    body = customer.get("/dashboard").get_data(as_text=True)
    assert "disabling every device has not been confirmed" in body
    body = customer.get("/device/u5-alice-phone").get_data(as_text=True)
    assert "Saved configuration" in body
    assert "data-auto-submit" not in body
    assert 'action="/device/u5-alice-phone/delete"' not in body


def test_startup_aborts_before_serving_when_pause_cannot_be_enforced(runtime, monkeypatch):
    from wg_panel import runner
    assert access.set_user_paused("alice", True)[0]
    monkeypatch.setattr(runner, "ENABLE_HTTP_REDIRECT", False)
    monkeypatch.setattr(runner, "CLIENTS_DIR", str(runtime[0]))
    monkeypatch.setattr(runner, "DATA_DIR", core.DATA_DIR)
    monkeypatch.setattr(runner, "ensure_admin", lambda: None)
    monkeypatch.setattr(wireguard, "_run_script", lambda *_args: (False, "helper missing"))
    started = []
    monkeypatch.setattr(app, "run", lambda **_kwargs: started.append(True))
    with pytest.raises(RuntimeError, match="pause reconciliation failed"):
        runner.main()
    assert not started
