"""Permanent owner policy, consent and recovery against fake local state."""

import base64
import json
import threading

import pytest

from wg_panel import account_policy, app, core, traffic, wireguard


@pytest.fixture
def policy_runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "USERS_FILE", str(data / "users.json"))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(data / "device_meta.json"))
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(clients.parent))
    monkeypatch.setitem(app.config, "TESTING", True)
    users = {
        name: {"password_hash": "unused-fixture", "approved": True, "role": role}
        for name, role in (("alice", "user"), ("bob", "user"), ("admin", "admin"))
    }
    core.save_users(users)
    name = "u5-alice-phone"
    config = clients / f"{name}.conf"
    config.write_text("[Interface]\nAddress = 10.0.0.2/32\n\n[Peer]\n", encoding="utf-8")
    traffic.set_device_meta(name, "alice", "phone")
    calls = []
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda ips, **_kw: calls.append(tuple(ips)))
    monkeypatch.setattr(wireguard, "qr_svg_b64", lambda _name: None)
    return name, config, calls


def authenticated_client(username):
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session.update(
            user=username,
            session_version=1,
            account_id=core.load_users()[username]["account_id"],
            _csrf_token="policy-test-token",
        )
    return client


def post_policy(client, name, **values):
    return client.post(
        f"/device/{name}/safe-internet",
        data={"csrf_token": "policy-test-token", **values},
        follow_redirects=True,
    )


@pytest.mark.parametrize("consent", [None, "", "true", "1", "off"])
def test_first_enable_requires_explicit_consent_in_http_and_backend(policy_runtime, consent):
    name, _config, calls = policy_runtime
    before = traffic.load_device_meta()
    values = {"safe_internet": "on"}
    if consent is not None:
        values["safe_internet_confirmed"] = consent
    response = post_policy(authenticated_client("alice"), name, **values)
    assert "Confirm permanent Safe internet protection" in response.get_data(as_text=True)
    assert not wireguard.set_account_safe_internet("alice")
    assert not account_policy.account_safe_internet_locked("alice")
    assert not wireguard.set_device_safe_internet(name, True)
    assert not traffic.set_device_safe_internet(name, True)
    assert traffic.load_device_meta() == before
    assert not calls


def test_confirmed_first_enable_locks_and_repeated_enable_repairs_enforcement(policy_runtime):
    name, _config, calls = policy_runtime
    assert wireguard.set_device_safe_internet(name, True, confirmed=True)
    assert traffic.load_device_meta()[name]["safe_internet_locked"] is True
    assert wireguard.set_device_safe_internet(name, True)
    assert not wireguard.set_device_safe_internet(name, False)
    assert not traffic.set_device_safe_internet(name, False)
    assert calls == [("10.0.0.2",), ("10.0.0.2",)]
    assert traffic.load_device_meta()[name]["safe_internet"] is True
    with pytest.raises(ValueError, match="manual server recovery"):
        traffic.set_device_meta(name, "alice", "phone")


def test_owner_cannot_submit_admin_recovery_flag_or_bypass_lock(policy_runtime):
    name, _config, calls = policy_runtime
    owner = authenticated_client("alice")
    post_policy(owner, name, safe_internet="on", safe_internet_confirmed="on")
    before = traffic.load_device_meta()
    calls.clear()
    response = post_policy(
        owner, name, allow_locked_disable="on", safe_internet_locked="off",
        safe_internet_confirmed="on",
    )
    assert "Safe internet cannot be disabled in the panel" in response.get_data(as_text=True)
    assert account_policy.account_safe_internet_locked("alice")
    assert traffic.load_device_meta() == before
    assert not calls


@pytest.mark.parametrize("owner", ["alice", "admin"])
def test_web_admin_cannot_disable_own_or_other_locked_device(policy_runtime, owner):
    name, _config, calls = policy_runtime
    traffic.mutate_device_meta(lambda records: records[name].update(owner=owner))
    assert wireguard.set_account_safe_internet(owner, confirmed=True)
    before = traffic.load_device_meta()
    calls.clear()
    admin = authenticated_client("admin")
    body = admin.get(f"/device/{name}").get_data(as_text=True)
    assert "including administrators, can turn it off" in body
    assert "data-auto-submit" not in body
    response = post_policy(admin, name, allow_locked_disable="on", admin_override="on")
    assert "Safe internet cannot be disabled in the panel" in response.get_data(as_text=True)
    assert traffic.load_device_meta() == before
    assert not calls


def test_manual_server_maintenance_requires_internal_flag(policy_runtime):
    name, _config, calls = policy_runtime
    assert wireguard.set_device_safe_internet(name, True, confirmed=True)
    assert wireguard.set_device_safe_internet(name, False, allow_locked_disable=True)
    assert traffic.load_device_meta()[name]["safe_internet"] is False
    assert not traffic.load_device_meta()[name].get("safe_internet_locked")
    assert calls == [("10.0.0.2",), ()]
    assert not wireguard.set_device_safe_internet(name, True)
    assert wireguard.set_device_safe_internet(name, True, confirmed=True)
    assert traffic.load_device_meta()[name]["safe_internet_locked"] is True


def test_consent_still_requires_csrf_and_device_ownership(policy_runtime):
    name, _config, calls = policy_runtime
    values = {"safe_internet": "on", "safe_internet_confirmed": "on"}
    owner = authenticated_client("alice")
    assert owner.post(f"/device/{name}/safe-internet", data=values).status_code == 400
    post_policy(authenticated_client("bob"), name, **values)
    assert not traffic.load_device_meta()[name]["safe_internet"]
    assert not calls


def test_legacy_enabled_state_is_not_silently_locked_by_read_migration_or_reconciliation(
    policy_runtime,
):
    name, _config, calls = policy_runtime
    traffic.mutate_device_meta(lambda records: records[name].update(safe_internet=True))
    wireguard.migrate_device_metadata()
    assert wireguard.reconcile_safe_dns()["safe_devices"] == 1
    assert wireguard.set_device_safe_internet(name, True)
    post_policy(authenticated_client("alice"), name, safe_internet="on")
    assert not traffic.load_device_meta()[name].get("safe_internet_locked")
    page = authenticated_client("alice").get(f"/device/{name}").get_data(as_text=True)
    assert "Protect all account profiles" in page
    assert "data-safe-lock" in page
    post_policy(
        authenticated_client("alice"), name, safe_internet="on", safe_internet_confirmed="on",
    )
    assert account_policy.account_safe_internet_locked("alice")
    assert traffic.load_device_meta()[name]["safe_internet"]
    assert all(ips == ("10.0.0.2",) for ips in calls)


def test_failed_firewall_or_metadata_write_does_not_persist_consent_lock(
    policy_runtime, monkeypatch,
):
    name, _config, calls = policy_runtime

    def fail_firewall(*_args, **_kwargs):
        raise wireguard.SafeDnsEnforcementError("fake enforcement failure")

    monkeypatch.setattr(wireguard, "_sync_safe_dns", fail_firewall)
    assert not wireguard.set_device_safe_internet(name, True, confirmed=True)
    assert not traffic.load_device_meta()[name].get("safe_internet_locked")
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda ips, **_kw: calls.append(tuple(ips)))

    def fail_storage(*_args, **_kwargs):
        raise OSError("fake storage failure")

    monkeypatch.setattr(wireguard, "_set_device_safe_internet", fail_storage)
    assert not wireguard.set_device_safe_internet(name, True, confirmed=True)
    assert calls == [("10.0.0.2",), ()]
    assert not traffic.load_device_meta()[name].get("safe_internet_locked")


def test_queued_disable_cannot_win_after_confirmed_enable(policy_runtime, monkeypatch):
    name, _config, _calls = policy_runtime
    enforcing = threading.Event()
    release = threading.Event()
    disabling = threading.Event()
    results = {}

    def slow_enforcement(_ips, **_kwargs):
        enforcing.set()
        assert release.wait(5)

    def disable():
        disabling.set()
        results["disable"] = wireguard.set_device_safe_internet(name, False)

    monkeypatch.setattr(wireguard, "_sync_safe_dns", slow_enforcement)
    enable_thread = threading.Thread(target=lambda: results.update(
        enable=wireguard.set_device_safe_internet(name, True, confirmed=True),
    ))
    disable_thread = threading.Thread(target=disable)
    enable_thread.start()
    assert enforcing.wait(5)
    disable_thread.start()
    assert disabling.wait(5)
    release.set()
    enable_thread.join(5)
    disable_thread.join(5)
    assert not enable_thread.is_alive() and not disable_thread.is_alive()
    assert results == {"enable": True, "disable": False}
    assert traffic.load_device_meta()[name]["safe_internet_locked"]


def test_locked_deleted_identity_survives_restart_and_cannot_be_recreated(
    policy_runtime, monkeypatch,
):
    name, config, _calls = policy_runtime
    assert wireguard.set_device_safe_internet(name, True, confirmed=True)
    removals = []

    def remove(script, removed_name, _timeout):
        removals.append((script, removed_name))
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    assert wireguard.delete_device(name) == (True, "")
    assert traffic.load_device_meta()[name]["revoked"]
    assert wireguard.get_all_devices() == []
    assert wireguard.get_device(name) is None
    wireguard.migrate_device_metadata()
    assert wireguard.reconcile_safe_dns() == {"safe_devices": 0, "ips": []}
    assert traffic.load_device_meta()[name]["safe_internet_locked"]
    assert wireguard.create_device("alice", "phone") == (
        False, "", "A permanently protected device requires manual server recovery via SSH",
    )
    assert removals == [("remove-client.sh", name)]
    config.write_text("[Interface]\nAddress = 10.0.0.2/32\n", encoding="utf-8")
    with pytest.raises(wireguard.DeviceMetadataMigrationError):
        wireguard.migrate_device_metadata()


def test_account_deletion_and_recreation_cannot_clear_locked_identity(policy_runtime, monkeypatch):
    name, config, _calls = policy_runtime
    assert wireguard.set_device_safe_internet(name, True, confirmed=True)

    def remove(*_args):
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    assert wireguard.delete_user("alice") == (True, "")
    assert "alice" not in core.load_users()
    assert traffic.load_device_meta()[name]["safe_internet_locked"]
    assert traffic.load_device_meta()[name]["revoked"]
    core.mutate_users(lambda users: users.update(alice={"approved": True, "role": "user"}))
    assert not wireguard.create_device("alice", "phone")[0]


def add_fake_profile(policy_runtime, owner, device, address):
    _name, config, _calls = policy_runtime
    name = f"u{len(owner)}-{owner}-{device}"
    (config.parent / f"{name}.conf").write_text(
        f"[Interface]\nAddress = {address}/32\n\n[Peer]\n", encoding="utf-8",
    )
    traffic.set_device_meta(name, owner, device)
    return name


def test_account_activation_enforces_all_current_profiles_and_isolates_other_owners(
    policy_runtime, monkeypatch,
):
    name, _config, calls = policy_runtime
    laptop = add_fake_profile(policy_runtime, "alice", "laptop", "10.0.0.3")
    other = add_fake_profile(policy_runtime, "bob", "phone", "10.0.0.4")
    before = traffic.load_device_meta()
    save = wireguard.save_account_policies

    def record_after_enforcement(policies):
        assert set(calls[-1]) == {"10.0.0.2", "10.0.0.3"}
        assert not account_policy.account_safe_internet_locked("alice")
        save(policies)

    monkeypatch.setattr(wireguard, "save_account_policies", record_after_enforcement)
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    assert traffic.load_device_meta() == before
    assert wireguard.get_device(name)["safe_internet"]
    assert wireguard.get_device(laptop)["safe_internet"]
    assert not wireguard.get_device(other)["safe_internet"]
    assert "DNS = 1.1.1.3, 1.0.0.3" in wireguard.get_config(laptop)
    assert "DNS = 1.1.1.1, 8.8.8.8" in wireguard.get_config(other)
    assert wireguard.reconcile_safe_dns()["safe_devices"] == 2
    assert not wireguard.set_device_safe_internet(name, False, allow_locked_disable=True)
    assert not traffic.set_device_safe_internet(name, False, allow_locked_disable=True)


def test_dashboard_can_lock_account_without_devices_and_ignores_forged_owner(policy_runtime):
    name, config, _calls = policy_runtime
    config.unlink()
    traffic.remove_device_meta(name)
    client = authenticated_client("alice")
    assert "All current and future VPN profiles of alice" in client.get("/dashboard").get_data(as_text=True)
    assert client.post("/account/safe-internet", data={"safe_internet": "on"}).status_code == 400
    response = client.post("/account/safe-internet", data={
        "csrf_token": "policy-test-token", "safe_internet": "on",
        "safe_internet_confirmed": "on", "owner": "bob", "account": "admin",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert account_policy.account_safe_internet_locked("alice")
    assert not account_policy.account_safe_internet_locked("bob")
    assert not account_policy.account_safe_internet_locked("admin")
    assert client.get("/account/safe-internet").status_code == 405
    assert "Account locked" in response.get_data(as_text=True)


def test_account_lock_survives_all_profiles_and_user_deletion_then_new_identity_profiles(
    policy_runtime, monkeypatch,
):
    name, config, _calls = policy_runtime
    assert wireguard.set_account_safe_internet("alice", confirmed=True)

    def remove(*_args):
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    old_identity = core.load_users()["alice"]["account_id"]
    assert wireguard.delete_user("alice")[0]
    assert not traffic.load_device_meta()
    wireguard.migrate_device_metadata()
    assert account_policy.account_safe_internet_locked("alice")
    core.mutate_users(lambda users: users.update(alice={"approved": True, "role": "user"}))
    assert core.load_users()["alice"]["account_id"] != old_identity
    fake_protected_provisioner(policy_runtime, monkeypatch)
    ok, different, error = wireguard.create_device("alice", "different-name")
    assert ok, error
    assert wireguard.get_device(different)["safe_internet"]
    assert "DNS = 1.1.1.3, 1.0.0.3" in wireguard.get_config(different)
    assert wireguard.reconcile_safe_dns()["ips"] == ["10.0.0.8"]
    assert name not in traffic.load_device_meta()


def test_account_policy_storage_and_enforcement_failures_preserve_previous_state(
    policy_runtime, monkeypatch,
):
    _name, _config, calls = policy_runtime
    other = add_fake_profile(policy_runtime, "bob", "phone", "10.0.0.4")
    traffic.mutate_device_meta(lambda meta: meta[other].update(safe_internet=True))

    def fail_enforcement(*_args, **_kwargs):
        raise wireguard.SafeDnsEnforcementError("fake enforcement failure")

    monkeypatch.setattr(wireguard, "_sync_safe_dns", fail_enforcement)
    assert not wireguard.set_account_safe_internet("alice", confirmed=True)
    assert not account_policy.account_safe_internet_locked("alice")
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda ips, **_kw: calls.append(tuple(ips)))

    def fail_storage(_policies):
        raise OSError("fake account policy storage failure")

    monkeypatch.setattr(wireguard, "save_account_policies", fail_storage)
    assert not wireguard.set_account_safe_internet("alice", confirmed=True)
    assert calls == [("10.0.0.2", "10.0.0.4"), ("10.0.0.4",)]
    assert not account_policy.account_safe_internet_locked("alice")
    assert wireguard.get_device(other)["safe_internet"]


def test_post_commit_storage_error_keeps_account_enforcement_instead_of_rolling_back(
    policy_runtime, monkeypatch,
):
    _name, _config, calls = policy_runtime
    save = wireguard.save_account_policies

    def committed_with_error(policies):
        save(policies)
        raise OSError("fake final chmod error after atomic replacement")

    monkeypatch.setattr(wireguard, "save_account_policies", committed_with_error)
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    assert account_policy.account_safe_internet_locked("alice")
    assert calls == [("10.0.0.2",)]


def test_invalid_account_registry_and_unsupported_profiles_fail_closed(policy_runtime):
    name, _config, calls = policy_runtime
    traffic.mutate_device_meta(lambda records: records[name].update(vpn_type="unsupported"))
    assert not wireguard.set_account_safe_internet("alice", confirmed=True)
    assert not account_policy.account_safe_internet_locked("alice")
    assert not calls
    account_policy.save_account_policies({"alice": {"safe_internet_locked": True}})
    assert wireguard.get_config(name) is None
    policy_path = account_policy.account_policy_path()
    with open(policy_path, "w", encoding="utf-8") as handle:
        json.dump({"version": 1, "owners": {"alice": False}}, handle)
    with pytest.raises(account_policy.AccountPolicyError):
        wireguard.reconcile_safe_dns()
    with pytest.raises(account_policy.AccountPolicyError):
        wireguard.get_config(name)


def fake_protected_provisioner(policy_runtime, monkeypatch, *, fail_at=None, fail_remove=False):
    _name, config, _calls = policy_runtime
    root = config.parent.parent
    (root / "add-client.sh").write_text("#!/bin/bash\n# WG-PANEL-PREPARE-PROTOCOL v1\n")
    server = root / "wg0.conf"
    server.write_text("[Interface]\n", encoding="utf-8")
    state = {"events": [], "safe": set(), "live": set()}

    def sync(ips, **_kwargs):
        state["events"].append(("sync", tuple(ips)))
        if fail_at == "sync" and "10.0.0.8" in ips:
            raise wireguard.SafeDnsEnforcementError("fake new-address enforcement failure")
        state["safe"] = set(ips)

    def helper(script, name, _timeout, *arguments):
        state["events"].append((script, arguments))
        path = config.parent / f"{name}.conf"
        if script == "add-client.sh":
            assert arguments == ("--prepare",)
            path.write_text("[Interface]\nAddress = 10.0.0.8/32\n\n[Peer]\n")
            block = f"# {name}\n[Peer]\nPublicKey = fake-public=\nAllowedIPs = 10.0.0.8/32\n"
            encoded = base64.b64encode(block.encode()).decode()
            server.write_text(
                "[Interface]\n# WG-PANEL-PAUSED-BEGIN v1 fake-public=\n"
                f"# WG-PANEL-PAUSED-DATA {encoded}\n# WG-PANEL-PAUSED-END v1 fake-public=\n",
            )
            if fail_at == "marker":
                server.write_text("[Interface]\n[Peer]\nPublicKey = fake-public=\n")
        elif script == "set-client-state.sh":
            assert arguments == ("resume",)
            assert "10.0.0.8" in state["safe"]
            assert traffic.load_device_meta()[name]["provisioning"]
            if fail_at == "resume":
                return False, "fake resume failure"
            state["live"].add(name)
        elif script == "remove-client.sh":
            if fail_remove:
                return False, "fake revoke failure"
            state["live"].discard(name)
            path.unlink()
            server.write_text("[Interface]\n")
        else:
            raise AssertionError(script)
        return True, ""

    monkeypatch.setattr(wireguard, "_sync_safe_dns", sync)
    monkeypatch.setattr(wireguard, "_run_script", helper)
    return state


def test_new_named_profile_is_inactive_until_inherited_enforcement_precedes_resume(
    policy_runtime, monkeypatch,
):
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    state = fake_protected_provisioner(policy_runtime, monkeypatch)
    result = wireguard.create_device("alice", "different-name")
    assert result[0], result[2]
    assert [event[0] for event in state["events"]] == [
        "sync", "add-client.sh", "sync", "set-client-state.sh",
    ]
    assert result[1] in state["live"]
    assert wireguard.get_device(result[1])["safe_internet"]
    assert not traffic.load_device_meta()[result[1]].get("provisioning")
    assert "DNS = 1.1.1.3, 1.0.0.3" in wireguard.get_config(result[1])


@pytest.mark.parametrize("failure", ["marker", "sync", "resume"])
def test_failed_protected_provision_rolls_back_profile_but_never_account_policy(
    policy_runtime, monkeypatch, failure,
):
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    before = traffic.load_device_meta()
    state = fake_protected_provisioner(policy_runtime, monkeypatch, fail_at=failure)
    result = wireguard.create_device("alice", "different-name")
    assert not result[0]
    assert not state["live"]
    assert account_policy.account_safe_internet_locked("alice")
    assert traffic.load_device_meta() == before
    assert state["safe"] == {"10.0.0.2"}


def test_failed_cleanup_retains_protected_provisioning_checkpoint(policy_runtime, monkeypatch):
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    state = fake_protected_provisioner(
        policy_runtime, monkeypatch, fail_at="resume", fail_remove=True,
    )
    result = wireguard.create_device("alice", "different-name")
    assert not result[0] and "cleanup requires recovery" in result[2]
    assert "10.0.0.8" in state["safe"]
    name = "u5-alice-different-name"
    assert traffic.load_device_meta()[name]["provisioning"]
    assert wireguard.get_device(name) is None
    assert wireguard.get_config(name) is None
    assert account_policy.account_safe_internet_locked("alice")
    assert not wireguard.create_device("alice", "different-name")[0]
    dashboard = authenticated_client("alice").get("/dashboard").get_data(as_text=True)
    assert "Standard DNS" not in dashboard


def test_old_helper_is_rejected_before_any_provision_mutation(policy_runtime, monkeypatch):
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    calls = []
    monkeypatch.setattr(wireguard, "_run_script", lambda *args: calls.append(args))
    result = wireguard.create_device("alice", "new-name")
    assert not result[0] and "current add-client.sh" in result[2]
    assert not calls


def test_browser_add_cannot_forge_unprotected_owner_or_policy(policy_runtime, monkeypatch):
    from wg_panel.routes import devices as device_routes

    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    state = fake_protected_provisioner(policy_runtime, monkeypatch)
    monkeypatch.setattr(device_routes, "send_telegram", lambda *_args, **_kwargs: None)
    response = authenticated_client("alice").post("/add", data={
        "csrf_token": "policy-test-token", "device": "renamed-phone", "owner": "bob",
        "safe_internet": "off", "safe_internet_locked": "off", "admin_override": "on",
    })
    assert response.status_code == 302
    name = "u5-alice-renamed-phone"
    assert name in state["live"]
    assert wireguard.get_device(name)["owner"] == "alice"
    assert wireguard.get_device(name)["safe_internet"]
    response = authenticated_client("admin").post("/device/" + name + "/safe-internet", data={
        "csrf_token": "policy-test-token", "owner": "bob", "allow_locked_disable": "on",
    })
    assert response.status_code == 302
    assert account_policy.account_safe_internet_locked("alice")


def test_protected_ownership_write_failure_never_resumes_peer(policy_runtime, monkeypatch):
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    state = fake_protected_provisioner(policy_runtime, monkeypatch)
    before = traffic.load_device_meta()

    def fail_storage(*_args, **_kwargs):
        raise OSError("fake metadata failure")

    monkeypatch.setattr(wireguard, "set_device_meta", fail_storage)
    assert not wireguard.create_device("alice", "new-name")[0]
    assert "set-client-state.sh" not in [event[0] for event in state["events"]]
    assert not state["live"]
    assert traffic.load_device_meta() == before
    assert account_policy.account_safe_internet_locked("alice")


def test_recreated_legacy_locked_profile_inherits_account_policy_without_name_block(
    policy_runtime, monkeypatch,
):
    name, config, _calls = policy_runtime
    assert wireguard.set_device_safe_internet(name, True, confirmed=True)
    assert wireguard.set_account_safe_internet("alice", confirmed=True)

    def remove(*_args):
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    assert wireguard.delete_device(name)[0]
    assert traffic.load_device_meta()[name]["revoked"]
    state = fake_protected_provisioner(policy_runtime, monkeypatch)
    ok, restored_name, error = wireguard.create_device("alice", "phone")
    assert ok, error
    assert restored_name == name and name in state["live"]
    assert wireguard.get_device(name)["safe_internet"]
    assert account_policy.account_safe_internet_locked("alice")


def test_account_activation_serializes_with_new_profile_and_attempted_disable(
    policy_runtime, monkeypatch,
):
    name, _config, _calls = policy_runtime
    state = fake_protected_provisioner(policy_runtime, monkeypatch)
    sync = wireguard._sync_safe_dns
    enforcing = threading.Event()
    release = threading.Event()
    queued = threading.Event()
    results = {}

    def slow_sync(ips, **kwargs):
        if threading.current_thread().name == "account-lock-test":
            enforcing.set()
            assert release.wait(5)
        sync(ips, **kwargs)

    def queued_changes():
        queued.set()
        results["disable"] = wireguard.set_device_safe_internet(name, False)
        results["create"] = wireguard.create_device("alice", "queued-new")

    monkeypatch.setattr(wireguard, "_sync_safe_dns", slow_sync)
    locking = threading.Thread(
        target=lambda: results.update(lock=wireguard.set_account_safe_internet("alice", confirmed=True)),
        name="account-lock-test",
    )
    changing = threading.Thread(target=queued_changes)
    locking.start()
    assert enforcing.wait(5)
    changing.start()
    assert queued.wait(5)
    release.set()
    locking.join(5)
    changing.join(5)
    assert not locking.is_alive() and not changing.is_alive()
    assert results["lock"] and not results["disable"] and results["create"][0]
    assert results["create"][1] in state["live"]
    assert wireguard.get_device(results["create"][1])["safe_internet"]


def test_web_admin_settings_and_legacy_restore_cannot_reassign_account_policy(policy_runtime):
    name, config, _calls = policy_runtime
    assert wireguard.set_account_safe_internet("alice", confirmed=True)
    before = account_policy.load_account_policies()
    response = authenticated_client("admin").post("/admin/users/alice/edit", data={
        "csrf_token": "policy-test-token", "telegram_username": "alice_handle",
        "max_devices": "3", "payment_day": "15", "username": "bob", "owner": "bob",
        "safe_internet": "off", "safe_internet_locked": "off",
    })
    assert response.status_code == 302
    assert traffic.load_device_meta()[name]["owner"] == "alice"
    assert account_policy.load_account_policies() == before
    assert wireguard.get_device(name)["safe_internet"]
    config.rename(config.parent / "alice-restored.conf")
    traffic.save_device_meta({})
    assert wireguard.migrate_device_metadata()["migrated"] == 1
    restored = wireguard.get_device("alice-restored")
    assert restored["owner"] == "alice" and restored["safe_internet"]
    assert account_policy.load_account_policies() == before
