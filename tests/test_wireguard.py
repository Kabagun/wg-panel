import json
import threading
from types import SimpleNamespace

import pytest

from wg_panel import core, traffic, wireguard


def configure_paths(monkeypatch, tmp_path, users):
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setattr(wireguard, "load_users", lambda: users)
    monkeypatch.setattr(traffic, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(tmp_path / "data" / "device_meta.json"))
    monkeypatch.setattr(traffic, "TRAFFIC_FILE", str(tmp_path / "data" / "traffic.json"))
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda *_args, **_kwargs: ())
    return clients


def write_config(clients, wg_name):
    path = clients / f"{wg_name}.conf"
    path.write_text("[Interface]\nAddress = 10.0.0.2/32\n", encoding="utf-8")
    return path


def test_legacy_metadata_migration_and_exact_ownership(monkeypatch, tmp_path):
    clients = configure_paths(monkeypatch, tmp_path, {"alice": {"approved": True}})
    write_config(clients, "alice-phone")
    report = wireguard.migrate_device_metadata(dry_run=True)
    assert report == {"total": 1, "migrated": 1, "ambiguous": [], "unowned": [], "stale": []}
    wireguard.migrate_device_metadata(dry_run=False)
    assert wireguard.get_user_devices("alice") == ["phone"]
    assert wireguard.user_owns_device("alice", "alice-phone")
    assert not wireguard.user_owns_device("ali", "alice-phone")


def test_metadata_dry_run_does_not_change_directory_permissions(monkeypatch, tmp_path):
    clients = configure_paths(monkeypatch, tmp_path, {"alice": {"approved": True}})
    write_config(clients, "alice-phone")
    monkeypatch.setattr(
        wireguard,
        "ensure_private_dir",
        lambda _path: (_ for _ in ()).throw(AssertionError("dry run must not chmod")),
    )
    assert wireguard.migrate_device_metadata(dry_run=True)["migrated"] == 1


def test_ambiguous_dashed_username_migration_aborts(monkeypatch, tmp_path):
    clients = configure_paths(
        monkeypatch,
        tmp_path,
        {"a": {"approved": True}, "a-b": {"approved": True}},
    )
    write_config(clients, "a-b-phone")
    report = wireguard.migrate_device_metadata(dry_run=True)
    assert report["ambiguous"] == [{"wg_name": "a-b-phone", "owners": ["a", "a-b"]}]
    try:
        wireguard.migrate_device_metadata(dry_run=False)
    except wireguard.DeviceMetadataMigrationError:
        pass
    else:
        raise AssertionError("ambiguous ownership must block migration")


def test_concurrent_device_creation_respects_quota(monkeypatch, tmp_path):
    users = {"alice": {"approved": True, "max_devices": 1}}
    clients = configure_paths(monkeypatch, tmp_path, users)

    def run_script(script_name, wg_name, _timeout):
        if script_name == "add-client.sh":
            write_config(clients, wg_name)
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", run_script)
    results = []

    def create(name):
        results.append(wireguard.create_device("alice", name))

    threads = [threading.Thread(target=create, args=(name,)) for name in ("phone", "laptop")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(1 for result in results if result[0]) == 1
    assert sum(1 for result in results if result[2] == "Device limit reached") == 1
    assert len(wireguard.get_user_devices("alice")) == 1


def test_revocation_failure_retains_config_and_metadata(monkeypatch, tmp_path):
    clients = configure_paths(monkeypatch, tmp_path, {"alice": {"approved": True}})
    config = write_config(clients, "alice-phone")
    wireguard.migrate_device_metadata(dry_run=False)
    monkeypatch.setattr(wireguard, "_run_script", lambda *_args: (False, "wg failed"))
    assert wireguard.delete_device("alice-phone") == (False, "wg failed")
    assert config.exists()
    assert "alice-phone" in traffic.load_device_meta()


def test_successful_revocation_removes_metadata_only_after_config(monkeypatch, tmp_path):
    clients = configure_paths(monkeypatch, tmp_path, {"alice": {"approved": True}})
    config = write_config(clients, "alice-phone")
    wireguard.migrate_device_metadata(dry_run=False)

    def remove(_script, _wg_name, _timeout):
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    assert wireguard.delete_device("alice-phone") == (True, "")
    assert "alice-phone" not in traffic.load_device_meta()


def test_user_mutations_do_not_lose_concurrent_updates(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    monkeypatch.setattr(core, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(core, "USERS_FILE", str(data_dir / "users.json"))
    core.save_users({})
    barrier = threading.Barrier(3)

    def add_user(username):
        barrier.wait()
        core.mutate_users(
            lambda users: users.update(
                {
                    username: {
                        "password_hash": "x",
                        "role": "user",
                        "approved": True,
                        "max_devices": 3,
                    }
                }
            )
        )

    threads = [threading.Thread(target=add_user, args=(name,)) for name in ("alice", "bob")]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert set(core.load_users()) == {"alice", "bob"}
    assert json.loads((data_dir / "users.json").read_text(encoding="utf-8"))


def test_qr_uses_safe_internet_dns(monkeypatch, tmp_path):
    users = {"alice": {"approved": True}}
    clients = configure_paths(monkeypatch, tmp_path, users)
    config = clients / "alice-phone.conf"
    config.write_text(
        "[Interface]\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\n",
        encoding="utf-8",
    )
    traffic.save_device_meta(
        {
            "alice-phone": {
                "owner": "alice",
                "device": "phone",
                "vpn_type": "wireguard",
                "safe_internet": True,
            }
        }
    )
    wireguard.migrate_device_metadata(dry_run=False)
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"] is True
    captured = {}

    def run_qr(_args, **kwargs):
        captured["input"] = kwargs["input"]
        return SimpleNamespace(returncode=0, stdout=b"<svg></svg>")

    monkeypatch.setattr(wireguard.subprocess, "run", run_qr)
    assert wireguard.qr_svg_b64("alice-phone").startswith("data:image/svg+xml;base64,")
    assert b"DNS = 1.1.1.3, 1.0.0.3" in captured["input"]
    assert b"DNS = 1.1.1.1, 8.8.8.8" not in captured["input"]


@pytest.mark.parametrize("victim,attacker", [("alice", "u5-alice"), ("victimuser", "u10")])
def test_modern_config_without_owner_never_uses_legacy_prefix(monkeypatch, tmp_path, victim, attacker):
    clients = configure_paths(monkeypatch, tmp_path, {victim: {}, attacker: {}})
    name = f"u{len(victim)}-{victim}-phone"
    write_config(clients, name)
    assert wireguard.get_all_devices() == []
    report = wireguard.migrate_device_metadata(dry_run=True)
    assert report["unowned"] == [name]
    with pytest.raises(wireguard.DeviceMetadataMigrationError):
        wireguard.migrate_device_metadata()
    assert not wireguard.user_owns_device(attacker, name)
    traffic.set_device_meta(name, victim, "phone")
    assert wireguard.migrate_device_metadata()["migrated"] == 0
    assert wireguard.user_owns_device(victim, name)


def test_listing_is_read_only_and_cannot_overwrite_metadata(monkeypatch, tmp_path):
    clients = configure_paths(monkeypatch, tmp_path, {"alice": {"approved": True}})
    write_config(clients, "alice-phone")
    traffic.set_device_meta("alice-phone", "alice", "phone")
    traffic.set_device_safe_internet("alice-phone", True)
    original = traffic.load_device_meta()
    monkeypatch.setattr(wireguard, "save_device_meta", lambda *_args: pytest.fail("listing wrote metadata"))
    assert wireguard.get_all_devices() == [("alice", "phone", "alice-phone")]
    assert traffic.load_device_meta() == original


def test_legacy_numeric_username_still_migrates_when_name_is_not_generated(monkeypatch, tmp_path):
    clients = configure_paths(monkeypatch, tmp_path, {"u10": {"approved": True}})
    write_config(clients, "u10-phone")
    assert wireguard.migrate_device_metadata()["migrated"] == 1
    assert wireguard.user_owns_device("u10", "u10-phone")


def test_revocation_blocks_unowned_configs_and_preserves_stale_recovery_state(monkeypatch, tmp_path):
    users = {"alice": {"approved": True}}
    clients = configure_paths(monkeypatch, tmp_path, users)
    monkeypatch.setattr(wireguard, "mutate_users", lambda callback: callback(users))
    orphan = write_config(clients, "u5-alice-phone")
    assert not wireguard.delete_user("alice")[0]
    assert users["alice"]["revoking"]
    traffic.set_device_meta("u5-alice-phone", "alice", "phone")
    orphan.unlink()
    wireguard.migrate_device_metadata()
    assert "u5-alice-phone" in traffic.load_device_meta()
    assert not wireguard.delete_user("alice")[0]
    assert "alice" in users


def test_account_revocation_retries_dns_cleanup_after_peer_is_gone(monkeypatch, tmp_path):
    users = {"alice": {"approved": True}}
    clients = configure_paths(monkeypatch, tmp_path, users)
    monkeypatch.setattr(wireguard, "mutate_users", lambda callback: callback(users))
    config = write_config(clients, "u5-alice-phone")
    traffic.set_device_meta("u5-alice-phone", "alice", "phone")
    traffic.set_device_safe_internet("u5-alice-phone", True)
    removals = []

    def remove(*args):
        removals.append(args)
        config.unlink()
        return True, ""

    def fail_cleanup(*_args, **_kwargs):
        raise wireguard.SafeDnsEnforcementError("transient firewall failure")

    monkeypatch.setattr(wireguard, "_run_script", remove)
    monkeypatch.setattr(wireguard, "_sync_safe_dns", fail_cleanup)
    assert not wireguard.delete_user("alice")[0]
    assert not config.exists() and users["alice"]["revoking"]
    assert traffic.load_device_meta()["u5-alice-phone"]["revoked"]
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda *_args, **_kwargs: ())
    wireguard.migrate_device_metadata()
    assert wireguard.reconcile_safe_dns() == {"safe_devices": 0, "ips": []}
    assert wireguard.delete_user("alice")[0]
    assert len(removals) == 1
    assert not users and not traffic.load_device_meta()


def test_migration_waits_for_ownership_publication(monkeypatch, tmp_path):
    users = {"alice": {"approved": True}, "u5-alice": {"approved": True}}
    clients = configure_paths(monkeypatch, tmp_path, users)
    published = threading.Event()
    finish = threading.Event()
    migration_started = threading.Event()
    results = {}

    def add(_script, name, _timeout):
        write_config(clients, name)
        published.set()
        assert finish.wait(5)
        return True, ""

    def migrate():
        migration_started.set()
        results["migration"] = wireguard.migrate_device_metadata()

    monkeypatch.setattr(wireguard, "_run_script", add)
    creator = threading.Thread(target=lambda: results.update(create=wireguard.create_device("alice", "phone")))
    migrator = threading.Thread(target=migrate)
    creator.start()
    assert published.wait(5)
    migrator.start()
    assert migration_started.wait(5)
    finish.set()
    creator.join(5)
    migrator.join(5)
    assert not creator.is_alive() and not migrator.is_alive()
    assert results["create"][0] and results["migration"]["migrated"] == 0
    assert wireguard.user_owns_device("alice", "u5-alice-phone")
    assert not wireguard.user_owns_device("u5-alice", "u5-alice-phone")


def test_migration_serializes_safe_internet_write(monkeypatch, tmp_path):
    clients = configure_paths(monkeypatch, tmp_path, {"alice": {"approved": True}})
    write_config(clients, "alice-phone")
    traffic.set_device_meta("alice-phone", "alice", "phone")
    snapshot = threading.Event()
    finish = threading.Event()
    writer_started = threading.Event()
    original_load = wireguard.load_device_meta
    results = {}

    def pause_snapshot():
        value = original_load()
        if threading.current_thread().name == "migration-test":
            snapshot.set()
            assert finish.wait(5)
        return value

    def enable():
        writer_started.set()
        results["enabled"] = wireguard.set_device_safe_internet("alice-phone", True)

    monkeypatch.setattr(wireguard, "load_device_meta", pause_snapshot)
    migrator = threading.Thread(target=wireguard.migrate_device_metadata, name="migration-test")
    writer = threading.Thread(target=enable)
    migrator.start()
    assert snapshot.wait(5)
    writer.start()
    assert writer_started.wait(5)
    finish.set()
    migrator.join(5)
    writer.join(5)
    assert not migrator.is_alive() and not writer.is_alive()
    assert results["enabled"]
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"]
    assert wireguard.reconcile_safe_dns()["ips"] == ["10.0.0.2"]


@pytest.mark.parametrize("first", ["create", "delete"])
def test_account_revocation_serializes_with_provisioning(monkeypatch, tmp_path, first):
    users = {"alice": {"approved": True, "max_devices": 3}}
    clients = configure_paths(monkeypatch, tmp_path, users)
    monkeypatch.setattr(wireguard, "mutate_users", lambda callback: callback(users))
    write_config(clients, "u5-alice-existing")
    traffic.set_device_meta("u5-alice-existing", "alice", "existing")
    live = {"u5-alice-existing"}
    paused = threading.Event()
    finish = threading.Event()
    second_started = threading.Event()
    results = {}

    def run(script, name, _timeout):
        should_pause = (first == "create" and script == "add-client.sh") or (
            first == "delete" and name == "u5-alice-existing"
        )
        if should_pause:
            paused.set()
            assert finish.wait(5)
        if script == "add-client.sh":
            live.add(name)
            write_config(clients, name)
        else:
            live.remove(name)
            (clients / f"{name}.conf").unlink()
        return True, ""

    def operation(kind):
        if kind != first:
            second_started.set()
        results[kind] = (wireguard.create_device("alice", "new") if kind == "create"
                         else wireguard.delete_user("alice"))

    monkeypatch.setattr(wireguard, "_run_script", run)
    a = threading.Thread(target=operation, args=(first,))
    b = threading.Thread(target=operation, args=("delete" if first == "create" else "create",))
    a.start()
    assert paused.wait(5)
    b.start()
    assert second_started.wait(5)
    finish.set()
    a.join(5)
    b.join(5)
    assert not a.is_alive() and not b.is_alive()
    assert results["delete"][0]
    assert results["create"][0] == (first == "create")
    assert not users and not live and not list(clients.glob("*.conf"))
    assert not traffic.load_device_meta()
