import json
import threading
from types import SimpleNamespace

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
