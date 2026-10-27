"""Infrastructure claims and operator recovery use synthetic identities only."""

import base64
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from wg_panel import core
from wg_panel import infrastructure as infra

PRIVATE = base64.b64encode(bytes([1]) * 32).decode()
PUBLIC = base64.b64encode(bytes([2]) * 32).decode()
SERVER = base64.b64encode(bytes([3]) * 32).decode()
PSK = base64.b64encode(bytes([4]) * 32).decode()
NAME = "opaque-router"
CONFIG = (
    f"[Interface]\r\nPrivateKey = {PRIVATE}\r\nAddress = 10.0.0.2/32\r\n"
    f"DNS = 192.0.2.53\r\n\r\n[Peer]\r\nPublicKey = {SERVER}\r\n"
    f"PresharedKey = {PSK}\r\nEndpoint = vpn.example.test:51820\r\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\r\nPersistentKeepalive = 25\r\n"
).encode()


@pytest.fixture
def storage(tmp_path, monkeypatch):
    wg = tmp_path / "wireguard"
    data = tmp_path / "data"
    clients = wg / "clients"
    clients.mkdir(parents=True)
    data.mkdir()
    for directory in (wg, data, clients):
        directory.chmod(0o700)
    monkeypatch.setattr(core, "WG_DIR", str(wg))
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(infra, "_public_key", lambda private: PUBLIC if private == PRIVATE else SERVER)
    monkeypatch.setattr(infra, "_require_root", lambda: None)

    @contextmanager
    def test_lock(_directory):
        yield

    monkeypatch.setattr(infra, "_maintenance_lock", test_lock)
    return SimpleNamespace(wg=wg, data=data, clients=clients, configs=wg / "infrastructure")


def record(content=CONFIG, **changes):
    return {
        "kind": "router", "label": "home-router", "public_key": PUBLIC,
        "ipv4": "10.0.0.2", "config_sha256": hashlib.sha256(content).hexdigest(), **changes,
    }


def write_registry(storage, peers=None):
    core.write_json_private(
        str(storage.data / "infrastructure_peers.json"),
        {"version": 1, "peers": peers if peers is not None else {NAME: record()}},
    )


def registered(storage):
    storage.configs.mkdir(mode=0o700)
    path = storage.configs / f"{NAME}.conf"
    path.write_bytes(CONFIG)
    path.chmod(0o600)
    write_registry(storage)
    return path


def source_profile(storage):
    source = storage.clients / f"{NAME}.conf"
    source.write_bytes(CONFIG)
    source.chmod(0o600)
    core.write_json_private(str(storage.data / "device_meta.json"), {
        NAME: {"owner": "alice", "device": "router", "vpn_type": "wireguard",
               "safe_internet": False, "safe_internet_locked": True},
        "alice-phone": {"owner": "alice", "device": "phone", "safe_internet": True},
    })
    core.write_json_private(str(storage.data / "account_policy.json"), {
        "version": 1, "owners": {"alice": {"safe_internet_locked": True}},
    })
    core.write_json_private(str(storage.data / "traffic.json"), {
        NAME: {"last_rx": 123, "last_tx": 456, "monthly": {"2026-10": {"rx": 23, "tx": 56}}},
    })
    server = storage.wg / "wg0.conf"
    server.write_text(
        "[Interface]\nAddress = 10.0.0.1/24\n\n"
        f"# {NAME}\n[Peer]\nPublicKey = {PUBLIC}\nPresharedKey = {PSK}\n"
        "AllowedIPs = 10.0.0.2/32\n", encoding="utf-8",
    )
    server.chmod(0o600)
    return source


def adoption(storage, **changes):
    def enforce():
        selected = {"10.0.0.3"}
        metadata = json.loads((storage.data / "device_meta.json").read_text())
        if NAME in metadata:
            selected.add("10.0.0.2")
        registry = storage.data / "infrastructure_peers.json"
        if registry.exists():
            selected.update(infra.infrastructure_safe_ips())
        return {"ips": sorted(selected)}

    return infra.adopt_infrastructure_peer(
        NAME, expected_public_key_fingerprint=infra.public_key_fingerprint(PUBLIC),
        maintenance=True, enforce=changes.pop("enforce", enforce), **changes,
    )


def test_empty_installations_are_backward_compatible_and_explicit_paths_are_isolated(storage):
    assert infra.load_infrastructure_peers() == {}
    assert infra.infrastructure_names() == frozenset()
    assert infra.infrastructure_safe_ips() == ()
    storage.configs.mkdir(mode=0o700)
    write_registry(storage, {})
    assert infra.assert_infrastructure_ready() == {}
    registered_root = storage.wg / "other"
    assert infra.load_infrastructure_peers(wg_dir=registered_root, data_dir=registered_root) == {}


def test_registered_peer_has_permanent_address_and_no_account_fields(storage):
    registered(storage)
    assert infra.infrastructure_names() == {NAME}
    assert infra.infrastructure_safe_ips() == ("10.0.0.2",)
    assert infra.get_infrastructure_peer(NAME) == record()
    assert infra.get_infrastructure_peer("missing") is None
    assert "owner" not in infra.get_infrastructure_peer(NAME)


@pytest.mark.parametrize("change", [
    {"kind": "user"}, {"owner": "alice"}, {"safe_internet": False},
    {"label": "../router"}, {"public_key": "invalid"}, {"ipv4": "10.0.0.1"},
    {"ipv4": "10.0.0.255"}, {"ipv4": "192.0.2.2"}, {"ipv4": "::1"},
    {"config_sha256": "invalid"},
])
def test_invalid_records_fail_closed(storage, change):
    registered(storage)
    write_registry(storage, {NAME: record(**change)})
    with pytest.raises(infra.InfrastructureStateError):
        infra.infrastructure_names()


@pytest.mark.parametrize("state", [
    [], {"version": True, "peers": {}}, {"version": 2, "peers": {}},
    {"version": 1, "peers": []}, {"version": 1, "peers": {}, "extra": True},
    {"version": 1, "peers": {"../router": record()}},
    {"version": 1, "peers": {NAME: record(), "duplicate": record()}},
])
def test_invalid_registry_schema_fails_closed(storage, state):
    core.write_json_private(str(storage.data / "infrastructure_peers.json"), state)
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()


def test_duplicate_json_fields_and_unreadable_registry_are_not_empty(storage):
    path = storage.data / "infrastructure_peers.json"
    path.write_text('{"version":1,"peers":{},"peers":{}}', encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()
    path.write_text("{", encoding="utf-8")
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()


def test_missing_or_orphan_config_fails_closed(storage):
    write_registry(storage)
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()
    registered_path = storage.configs
    registered_path.mkdir(mode=0o700)
    (registered_path / "orphan.conf").write_bytes(CONFIG)
    write_registry(storage, {})
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()


@pytest.mark.parametrize("mutate", [
    lambda content: content + b"# changed\n",
    lambda content: content.replace(b"10.0.0.2/32", b"10.0.0.3/32"),
    lambda content: content.replace(PRIVATE.encode(), SERVER.encode()),
])
def test_config_tamper_or_identity_mismatch_fails_closed(storage, mutate):
    path = registered(storage)
    content = mutate(CONFIG)
    path.write_bytes(content)
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()
    if not content.endswith(b"# changed\n"):
        write_registry(storage, {NAME: record(content)})
        with pytest.raises(infra.InfrastructureStateError):
            infra.load_infrastructure_peers()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/modes and symlink protection")
def test_symlink_and_public_config_permissions_are_rejected(storage):
    path = registered(storage)
    path.chmod(0o644)
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()
    path.chmod(0o600)
    alternate = storage.wg / "elsewhere.conf"
    path.rename(alternate)
    path.symlink_to(alternate)
    with pytest.raises(infra.InfrastructureStateError):
        infra.load_infrastructure_peers()


def test_adoption_preserves_tunnel_config_policy_traffic_and_selected_set(storage):
    source = source_profile(storage)
    protected = {name: (storage.data / name).read_bytes()
                 for name in ("account_policy.json", "traffic.json")}
    server = (storage.wg / "wg0.conf").read_bytes()
    assert adoption(storage) == {"name": NAME, "already_adopted": False}
    assert not source.exists()
    assert (storage.configs / source.name).read_bytes() == CONFIG
    metadata = json.loads((storage.data / "device_meta.json").read_text())
    assert NAME not in metadata and "alice-phone" in metadata
    assert (storage.wg / "wg0.conf").read_bytes() == server
    for name, content in protected.items():
        assert (storage.data / name).read_bytes() == content
    assert infra.assert_infrastructure_ready() == {NAME: record()}
    assert adoption(storage) == {"name": NAME, "already_adopted": True}


def test_adoption_requires_explicit_identity_and_maintenance(storage):
    source = source_profile(storage)
    with pytest.raises(infra.InfrastructureStateError, match="fingerprint"):
        infra.adopt_infrastructure_peer(
            NAME, expected_public_key_fingerprint="SHA256:incorrect", maintenance=True,
            enforce=lambda: ("10.0.0.2",),
        )
    with pytest.raises(infra.InfrastructureStateError, match="Stop the panel"):
        infra.adopt_infrastructure_peer(NAME, expected_public_key_fingerprint="SHA256:incorrect")
    assert source.read_bytes() == CONFIG
    assert not storage.configs.exists()
    assert not (storage.data / "infrastructure_adoption.json").exists()


@pytest.mark.parametrize("fault", ["copy", "registry", "metadata", "source", "enforce"])
def test_every_interrupted_adoption_stage_is_resumable(storage, monkeypatch, fault):
    source_profile(storage)
    real_copy = infra._copy_config
    real_write = infra._write_json
    real_unlink = infra.os.unlink
    failed = False

    def fail_copy(path, content):
        nonlocal failed
        real_copy(path, content)
        if fault == "copy" and not failed:
            failed = True
            raise OSError("synthetic copy checkpoint failure")

    def fail_write(path, value):
        nonlocal failed
        real_write(path, value)
        selected = (fault == "registry" and Path(path).name == "infrastructure_peers.json"
                    or fault == "metadata" and Path(path).name == "device_meta.json")
        if selected and not failed:
            failed = True
            raise OSError("synthetic persistence checkpoint failure")

    def fail_unlink(path):
        nonlocal failed
        real_unlink(path)
        if fault == "source" and Path(path) == storage.clients / f"{NAME}.conf" and not failed:
            failed = True
            raise OSError("synthetic source checkpoint failure")

    def fail_enforce():
        nonlocal failed
        if (storage.data / "infrastructure_peers.json").exists() and not failed:
            failed = True
            raise infra.SafeDnsEnforcementError("synthetic enforcement failure")
        return {"ips": ["10.0.0.2", "10.0.0.3"]}

    monkeypatch.setattr(infra, "_copy_config", fail_copy)
    monkeypatch.setattr(infra, "_write_json", fail_write)
    monkeypatch.setattr(infra.os, "unlink", fail_unlink)
    with pytest.raises((OSError, infra.SafeDnsEnforcementError)):
        adoption(storage, **({"enforce": fail_enforce} if fault == "enforce" else {}))
    assert failed
    assert (storage.data / "infrastructure_adoption.json").exists()
    with pytest.raises(infra.InfrastructureStateError, match="operator recovery"):
        infra.assert_infrastructure_ready()
    assert adoption(storage) == {"name": NAME, "already_adopted": False}
    assert infra.infrastructure_safe_ips() == ("10.0.0.2",)
    assert not (storage.data / "infrastructure_adoption.json").exists()


@pytest.mark.parametrize("filename", ["account_policy.json", "traffic.json"])
def test_recovery_never_overwrites_changed_account_policy_or_traffic(storage, monkeypatch, filename):
    source_profile(storage)
    real_copy = infra._copy_config

    def interrupt(path, content):
        real_copy(path, content)
        raise OSError("synthetic failure")

    monkeypatch.setattr(infra, "_copy_config", interrupt)
    with pytest.raises(OSError):
        adoption(storage)
    path = storage.data / filename
    changed = path.read_bytes() + b"\n"
    path.write_bytes(changed)
    with pytest.raises(infra.InfrastructureStateError, match="changed during adoption"):
        adoption(storage)
    assert path.read_bytes() == changed


def test_changed_full_safe_set_leaves_recovery_checkpoint(storage):
    source_profile(storage)
    calls = 0

    def enforce():
        nonlocal calls
        calls += 1
        return {"ips": ["10.0.0.2", "10.0.0.3"] if calls == 1 else ["10.0.0.2"]}

    with pytest.raises(infra.InfrastructureStateError, match="Selected safe address set changed"):
        adoption(storage, enforce=enforce)
    assert (storage.data / "infrastructure_adoption.json").exists()
    assert adoption(storage)["already_adopted"] is False


def test_public_key_verification_uses_only_stdin_and_never_a_shell(monkeypatch):
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0, stdout=PUBLIC + "\n")

    monkeypatch.setattr(infra.subprocess, "run", run)
    assert infra._public_key(PRIVATE) == PUBLIC
    assert calls[0][0] == ["wg", "pubkey"]
    assert calls[0][1]["input"] == PRIVATE + "\n"
    assert not calls[0][1].get("shell")
