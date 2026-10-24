from pathlib import Path
from types import SimpleNamespace

import pytest

from wg_panel import app, dns_enforcement, traffic, wireguard


def _device_runtime(monkeypatch, tmp_path, *, safe=False):
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setattr(wireguard, "load_users", lambda: {"alice": {"approved": True}})
    monkeypatch.setattr(traffic, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(tmp_path / "data" / "device_meta.json"))
    monkeypatch.setattr(traffic, "TRAFFIC_FILE", str(tmp_path / "data" / "traffic.json"))
    config = clients / "alice-phone.conf"
    config.write_text("[Interface]\nAddress = 10.0.0.2/32\n", encoding="utf-8")
    traffic.save_device_meta(
        {
            "alice-phone": {
                "owner": "alice",
                "device": "phone",
                "vpn_type": "wireguard",
                "safe_internet": safe,
            }
        }
    )
    return clients, config


def test_normalize_safe_client_ips_is_ipv4_pool_only_and_stable():
    assert dns_enforcement.normalize_safe_client_ips(
        ["10.0.0.20", "10.0.0.2", "10.0.0.20"]
    ) == ("10.0.0.2", "10.0.0.20")

    for invalid in ("10.0.0.1", "10.0.0.255", "10.0.1.2", "fd00::2", "10.0.0.2/32"):
        with pytest.raises(dns_enforcement.SafeDnsEnforcementError):
            dns_enforcement.normalize_safe_client_ips([invalid])


def test_sync_safe_dns_uses_argv_without_shell_and_forces_wg0(monkeypatch, tmp_path):
    helper = tmp_path / "safe-dns.sh"
    helper.write_text("#!/bin/bash\n", encoding="utf-8")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dns_enforcement.subprocess, "run", run)
    result = dns_enforcement.sync_safe_dns(
        ["10.0.0.8", "10.0.0.2"], helper_path=str(helper)
    )

    assert result == ("10.0.0.2", "10.0.0.8")
    assert calls[0][0] == [str(helper), "--sync", "10.0.0.2", "10.0.0.8"]
    assert "shell" not in calls[0][1]
    assert calls[0][1]["env"]["WG_INTERFACE_NAME"] == "wg0"


def test_sync_safe_dns_fails_closed_when_helper_is_missing(tmp_path):
    with pytest.raises(dns_enforcement.SafeDnsEnforcementError, match="not installed"):
        dns_enforcement.sync_safe_dns(["10.0.0.2"], helper_path=str(tmp_path / "missing.sh"))


def test_empty_startup_reconciliation_can_precede_first_helper_install(tmp_path):
    assert dns_enforcement.sync_safe_dns(
        [], helper_path=str(tmp_path / "missing.sh"), require_helper=False
    ) == ()


def test_toggle_applies_firewall_before_persisting_metadata(monkeypatch, tmp_path):
    _clients, _config = _device_runtime(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        wireguard,
        "_sync_safe_dns",
        lambda ips, **_kwargs: calls.append(tuple(ips)),
    )

    assert wireguard.set_device_safe_internet("alice-phone", True, confirmed=True)
    assert calls == [("10.0.0.2",)]
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"] is True


def test_toggle_rolls_firewall_back_when_metadata_persistence_fails(monkeypatch, tmp_path):
    _clients, _config = _device_runtime(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        wireguard,
        "_sync_safe_dns",
        lambda ips, **_kwargs: calls.append(tuple(ips)),
    )
    monkeypatch.setattr(
        wireguard,
        "_set_device_safe_internet",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read-only metadata")),
    )

    assert not wireguard.set_device_safe_internet("alice-phone", True, confirmed=True)
    assert calls == [("10.0.0.2",), ()]
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"] is False


def test_safe_device_delete_removes_firewall_address_after_peer(monkeypatch, tmp_path):
    _clients, config = _device_runtime(monkeypatch, tmp_path, safe=True)
    events = []
    monkeypatch.setattr(
        wireguard,
        "_sync_safe_dns",
        lambda ips, **_kwargs: events.append(("sync", tuple(ips))),
    )

    def remove(_script, _wg_name, _timeout):
        events.append(("remove",))
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    assert wireguard.delete_device("alice-phone") == (True, "")
    assert events == [("remove",), ("sync", ())]
    assert "alice-phone" not in traffic.load_device_meta()


def test_safe_device_delete_keeps_fail_closed_policy_when_cleanup_fails(monkeypatch, tmp_path):
    _clients, config = _device_runtime(monkeypatch, tmp_path, safe=True)
    events = []

    def sync(ips, **_kwargs):
        events.append(("sync", tuple(ips)))
        raise dns_enforcement.SafeDnsEnforcementError("nft unavailable")

    monkeypatch.setattr(wireguard, "_sync_safe_dns", sync)

    def remove(_script, _wg_name, _timeout):
        events.append(("remove",))
        config.unlink()
        return True, ""

    monkeypatch.setattr(wireguard, "_run_script", remove)
    ok, error = wireguard.delete_device("alice-phone")
    assert not ok
    assert "cleanup failed" in error
    assert events == [("remove",), ("sync", ())]
    assert traffic.load_device_meta()["alice-phone"]["safe_internet"] is True


def test_device_creation_reconciles_before_an_address_can_be_reused(monkeypatch, tmp_path):
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(tmp_path / "wireguard"))
    monkeypatch.setattr(
        wireguard,
        "load_users",
        lambda: {"alice": {"approved": True, "max_devices": 3}},
    )
    monkeypatch.setattr(traffic, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(tmp_path / "data" / "device_meta.json"))
    traffic.save_device_meta({})
    helper_calls = []

    def fail_reconciliation(ips, **kwargs):
        helper_calls.append((tuple(ips), kwargs))
        raise dns_enforcement.SafeDnsEnforcementError("stale safe set cannot be cleared")

    monkeypatch.setattr(wireguard, "_sync_safe_dns", fail_reconciliation)
    monkeypatch.setattr(
        wireguard,
        "_run_script",
        lambda *_args: (_ for _ in ()).throw(AssertionError("peer allocation must not start")),
    )

    previous = app.config.get("TESTING")
    app.config["TESTING"] = False
    try:
        ok, _wg_name, error = wireguard.create_device("alice", "laptop")
    finally:
        app.config["TESTING"] = previous

    assert not ok
    assert "reconciliation failed" in error
    assert helper_calls == [((), {"allow_unavailable": False, "require_helper": True})]


def test_client_ipv4_reads_exact_address_key(monkeypatch, tmp_path):
    _clients, config = _device_runtime(monkeypatch, tmp_path)
    config.write_text(
        "[Interface]\nAddressExtra = 10.0.0.99/32\nAddress = 10.0.0.2/32\n",
        encoding="utf-8",
    )
    assert wireguard._client_ipv4("alice-phone") == "10.0.0.2"


def test_startup_reconciliation_uses_all_persisted_safe_addresses(monkeypatch, tmp_path):
    _clients, _config = _device_runtime(monkeypatch, tmp_path, safe=True)
    calls = []
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda ips, **_kwargs: calls.append(tuple(ips)))
    previous = app.config.get("TESTING")
    app.config["TESTING"] = False
    try:
        assert wireguard.reconcile_safe_dns() == {"safe_devices": 1, "ips": ["10.0.0.2"]}
    finally:
        app.config["TESTING"] = previous
    assert calls == [("10.0.0.2",)]


def test_sync_safe_dns_reports_helper_failure(tmp_path, monkeypatch):
    helper = tmp_path / "safe-dns.sh"
    helper.write_text("#!/bin/bash\n", encoding="utf-8")
    monkeypatch.setattr(
        dns_enforcement.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=7, stdout="", stderr="nft: permission denied\n"
        ),
    )
    with pytest.raises(dns_enforcement.SafeDnsEnforcementError, match="permission denied"):
        dns_enforcement.sync_safe_dns(["10.0.0.2"], helper_path=str(helper))


def test_safe_dns_script_is_scoped_to_managed_table():
    script = (Path(__file__).resolve().parents[1] / "scripts" / "safe-dns.sh").read_text(
        encoding="utf-8"
    )
    assert 'TABLE_NAME="wg_panel_safe_dns"' in script
    assert 'DNS_TARGET="1.1.1.3:53"' in script
    assert 'iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME udp dport 53 dnat ip to $DNS_TARGET' in script
    assert 'iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME tcp dport 53 dnat ip to $DNS_TARGET' in script
    assert 'iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME tcp dport 853 counter drop' in script
    assert 'iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME udp dport 853 counter drop' in script
    for protocol in ("tcp", "udp"):
        assert (
            'iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME ip daddr @$DOH_SET_NAME '
            f'{protocol} dport {{ 443, 5443, 8853, 9953 }} counter drop'
        ) in script
    assert "delete table" in script
    assert "flush table" not in script
    assert "flush ruleset" not in script
