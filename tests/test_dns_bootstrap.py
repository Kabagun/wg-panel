import configparser
import json
import os
from pathlib import Path

import pytest

from wg_panel import core, dns_bootstrap, traffic, wireguard
from wg_panel.dns_enforcement import SafeDnsEnforcementError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def preparation(monkeypatch):
    calls = []

    def infrastructure(**kwargs):
        calls.append(("infrastructure", kwargs))
        return {"router": {"ipv4": "10.0.0.2"}}

    def target(wg_dir):
        calls.append(("target", wg_dir))

    def ownership(**kwargs):
        calls.append(("ownership", kwargs))
        return {"total": 2, "migrated": 0, "ambiguous": [], "unowned": [], "stale": []}

    def reconcile(**kwargs):
        calls.append(("reconcile", kwargs))
        return {"safe_devices": 2, "ips": ["10.0.0.2", "10.0.0.3", "10.0.0.4"]}

    monkeypatch.setattr(dns_bootstrap, "WG_DIR", "synthetic-wireguard-directory")
    monkeypatch.setattr(dns_bootstrap, "assert_infrastructure_ready", infrastructure)
    monkeypatch.setattr(dns_bootstrap, "load_safe_dns_target", target)
    monkeypatch.setattr(dns_bootstrap, "migrate_device_metadata", ownership)
    monkeypatch.setattr(dns_bootstrap, "reconcile_safe_dns", reconcile)
    return calls


def test_bootstrap_validates_before_enforcing_without_peer_activation(preparation, monkeypatch):
    def unexpected_peer_change(*_args, **_kwargs):
        pytest.fail("bootstrap must not activate or modify a WireGuard peer")

    monkeypatch.setattr(wireguard, "_run_script", unexpected_peer_change)
    monkeypatch.setattr(core, "ensure_admin", unexpected_peer_change)
    assert dns_bootstrap.bootstrap_safe_dns() == {
        "personal_profiles": 2, "infrastructure_peers": 1, "safe_devices": 2, "safe_addresses": 3
    }
    assert preparation == [
        ("infrastructure", {"wg_dir": "synthetic-wireguard-directory"}),
        ("target", "synthetic-wireguard-directory"),
        ("ownership", {"dry_run": True}),
        ("reconcile", {"require_helper": True, "allow_unavailable": False}),
    ]


@pytest.mark.parametrize(
    "stage,expected_calls",
    [("assert_infrastructure_ready", 0), ("load_safe_dns_target", 1),
     ("migrate_device_metadata", 2), ("reconcile_safe_dns", 3)],
)
def test_bootstrap_stops_at_first_failed_stage(preparation, monkeypatch, stage, expected_calls):
    failure = SafeDnsEnforcementError("synthetic private deployment detail")

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(dns_bootstrap, stage, fail)
    with pytest.raises(SafeDnsEnforcementError) as raised:
        dns_bootstrap.bootstrap_safe_dns()
    assert raised.value is failure
    assert len(preparation) == expected_calls


@pytest.mark.parametrize(
    "pending", [{"ambiguous": [{"wg_name": "synthetic-peer"}]},
                {"unowned": ["synthetic-peer"]}, {"migrated": 1}],
)
def test_unprepared_ownership_blocks_enforcement(preparation, monkeypatch, pending):
    report = {"total": 1, "migrated": 0, "ambiguous": [], "unowned": [], "stale": []}
    report.update(pending)
    monkeypatch.setattr(dns_bootstrap, "migrate_device_metadata", lambda **_kwargs: report)
    with pytest.raises(SafeDnsEnforcementError, match="prepared personal ownership"):
        dns_bootstrap.bootstrap_safe_dns()
    assert [stage for stage, _args in preparation] == ["infrastructure", "target"]


def test_bootstrap_ownership_check_does_not_write_personal_state(tmp_path, monkeypatch):
    clients = tmp_path / "clients"
    clients.mkdir()
    config = clients / "alice-phone.conf"
    config.write_text("[Interface]\nAddress = 10.0.0.3/32\n", encoding="utf-8")
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({"alice": {"approved": True}}), encoding="utf-8")
    meta_file = tmp_path / "device_meta.json"
    meta_file.write_text(json.dumps({
        "alice-phone": {"owner": "alice", "device": "phone", "safe_internet": True}
    }), encoding="utf-8")
    monkeypatch.setattr(core, "USERS_FILE", str(users_file))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(meta_file))
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(dns_bootstrap, "WG_DIR", str(tmp_path))
    monkeypatch.setattr(dns_bootstrap, "assert_infrastructure_ready", lambda **_kwargs: {})
    monkeypatch.setattr(dns_bootstrap, "migrate_device_metadata", wireguard.migrate_device_metadata)
    monkeypatch.setattr(dns_bootstrap, "reconcile_safe_dns", lambda **_kwargs: {
        "safe_devices": 1, "ips": ["10.0.0.3"]
    })
    before = {path.name: (path.read_bytes(), path.stat().st_mode)
              for path in (users_file, meta_file, config)}
    assert dns_bootstrap.bootstrap_safe_dns()["personal_profiles"] == 1
    assert {path.name: (path.read_bytes(), path.stat().st_mode)
            for path in (users_file, meta_file, config)} == before


def test_main_logs_only_counts_on_success(preparation, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert dns_bootstrap.main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == (
        "[SAFE DNS BOOTSTRAP] personal_profiles=2 infrastructure_peers=1 "
        "safe_devices=2 safe_addresses=3\n"
    )
    assert "10.0.0." not in captured.out


@pytest.mark.parametrize("failure", [SafeDnsEnforcementError, OSError, RuntimeError])
def test_main_reports_generic_failure_without_exception_details(monkeypatch, capsys, failure):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)

    def fail():
        raise failure("synthetic private deployment detail")

    monkeypatch.setattr(dns_bootstrap, "bootstrap_safe_dns", fail)
    assert dns_bootstrap.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Safe DNS bootstrap failed; operator preparation is required\n"


def test_nonroot_main_fails_before_reading_or_mutating_state(monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)

    def unexpected_bootstrap():
        pytest.fail("nonroot bootstrap must not inspect or change state")

    monkeypatch.setattr(dns_bootstrap, "bootstrap_safe_dns", unexpected_bootstrap)
    assert dns_bootstrap.main() == 1
    assert capsys.readouterr().err == "Safe DNS bootstrap requires root\n"


def read_unit(relative_path):
    unit = configparser.ConfigParser(interpolation=None)
    unit.read(ROOT / "systemd" / relative_path, encoding="utf-8")
    return unit


def test_service_orders_dns_before_wireguard_without_reverse_dependency():
    unit = read_unit("wg-panel-safe-dns.service")
    assert "wg-quick@wg0.service" in unit["Unit"]["Before"].split()
    assert "wg-quick@wg0.service" not in unit["Unit"].get("After", "").split()
    assert "wg-quick@wg0.service" not in unit["Unit"].get("Requires", "").split()
    service = unit["Service"]
    assert service["Type"] == "oneshot"
    assert service["User"] == service["Group"] == "root"
    assert service["RemainAfterExit"] == "yes"
    assert service["WorkingDirectory"] == "/opt/wg-panel"
    assert service["EnvironmentFile"] == "/etc/wg-panel/wg-panel.env"
    assert service["ExecStart"] == "/opt/wg-panel/venv/bin/python -m wg_panel.dns_bootstrap"
    assert "ExecStop" not in unit["Service"]
    assert "ExecStartPost" not in unit["Service"]


@pytest.mark.parametrize("service", ["wg-quick@wg0.service", "wg-panel.service"])
def test_service_dropins_require_successful_dns_bootstrap(service):
    unit = read_unit(f"{service}.d/safe-dns.conf")
    assert unit.sections() == ["Unit"]
    assert unit["Unit"]["Requires"].split() == ["wg-panel-safe-dns.service"]
    assert unit["Unit"]["After"].split() == ["wg-panel-safe-dns.service"]
