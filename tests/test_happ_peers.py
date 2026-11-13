"""Real lifecycle coordination with synthetic helpers; no host WG mutations."""

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from wg_panel import (
    access,
    account_policy,
    core,
    device_cleanup,
    happ_peers,
    happ_pilot,
    traffic,
    wireguard,
)
from wg_panel.dns_enforcement import SafeDnsEnforcementError

PARENT = "u5-alice-phone"


def key(value):
    return base64.b64encode(bytes([value]) * 32).decode()


def config(index):
    return (f"[Interface]\nPrivateKey = {key(index)}\nAddress = 10.0.0.{index}/32\n"
            "DNS = 1.1.1.1\nMTU = 1380\n[Peer]\n"
            f"PublicKey = {key(90)}\nPresharedKey = {key(index + 100)}\n"
            "Endpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n")


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    data, wg = tmp_path / "data", tmp_path / "wireguard"
    clients = wg / "clients"
    clients.mkdir(parents=True)
    for module, field, value in (
        (core, "DATA_DIR", data), (core, "USERS_FILE", data / "users.json"),
        (core, "DEVICE_META_FILE", data / "device_meta.json"), (core, "TRAFFIC_FILE", data / "traffic.json"),
        (traffic, "DEVICE_META_FILE", data / "device_meta.json"), (traffic, "TRAFFIC_FILE", data / "traffic.json"),
        (traffic, "CLIENTS_DIR", clients), (wireguard, "CLIENTS_DIR", clients), (wireguard, "WG_DIR", wg),
    ):
        monkeypatch.setattr(module, field, str(value))
    monkeypatch.setitem(core.app.config, "TESTING", True)
    monkeypatch.setitem(core.app.config, "HAPP_PILOT_ENABLED", True)
    monkeypatch.setitem(core.app.config, "HAPP_ROLLOUT_ENABLED", True)
    core.save_users({"alice": {"approved": True, "role": "user", "account_id": "a" * 64, "max_devices": 1}})
    account_policy.save_account_policies({})
    (clients / f"{PARENT}.conf").write_text(config(2), encoding="utf-8", newline="\n")
    (wg / "safe-dns-target").write_text("10.0.0.1:18004\n")
    traffic.save_device_meta({PARENT: {"owner": "alice", "device": "phone", "vpn_type": "wireguard",
                                      "happ_pilot": True, "safe_internet": False,
                                      "happ_subscription_nonce": "b" * 64}})
    events, active, prepared, failures = [], {PARENT}, set(), {}
    sequence = [2]
    dns_addresses = set()
    def dns(**kwargs):
        events.append(("dns",))
        if failures.get("dns"):
            failures["dns"] -= 1
            if failures["dns"] == 0:
                raise SafeDnsEnforcementError("synthetic failure")
        dns_addresses.clear()
        dns_addresses.update(wireguard._safe_dns_ips(traffic.load_device_meta()))
        return {"ips": list(dns_addresses)}
    def helper(script, name, _timeout, *arguments):
        events.append((script, name, *arguments))
        if (script, name) in failures or (script, arguments[-1] if arguments else "") in failures:
            return False, "synthetic helper failure"
        path = clients / f"{name}.conf"
        if script == "add-client.sh":
            assert arguments == ("--prepare",)
            sequence[0] += 1
            path.write_text(config(sequence[0]), encoding="utf-8", newline="\n")
            prepared.add(name)
        elif script == "set-client-state.sh":
            if arguments == ("resume",):
                assert wireguard._client_ipv4(name) in dns_addresses
                assert traffic.load_device_meta()[name].get("happ_pilot") is True
                active.add(name)
                prepared.discard(name)
            else:
                active.discard(name)
                prepared.add(name)
        elif script == "remove-client.sh":
            active.discard(name)
            prepared.discard(name)
            path.unlink(missing_ok=True)
        return True, ""
    monkeypatch.setattr(wireguard, "_run_script", helper)
    monkeypatch.setattr(wireguard, "_supports_prepared_clients", lambda: True)
    monkeypatch.setattr(wireguard, "_is_prepared_client", lambda name: name in prepared)
    monkeypatch.setattr(wireguard, "reconcile_safe_dns", dns)
    monkeypatch.setattr(wireguard, "_sync_safe_dns", lambda *a, **kw: ())
    monkeypatch.setattr(happ_peers, "_public_key", lambda private: base64.b64encode(hashlib.sha256(base64.b64decode(private)).digest()).decode())
    return SimpleNamespace(data=data, wg=wg, clients=clients, events=events, active=active,
                           prepared=prepared, failures=failures, dns=dns)


def test_prepare_dns_activation_order_idempotence_and_parent_unchanged(runtime):
    path = runtime.clients / f"{PARENT}.conf"
    original = path.read_bytes()
    mapping = happ_peers.ensure_mode_peers(PARENT)
    assert set(mapping) == {"all", "custom", "by-ru-direct"} and mapping["all"] == PARENT
    assert path.read_bytes() == original
    identities = [happ_peers._identity(name) for name in mapping.values()]
    assert len({identity["public_key"] for identity in identities}) == 3
    assert len({identity["address"] for identity in identities}) == 3
    assert len({identity["psk"] for identity in identities}) == 3
    resumes = [index for index, event in enumerate(runtime.events) if event[0] == "set-client-state.sh"]
    dns_index = max(index for index, event in enumerate(runtime.events) if event[0] == "dns")
    assert dns_index < min(resumes)
    before = list(runtime.events), (runtime.data / "device_meta.json").read_bytes()
    assert happ_peers.ensure_mode_peers(PARENT) == mapping
    assert happ_peers.mode_mapping(PARENT) == mapping
    assert before == (runtime.events, (runtime.data / "device_meta.json").read_bytes())


def test_internal_children_are_not_devices_quotas_ownership_or_confirmations(runtime):
    mapping = happ_peers.ensure_mode_peers(PARENT)
    assert wireguard.get_user_devices("alice") == ["phone"]
    assert wireguard.get_all_devices() == [("alice", "phone", PARENT)]
    assert len(wireguard.get_all_devices(include_internal=True)) == 3
    for name in (mapping["custom"], mapping["by-ru-direct"]):
        assert wireguard.get_device(name) and wireguard.get_config(name)
        assert not wireguard.user_owns_device("alice", name)
        assert not happ_pilot.is_pilot_device(wireguard.get_device(name))
        assert wireguard.begin_device_deletion(name, "synthetic") is None
        assert wireguard.delete_device(name)[0] is False
    assert wireguard.create_device("alice", "second")[2] == "Device limit reached"


def test_exports_use_distinct_transports_preserve_legacy_routing_and_never_provision(runtime):
    parent = wireguard.get_device(PARENT)
    with pytest.raises(ValueError):
        happ_pilot.exported_bundle(parent, [])
    assert happ_pilot.exported_config(parent, "all", [])
    assert not runtime.events
    happ_peers.ensure_mode_peers(PARENT)
    before = list(runtime.events)
    bundle = happ_pilot.exported_bundle(wireguard.get_device(PARENT), [])
    transports = [item["outbounds"][0]["settings"] for item in bundle]
    assert len({item["secretKey"] for item in transports}) == 3
    assert len({tuple(item["address"]) for item in transports}) == 3
    assert all(item["remoteDNS"] == ["10.0.0.1"] for item in transports)
    for mode, country in (("by-direct", "geoip:by"), ("ru-direct", "geoip:ru")):
        exported = happ_pilot.exported_config(wireguard.get_device(PARENT), mode, [])
        assert exported["outbounds"][0]["settings"]["secretKey"] == transports[2]["secretKey"]
        assert any(rule.get("ip") == [country] for rule in exported["routing"]["rules"])
    assert runtime.events == before


@pytest.mark.parametrize("field,value", [("owner", "other"), ("happ_parent_fingerprint", "bad"),
                                         ("happ_mode", "all"), ("happ_transport_internal", False)])
def test_mapping_rejects_corrupt_child_binding_without_mutation(runtime, field, value):
    mapping = happ_peers.ensure_mode_peers(PARENT)
    traffic.mutate_device_meta(lambda meta: meta[mapping["custom"]].update({field: value}))
    before = list(runtime.events)
    with pytest.raises(ValueError):
        happ_peers.mode_mapping(PARENT)
    assert runtime.events == before


def test_changed_parent_or_child_config_invalidates_mapping(runtime):
    mapping = happ_peers.ensure_mode_peers(PARENT)
    path = runtime.clients / f"{mapping['custom']}.conf"
    path.write_text(config(9), encoding="utf-8")
    with pytest.raises(ValueError):
        happ_peers.mode_mapping(PARENT)
    with pytest.raises(ValueError):
        happ_peers.ensure_mode_peers(PARENT)


def test_collision_is_not_adopted_or_rolled_back(runtime):
    _meta, _parent, _user, _identity, binding = happ_peers._parent(PARENT)
    candidate = happ_peers._names(PARENT, binding)["custom"]
    path = runtime.clients / f"{candidate}.conf"
    path.write_text(config(7), encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(ValueError):
        happ_peers.ensure_mode_peers(PARENT)
    assert path.read_bytes() == before and not runtime.events


@pytest.mark.parametrize("stage", ["dns", "resume"])
def test_failed_provision_rolls_back_only_new_children_and_preserves_parent(runtime, stage):
    original = (runtime.clients / f"{PARENT}.conf").read_bytes()
    if stage == "dns":
        runtime.failures["dns"] = 2
    else:
        runtime.failures[("set-client-state.sh", "resume")] = True
    with pytest.raises(ValueError):
        happ_peers.ensure_mode_peers(PARENT)
    assert list(runtime.clients.glob("*.conf")) == [runtime.clients / f"{PARENT}.conf"]
    assert (runtime.clients / f"{PARENT}.conf").read_bytes() == original
    assert traffic.load_device_meta()[PARENT].get("happ_transports") is None
    assert runtime.active == {PARENT}
    assert not any(event[:2] == ("remove-client.sh", PARENT) for event in runtime.events)


def test_partial_activation_and_failed_removal_leave_children_paused_unexportable(runtime, monkeypatch):
    binding = happ_peers._parent(PARENT)[4]
    names = happ_peers._names(PARENT, binding)
    original_helper = wireguard._run_script
    def helper(script, name, timeout, *arguments):
        if script == "set-client-state.sh" and arguments == ("resume",) and name == names["by-ru-direct"]:
            return False, "synthetic activation failure"
        return original_helper(script, name, timeout, *arguments)
    monkeypatch.setattr(wireguard, "_run_script", helper)
    runtime.failures[("remove-client.sh", names["custom"])] = True
    with pytest.raises(ValueError):
        happ_peers.ensure_mode_peers(PARENT)
    assert runtime.active == {PARENT}
    assert traffic.load_device_meta()[PARENT]["happ_transport_provisioning"] is True
    assert (runtime.clients / f"{names['custom']}.conf").exists()
    with pytest.raises(ValueError):
        happ_peers.mode_mapping(PARENT)


def test_parent_delete_revokes_children_first_and_retry_has_no_orphans(runtime):
    mapping = happ_peers.ensure_mode_peers(PARENT)
    child = mapping["by-ru-direct"]
    runtime.failures[("remove-client.sh", child)] = True
    assert wireguard.delete_device(PARENT)[0] is False
    assert PARENT in traffic.load_device_meta() and not runtime.active
    assert not (runtime.clients / f"{mapping['custom']}.conf").exists()
    runtime.failures.clear()
    assert wireguard.delete_device(PARENT) == (True, "")
    assert not traffic.load_device_meta() and not list(runtime.clients.glob("*.conf"))
    removes = [event[1] for event in runtime.events if event[0] == "remove-client.sh"]
    assert removes[-1] == PARENT


def test_account_pause_resume_and_delete_include_children(runtime):
    mapping = happ_peers.ensure_mode_peers(PARENT)
    assert access.set_user_paused("alice", True)[0] is True
    assert not runtime.active
    assert access.set_user_paused("alice", False)[0] is True
    assert runtime.active == set(mapping.values())
    assert wireguard.delete_user("alice") == (True, "")
    assert not runtime.active and "alice" not in core.load_users()
    assert not traffic.load_device_meta()


def test_family_parent_needs_no_children_and_no_split_export(runtime):
    traffic.mutate_device_meta(lambda meta: meta[PARENT].update(safe_internet=True))
    assert happ_peers.ensure_mode_peers(PARENT) == {"all": PARENT}
    assert not runtime.events
    assert len(happ_pilot.exported_bundle(wireguard.get_device(PARENT), [])) == 1
    with pytest.raises(ValueError):
        happ_pilot.exported_config(wireguard.get_device(PARENT), "custom", [])


def test_traffic_children_roll_up_deltas_independently_and_resets_preserve_history(runtime, monkeypatch):
    mapping = happ_peers.ensure_mode_peers(PARENT)
    original_validation = happ_peers.children_for_parent
    validations = []
    def validate(parent):
        validations.append(parent)
        return original_validation(parent)
    monkeypatch.setattr(happ_peers, "children_for_parent", validate)
    month = datetime.now(UTC).strftime("%Y-%m")
    traffic.save_traffic({PARENT: {"last_rx": 100, "last_tx": 200,
                                  "monthly": {month: {"rx": 1000, "tx": 2000}}}})
    stats = {wireguard._client_ipv4(PARENT): (110, 220),
             wireguard._client_ipv4(mapping["custom"]): (30, 40),
             wireguard._client_ipv4(mapping["by-ru-direct"]): (50, 60)}
    monkeypatch.setattr(traffic, "get_wg_peer_stats", lambda: copy.deepcopy(stats))
    traffic.collect_traffic()
    assert validations == [PARENT]
    record = traffic.load_traffic()[PARENT]
    assert record["monthly"][month] == {"rx": 1090, "tx": 2120}
    assert (record["last_rx"], record["last_tx"]) == (110, 220)
    assert set(traffic.load_traffic()) == {PARENT}
    stats[wireguard._client_ipv4(mapping["custom"])] = (3, 4)
    stats[wireguard._client_ipv4(mapping["by-ru-direct"])] = (55, 66)
    traffic.collect_traffic()
    record = traffic.load_traffic()[PARENT]
    assert record["monthly"][month] == {"rx": 1098, "tx": 2130}
    traffic.reset_peer_counters(mapping["custom"])
    assert traffic.load_traffic()[PARENT]["last_rx"] == 110
    assert traffic.load_traffic()[PARENT]["monthly"] == record["monthly"]


def test_cleanup_rolls_child_activity_into_parent_and_never_lists_children(runtime, monkeypatch):
    mapping = happ_peers.ensure_mode_peers(PARENT)
    peers = {}
    for name in mapping.values():
        identity = happ_peers._identity(name)
        peers[identity["public_key"]] = {"rx": 0, "tx": 0, "handshake": 0,
                                         "addresses": {identity["address"]}}
    monkeypatch.setattr(device_cleanup, "_peer_stats", lambda: copy.deepcopy(peers))
    monkeypatch.setattr(device_cleanup, "_generation", lambda: "synthetic-generation")
    monkeypatch.setattr(device_cleanup.connection_config, "_public_key", happ_peers._public_key)
    now = datetime(2026, 11, 13, tzinfo=UTC)
    first = device_cleanup.cleanup_inactive_devices(now=now)
    assert first["observed"] == first["initialized"] == 1
    state = json.loads((runtime.data / "device_activity.json").read_text())
    assert set(state["devices"]) == {PARENT}
    child_key = happ_peers._identity(mapping["custom"])["public_key"]
    peers[child_key]["rx"] = 10
    result = device_cleanup.cleanup_inactive_devices(now=now + timedelta(hours=1))
    assert result["active"] == 1 and result["deleted"] == 0
    (runtime.clients / f"{mapping['custom']}.conf").unlink()
    result = device_cleanup.cleanup_inactive_devices(now=now + timedelta(hours=2))
    assert result["observed"] == result["deleted"] == 0
    assert not json.loads((runtime.data / "device_activity.json").read_text())["devices"]
