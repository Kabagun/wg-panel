import base64
import copy
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from wg_panel import device_cleanup as cleanup

NOW = datetime(2026, 10, 1, tzinfo=UTC)
KEY = base64.b64encode(b"a" * 32).decode()
OTHER_KEY = base64.b64encode(b"b" * 32).decode()


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    users = {"alice": {"account_id": "synthetic-account", "approved": True}}
    meta = {"alice-phone": {"owner": "alice", "device": "phone", "vpn_type": "wireguard"}}
    peers = {KEY: {"rx": 10, "tx": 20, "handshake": 0, "addresses": {"10.0.0.2/32"}}}
    details = {"address": "10.0.0.2/32", "client_public_key": KEY}
    deleted = []
    monkeypatch.setattr(cleanup.core, "DATA_DIR", str(root))
    monkeypatch.setattr(cleanup.core, "load_users", lambda: copy.deepcopy(users))
    monkeypatch.setattr(cleanup, "load_device_meta", lambda: copy.deepcopy(meta))
    monkeypatch.setattr(cleanup.wireguard, "get_all_devices", lambda: [
        (value["owner"], value["device"], name) for name, value in meta.items()
    ])
    monkeypatch.setattr(cleanup.wireguard, "get_config", lambda name: name)
    monkeypatch.setattr(cleanup.connection_config, "connection_details", lambda *a, **kw: details)
    monkeypatch.setattr(cleanup, "_peer_stats", lambda: copy.deepcopy(peers))
    monkeypatch.setattr(cleanup, "_generation", lambda: "synthetic-boot:2")

    def delete(name):
        deleted.append(name)
        meta.pop(name)
        return True, ""

    monkeypatch.setattr(cleanup.wireguard, "delete_device", delete)
    history = root / "traffic.json"
    history.write_text('{"alice-phone":{"monthly":{"2026-01":{"rx":123,"tx":456}}}}')
    return SimpleNamespace(
        root=root, users=users, meta=meta, peers=peers, details=details,
        deleted=deleted, state=root / "device_activity.json", history=history,
    )


def seed(runtime, *, now=NOW, age=timedelta(days=61)):
    cleanup.cleanup_inactive_devices(now=now)
    state = json.loads(runtime.state.read_text())
    tracker = state["devices"]["alice-phone"]
    tracker["idle_since"] = (now - age).timestamp()
    tracker["last_successful_observation_at"] = (now - timedelta(hours=1)).timestamp()
    runtime.state.write_text(json.dumps(state))
    return state


def tracker(runtime):
    return json.loads(runtime.state.read_text())["devices"].get("alice-phone")


def test_initialization_and_strict_sixty_day_boundary(runtime):
    first = cleanup.cleanup_inactive_devices(now=NOW)
    assert first["initialized"] == 1
    assert first["candidates"] == 0
    assert tracker(runtime)["idle_since"] == NOW.timestamp()
    seed(runtime, age=timedelta(days=60))
    assert cleanup.cleanup_inactive_devices(now=NOW)["deleted"] == 0
    result = cleanup.cleanup_inactive_devices(now=NOW + timedelta(seconds=1))
    assert result["deleted"] == 1
    assert runtime.deleted == ["alice-phone"]
    assert tracker(runtime) is None


def test_continuous_hourly_observations_reach_boundary():
    observation = {"identity": "identity", "generation": "boot:2", "rx": 0, "tx": 0,
                   "handshake": 0}
    state = None
    for hour in range(60 * 24 + 2):
        state, due, _active, _initialized = cleanup._advance(
            state, observation, NOW.timestamp() + hour * 3600,
        )
        assert due is (hour > 60 * 24)


@pytest.mark.parametrize("field", ["rx", "tx", "handshake"])
def test_new_activity_resets_old_deadline(runtime, field):
    seed(runtime)
    runtime.peers[KEY][field] += 1
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["active"] == 1
    assert result["deleted"] == 0
    assert tracker(runtime)["idle_since"] == NOW.timestamp()
    assert tracker(runtime)["last_activity_at"] == NOW.timestamp()


@pytest.mark.parametrize("target,flag", [
    ("meta", "deletion_protected"), ("meta", "paused"), ("meta", "pause_pending"),
    ("meta", "provisioning"), ("meta", "revoked"), ("meta", "revoking"),
    ("user", "paused"), ("user", "pause_pending"), ("user", "revoking"),
    ("user", "provisioning"),
])
def test_exclusions_forget_deadline_and_resume_with_full_grace(runtime, target, flag):
    seed(runtime)
    record = runtime.meta["alice-phone"] if target == "meta" else runtime.users["alice"]
    record[flag] = True
    assert cleanup.cleanup_inactive_devices(now=NOW)["skipped"] == 1
    assert tracker(runtime) is None
    record.pop(flag)
    result = cleanup.cleanup_inactive_devices(now=NOW + timedelta(hours=1))
    assert result["initialized"] == 1
    assert result["deleted"] == 0


@pytest.mark.parametrize("change", [
    "gap", "clock", "generation", "account", "key", "rx_decrease", "tx_decrease",
    "handshake_decrease", "bad_record", "future_record",
])
def test_incomparable_observations_restart_grace(runtime, monkeypatch, change):
    state = seed(runtime)
    now = NOW
    if change == "gap":
        now += timedelta(hours=3, seconds=1)
    elif change == "clock":
        now -= timedelta(hours=2)
    elif change == "generation":
        monkeypatch.setattr(cleanup, "_generation", lambda: "different-boot:3")
    elif change == "account":
        runtime.users["alice"]["account_id"] = "replacement-account"
    elif change == "key":
        runtime.details["client_public_key"] = OTHER_KEY
        runtime.peers[OTHER_KEY] = runtime.peers.pop(KEY)
    elif change == "rx_decrease":
        runtime.peers[KEY]["rx"] -= 1
    elif change == "tx_decrease":
        runtime.peers[KEY]["tx"] -= 1
    elif change == "handshake_decrease":
        state["devices"]["alice-phone"]["handshake"] = 100
        runtime.state.write_text(json.dumps(state))
    elif change == "bad_record":
        state["devices"]["alice-phone"]["rx"] = "10"
        runtime.state.write_text(json.dumps(state))
    elif change == "future_record":
        state["devices"]["alice-phone"]["idle_since"] = (NOW + timedelta(days=1)).timestamp()
        runtime.state.write_text(json.dumps(state))
    result = cleanup.cleanup_inactive_devices(now=now)
    assert result["initialized"] == 1
    assert result["deleted"] == 0
    assert tracker(runtime)["idle_since"] == now.timestamp()


@pytest.mark.parametrize("change", ["missing_peer", "stats", "generation", "ip", "identity",
                                   "unknown_status", "bad_pause"])
def test_unknown_observations_drop_tracking(runtime, monkeypatch, change):
    seed(runtime)
    if change == "missing_peer":
        runtime.peers.clear()
    elif change == "stats":
        monkeypatch.setattr(cleanup, "_peer_stats", lambda: None)
    elif change == "generation":
        monkeypatch.setattr(cleanup, "_generation", lambda: None)
    elif change == "ip":
        runtime.details["address"] = "10.0.0.3/32"
    elif change == "identity":
        runtime.users["alice"].pop("account_id")
    elif change == "unknown_status":
        runtime.meta["alice-phone"]["status"] = "unknown"
    elif change == "bad_pause":
        runtime.users["alice"]["paused"] = "false"
    assert cleanup.cleanup_inactive_devices(now=NOW)["deleted"] == 0
    assert tracker(runtime) is None


@pytest.mark.parametrize("content", ["{", "[]", '{"version":2,"devices":{}}',
                                    '{"version":1,"devices":[]}'])
def test_corrupt_store_is_new_grace(runtime, content):
    runtime.state.write_text(content)
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["initialized"] == 1
    assert result["deleted"] == 0


@pytest.mark.parametrize("race", ["rx", "tx", "handshake", "paused", "protected", "identity",
                                 "generation", "stats"])
def test_recheck_prevents_racing_deletion(runtime, monkeypatch, race):
    seed(runtime)
    calls = 0

    def stats():
        nonlocal calls
        calls += 1
        if calls == 2:
            if race in {"rx", "tx", "handshake"}:
                runtime.peers[KEY][race] += 1
            elif race == "paused":
                runtime.users["alice"]["pause_pending"] = True
            elif race == "protected":
                runtime.meta["alice-phone"]["deletion_protected"] = True
            elif race == "identity":
                runtime.users["alice"]["account_id"] = "new-owner"
            elif race == "generation":
                monkeypatch.setattr(cleanup, "_generation", lambda: "changed-boot:3")
            elif race == "stats":
                return None
        return copy.deepcopy(runtime.peers)

    monkeypatch.setattr(cleanup, "_peer_stats", stats)
    assert cleanup.cleanup_inactive_devices(now=NOW)["deleted"] == 0
    assert runtime.deleted == []
    assert tracker(runtime) is None or tracker(runtime)["idle_since"] == NOW.timestamp()


def test_delete_failure_preserves_tracker_and_does_not_expose_error(runtime, monkeypatch):
    seed(runtime)
    monkeypatch.setattr(cleanup.wireguard, "delete_device", lambda name: (False, "sensitive-error"))
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["errors"] == 1
    assert tracker(runtime)
    assert "sensitive-error" not in str(result)


def test_persistence_failure_prevents_deletion(runtime, monkeypatch):
    seed(runtime)

    def fail(*args):
        raise OSError("storage unavailable")

    monkeypatch.setattr(cleanup.core, "write_json_private", fail)
    assert cleanup.cleanup_inactive_devices(now=NOW)["errors"] == 1
    assert runtime.deleted == []


def test_dry_run_never_writes_or_deletes_even_without_store(runtime):
    assert cleanup.cleanup_inactive_devices(now=NOW, dry_run=True)["candidates"] == 0
    assert not runtime.state.exists()
    seed(runtime)
    before = runtime.state.read_bytes()
    result = cleanup.cleanup_inactive_devices(now=NOW, dry_run=True)
    assert result["candidates"] == 1
    assert result["deleted"] == 0
    assert runtime.state.read_bytes() == before
    assert runtime.deleted == []


def test_account_and_monthly_history_remain_unchanged(runtime):
    seed(runtime)
    before_history, before_users = runtime.history.read_bytes(), copy.deepcopy(runtime.users)
    assert cleanup.cleanup_inactive_devices(now=NOW)["deleted"] == 1
    assert runtime.history.read_bytes() == before_history
    assert runtime.users == before_users


def test_ambiguous_shared_peer_is_never_deleted(runtime):
    seed(runtime)
    runtime.users["bob"] = {"account_id": "second-account", "approved": True}
    runtime.meta["bob-phone"] = {"owner": "bob", "device": "phone"}
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["candidates"] == 0
    assert result["deleted"] == 0
    assert json.loads(runtime.state.read_text())["devices"] == {}


@pytest.mark.parametrize("exclusion", ["protected", "paused", "pause_pending", "provisioning"])
def test_excluded_clone_of_candidate_key_prevents_revoking_shared_peer(runtime, exclusion):
    seed(runtime)
    runtime.users["bob"] = {"account_id": "second-account", "approved": True}
    runtime.meta["bob-phone"] = {"owner": "bob", "device": "phone"}
    if exclusion == "protected":
        runtime.meta["bob-phone"]["deletion_protected"] = True
    elif exclusion == "provisioning":
        runtime.meta["bob-phone"]["provisioning"] = True
    else:
        runtime.users["bob"][exclusion] = True
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["candidates"] == 0
    assert result["deleted"] == 0
    assert runtime.deleted == []
    assert tracker(runtime) is None


def test_unknown_excluded_config_identity_blocks_deletion_but_monitors_known(runtime, monkeypatch):
    seed(runtime)
    runtime.users["bob"] = {"account_id": "second-account", "approved": True, "paused": True}
    runtime.meta["bob-phone"] = {"owner": "bob", "device": "phone"}
    decoded = []

    def details(config, **kwargs):
        decoded.append(config)
        return runtime.details if config == "alice-phone" else {"client_public_key": ""}

    monkeypatch.setattr(cleanup.connection_config, "connection_details", details)
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["candidates"] == 0
    assert result["deleted"] == 0
    assert result["errors"] == 1
    assert result["observed"] == 1
    assert tracker(runtime)["last_successful_observation_at"] == NOW.timestamp()
    assert decoded == ["alice-phone", "bob-phone"]


@pytest.mark.parametrize("change", ["protected_clone", "paused_clone", "unknown_identity"])
def test_final_attribution_recheck_rejects_new_clone_or_unknown_config(runtime, monkeypatch, change):
    seed(runtime)
    calls = 0

    def stats():
        nonlocal calls
        calls += 1
        if calls == 2:
            runtime.users["bob"] = {"account_id": "second-account", "approved": True}
            runtime.meta["bob-phone"] = {"owner": "bob", "device": "phone"}
            if change == "protected_clone":
                runtime.meta["bob-phone"]["deletion_protected"] = True
            elif change == "paused_clone":
                runtime.users["bob"]["paused"] = True
            else:
                monkeypatch.setattr(cleanup.connection_config, "connection_details",
                                    lambda config, **kw: runtime.details if config == "alice-phone"
                                    else {"client_public_key": ""})
        return copy.deepcopy(runtime.peers)

    monkeypatch.setattr(cleanup, "_peer_stats", stats)
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["candidates"] == 1
    assert result["deleted"] == 0
    assert runtime.deleted == []
    assert tracker(runtime) is None


def test_one_failed_delete_does_not_block_independent_candidate(runtime, monkeypatch):
    cleanup.cleanup_inactive_devices(now=NOW)
    runtime.meta["alice-tablet"] = {"owner": "alice", "device": "tablet"}
    second_details = {"address": "10.0.0.3/32", "client_public_key": OTHER_KEY}
    runtime.peers[OTHER_KEY] = {"rx": 0, "tx": 0, "handshake": 0,
                                "addresses": {"10.0.0.3/32"}}
    monkeypatch.setattr(cleanup.connection_config, "connection_details", lambda config, **kw:
                        second_details if config == "alice-tablet" else runtime.details)
    cleanup.cleanup_inactive_devices(now=NOW)
    state = json.loads(runtime.state.read_text())
    for item in state["devices"].values():
        item["idle_since"] = (NOW - timedelta(days=61)).timestamp()
    runtime.state.write_text(json.dumps(state))

    def delete(name):
        if name == "alice-phone":
            raise OSError("synthetic helper failure")
        runtime.deleted.append(name)
        return True, ""

    monkeypatch.setattr(cleanup.wireguard, "delete_device", delete)
    result = cleanup.cleanup_inactive_devices(now=NOW)
    assert result["errors"] == 1
    assert result["deleted"] == 1
    assert runtime.deleted == ["alice-tablet"]
    assert tracker(runtime)


def test_lifecycle_read_failure_resets_grace(runtime, monkeypatch):
    seed(runtime)

    def fail():
        raise ValueError("invalid users")

    monkeypatch.setattr(cleanup.core, "load_users", fail)
    assert cleanup.cleanup_inactive_devices(now=NOW)["errors"] == 1
    assert tracker(runtime) is None


def test_tracker_contains_no_key_or_config(runtime):
    cleanup.cleanup_inactive_devices(now=NOW)
    assert KEY not in runtime.state.read_text()
    assert "client_public_key" not in runtime.state.read_text()


@pytest.mark.parametrize("returncode,stdout", [(1, ""), (0, ""), (0, "broken")])
def test_failed_or_empty_dump_returns_unknown(monkeypatch, returncode, stdout):
    monkeypatch.setattr(cleanup.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=returncode, stdout=stdout,
    ))
    assert cleanup._peer_stats() is None


def test_missing_wg_binary_returns_unknown(monkeypatch):
    def fail(*args, **kwargs):
        raise FileNotFoundError("wg unavailable")

    monkeypatch.setattr(cleanup.subprocess, "run", fail)
    assert cleanup._peer_stats() is None


def test_aware_utc_now_required(runtime):
    with pytest.raises(ValueError, match="timezone-aware"):
        cleanup.cleanup_inactive_devices(now=datetime(2026, 10, 1))


@pytest.mark.parametrize("bad", ["columns", "negative", "duplicate", "key", "address", "header",
                                 "keepalive"])
def test_strict_dump_parser_fails_closed(monkeypatch, bad):
    peer = f"{KEY}\t(none)\t(none)\t10.0.0.2/32\t0\t10\t20\t0"
    header = "(none)\t(none)\t51820\toff"
    if bad == "columns":
        peer += "\textra"
    elif bad == "negative":
        peer = peer.replace("\t10\t", "\t-10\t")
    elif bad == "duplicate":
        peer += "\n" + peer
    elif bad == "key":
        peer = peer.replace(KEY, "bad-key")
    elif bad == "address":
        peer = peer.replace("10.0.0.2/32", "invalid")
    elif bad == "header":
        header = "bad"
    elif bad == "keepalive":
        peer = peer.rsplit("\t", 1)[0] + "\tdisabled"
    monkeypatch.setattr(cleanup.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout=header + "\n" + peer,
    ))
    assert cleanup._peer_stats() is None


@pytest.mark.parametrize("keepalive", ["0", "off", "25"])
def test_valid_dump_tracks_by_public_key_and_counts_handshake(monkeypatch, keepalive):
    dump = (f"(none)\t(none)\t51820\toff\n"
            f"{KEY}\t(none)\t(none)\t10.0.0.2/32\t100\t10\t20\t{keepalive}\n")
    monkeypatch.setattr(cleanup.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout=dump,
    ))
    assert cleanup._peer_stats()[KEY] == {
        "rx": 10, "tx": 20, "handshake": 100, "addresses": {"10.0.0.2/32"},
    }
