"""Conservative inactivity tracking, separate from historical traffic totals.

Only continuous successful observations can establish sixty days of inactivity.
An unknown interval always starts a new grace period; historical monthly totals
are deliberately never used as evidence for deleting a profile.
"""

import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import connection_config, core, wireguard
from .traffic import load_device_meta

INACTIVITY_PERIOD = timedelta(days=60)
MAX_OBSERVATION_GAP = timedelta(hours=3)
STATE_VERSION = 1
_FIELDS = {
    "identity", "generation", "last_successful_observation_at", "idle_since",
    "last_activity_at", "rx", "tx", "handshake",
}


def _state_path():
    return os.path.join(core.DATA_DIR, "device_activity.json")


def _key(value):
    try:
        return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


def _integer(value):
    return type(value) is int and value >= 0


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _generation():
    """A reboot or interface replacement makes previous counters incomparable."""
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        index = Path("/sys/class/net/wg0/ifindex").read_text(encoding="ascii").strip()
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", boot) or not index.isdecimal():
            return None
        return f"{boot}:{int(index)}" if int(index) > 0 else None
    except (OSError, UnicodeError, ValueError):
        return None


def _peer_stats():
    """Parse the exact wg0 dump format without exposing keys or stderr."""
    try:
        result = subprocess.run(
            ["wg", "show", "wg0", "dump"], capture_output=True, text=True,
            timeout=5, check=False,
        )
        if result.returncode != 0:
            return None
        lines = result.stdout.splitlines()
        if not lines or len(lines[0].split("\t")) != 4:
            return None
        peers = {}
        for line in lines[1:]:
            fields = line.split("\t")
            if len(fields) != 8 or not _key(fields[0]) or fields[0] in peers:
                return None
            handshake, rx, tx = (int(fields[index]) for index in (4, 5, 6))
            keepalive = 0 if fields[7] == "off" else int(fields[7])
            if min(handshake, rx, tx, keepalive) < 0:
                return None
            addresses = frozenset(
                str(ipaddress.ip_network(address, strict=True))
                for address in fields[3].split(",")
            )
            if not addresses:
                return None
            peers[fields[0]] = {
                "handshake": handshake, "rx": rx, "tx": tx, "addresses": addresses,
            }
        return peers
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        return None


def _load_state():
    try:
        with open(_state_path(), encoding="utf-8") as handle:
            state = json.load(handle)
        if (
            not isinstance(state, dict) or type(state.get("version")) is not int
            or state["version"] != STATE_VERSION or not isinstance(state.get("devices"), dict)
        ):
            return {}
        return state["devices"]
    except (OSError, UnicodeError, ValueError):
        return {}


def _save_state(devices):
    core.write_json_private(_state_path(), {"version": STATE_VERSION, "devices": devices})


def _eligible(meta, user):
    if not isinstance(meta, dict) or not isinstance(user, dict):
        return False
    if not isinstance(user.get("account_id"), str) or not user["account_id"]:
        return False
    if user.get("approved") is not True or meta.get("vpn_type", "wireguard") != "wireguard":
        return False
    for record in (meta, user):
        for flag in ("paused", "pause_pending", "revoking", "provisioning", "revoked",
                     "happ_transport_provisioning", "happ_transport_deleting"):
            if record.get(flag, False) is not False:
                return False
        for field in ("state", "status"):
            if field in record and record[field] != "active":
                return False
    return meta.get("deletion_protected", False) is False


def _profile_identities(devices):
    """Attribute every visible config, including excluded profiles, once.

    An undecodable profile could be another copy of any live peer. Its presence
    blocks all deletion, while known profiles can still be monitored safely.
    """
    details_by_name, peer_names = {}, {}
    complete = True
    for _owner, _device, name in devices:
        try:
            details = connection_config.connection_details(
                wireguard.get_config(name), include_public_key=True,
            )
            key = details.get("client_public_key")
            if name in details_by_name or not _key(key):
                complete = False
                continue
            details_by_name[name] = details
            peer = hashlib.sha256(key.encode()).hexdigest()
            peer_names.setdefault(peer, set()).add(name)
        except Exception:  # noqa: BLE001 - unknown config identity blocks all deletion.
            complete = False
    return details_by_name, peer_names, complete


def _observe(name, owner, device, meta, users, peers, generation, details):
    record = meta.get(name)
    user = users.get(owner)
    if (
        not generation or peers is None or not _eligible(record, user)
        or record.get("owner") != owner or record.get("device") != device
        or not isinstance(owner, str) or not isinstance(device, str) or not device
    ):
        return None
    if details is None:
        return None
    key = details.get("client_public_key")
    if not _key(key) or key not in peers:
        return None
    peer = peers[key]
    addresses = [ipaddress.ip_interface(value.strip()) for value in details["address"].split(",")]
    # A config address alone is not identity. Require its host route on the
    # matching public-key peer too, including every address in dual-stack configs.
    expected = {f"{address.ip}/{address.max_prefixlen}" for address in addresses}
    if not expected or expected != peer["addresses"]:
        return None
    identity = hashlib.sha256((key + "\0" + user["account_id"]).encode()).hexdigest()
    return {
        "identity": identity, "generation": generation,
        "rx": peer["rx"], "tx": peer["tx"], "handshake": peer["handshake"],
        "_peer": hashlib.sha256(key.encode()).hexdigest(),
    }


def _valid_previous(previous, current, timestamp):
    fields = _FIELDS | ({"transports"} if "transports" in current else set())
    if not isinstance(previous, dict) or set(previous) != fields:
        return False
    if any(previous[field] != current[field] for field in ("identity", "generation")):
        return False
    if not all(_integer(previous[field]) for field in ("rx", "tx", "handshake")):
        return False
    observed, idle = previous["last_successful_observation_at"], previous["idle_since"]
    activity = previous["last_activity_at"]
    if not _number(observed) or not _number(idle) or not idle <= observed <= timestamp:
        return False
    if activity is not None and (not _number(activity) or not idle <= activity <= observed):
        return False
    if timestamp - observed > MAX_OBSERVATION_GAP.total_seconds():
        return False
    if "transports" in current:
        before, after = previous["transports"], current["transports"]
        if not isinstance(before, dict) or set(before) != set(after):
            return False
        for name, counters in after.items():
            old = before[name]
            if (not isinstance(old, list) or len(old) != 3 or not all(_integer(value) for value in old)
                    or any(value < old[index] for index, value in enumerate(counters))):
                return False
    return all(current[field] >= previous[field] for field in ("rx", "tx", "handshake"))


def _advance(previous, current, timestamp):
    valid = _valid_previous(previous, current, timestamp)
    active = valid and any(
        current[field] > previous[field] for field in ("rx", "tx", "handshake")
    )
    result = {
        **{field: current[field] for field in ("identity", "generation", "rx", "tx", "handshake")},
        "last_successful_observation_at": timestamp,
        "idle_since": previous["idle_since"] if valid and not active else timestamp,
        "last_activity_at": timestamp if active else previous["last_activity_at"] if valid else None,
    }
    if "transports" in current:
        result["transports"] = current["transports"]
    due = valid and timestamp - result["idle_since"] > INACTIVITY_PERIOD.total_seconds()
    return result, due, active, not valid


def _raw_devices(devices, meta):
    from .happ_peers import is_internal
    return list(devices) + [
        (record.get("owner"), record.get("device"), name)
        for name, record in meta.items() if is_internal(record)
    ]


def _observe_logical(name, owner, device, meta, users, peers, generation, details):
    observation = _observe(name, owner, device, meta, users, peers, generation, details.get(name))
    record = meta.get(name, {})
    if observation is None or not record.get("happ_pilot"):
        return observation
    from . import happ_peers
    try:
        children = happ_peers.children_for_parent(name)
        actual = wireguard.get_device(name)
        if not children and not (actual and actual["safe_internet"]):
            return None
        members = [observation]
        for child in children:
            child_record = meta[child]
            observed = _observe(child, owner, child_record["device"], meta, users, peers,
                                generation, details.get(child))
            if observed is None:
                return None
            members.append(observed)
        components = {member["_peer"]: [member["rx"], member["tx"], member["handshake"]] for member in members}
        if len(components) != len(members):
            return None
        return {**observation,
                "identity": hashlib.sha256("\0".join(sorted(member["identity"] for member in members)).encode()).hexdigest(),
                "rx": sum(member["rx"] for member in members),
                "tx": sum(member["tx"] for member in members),
                "handshake": sum(member["handshake"] for member in members),
                "transports": components}
    except (OSError, ValueError, KeyError):
        return None


def cleanup_inactive_devices(*, now=None, dry_run=False):
    """Observe devices and remove only peers idle for strictly more than 60 days.

    ``now`` must be an aware datetime (converted to UTC). Summary values contain
    counts only. Dry runs neither persist observations nor remove profiles.
    Call hourly; a gap exceeding three hours discards the accumulated grace.
    """
    now = datetime.now(UTC) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    timestamp = now.astimezone(UTC).timestamp()
    if timestamp < 0:
        raise ValueError("now must not precede the Unix epoch")
    summary = dict.fromkeys(("observed", "initialized", "active", "candidates", "deleted",
                             "skipped", "errors"), 0)
    summary["dry_run"] = bool(dry_run)
    with core._wireguard_lock:
        previous = _load_state()
        current = {}
        candidates = []
        try:
            users, meta = core.load_users(), load_device_meta()
            devices = wireguard.get_all_devices()
            peers, generation = _peer_stats(), _generation()
            if not isinstance(users, dict) or not isinstance(meta, dict):
                raise TypeError("Invalid lifecycle state")
            profile_details, peer_names, identities_complete = _profile_identities(_raw_devices(devices, meta))
        except Exception:  # noqa: BLE001 - failures must not expose config or allow deletion.
            summary["errors"] += 1
            if not dry_run:
                try:
                    _save_state({})
                except Exception:  # noqa: BLE001 - unavailable storage must never trigger deletion.
                    summary["errors"] += 1
            return summary
        if peers is None or generation is None:
            summary["errors"] += 1
        if not identities_complete:
            summary["errors"] += 1
        ambiguous = {name for names in peer_names.values() if len(names) > 1 for name in names}
        for owner, device, name in devices:
            try:
                if name in ambiguous:
                    summary["skipped"] += 1
                    continue
                observation = _observe_logical(name, owner, device, meta, users, peers, generation, profile_details)
                if observation is None:
                    summary["skipped"] += 1
                    continue
                tracker, due, active, initialized = _advance(
                    previous.get(name), observation, timestamp,
                )
                current[name] = tracker
                summary["observed"] += 1
                summary["active"] += int(active)
                summary["initialized"] += int(initialized)
                if due and identities_complete:
                    candidates.append((owner, device, name, observation))
            except Exception:  # noqa: BLE001 - isolate unknown device/config state.
                summary["skipped"] += 1
                summary["errors"] += 1
        summary["candidates"] = len(candidates)
        if dry_run:
            return summary
        try:
            # Persist even when observations failed: unknown intervals may
            # never preserve an old inactivity deadline through recovery.
            _save_state(current)
        except Exception:  # noqa: BLE001 - no deletion unless monitoring state was saved.
            summary["errors"] += 1
            return summary
        for owner, device, name, observation in candidates:
            try:
                fresh_peers, fresh_generation = _peer_stats(), _generation()
                fresh_devices = wireguard.get_all_devices()
                fresh_meta = load_device_meta()
                fresh_details, fresh_names, fresh_complete = _profile_identities(_raw_devices(fresh_devices, fresh_meta))
                if (
                    not fresh_complete or (owner, device, name) not in fresh_devices
                    or fresh_names.get(observation["_peer"]) != {name}
                ):
                    fresh = None
                else:
                    fresh = _observe_logical(name, owner, device, fresh_meta, core.load_users(),
                                             fresh_peers, fresh_generation, fresh_details)
            except Exception:  # noqa: BLE001 - isolate a failed final device observation.
                fresh = None
                summary["errors"] += 1
            if fresh != observation:
                if fresh is None:
                    current.pop(name, None)
                else:
                    current[name], _due, _active, _initialized = _advance(None, fresh, timestamp)
                summary["skipped"] += 1
                try:
                    _save_state(current)
                except Exception:  # noqa: BLE001 - stop all deletions on persistence failure.
                    summary["errors"] += 1
                    break
                continue
            try:
                ok, _error = wireguard.delete_device(name)
            except Exception:  # noqa: BLE001 - isolate helper failure; never expose its output.
                ok = False
            if not ok:
                summary["errors"] += 1
                continue
            current.pop(name, None)
            summary["deleted"] += 1
            try:
                _save_state(current)
            except Exception:  # noqa: BLE001 - stop all deletions on persistence failure.
                summary["errors"] += 1
                break
    return summary
