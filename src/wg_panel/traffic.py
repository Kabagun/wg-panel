import json
import os
import subprocess
from datetime import UTC, datetime

from .account_policy import account_safe_internet_locked
from .core import (
    CLIENTS_DIR,
    DEVICE_META_FILE,
    TRAFFIC_FILE,
    _device_meta_lock,
    _traffic_lock,
    _wireguard_lock,
    ensure_private_dir,
    write_json_private,
)


def fmt_bytes(value):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024
    return f"{value:.2f} PB"


def _read_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def load_traffic():
    with _traffic_lock:
        return _read_json(TRAFFIC_FILE)


def save_traffic(data):
    with _traffic_lock:
        write_json_private(TRAFFIC_FILE, data)


def mutate_traffic(mutator):
    with _traffic_lock:
        traffic = _read_json(TRAFFIC_FILE)
        result = mutator(traffic)
        write_json_private(TRAFFIC_FILE, traffic)
        return result


def load_device_meta():
    """Read ownership and policy within the device lifecycle transaction."""
    with _wireguard_lock, _device_meta_lock:
        return _read_json(DEVICE_META_FILE)


def save_device_meta(meta):
    """Replace metadata; callers retaining a snapshot must hold the lifecycle lock."""
    with _wireguard_lock, _device_meta_lock:
        write_json_private(DEVICE_META_FILE, meta)


def mutate_device_meta(mutator):
    """Mutate ownership or policy atomically with provisioning and migration."""
    with _wireguard_lock, _device_meta_lock:
        meta = _read_json(DEVICE_META_FILE)
        result = mutator(meta)
        write_json_private(DEVICE_META_FILE, meta)
        return result


def set_device_meta(wg_name, owner, device, *, provisioning=False):
    """Create metadata for a newly provisioned WireGuard device."""
    def update(meta):
        existing = meta.get(wg_name, {})
        if existing.get("safe_internet_locked") and not (
            existing.get("owner") == owner and existing.get("revoked")
            and account_safe_internet_locked(owner)
        ):
            raise ValueError("A permanently protected device requires manual server recovery via SSH")
        meta[wg_name] = {
            "owner": owner,
            "device": device,
            "vpn_type": "wireguard",
            "safe_internet": False,
        }
        if provisioning:
            meta[wg_name]["provisioning"] = True

    mutate_device_meta(update)


def set_device_safe_internet(wg_name, enabled, *, confirmed=False, allow_locked_disable=False):
    """Commit a confirmed first enable and retain its permanent owner lock.

    The WireGuard layer applies firewall changes before calling this mutator.
    The same checks here prevent other policy writers from bypassing consent
    or clearing the lock. ``allow_locked_disable`` is reserved for deliberate
    server maintenance through SSH; no web route may pass it.
    """
    def update(meta):
        device = meta.get(wg_name)
        if not device or device.get("revoked"):
            return False
        if not enabled and account_safe_internet_locked(device.get("owner")):
            return False
        if enabled and not device.get("safe_internet") and not confirmed:
            return False
        if not enabled and device.get("safe_internet_locked") and not allow_locked_disable:
            return False
        device["safe_internet"] = bool(enabled)
        if enabled and confirmed:
            device["safe_internet_locked"] = True
        elif not enabled and allow_locked_disable:
            device.pop("safe_internet_locked", None)
        return True

    return mutate_device_meta(update)


def remove_device_meta(wg_name, *, preserve_locked=True):
    """Retain a locked identity after peer revocation to prevent name reuse."""
    def update(meta):
        device = meta.get(wg_name, {})
        if preserve_locked and device.get("safe_internet_locked"):
            meta[wg_name] = {
                "owner": device["owner"],
                "device": device["device"],
                "vpn_type": "wireguard",
                "safe_internet": True,
                "safe_internet_locked": True,
                "revoked": True,
            }
        else:
            meta.pop(wg_name, None)

    mutate_device_meta(update)


def get_device_type(wg_name):
    return load_device_meta().get(wg_name, {}).get("vpn_type", "wireguard")


def set_device_type(wg_name, vpn_type):
    def update(meta):
        meta.setdefault(wg_name, {})["vpn_type"] = vpn_type

    mutate_device_meta(update)


def get_wg_peer_stats():
    """Return {client_ip: (received_bytes, transmitted_bytes)}."""
    try:
        result = subprocess.run(
            ["wg", "show", "all", "dump"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode != 0:
        return {}

    stats = {}
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        try:
            stats[parts[4].split("/")[0]] = (int(parts[6]), int(parts[7]))
        except (ValueError, IndexError):
            continue
    return stats


def get_client_ip(wg_name):
    path = os.path.join(CLIENTS_DIR, f"{wg_name}.conf")
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.strip().startswith("Address"):
                    return line.split("=", 1)[1].strip().split("/")[0]
    except (OSError, IndexError):
        return None
    return None


def collect_traffic():
    """Collect WireGuard counters and atomically accumulate monthly deltas."""
    from .wireguard import get_all_devices

    ensure_private_dir(os.path.dirname(TRAFFIC_FILE))
    peer_stats = get_wg_peer_stats()
    if not peer_stats:
        return
    devices = get_all_devices()
    month_key = datetime.now(UTC).strftime("%Y-%m")

    def apply(traffic):
        for _owner, _device, wg_name in devices:
            address = get_client_ip(wg_name)
            if not address or address not in peer_stats:
                continue
            received_now, transmitted_now = peer_stats[address]
            entry = traffic.setdefault(
                wg_name,
                {"last_rx": 0, "last_tx": 0, "monthly": {}},
            )
            monthly = entry.setdefault("monthly", {})
            current = monthly.setdefault(month_key, {"rx": 0, "tx": 0})
            previous_rx = entry.get("last_rx", 0)
            previous_tx = entry.get("last_tx", 0)
            current["rx"] += received_now - previous_rx if received_now >= previous_rx else received_now
            current["tx"] += (
                transmitted_now - previous_tx if transmitted_now >= previous_tx else transmitted_now
            )
            entry["last_rx"] = received_now
            entry["last_tx"] = transmitted_now

    mutate_traffic(apply)
