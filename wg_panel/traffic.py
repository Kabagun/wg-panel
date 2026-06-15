import json
import os
import subprocess
from datetime import datetime, timezone

from .core import CLIENTS_DIR, DATA_DIR, DEVICE_META_FILE, TRAFFIC_FILE, _device_meta_lock, _traffic_lock

def fmt_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} B"
        b /= 1024
    return f"{b:.2f} PB"

def load_traffic():
    if not os.path.exists(TRAFFIC_FILE):
        return {}
    try:
        with open(TRAFFIC_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_traffic(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _traffic_lock:
        tmp = TRAFFIC_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, TRAFFIC_FILE)

def load_device_meta():
    if not os.path.exists(DEVICE_META_FILE):
        return {}
    try:
        with open(DEVICE_META_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_device_meta(meta):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _device_meta_lock:
        tmp = DEVICE_META_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(meta, f, indent=2)
        os.replace(tmp, DEVICE_META_FILE)

def get_device_type(wg_name):
    """Returns device VPN type."""
    return "wireguard"

def set_device_type(wg_name, vpn_type):
    meta = load_device_meta()
    meta.setdefault(wg_name, {})["vpn_type"] = vpn_type
    save_device_meta(meta)

def remove_device_meta(wg_name):
    meta = load_device_meta()
    if wg_name in meta:
        del meta[wg_name]
        save_device_meta(meta)

def get_wg_peer_stats():
    """Returns dict: {ip: (rx_bytes, tx_bytes)} from wg show all dump."""
    stats = {}
    try:
        r = subprocess.run(["wg", "show", "all", "dump"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 8:
                try:
                    ip = parts[4].split("/")[0]
                    rx = int(parts[6])
                    tx = int(parts[7])
                    stats[ip] = (rx, tx)
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return stats

def get_client_ip(wg_name):
    """Get client VPN IP from their conf file."""
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            for line in f:
                if line.strip().startswith("Address"):
                    addr = line.split("=", 1)[1].strip()
                    return addr.split("/")[0]
    except Exception:
        pass
    return None

def collect_traffic():
    """Collect current WireGuard stats and accumulate into monthly totals."""
    from .wireguard import get_all_devices

    peer_stats = get_wg_peer_stats()
    if not peer_stats:
        return
    traffic = load_traffic()
    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    for owner, device, wg_name in get_all_devices():
        ip = get_client_ip(wg_name)
        if not ip or ip not in peer_stats:
            continue
        rx_now, tx_now = peer_stats[ip]
        if wg_name not in traffic:
            traffic[wg_name] = {"last_rx": 0, "last_tx": 0, "monthly": {}}
        entry = traffic[wg_name]
        last_rx = entry.get("last_rx", 0)
        last_tx = entry.get("last_tx", 0)
        if month_key not in entry["monthly"]:
            entry["monthly"][month_key] = {"rx": 0, "tx": 0}
        delta_rx = rx_now - last_rx if rx_now >= last_rx else rx_now
        delta_tx = tx_now - last_tx if tx_now >= last_tx else tx_now
        entry["monthly"][month_key]["rx"] += delta_rx
        entry["monthly"][month_key]["tx"] += delta_tx
        entry["last_rx"] = rx_now
        entry["last_tx"] = tx_now
    save_traffic(traffic)
