import base64
import os
import re
import subprocess

from .core import CLIENTS_DIR, WG_DIR, _wireguard_lock, ensure_private_dir, load_users
from .traffic import (
    load_device_meta,
    remove_device_meta,
    save_device_meta,
    set_device_meta,
)
from .traffic import set_device_safe_internet as _set_device_safe_internet

SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
DEFAULT_DNS_SERVERS = "1.1.1.1, 8.8.8.8"
SAFE_DNS_SERVERS = "1.1.1.3, 1.0.0.3"


class DeviceMetadataMigrationError(RuntimeError):
    pass


def _config_path(wg_name):
    if not SAFE_NAME_RE.fullmatch(wg_name):
        return None
    return os.path.join(CLIENTS_DIR, f"{wg_name}.conf")


def migrate_device_metadata(dry_run=False):
    """Map every legacy config to one exact user/device owner."""
    if not os.path.isdir(CLIENTS_DIR):
        if dry_run:
            return {"total": 0, "migrated": 0, "ambiguous": [], "unowned": [], "stale": []}
        ensure_private_dir(CLIENTS_DIR)
    elif not dry_run:
        ensure_private_dir(CLIENTS_DIR)
    users = load_users()
    meta = load_device_meta()
    migrated = 0
    ambiguous = []
    unowned = []
    config_names = sorted(
        filename[:-5]
        for filename in os.listdir(CLIENTS_DIR)
        if filename.endswith(".conf")
    )

    for wg_name in config_names:
        current = meta.get(wg_name, {})
        owner = current.get("owner")
        device = current.get("device")
        if owner in users and isinstance(device, str) and device:
            current["vpn_type"] = "wireguard"
            current.setdefault("safe_internet", False)
            continue

        candidates = []
        for username in users:
            prefix = f"{username}-"
            if wg_name.startswith(prefix) and len(wg_name) > len(prefix):
                candidates.append((username, wg_name[len(prefix) :]))
        if not candidates:
            unowned.append(wg_name)
            continue
        if len(candidates) != 1:
            ambiguous.append({"wg_name": wg_name, "owners": [item[0] for item in candidates]})
            continue
        owner, device = candidates[0]
        meta[wg_name] = {
            "owner": owner,
            "device": device,
            "vpn_type": "wireguard",
            "safe_internet": False,
        }
        migrated += 1

    stale = sorted(name for name in meta if name not in config_names)
    report = {
        "total": len(config_names),
        "migrated": migrated,
        "ambiguous": ambiguous,
        "unowned": unowned,
        "stale": stale,
    }
    if (ambiguous or unowned) and not dry_run:
        raise DeviceMetadataMigrationError(
            f"Device metadata migration blocked: ambiguous={len(ambiguous)}, unowned={len(unowned)}"
        )
    if not dry_run:
        for name in stale:
            meta.pop(name, None)
        save_device_meta(meta)
        for wg_name in config_names:
            path = _config_path(wg_name)
            if path:
                os.chmod(path, 0o600)
    return report


def get_all_devices():
    migrate_device_metadata(dry_run=False)
    meta = load_device_meta()
    result = []
    for wg_name, item in meta.items():
        path = _config_path(wg_name)
        if path and os.path.exists(path) and item.get("owner") and item.get("device"):
            result.append((item["owner"], item["device"], wg_name))
    return sorted(result, key=lambda item: (item[0], item[1], item[2]))


def get_user_devices(username):
    return [device for owner, device, _wg_name in get_all_devices() if owner == username]


def client_name(username, device):
    for owner, display_name, wg_name in get_all_devices():
        if owner == username and display_name == device:
            return wg_name
    return f"u{len(username)}-{username}-{device}"


def get_device(wg_name):
    item = load_device_meta().get(wg_name)
    path = _config_path(wg_name)
    if not item or not path or not os.path.exists(path):
        return None
    if not item.get("owner") or not item.get("device"):
        return None
    return {"wg_name": wg_name, **item, "safe_internet": bool(item.get("safe_internet"))}


def user_owns_device(username, wg_name):
    device = get_device(wg_name)
    return bool(device and device["owner"] == username)


def set_device_safe_internet(wg_name, enabled):
    """Persist the Safe internet preference for an existing WireGuard device."""
    with _wireguard_lock:
        if not get_device(wg_name):
            return False
        return _set_device_safe_internet(wg_name, enabled)


def get_config(wg_name):
    """Return a client config rendered with its device's current DNS preference."""
    path = _config_path(wg_name)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            config = handle.read()
    except OSError:
        return None

    device = get_device(wg_name)
    dns_servers = SAFE_DNS_SERVERS if device and device["safe_internet"] else DEFAULT_DNS_SERVERS
    return _render_config_dns(config, dns_servers)


def _render_config_dns(config, dns_servers):
    lines = config.splitlines()
    trailing_newline = config.endswith(("\n", "\r"))
    interface_start = next(
        (index for index, line in enumerate(lines) if line.strip().lower() == "[interface]"),
        None,
    )
    if interface_start is None:
        return config

    interface_end = next(
        (
            index
            for index in range(interface_start + 1, len(lines))
            if lines[index].strip().startswith("[") and lines[index].strip().endswith("]")
        ),
        len(lines),
    )
    dns_indexes = [
        index
        for index in range(interface_start + 1, interface_end)
        if re.match(r"^\s*DNS\s*=", lines[index], re.IGNORECASE)
    ]
    dns_line = f"DNS = {dns_servers}"
    if dns_indexes:
        lines[dns_indexes[0]] = dns_line
        for index in reversed(dns_indexes[1:]):
            del lines[index]
    else:
        insert_at = interface_end
        while insert_at > interface_start + 1 and not lines[insert_at - 1].strip():
            insert_at -= 1
        lines.insert(insert_at, dns_line)

    rendered = "\n".join(lines)
    return rendered + "\n" if trailing_newline else rendered


def _script_environment():
    environment = os.environ.copy()
    environment.update({"WG_DIR": WG_DIR, "CLIENTS_DIR": CLIENTS_DIR})
    return environment


def _run_script(script_name, wg_name, timeout):
    script = os.path.join(WG_DIR, script_name)
    try:
        result = subprocess.run(
            [script, wg_name],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_script_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if result.returncode != 0:
        error = (result.stderr or result.stdout or "WireGuard helper failed").strip()
        return False, error[:500]
    return True, ""


def create_device(username, device):
    """Provision a device under one process-wide quota/IP transaction."""
    if not SAFE_NAME_RE.fullmatch(username) or not SAFE_NAME_RE.fullmatch(device):
        return False, "", "Invalid user or device name"
    with _wireguard_lock:
        users = load_users()
        user = users.get(username)
        if not user or not user.get("approved"):
            return False, "", "User is not approved"
        current = get_user_devices(username)
        if device in current:
            return True, client_name(username, device), ""
        limit = user.get("max_devices", 3)
        if limit != -1 and len(current) >= limit:
            return False, "", "Device limit reached"

        wg_name = f"u{len(username)}-{username}-{device}"
        if not SAFE_NAME_RE.fullmatch(wg_name):
            return False, "", "Generated client name is invalid"
        path = _config_path(wg_name)
        if wg_name in load_device_meta() or (path and os.path.exists(path)):
            return False, "", "Client name collision"

        ok, error = _run_script("add-client.sh", wg_name, 45)
        if not ok:
            return False, "", error
        if not path or not os.path.exists(path):
            return False, "", "Provisioning completed without a client configuration"
        os.chmod(path, 0o600)
        try:
            set_device_meta(wg_name, username, device)
        except OSError as exc:
            _run_script("remove-client.sh", wg_name, 30)
            return False, "", f"Failed to persist device ownership: {exc}"
        return True, wg_name, ""


def delete_device(wg_name):
    """Revoke a device and remove metadata only after verified helper success."""
    if not get_device(wg_name):
        return False, "Device not found"
    with _wireguard_lock:
        ok, error = _run_script("remove-client.sh", wg_name, 30)
        if not ok:
            return False, error
        path = _config_path(wg_name)
        if path and os.path.exists(path):
            return False, "WireGuard helper returned success but the client config still exists"
        remove_device_meta(wg_name)
        return True, ""


def qr_svg_b64(wg_name):
    """Return a QR code for the currently rendered client configuration."""
    config = get_config(wg_name)
    if not config:
        return None
    try:
        result = subprocess.run(
            ["qrencode", "-t", "SVG", "-o", "-"],
            input=config.encode(),
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return "data:image/svg+xml;base64," + base64.b64encode(result.stdout).decode()
