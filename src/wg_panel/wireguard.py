import base64
import logging
import os
import re
import subprocess

from .core import (
    CLIENTS_DIR,
    WG_DIR,
    _wireguard_lock,
    app,
    ensure_private_dir,
    load_users,
    mutate_users,
)
from .dns_enforcement import SafeDnsEnforcementError, sync_safe_dns
from .traffic import (
    load_device_meta,
    mutate_device_meta,
    remove_device_meta,
    save_device_meta,
    set_device_meta,
)
from .traffic import set_device_safe_internet as _set_device_safe_internet

SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
DEFAULT_DNS_SERVERS = "1.1.1.1, 8.8.8.8"
SAFE_DNS_SERVERS = "1.1.1.3, 1.0.0.3"
logger = logging.getLogger(__name__)


class DeviceMetadataMigrationError(RuntimeError):
    pass


def _config_path(wg_name):
    if not SAFE_NAME_RE.fullmatch(wg_name):
        return None
    return os.path.join(CLIENTS_DIR, f"{wg_name}.conf")


def _is_generated_name(wg_name):
    match = re.match(r"^u([1-9][0-9]*)-(.+)$", wg_name)
    if not match:
        return False
    length = int(match[1])
    remainder = match[2]
    return len(remainder) > length + 1 and remainder[length] == "-"


def migrate_device_metadata(dry_run=False):
    """Map every legacy config to one exact user/device owner."""
    with _wireguard_lock:
        return _migrate_device_metadata(dry_run)


def _migrate_device_metadata(dry_run):
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

        # Generated names require authoritative metadata, even if a username
        # happens to match a legacy prefix. Never transfer an existing owner.
        if owner or _is_generated_name(wg_name):
            unowned.append(wg_name)
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
            if not users.get(meta[name].get("owner"), {}).get("revoking"):
                meta.pop(name, None)
        save_device_meta(meta)
        for wg_name in config_names:
            path = _config_path(wg_name)
            if path:
                os.chmod(path, 0o600)
    return report


def get_all_devices():
    """List committed ownership without running migrations or writing state."""
    with _wireguard_lock:
        return _get_all_devices()


def _get_all_devices():
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
    if not item or item.get("revoked") or not path or not os.path.exists(path):
        return None
    if not item.get("owner") or not item.get("device"):
        return None
    return {"wg_name": wg_name, **item, "safe_internet": bool(item.get("safe_internet"))}


def user_owns_device(username, wg_name):
    device = get_device(wg_name)
    return bool(device and device["owner"] == username)


def _client_ipv4(wg_name):
    """Read one client IPv4 address from its runtime config."""
    path = _config_path(wg_name)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                key, separator, value = line.partition("=")
                if separator and key.strip().lower() == "address":
                    return value.strip().split(",", 1)[0].strip().split("/", 1)[0]
    except (OSError, IndexError):
        return None
    return None


def _safe_dns_ips(meta, excluded=None, override=None):
    """Return the exact IPv4 set represented by Safe internet metadata."""
    ips = []
    for name, item in meta.items():
        if name == excluded or item.get("revoked"):
            continue
        enabled = bool(item.get("safe_internet"))
        if override and name in override:
            enabled = bool(override[name])
        if not enabled:
            continue
        address = _client_ipv4(name)
        if not address:
            raise SafeDnsEnforcementError(
                f"Safe internet device '{name}' has no client IPv4 address"
            )
        ips.append(address)
    return ips


def _sync_safe_dns(ips, *, allow_unavailable=False, require_helper=True):
    """Apply the managed firewall policy through the installed helper."""
    return sync_safe_dns(
        ips,
        wg_dir=WG_DIR,
        allow_unavailable=allow_unavailable,
        require_helper=require_helper,
    )


def reconcile_safe_dns(*, require_helper=None, allow_unavailable=False):
    """Reconcile all persisted Safe internet devices during startup.

    A non-empty safe set is fail-closed: missing or failing nftables support
    raises and prevents the panel from serving an unenforced configuration.
    A fresh install with no enabled devices may start before the helper is
    installed; once a device is enabled, the helper is mandatory.
    """
    with _wireguard_lock:
        meta = load_device_meta()
        ips = _safe_dns_ips(meta)
        if require_helper is None:
            require_helper = bool(ips)
        _sync_safe_dns(
            ips,
            allow_unavailable=allow_unavailable,
            require_helper=require_helper,
        )
        return {
            "safe_devices": sum(
                bool(item.get("safe_internet")) and not item.get("revoked", False)
                for item in meta.values()
            ),
            "ips": ips,
        }


def set_device_safe_internet(wg_name, enabled):
    """Persist Safe internet only after server enforcement succeeds.

    The firewall is reconciled before metadata changes. If metadata persistence
    fails, the previous firewall set is restored; an enable failure therefore
    cannot leave a client marked safe without server enforcement.
    """
    enabled = bool(enabled)
    with _wireguard_lock:
        if not get_device(wg_name):
            return False
        meta = load_device_meta()
        current = meta.get(wg_name)
        if not current:
            return False
        was_enabled = bool(current.get("safe_internet"))
        try:
            previous_ips = _safe_dns_ips(meta)
            desired_ips = _safe_dns_ips(meta, override={wg_name: enabled})
        except SafeDnsEnforcementError as exc:
            logger.warning("Safe internet state rejected for %s: %s", wg_name, exc)
            return False

        # Reconciliation on an already-enabled device repairs drift without
        # changing metadata. Disabling an already-disabled device is a no-op.
        if was_enabled == enabled:
            if not enabled:
                return True
            try:
                _sync_safe_dns(desired_ips, allow_unavailable=bool(app.config.get("TESTING")))
            except SafeDnsEnforcementError as exc:
                logger.error("Safe internet reconciliation failed for %s: %s", wg_name, exc)
                return False
            return True

        try:
            _sync_safe_dns(desired_ips, allow_unavailable=bool(app.config.get("TESTING")))
        except SafeDnsEnforcementError as exc:
            logger.error("Safe internet firewall update failed for %s: %s", wg_name, exc)
            return False

        try:
            changed = _set_device_safe_internet(wg_name, enabled)
        except Exception as exc:  # noqa: BLE001 - every storage failure must trigger rollback.
            changed = False
            logger.error("Safe internet metadata update failed for %s: %s", wg_name, exc)
        if changed:
            return True

        try:
            _sync_safe_dns(previous_ips, allow_unavailable=bool(app.config.get("TESTING")))
        except SafeDnsEnforcementError as exc:
            logger.critical("Safe internet rollback failed for %s: %s", wg_name, exc)
        return False


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
        if not user or not user.get("approved") or user.get("revoking"):
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

        # A failed cleanup after an earlier peer revoke can leave its address in
        # the fail-closed nftables set. Reconcile before the allocator can reuse
        # that address, and require the installed helper on production creates.
        try:
            reconcile_safe_dns(
                require_helper=True,
                allow_unavailable=bool(app.config.get("TESTING")),
            )
        except SafeDnsEnforcementError as exc:
            logger.error("Safe internet reconciliation blocked device creation: %s", exc)
            return False, "", f"Safe internet firewall reconciliation failed: {exc}"

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
    with _wireguard_lock:
        meta = load_device_meta()
        device_meta = meta.get(wg_name, {})
        revoked = bool(device_meta.get("revoked"))
        path = _config_path(wg_name)
        if not path or (not revoked and not get_device(wg_name)):
            return False, "Device not found"
        if revoked and os.path.exists(path):
            return False, "Revoked device has an unexpected client configuration"
        was_safe = bool(device_meta.get("safe_internet"))
        previous_ips = []
        desired_ips = []
        if was_safe:
            try:
                previous_ips = _safe_dns_ips(meta)
                desired_ips = _safe_dns_ips(meta, excluded=wg_name)
            except SafeDnsEnforcementError as exc:
                logger.error("Safe internet state is invalid for %s: %s", wg_name, exc)
                return False, f"Safe internet state is invalid: {exc}"

        # Keep the safe address in the managed set until the peer and runtime
        # config are both gone. This avoids a fail-open window during revoke.
        if not revoked:
            ok, error = _run_script("remove-client.sh", wg_name, 30)
            if not ok:
                return False, error
            if os.path.exists(path):
                return False, "WireGuard helper returned success but the client config still exists"
            try:
                mutate_device_meta(lambda records: records[wg_name].update(revoked=True))
            except (OSError, ValueError) as exc:
                return False, f"Peer removed but its revocation checkpoint could not be saved: {exc}"
        if was_safe:
            try:
                _sync_safe_dns(desired_ips)
            except SafeDnsEnforcementError as exc:
                # The peer is gone, but retaining the old address in the
                # managed set is fail-closed. Startup reconciliation can retry
                # cleanup; return the operational error to the caller now.
                logger.critical("Safe internet firewall cleanup failed after deleting %s: %s", wg_name, exc)
                return False, f"WireGuard peer removed but Safe internet cleanup failed: {exc}"
        try:
            remove_device_meta(wg_name)
        except Exception as exc:  # noqa: BLE001 - keep the firewall fail-closed on storage failure.
            logger.error("Failed to remove device metadata for %s: %s", wg_name, exc)
            if was_safe:
                try:
                    _sync_safe_dns(previous_ips)
                except SafeDnsEnforcementError as rollback_exc:
                    logger.critical(
                        "Safe internet rollback failed after metadata removal error for %s: %s",
                        wg_name,
                        rollback_exc,
                    )
            return False, f"Failed to remove device metadata: {exc}"
        return True, ""


def delete_user(username):
    """Disable an account, revoke its peers, then remove it in one transaction.

    A failure retains the disabled account and ownership for an administrator
    to retry. Provisioning and protected device requests share this lock.
    """
    with _wireguard_lock:
        def begin(users):
            user = users.get(username)
            if not user or user.get("role") == "admin":
                return False
            user["revoking"] = True
            user["approved"] = False
            user["payment_enabled"] = False
            user.pop("approval_token", None)
            return True

        if not mutate_users(begin):
            return False, "User not found or protected"
        failures = []
        meta = load_device_meta()
        # A config that was published without ownership (for example after a
        # storage failure) is unresolved authority, not proof of no devices.
        if os.path.isdir(CLIENTS_DIR):
            unknown = [name for name in os.listdir(CLIENTS_DIR) if name.endswith(".conf")
                       and not meta.get(name[:-5], {}).get("owner")]
            if unknown:
                return False, "Unowned client configurations require ownership recovery"
        # Include stale metadata as well as visible configs. Unresolved peer
        # state must block successful deletion, never silently disappear.
        for wg_name, item in meta.items():
            if item.get("owner") != username:
                continue
            ok, error = delete_device(wg_name)
            if not ok:
                failures.append(f"{item.get('device', wg_name)}: {error}")
        if failures:
            return False, "; ".join(failures)
        mutate_users(lambda users: users.pop(username, None))
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
