import base64
import logging
import os
import re
import subprocess

from .account_policy import (
    AccountPolicyError,
    account_safe_internet_locked,
    effective_safe_internet,
    load_account_policies,
    save_account_policies,
)
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
from .infrastructure import (
    assert_infrastructure_ready,
    infrastructure_dir,
    infrastructure_registry_path,
    load_infrastructure_peers,
)
from .safe_dns_settings import load_safe_dns_target
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
    infrastructure = assert_infrastructure_ready(wg_dir=WG_DIR)
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
        if filename.endswith(".conf") and filename[:-5] not in infrastructure
    )

    for wg_name in config_names:
        current = meta.get(wg_name, {})
        owner = current.get("owner")
        device = current.get("device")
        if current.get("revoked"):
            # A restored file is not authority to revive a revoked peer or to
            # discard its permanent protection checkpoint.
            unowned.append(wg_name)
            continue
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

    stale = sorted(name for name in meta if name not in config_names and name not in infrastructure)
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
            if (
                not meta[name].get("safe_internet_locked")
                and not users.get(meta[name].get("owner"), {}).get("revoking")
            ):
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
    infrastructure = assert_infrastructure_ready(wg_dir=WG_DIR)
    meta = load_device_meta()
    result = []
    for wg_name, item in meta.items():
        if wg_name in infrastructure:
            continue
        path = _config_path(wg_name)
        if (
            path and os.path.exists(path) and not item.get("revoked")
            and item.get("owner") and item.get("device")
        ):
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
    if wg_name in assert_infrastructure_ready(wg_dir=WG_DIR):
        return None
    item = load_device_meta().get(wg_name)
    path = _config_path(wg_name)
    if (
        not item or item.get("revoked") or item.get("provisioning")
        or not path or not os.path.exists(path)
    ):
        return None
    if not item.get("owner") or not item.get("device"):
        return None
    account_locked = account_safe_internet_locked(item["owner"])
    if account_locked and item.get("vpn_type", "wireguard") != "wireguard":
        return None
    return {
        "wg_name": wg_name, **item,
        "safe_internet": effective_safe_internet(item),
        "account_safe_internet_locked": account_locked,
    }


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


def _safe_dns_ips(meta, excluded=None, override=None, policies=None):
    """Combine account protection with independent infrastructure protection.

    Read registered claims during adoption, when the enforcer must run before
    its recovery checkpoint is removed. Ordinary callers check readiness first.
    """
    infrastructure = load_infrastructure_peers(wg_dir=WG_DIR)
    ips = [item["ipv4"] for item in infrastructure.values()]
    if policies is None:
        policies = load_account_policies()
    for name, item in meta.items():
        if name in infrastructure or name == excluded or item.get("revoked"):
            continue
        enabled = effective_safe_internet(item, policies)
        if override and name in override:
            enabled = bool(override[name]) or account_safe_internet_locked(item.get("owner"), policies)
        if not enabled:
            continue
        if item.get("vpn_type", "wireguard") != "wireguard":
            raise SafeDnsEnforcementError("Safe internet requires a WireGuard profile")
        address = _client_ipv4(name)
        if not address:
            raise SafeDnsEnforcementError(
                f"Safe internet device '{name}' has no client IPv4 address"
            )
        ips.append(address)
    return ips


def _sync_safe_dns(ips, *, allow_unavailable=False, require_helper=True):
    """Apply the managed firewall policy through the installed helper."""
    load_safe_dns_target(WG_DIR)
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
        load_safe_dns_target(WG_DIR)
        meta = load_device_meta()
        policies = load_account_policies()
        infrastructure = load_infrastructure_peers(wg_dir=WG_DIR)
        ips = _safe_dns_ips(meta, policies=policies)
        if require_helper is None:
            require_helper = bool(ips)
        _sync_safe_dns(
            ips,
            allow_unavailable=allow_unavailable,
            require_helper=require_helper,
        )
        return {
            "safe_devices": sum(
                effective_safe_internet(item, policies) and not item.get("revoked", False)
                for name, item in meta.items()
                if name not in infrastructure
            ),
            "ips": ips,
        }


def set_account_safe_internet(owner, *, confirmed=False):
    """Enforce every current profile before permanently locking this owner.

    The owner key is the normalized login name, deliberately independent of the
    user's replaceable account_id. Deleting/recreating that login inherits it.
    Only deliberate SSH maintenance can remove the registry entry.
    """
    with _wireguard_lock:
        assert_infrastructure_ready(wg_dir=WG_DIR)
        user = load_users().get(owner)
        if not user or not user.get("approved") or user.get("revoking"):
            return False
        if not SAFE_NAME_RE.fullmatch(owner):
            return False
        policies = load_account_policies()
        already_locked = account_safe_internet_locked(owner, policies)
        if not already_locked and not confirmed:
            return False
        desired = {**policies, owner: {"safe_internet_locked": True}}
        meta = load_device_meta()
        try:
            previous_ips = _safe_dns_ips(meta, policies=policies)
            desired_ips = _safe_dns_ips(meta, policies=desired)
            _sync_safe_dns(desired_ips, allow_unavailable=bool(app.config.get("TESTING")))
        except SafeDnsEnforcementError as exc:
            logger.error("Account Safe internet enforcement failed: %s", exc)
            return False
        if already_locked:
            return True
        try:
            save_account_policies(desired)
        except (OSError, ValueError, AccountPolicyError) as exc:
            logger.error("Account Safe internet policy persistence failed: %s", exc)
            # Atomic replacement may have committed before a final chmod or
            # fsync reported an error. Never roll back enforcement beneath a
            # lock that is already durably visible.
            try:
                if account_safe_internet_locked(owner):
                    return True
            except AccountPolicyError:
                return False
            try:
                _sync_safe_dns(previous_ips, allow_unavailable=bool(app.config.get("TESTING")))
            except SafeDnsEnforcementError as rollback_exc:
                logger.critical("Account Safe internet rollback failed: %s", rollback_exc)
            return False
        return True


def set_device_safe_internet(wg_name, enabled, *, confirmed=False, allow_locked_disable=False):
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
        if not enabled and account_safe_internet_locked(current.get("owner")):
            return False
        was_enabled = bool(current.get("safe_internet"))
        if enabled and not was_enabled and not confirmed:
            return False
        if not enabled and current.get("safe_internet_locked") and not allow_locked_disable:
            return False
        try:
            previous_ips = _safe_dns_ips(meta)
            desired_ips = _safe_dns_ips(meta, override={wg_name: enabled})
        except SafeDnsEnforcementError as exc:
            logger.warning("Safe internet state rejected for %s: %s", wg_name, exc)
            return False

        # A legacy enabled device may explicitly confirm its permanent lock
        # without an unprotected interval. Plain retries only repair drift.
        changes_lock = (
            enabled and confirmed and not current.get("safe_internet_locked")
        ) or (
            not enabled and current.get("safe_internet_locked") and allow_locked_disable
        )
        if was_enabled == enabled and not changes_lock:
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
            changed = _set_device_safe_internet(
                wg_name,
                enabled,
                confirmed=confirmed,
                allow_locked_disable=allow_locked_disable,
            )
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
    device = get_device(wg_name)
    if not device:
        return None
    path = _config_path(wg_name)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            config = handle.read()
    except OSError:
        return None

    dns_servers = (
        load_safe_dns_target(WG_DIR).client_dns_servers
        if device["safe_internet"] else DEFAULT_DNS_SERVERS
    )
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
    environment.update({
        "WG_DIR": WG_DIR, "CLIENTS_DIR": CLIENTS_DIR,
        "INFRASTRUCTURE_CLIENTS_DIR": infrastructure_dir(wg_dir=WG_DIR),
        "INFRASTRUCTURE_REGISTRY": infrastructure_registry_path(),
    })
    return environment


def _run_script(script_name, wg_name, timeout, *arguments):
    script = os.path.join(WG_DIR, script_name)
    try:
        result = subprocess.run(
            [script, wg_name, *arguments],
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


def _supports_prepared_clients():
    """Inspect versioned source before any helper mutation, including on skew."""
    try:
        with open(os.path.join(WG_DIR, "add-client.sh"), encoding="utf-8") as handle:
            return "# WG-PANEL-PREPARE-PROTOCOL v1" in handle.read(512).splitlines()
    except (OSError, UnicodeError):
        return False


def _is_prepared_client(wg_name):
    """Recognize one inactive persistent envelope before enabling a new peer."""
    try:
        with open(os.path.join(WG_DIR, "wg0.conf"), encoding="utf-8") as handle:
            config = handle.read()
        envelopes = re.findall(
            r"(?m)^# WG-PANEL-PAUSED-BEGIN v1 (\S+)\n"
            r"# WG-PANEL-PAUSED-DATA ([A-Za-z0-9+/]*={0,2})\n"
            r"# WG-PANEL-PAUSED-END v1 \1$", config,
        )
        matches = []
        address = _client_ipv4(wg_name)
        for public_key, encoded in envelopes:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
            if f"# {wg_name}" not in decoded.splitlines():
                continue
            if (
                re.findall(r"(?m)^\[[^\]\r\n]+\]$", decoded) != ["[Peer]"]
                or re.findall(r"(?m)^PublicKey = (.+)$", decoded) != [public_key]
                or re.findall(r"(?m)^AllowedIPs = (.+)$", decoded) != [f"{address}/32"]
                or re.search(
                    rf"(?m)^\s*PublicKey\s*=\s*{re.escape(public_key)}\s*(?:#.*)?$", config,
                )
            ):
                return False
            matches.append(public_key)
        return len(matches) == 1
    except (OSError, ValueError, UnicodeError):
        return False


def _rollback_provision(wg_name, previous_meta):
    """Remove the peer before dropping its inherited safe address or checkpoint."""
    ok, error = _run_script("remove-client.sh", wg_name, 30)
    path = _config_path(wg_name)
    if not ok or (path and os.path.exists(path)):
        return False, error or "Prepared profile cleanup is incomplete"
    try:
        save_device_meta(previous_meta)
        reconcile_safe_dns(allow_unavailable=bool(app.config.get("TESTING")))
    except (OSError, SafeDnsEnforcementError) as exc:
        return False, str(exc)
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
        if user.get("paused"):
            return False, "", "VPN access is paused"
        account_locked = account_safe_internet_locked(username)
        if not account_locked and any(
            item.get("owner") == username and item.get("device") == device
            and item.get("safe_internet_locked") and item.get("revoked")
            for item in load_device_meta().values()
        ):
            return False, "", "A permanently protected device requires manual server recovery via SSH"
        current = get_user_devices(username)
        if device in current:
            existing_name = client_name(username, device)
            if load_device_meta().get(existing_name, {}).get("provisioning"):
                return False, "", "Incomplete profile provisioning requires manual server recovery via SSH"
            return True, existing_name, ""
        limit = user.get("max_devices", 3)
        if limit != -1 and len(current) >= limit:
            return False, "", "Device limit reached"

        wg_name = f"u{len(username)}-{username}-{device}"
        if not SAFE_NAME_RE.fullmatch(wg_name):
            return False, "", "Generated client name is invalid"
        if wg_name in assert_infrastructure_ready(wg_dir=WG_DIR):
            return False, "", "Client name is reserved for infrastructure"
        path = _config_path(wg_name)
        existing = load_device_meta().get(wg_name, {})
        replacing_tombstone = (
            account_locked and existing.get("revoked")
            and existing.get("owner") == username and existing.get("device") == device
        )
        if (existing and not replacing_tombstone) or (path and os.path.exists(path)):
            return False, "", "Client name collision"
        if account_locked and not _supports_prepared_clients():
            return False, "", "Protected provisioning requires the current add-client.sh helper"

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

        previous_meta = load_device_meta()
        arguments = ("--prepare",) if account_locked else ()
        ok, error = _run_script("add-client.sh", wg_name, 45, *arguments)
        if not ok:
            return False, "", error
        if not path or not os.path.exists(path):
            return False, "", "Provisioning completed without a client configuration"
        os.chmod(path, 0o600)
        if account_locked and not _is_prepared_client(wg_name):
            _rollback_provision(wg_name, previous_meta)
            return False, "", "Protected provisioning did not produce a recognized inactive peer"
        try:
            set_device_meta(wg_name, username, device, provisioning=account_locked)
            if account_locked:
                reconcile_safe_dns(allow_unavailable=bool(app.config.get("TESTING")))
                ok, error = _run_script("set-client-state.sh", wg_name, 30, "resume")
                if not ok:
                    raise SafeDnsEnforcementError(error)
                mutate_device_meta(lambda meta: meta[wg_name].pop("provisioning", None))
        except (OSError, ValueError, SafeDnsEnforcementError) as exc:
            _ok, cleanup_error = _rollback_provision(wg_name, previous_meta)
            suffix = f"; cleanup requires recovery: {cleanup_error}" if not _ok else ""
            return False, "", f"Failed to provision device: {exc}{suffix}"
        return True, wg_name, ""


def delete_device(wg_name):
    """Revoke a device and remove metadata only after verified helper success."""
    with _wireguard_lock:
        if wg_name in assert_infrastructure_ready(wg_dir=WG_DIR):
            return False, "Device not found"
        meta = load_device_meta()
        device_meta = meta.get(wg_name, {})
        revoked = bool(device_meta.get("revoked"))
        path = _config_path(wg_name)
        if not path or (not revoked and not get_device(wg_name)):
            return False, "Device not found"
        if revoked and os.path.exists(path):
            return False, "Revoked device has an unexpected client configuration"
        was_safe = effective_safe_internet(device_meta)
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
        infrastructure = assert_infrastructure_ready(wg_dir=WG_DIR)
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
            if wg_name in infrastructure or item.get("owner") != username:
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
