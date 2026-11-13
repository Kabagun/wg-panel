"""Bound internal WireGuard transports for one logical Happ device.

Only explicit provisioning mutates peers. Export, ownership and accounting
resolve committed bindings without allocating, repairing or adopting profiles.
"""

import base64
import hashlib
import json
import os
import stat

from . import core, traffic, wireguard
from .connection_config import _public_key
from .dns_enforcement import SafeDnsEnforcementError
from .happ_config import _parse_wireguard

CHILD_MODES = ("custom", "by-ru-direct")
_GROUP_FIELDS = {"version", "binding", "peers"}
_ERROR = "Happ transport state is unavailable"


def is_internal(record):
    return bool(isinstance(record, dict) and (
        record.get("happ_transport_internal") or "happ_parent" in record or "happ_mode" in record
    ))


def _raw(name):
    path = wireguard._config_path(name)
    if not path:
        raise ValueError(_ERROR)
    try:
        initial = os.lstat(path)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_size > 65536
                or getattr(initial, "st_file_attributes", 0) & reparse):
            raise ValueError(_ERROR)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as handle:
            if not os.path.samestat(initial, os.fstat(handle.fileno())):
                raise ValueError(_ERROR)
            content = handle.read(65537)
        if len(content) > 65536:
            raise ValueError(_ERROR)
        return content
    except (OSError, ValueError):
        raise ValueError(_ERROR) from None


def _identity(name):
    content = _raw(name)
    try:
        parsed = _parse_wireguard(content.decode("utf-8"))
        if len(parsed.addresses) != 1 or not parsed.addresses[0].endswith("/32"):
            raise ValueError(_ERROR)
        public = _public_key(parsed.secret_key)
        if not public or len(base64.b64decode(public, validate=True)) != 32:
            raise ValueError(_ERROR)
        return {"sha256": hashlib.sha256(content).hexdigest(), "public_key": public,
                "address": parsed.addresses[0], "server_key": parsed.peer["publicKey"],
                "endpoint": parsed.peer["endpoint"],
                "psk": parsed.peer.get("preSharedKey"), "secret": parsed.secret_key}
    except (ValueError, UnicodeError):
        raise ValueError(_ERROR) from None


def _parent(name, *, active=False, allow_protected=False):
    meta = traffic.load_device_meta()
    parent = meta.get(name)
    user = core.load_users().get(parent.get("owner"), {}) if isinstance(parent, dict) else {}
    if (
        not isinstance(parent, dict) or parent.get("happ_pilot") is not True or is_internal(parent)
        or parent.get("revoked") or parent.get("provisioning")
        or parent.get("vpn_type", "wireguard") != "wireguard"
        or not parent.get("owner") or not parent.get("device") or not user.get("account_id")
        or (parent.get("deletion_protected") and not allow_protected)
        or name in wireguard.assert_infrastructure_ready(wg_dir=wireguard.WG_DIR)
    ):
        raise ValueError(_ERROR)
    if active:
        from .happ_pilot import available_for_user
        if not available_for_user(user) or parent.get("happ_transport_deleting"):
            raise ValueError(_ERROR)
    identity = _identity(name)
    binding = hashlib.sha256(json.dumps(
        [name, parent["owner"], user["account_id"], identity["sha256"]],
        separators=(",", ":"),
    ).encode()).hexdigest()
    return meta, parent, user, identity, binding


def _names(parent, binding):
    prefix = hashlib.sha256((parent + "\0" + binding).encode()).hexdigest()[:24]
    return {mode: f"happ-{prefix}-{mode}" for mode in CHILD_MODES}


def _group(parent, binding):
    value = parent.get("happ_transports")
    if (
        not isinstance(value, dict) or set(value) != _GROUP_FIELDS
        or type(value["version"]) is not int or value["version"] != 1
        or value["binding"] != binding or not isinstance(value["peers"], dict)
        or set(value["peers"]) != set(CHILD_MODES)
    ):
        raise ValueError(_ERROR)
    return value["peers"]


def _child_record(record, parent_name, owner, mode, binding):
    return bool(isinstance(record, dict) and record.get("happ_transport_internal") is True
                and record.get("happ_pilot") is True and record.get("owner") == owner
                and record.get("happ_parent") == parent_name and record.get("happ_mode") == mode
                and record.get("happ_parent_fingerprint") == binding
                and record.get("vpn_type", "wireguard") == "wireguard"
                and not record.get("deletion_protected"))


def _unique_files(meta):
    """Verify every personal reservation and reject copied keys/addresses."""
    public, addresses = {}, {}
    identities = {}
    for entry in os.scandir(wireguard.CLIENTS_DIR):
        if not entry.name.endswith(".conf"):
            continue
        name = entry.name[:-5]
        record = meta.get(name)
        if not isinstance(record, dict) or not record.get("owner") or record.get("revoked"):
            raise ValueError(_ERROR)
        identity = _identity(name)
        if identity["public_key"] in public or identity["address"] in addresses:
            raise ValueError(_ERROR)
        public[identity["public_key"]] = name
        addresses[identity["address"]] = name
        identities[name] = identity
    infrastructure = wireguard.load_infrastructure_peers(wg_dir=wireguard.WG_DIR)
    if any(record["public_key"] in public or record["ipv4"] + "/32" in addresses
           for record in infrastructure.values()):
        raise ValueError(_ERROR)
    return identities


def _linked(parent_name, *, allow_deleted=False, allow_provisioning=False):
    meta, parent, _user, identity, binding = _parent(parent_name, allow_protected=True)
    claimed = {name for name, item in meta.items() if item.get("happ_parent") == parent_name}
    if "happ_transports" not in parent:
        if claimed:
            raise ValueError(_ERROR)
        return {}, identity
    names = _group(parent, binding)
    if names != _names(parent_name, binding):
        raise ValueError(_ERROR)
    deleted = parent.get("happ_deleted_transports", [])
    if (not isinstance(deleted, list) or len(set(deleted)) != len(deleted)
            or not set(deleted) <= set(names.values())
            or (deleted and not parent.get("happ_transport_deleting"))
            or (deleted and not allow_deleted)):
        raise ValueError(_ERROR)
    if claimed != set(names.values()) - set(deleted):
        raise ValueError(_ERROR)
    identities = _unique_files(meta)
    members = [identity]
    for mode, name in names.items():
        if name in deleted:
            if name in meta or os.path.lexists(wireguard._config_path(name)):
                raise ValueError(_ERROR)
            continue
        record = meta.get(name)
        if not _child_record(record, parent_name, parent["owner"], mode, binding):
            raise ValueError(_ERROR)
        if record.get("revoked"):
            if not allow_deleted or os.path.lexists(wireguard._config_path(name)):
                raise ValueError(_ERROR)
            continue
        if record.get("provisioning") and not allow_provisioning:
            raise ValueError(_ERROR)
        child = identities.get(name)
        if (
            not child or child["sha256"] != record.get("happ_config_sha256")
            or (child["server_key"], child["endpoint"]) != (identity["server_key"], identity["endpoint"])
        ):
            raise ValueError(_ERROR)
        members.append(child)
    if len({member["psk"] for member in members}) != len(members):
        raise ValueError(_ERROR)
    return {mode: name for mode, name in names.items() if name not in deleted}, identity


def children_for_parent(parent_name):
    """Return committed child names for accounting/cleanup, rejecting partial groups."""
    with core._wireguard_lock:
        names, _identity_value = _linked(parent_name)
        parent = traffic.load_device_meta()[parent_name]
        if parent.get("happ_transport_provisioning") or parent.get("happ_transport_deleting"):
            raise ValueError(_ERROR)
        return list(names.values())


def mode_mapping(parent_name):
    """Read-only export mapping. Legacy single all-mode exports need no children."""
    with core._wireguard_lock:
        _meta, _parent_record, _user, _identity_value, _binding = _parent(parent_name, active=True)
        device = wireguard.get_device(parent_name)
        if not device:
            raise ValueError(_ERROR)
        if device["safe_internet"]:
            return {"all": parent_name}
        children = children_for_parent(parent_name)
        names = traffic.load_device_meta()[parent_name].get("happ_transports", {}).get("peers", {})
        if len(children) != len(CHILD_MODES) or set(names) != set(CHILD_MODES):
            raise ValueError(_ERROR)
        return {"all": parent_name, **names}


def validate_internal(name):
    """Bind an internal maintenance target to its exact parent and config."""
    with core._wireguard_lock:
        record = traffic.load_device_meta().get(name, {})
        parent_name = record.get("happ_parent")
        if not is_internal(record) or not isinstance(parent_name, str):
            raise ValueError(_ERROR)
        names, _identity_value = _linked(parent_name, allow_deleted=True)
        if name not in names.values():
            raise ValueError(_ERROR)
        return parent_name


def _rollback(parent_name, fresh):
    # A later activation may fail after an earlier child was resumed. Pause
    # every fresh peer first so a failed removal cannot leave it usable.
    for name in fresh:
        wireguard._run_script("set-client-state.sh", name, 30, "pause")
    complete = True
    for name in reversed(fresh):
        # Every name was absent before this transaction. Never touch an adopted
        # or colliding config, even when another group member failed.
        ok, _error = wireguard._run_script("remove-client.sh", name, 30)
        if not ok or os.path.lexists(wireguard._config_path(name)):
            complete = False
        else:
            traffic.mutate_device_meta(lambda records, key=name: records.pop(key, None))
    if complete:
        def restore(records):
            parent = records[parent_name]
            parent.pop("happ_transports", None)
            parent.pop("happ_transport_provisioning", None)
        traffic.mutate_device_meta(restore)
        wireguard.reconcile_safe_dns(allow_unavailable=bool(core.app.config.get("TESTING")))
    return complete


def ensure_mode_peers(parent_name):
    """Explicitly allocate two fresh inactive peers, enforce DNS, then activate."""
    with core._wireguard_lock:
        meta, parent, _user, parent_identity, binding = _parent(parent_name, active=True)
        if wireguard.get_device(parent_name)["safe_internet"]:
            return {"all": parent_name}
        if "happ_transports" in parent:
            return mode_mapping(parent_name)
        if any(record.get("happ_parent") == parent_name for record in meta.values()):
            raise ValueError(_ERROR)
        names = _names(parent_name, binding)
        infrastructure = wireguard.assert_infrastructure_ready(wg_dir=wireguard.WG_DIR)
        if any(name in meta or name in infrastructure or os.path.lexists(wireguard._config_path(name))
               for name in names.values()) or not wireguard._supports_prepared_clients():
            raise ValueError(_ERROR)
        _unique_files(meta)
        wireguard.reconcile_safe_dns(require_helper=True,
                                     allow_unavailable=bool(core.app.config.get("TESTING")))
        traffic.mutate_device_meta(lambda records: records[parent_name].update(
            happ_transports={"version": 1, "binding": binding, "peers": names},
            happ_transport_provisioning=True,
        ))
        fresh = []
        try:
            for mode, name in names.items():
                fresh.append(name)
                ok, _error = wireguard._run_script("add-client.sh", name, 45, "--prepare")
                if not ok or not wireguard._is_prepared_client(name):
                    raise ValueError(_ERROR)
                identity = _identity(name)
                if (identity["public_key"] == parent_identity["public_key"]
                        or identity["address"] == parent_identity["address"]):
                    raise ValueError(_ERROR)
                record = {"owner": parent["owner"], "device": name, "vpn_type": "wireguard",
                          "safe_internet": False, "happ_pilot": True, "happ_transport_internal": True,
                          "happ_parent": parent_name, "happ_mode": mode,
                          "happ_parent_fingerprint": binding, "happ_config_sha256": identity["sha256"],
                          "provisioning": True}
                traffic.mutate_device_meta(lambda records, key=name, value=record: records.update({key: value}))
            _linked(parent_name, allow_provisioning=True)
            wireguard.reconcile_safe_dns(require_helper=True,
                                         allow_unavailable=bool(core.app.config.get("TESTING")))
            for name in names.values():
                ok, _error = wireguard._run_script("set-client-state.sh", name, 30, "resume")
                if not ok:
                    raise ValueError(_ERROR)
            def commit(records):
                records[parent_name].pop("happ_transport_provisioning", None)
                for name in names.values():
                    records[name].pop("provisioning", None)
            traffic.mutate_device_meta(commit)
            return mode_mapping(parent_name)
        except (OSError, ValueError, SafeDnsEnforcementError):
            # All fresh peers are removed before dropping DNS reservations.
            try:
                _rollback(parent_name, fresh)
            except (OSError, ValueError, SafeDnsEnforcementError):
                pass  # Retained provisioning checkpoints require recovery, never export.
            raise ValueError(_ERROR) from None


def delete_mode_peers(parent_name):
    """Revoke bound children first, retaining retry progress until parent removal."""
    with core._wireguard_lock:
        names, _identity_value = _linked(parent_name, allow_deleted=True)
        if not names:
            return True, ""
        traffic.mutate_device_meta(lambda records: records[parent_name].update(happ_transport_deleting=True))
        ok, _error = wireguard._run_script("set-client-state.sh", parent_name, 30, "pause")
        if not ok:
            return False, _ERROR
        for name in names.values():
            ok, _error = wireguard._delete_single_device(name)
            if not ok:
                for remaining in names.values():
                    if remaining in traffic.load_device_meta():
                        wireguard._run_script("set-client-state.sh", remaining, 30, "pause")
                return False, _ERROR
            traffic.mutate_device_meta(lambda records, key=name: records[parent_name].setdefault(
                "happ_deleted_transports", []).append(key))
        return True, ""
