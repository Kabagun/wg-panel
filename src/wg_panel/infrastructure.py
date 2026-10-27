"""Root-managed WireGuard infrastructure peers, independent of web accounts.

An infrastructure claim permanently protects its address and keeps its client
secret outside the personal client directory. There is deliberately no general
setter or account-owner field. Adoption requires the panel service to be stopped
by its controller, then holds the same file lock as the installed WG helpers.
"""

import base64
import configparser
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
from contextlib import contextmanager

from . import core
from .account_policy import effective_safe_internet
from .dns_enforcement import SafeDnsEnforcementError, normalize_safe_client_ips

try:
    import fcntl
except ImportError:  # pragma: no cover - operator adoption is Linux-only.
    fcntl = None

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9 _-]{0,63}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
RECORD_FIELDS = {"kind", "label", "public_key", "ipv4", "config_sha256"}


class InfrastructureStateError(SafeDnsEnforcementError):
    """Infrastructure state cannot safely be interpreted or changed."""


def infrastructure_dir(*, wg_dir=None):
    return os.path.join(wg_dir or core.WG_DIR, "infrastructure")


def infrastructure_registry_path(*, data_dir=None):
    return os.path.join(data_dir or core.DATA_DIR, "infrastructure_peers.json")


def _checkpoint_path(data_dir=None):
    return os.path.join(data_dir or core.DATA_DIR, "infrastructure_adoption.json")


def _private_directory(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InfrastructureStateError("Cannot inspect infrastructure directory") from exc
    if not stat.S_ISDIR(info.st_mode) or (
        os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.geteuid())
    ):
        raise InfrastructureStateError("Infrastructure directory must be private and owned")
    return True


def _read_private(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or os.path.islink(path) or (
                os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.geteuid())
            ):
                raise InfrastructureStateError("Infrastructure file must be private and owned")
            return handle.read()
    except InfrastructureStateError:
        raise
    except OSError as exc:
        raise InfrastructureStateError("Cannot read infrastructure state") from exc


def _read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    try:
        return json.loads(_read_private(path), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise InfrastructureStateError("Invalid infrastructure JSON") from exc


def _key(value):
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise InfrastructureStateError("Invalid WireGuard identity") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise InfrastructureStateError("Invalid WireGuard identity")
    return value


def public_key_fingerprint(public_key):
    """Return SHA256:<unpadded base64 digest> without exposing a private key."""
    decoded = base64.b64decode(_key(public_key))
    digest = base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _public_key(private_key):
    try:
        result = subprocess.run(
            ["wg", "pubkey"], input=_key(private_key) + "\n", capture_output=True,
            text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InfrastructureStateError("Cannot verify infrastructure identity") from exc
    if result.returncode:
        raise InfrastructureStateError("Cannot verify infrastructure identity")
    return _key(result.stdout.strip())


def _config_identity(content):
    try:
        parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
        parser.read_string(content.decode("utf-8"))
        if parser.sections() != ["Interface", "Peer"] or parser.defaults():
            raise ValueError("Invalid client sections")
        address = parser["Interface"]["Address"]
        if not address.endswith("/32"):
            raise ValueError("Invalid client prefix")
        ipv4 = address[:-3]
        if normalize_safe_client_ips([ipv4]) != (ipv4,):
            raise ValueError("Invalid client address")
        _key(parser["Peer"]["PublicKey"])
        _key(parser["Peer"]["PresharedKey"])
        return _public_key(parser["Interface"]["PrivateKey"]), ipv4
    except (configparser.Error, KeyError, ValueError, UnicodeError, SafeDnsEnforcementError) as exc:
        raise InfrastructureStateError("Invalid infrastructure client configuration") from exc


def _record(record):
    if (
        not isinstance(record, dict) or set(record) != RECORD_FIELDS
        or record.get("kind") != "router"
        or not isinstance(record.get("label"), str) or not LABEL_RE.fullmatch(record["label"])
        or not isinstance(record.get("config_sha256"), str)
        or not HASH_RE.fullmatch(record["config_sha256"])
        or not isinstance(record.get("ipv4"), str)
    ):
        raise InfrastructureStateError("Invalid infrastructure peer record")
    _key(record["public_key"])
    try:
        if normalize_safe_client_ips([record["ipv4"]]) != (record["ipv4"],):
            raise InfrastructureStateError("Invalid infrastructure peer address")
    except SafeDnsEnforcementError as exc:
        raise InfrastructureStateError("Invalid infrastructure peer address") from exc
    return record


def _registry(*, data_dir=None):
    path = infrastructure_registry_path(data_dir=data_dir)
    _private_directory(os.path.dirname(path))
    if not os.path.lexists(path):
        return {}
    state = _read_json(path)
    if (
        not isinstance(state, dict) or set(state) != {"version", "peers"}
        or type(state["version"]) is not int or state["version"] != 1
        or not isinstance(state["peers"], dict)
    ):
        raise InfrastructureStateError("Invalid infrastructure registry")
    addresses = set()
    keys = set()
    for name, record in state["peers"].items():
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise InfrastructureStateError("Invalid infrastructure peer name")
        _record(record)
        if record["ipv4"] in addresses or record["public_key"] in keys:
            raise InfrastructureStateError("Duplicate infrastructure identity or address")
        addresses.add(record["ipv4"])
        keys.add(record["public_key"])
    return state["peers"]


def load_infrastructure_peers(*, wg_dir=None, data_dir=None):
    """Read a strict name -> record map; missing, empty installations are valid.

    A registered claim remains readable during operator adoption so the injected
    full-set enforcer can run. Startup/controllers must additionally call
    ``assert_infrastructure_ready`` before serving or ordinary lifecycle work.
    """
    with core._wireguard_lock:
        peers = _registry(data_dir=data_dir)
        directory = infrastructure_dir(wg_dir=wg_dir)
        exists = _private_directory(directory)
        try:
            filenames = set(os.listdir(directory)) if exists else set()
        except OSError as exc:
            raise InfrastructureStateError("Cannot list infrastructure configurations") from exc
        if filenames != {f"{name}.conf" for name in peers}:
            raise InfrastructureStateError("Infrastructure registry/configuration mismatch")
        for name, record in peers.items():
            content = _read_private(os.path.join(directory, f"{name}.conf"))
            if hashlib.sha256(content).hexdigest() != record["config_sha256"]:
                raise InfrastructureStateError("Infrastructure configuration changed")
            public_key, ipv4 = _config_identity(content)
            if public_key != record["public_key"] or ipv4 != record["ipv4"]:
                raise InfrastructureStateError("Infrastructure identity/address mismatch")
        return peers


def infrastructure_names(*, wg_dir=None, data_dir=None):
    return frozenset(load_infrastructure_peers(wg_dir=wg_dir, data_dir=data_dir))


def infrastructure_safe_ips(*, wg_dir=None, data_dir=None):
    peers = load_infrastructure_peers(wg_dir=wg_dir, data_dir=data_dir)
    return normalize_safe_client_ips(record["ipv4"] for record in peers.values())


def get_infrastructure_peer(name, *, wg_dir=None, data_dir=None):
    return load_infrastructure_peers(wg_dir=wg_dir, data_dir=data_dir).get(name)


def assert_infrastructure_ready(*, wg_dir=None, data_dir=None):
    """Block startup/lifecycle use until an interrupted operator move is resumed."""
    if os.path.lexists(_checkpoint_path(data_dir)):
        raise InfrastructureStateError("Infrastructure adoption requires operator recovery")
    return load_infrastructure_peers(wg_dir=wg_dir, data_dir=data_dir)


def _fsync_directory(directory):
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _write_json(path, value):
    core.write_json_private(path, value)
    _fsync_directory(os.path.dirname(path))


def _copy_config(path, content):
    directory = os.path.dirname(path)
    _private_directory(directory)
    core.ensure_private_dir(directory)
    temporary = os.path.join(directory, f".adoption-{secrets.token_hex(8)}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(directory)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _file_hash(path):
    return hashlib.sha256(_read_private(path)).hexdigest() if os.path.lexists(path) else None


def _require_root():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise InfrastructureStateError("Infrastructure adoption requires root on Linux")


@contextmanager
def _maintenance_lock(wg_dir):
    if fcntl is None:
        raise InfrastructureStateError("Infrastructure adoption requires Linux file locking")
    if not _private_directory(wg_dir):
        raise InfrastructureStateError("WireGuard directory is missing")
    path = os.path.join(wg_dir, ".wg-panel.lock")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _personal_metadata(path):
    records = _read_json(path)
    if not isinstance(records, dict) or any(not isinstance(item, dict) for item in records.values()):
        raise InfrastructureStateError("Invalid personal device metadata")
    return records


def _enforced_ips(enforce):
    result = enforce()
    try:
        return normalize_safe_client_ips(result["ips"] if isinstance(result, dict) else result)
    except (TypeError, KeyError) as exc:
        raise InfrastructureStateError("Enforcer must return the complete selected address set") from exc


def _verify_persistent_peer(wg_dir, public_key, ipv4):
    content = _read_private(os.path.join(wg_dir, "wg0.conf")).decode("utf-8")
    matches = []
    for block in re.split(r"(?m)^\s*\[Peer\]\s*(?:#.*)?$", content)[1:]:
        block = re.split(r"(?m)^\s*\[[^\]]+\]", block, maxsplit=1)[0]
        keys = re.findall(r"(?m)^\s*PublicKey\s*=\s*([^#\r\n]+?)\s*(?:#.*)?$", block)
        if public_key in keys:
            addresses = re.findall(
                r"(?m)^\s*AllowedIPs\s*=\s*([^#\r\n]+?)\s*(?:#.*)?$", block,
            )
            matches.append(keys == [public_key] and addresses == [f"{ipv4}/32"])
    if matches != [True] or f"# WG-PANEL-PAUSED-BEGIN v1 {public_key}" in content:
        raise InfrastructureStateError("Expected one active persistent infrastructure peer")


def _checkpoint(value, name, fingerprint):
    fields = {"version", "name", "record", "source_meta", "safe_ips", "policy_hash", "traffic_hash"}
    if (
        not isinstance(value, dict) or set(value) != fields
        or type(value["version"]) is not int or value["version"] != 1
        or value["name"] != name or not isinstance(value["source_meta"], dict)
        or not isinstance(value["safe_ips"], list)
        or any(value[key] is not None and not HASH_RE.fullmatch(str(value[key]))
               for key in ("policy_hash", "traffic_hash"))
    ):
        raise InfrastructureStateError("Invalid infrastructure adoption checkpoint")
    _record(value["record"])
    if (
        public_key_fingerprint(value["record"]["public_key"]) != fingerprint
        or list(normalize_safe_client_ips(value["safe_ips"])) != value["safe_ips"]
        or value["record"]["ipv4"] not in value["safe_ips"]
    ):
        raise InfrastructureStateError("Infrastructure adoption checkpoint identity mismatch")
    return value


def adopt_infrastructure_peer(
    name, *, expected_public_key_fingerprint, label="home-router", maintenance=False,
    enforce=None, wg_dir=None, data_dir=None, clients_dir=None,
):
    """Adopt or resume one unchanged personal config without touching WireGuard.

    The controller MUST stop the panel service/collector first and set
    ``maintenance=True``. ``enforce()`` must apply and return the complete current
    safe address set (``wireguard.reconcile_safe_dns`` satisfies this contract).
    A durable checkpoint is retained on every incomplete move; retry with the
    same identity. Accounts, owner locks, kernel peers and traffic are not edited.
    """
    _require_root()
    if maintenance is not True or not callable(enforce):
        raise InfrastructureStateError("Stop the panel service and provide the full-set enforcer")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise InfrastructureStateError("Invalid infrastructure peer name")
    if not isinstance(label, str) or not LABEL_RE.fullmatch(label):
        raise InfrastructureStateError("Invalid infrastructure peer label")
    if not isinstance(expected_public_key_fingerprint, str):
        raise InfrastructureStateError("Expected public-key fingerprint is required")
    wg_dir = wg_dir or core.WG_DIR
    data_dir = data_dir or core.DATA_DIR
    clients_dir = clients_dir or core.CLIENTS_DIR
    metadata_path = os.path.join(data_dir, "device_meta.json")
    traffic_path = os.path.join(data_dir, "traffic.json")
    policy_path = os.path.join(data_dir, "account_policy.json")
    source = os.path.join(clients_dir, f"{name}.conf")
    target = os.path.join(infrastructure_dir(wg_dir=wg_dir), f"{name}.conf")
    checkpoint_path = _checkpoint_path(data_dir)

    with core._wireguard_lock, _maintenance_lock(wg_dir):
        if not _private_directory(clients_dir):
            raise InfrastructureStateError("Personal client directory is missing")
        if os.path.lexists(checkpoint_path):
            pending = _checkpoint(_read_json(checkpoint_path), name, expected_public_key_fingerprint)
            if pending["record"]["label"] != label:
                raise InfrastructureStateError("Adoption label does not match the checkpoint")
        else:
            peers = load_infrastructure_peers(wg_dir=wg_dir, data_dir=data_dir)
            if name in peers:
                if (
                    not hmac.compare_digest(
                        public_key_fingerprint(peers[name]["public_key"]),
                        expected_public_key_fingerprint,
                    ) or os.path.lexists(source) or name in _personal_metadata(metadata_path)
                ):
                    raise InfrastructureStateError("Infrastructure identity has conflicting personal state")
                if peers[name]["ipv4"] not in _enforced_ips(enforce):
                    raise InfrastructureStateError("Infrastructure address is not enforced")
                return {"name": name, "already_adopted": True}
            content = _read_private(source)
            public_key, ipv4 = _config_identity(content)
            if not hmac.compare_digest(
                public_key_fingerprint(public_key), expected_public_key_fingerprint,
            ):
                raise InfrastructureStateError("Infrastructure public-key fingerprint mismatch")
            metadata = _personal_metadata(metadata_path).get(name)
            if (
                not metadata or not metadata.get("owner") or not metadata.get("device")
                or metadata.get("revoked") or metadata.get("provisioning")
                or metadata.get("vpn_type", "wireguard") != "wireguard"
            ):
                raise InfrastructureStateError("Expected one active personally owned source profile")
            # Use this adoption's data directory, not a process-global account
            # directory: explicit paths must never read another installation.
            policies = {}
            if os.path.lexists(policy_path):
                state = _read_json(policy_path)
                if (
                    not isinstance(state, dict) or set(state) != {"version", "owners"}
                    or type(state["version"]) is not int or state["version"] != 1
                    or not isinstance(state["owners"], dict)
                    or any(not isinstance(owner, str) or not NAME_RE.fullmatch(owner)
                           or record != {"safe_internet_locked": True}
                           for owner, record in state["owners"].items())
                ):
                    raise InfrastructureStateError("Invalid permanent account policy")
                policies = state["owners"]
            if not effective_safe_internet(metadata, policies):
                raise InfrastructureStateError("Source profile must already have enforced safe internet")
            if ipv4 in {record["ipv4"] for record in peers.values()}:
                raise InfrastructureStateError("Infrastructure address is already claimed")
            _verify_persistent_peer(wg_dir, public_key, ipv4)
            safe_ips = _enforced_ips(enforce)
            if ipv4 not in safe_ips:
                raise InfrastructureStateError("Source profile address is not enforced")
            pending = {
                "version": 1, "name": name,
                "record": {"kind": "router", "label": label, "public_key": public_key,
                           "ipv4": ipv4, "config_sha256": hashlib.sha256(content).hexdigest()},
                "source_meta": metadata, "safe_ips": list(safe_ips),
                "policy_hash": _file_hash(policy_path), "traffic_hash": _file_hash(traffic_path),
            }
            _write_json(checkpoint_path, pending)

        record = pending["record"]
        if (
            _file_hash(policy_path) != pending["policy_hash"]
            or _file_hash(traffic_path) != pending["traffic_hash"]
        ):
            raise InfrastructureStateError("Protected account policy or traffic state changed during adoption")
        _verify_persistent_peer(wg_dir, record["public_key"], record["ipv4"])
        if not os.path.lexists(target):
            content = _read_private(source)
            if hashlib.sha256(content).hexdigest() != record["config_sha256"]:
                raise InfrastructureStateError("Source configuration changed during adoption")
            _copy_config(target, content)
        if _file_hash(target) != record["config_sha256"]:
            raise InfrastructureStateError("Adopted configuration does not match its checkpoint")
        peers = _registry(data_dir=data_dir)
        if name in peers and peers[name] != record:
            raise InfrastructureStateError("Infrastructure claim changed during adoption")
        if name not in peers:
            if any(item["ipv4"] == record["ipv4"] or item["public_key"] == record["public_key"]
                   for item in peers.values()):
                raise InfrastructureStateError("Infrastructure identity/address is already claimed")
            peers[name] = record
            _write_json(infrastructure_registry_path(data_dir=data_dir), {"version": 1, "peers": peers})
        # The permanent infrastructure claim is durable before removing any
        # personal authority or source config. Enforcement remains selected.
        metadata = _personal_metadata(metadata_path)
        if name in metadata:
            if metadata[name] != pending["source_meta"]:
                raise InfrastructureStateError("Personal source metadata changed during adoption")
            metadata.pop(name)
            _write_json(metadata_path, metadata)
        if os.path.lexists(source):
            if _file_hash(source) != record["config_sha256"]:
                raise InfrastructureStateError("Personal source configuration changed during adoption")
            os.unlink(source)
            _fsync_directory(clients_dir)
        load_infrastructure_peers(wg_dir=wg_dir, data_dir=data_dir)
        if _enforced_ips(enforce) != tuple(pending["safe_ips"]):
            raise InfrastructureStateError("Selected safe address set changed during adoption")
        if (
            _file_hash(policy_path) != pending["policy_hash"]
            or _file_hash(traffic_path) != pending["traffic_hash"]
        ):
            raise InfrastructureStateError("Protected account policy or traffic state changed during adoption")
        os.unlink(checkpoint_path)
        _fsync_directory(data_dir)
        return {"name": name, "already_adopted": False}
