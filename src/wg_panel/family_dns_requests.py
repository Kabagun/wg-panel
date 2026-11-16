"""Private administrator-reviewed proposals for independent DNS and Smart lists.

The store lock covers local transactions only. A persisted five-minute claim covers
each helper call; adapters confirm application before a request becomes approved.
"""

import copy
import json
import os
import re
import secrets
import threading
import unicodedata
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import core, family_dns, happ_shared_rules

MAX_PENDING_PER_ACCOUNT = 10
MAX_RECORDS = 2000
MAX_STORE_BYTES = 8 * 1024 * 1024
LEASE_SECONDS = 300
_FILENAME = "family_dns_requests.json"
_SMART_FILENAME = "smart_vpn_requests.json"
_LOCK = threading.RLock()
_ID = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)
_ACCOUNT = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_USERNAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                    r"(?:\.[0-9]{1,6})?Z\Z", re.ASCII)
_ACTIVE = {"pending", "applying"}
_TERMINAL = {"approved", "rejected"}
_FIELDS = {"id", "username", "account_id", "domain", "reason", "status", "created_at",
           "reviewed_at", "reviewer", "claim", "lease_until"}
_CODES = {"invalid_domain", "invalid_reason", "invalid_request", "capacity", "unavailable",
          "not_found", "ineligible", "conflict", "busy"}


class RequestError(RuntimeError):
    """A stable interface error without request, account or helper details."""

    def __init__(self, code="unavailable"):
        self.code = code if isinstance(code, str) and code in _CODES else "unavailable"
        super().__init__(self.code)


def _kind(kind):
    if not isinstance(kind, str) or kind not in {"dns", "smart"}:
        raise RequestError("invalid_request")
    return kind


def _require_active_kind(kind):
    from .account_policy import family_protection_enabled
    _kind(kind)
    if kind == "dns" and not family_protection_enabled():
        raise RequestError("ineligible")


def _normalize_domain(value, kind):
    _kind(kind)
    if kind == "smart":
        return happ_shared_rules.normalize_domain(value)
    return family_dns.normalize_domain(value)


def _smart_error(error):
    code = str(error) if isinstance(error, ValueError) else "unavailable"
    return RequestError({"invalid_domain": "invalid_domain", "stale_revision": "busy"}.get(
        code, "unavailable"))


def _now():
    return datetime.now(UTC)


def _stamp(at):
    return at.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _date(value):
    if not isinstance(value, str) or not _STAMP.fullmatch(value):
        raise ValueError
    return datetime.fromisoformat(value)


def _matches(pattern, value):
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def _safe_text(value, maximum, *, nonempty=False):
    return (isinstance(value, str) and len(value) <= maximum
            and (not nonempty or bool(value.strip()))
            and not any(unicodedata.category(char).startswith("C") for char in value))


def _reason(value):
    if not isinstance(value, str) or len(value) > 500:
        return None
    single_line = value.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if not _safe_text(single_line, 500):
        return None
    return " ".join(single_line.split())


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _validate(store, *, kind="dns"):
    if (not isinstance(store, dict) or set(store) != {"version", "requests"}
            or type(store["version"]) is not int or store["version"] != 1
            or not isinstance(store["requests"], list) or len(store["requests"]) > MAX_RECORDS):
        raise ValueError
    ids, active = set(), set()
    counts = {}
    for record in store["requests"]:
        if (not isinstance(record, dict) or set(record) != _FIELDS
                or not _matches(_ID, record["id"]) or record["id"] in ids
                or not _matches(_USERNAME, record["username"])
                or not _matches(_ACCOUNT, record["account_id"])
                or _normalize_domain(record["domain"], kind) != record["domain"]
                or not _safe_text(record["reason"], 500)
                or _reason(record["reason"]) != record["reason"]
                or not isinstance(record["status"], str)
                or record["status"] not in _ACTIVE | _TERMINAL):
            raise ValueError
        created = _date(record["created_at"])
        ids.add(record["id"])
        if record["status"] in _ACTIVE:
            key = (record["account_id"], record["domain"])
            counts[record["account_id"]] = counts.get(record["account_id"], 0) + 1
            if (key in active or counts[record["account_id"]] > MAX_PENDING_PER_ACCOUNT
                    or record["reviewed_at"] is not None or record["reviewer"] is not None):
                raise ValueError
            active.add(key)
        elif (_date(record["reviewed_at"]) < created
              or not _safe_text(record["reviewer"], 128, nonempty=True)):
            raise ValueError
        if record["status"] == "applying":
            if (not _matches(_ID, record["claim"]) or _date(record["lease_until"]) < created):
                raise ValueError
        elif record["claim"] is not None or record["lease_until"] is not None:
            raise ValueError
    return store


def _read(path, *, kind="dns"):
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_STORE_BYTES + 1)
    except FileNotFoundError:
        return {"version": 1, "requests": []}
    if len(raw) > MAX_STORE_BYTES:
        raise RequestError()
    try:
        return _validate(json.loads(raw, object_pairs_hook=_unique_object), kind=kind)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            family_dns.FamilyDnsError):
        raise RequestError() from None


def _write(path, store, *, kind="dns"):
    try:
        _validate(store, kind=kind)
        if len(json.dumps(store, ensure_ascii=False, indent=2).encode("utf-8")) > MAX_STORE_BYTES:
            raise ValueError
        core.write_json_private(str(path), store)
    except (ValueError, TypeError, UnicodeError, family_dns.FamilyDnsError):
        raise RequestError() from None


@contextmanager
def _locked(*, kind="dns"):
    _kind(kind)
    with _LOCK:
        descriptor = None
        locked = False
        try:
            core.ensure_private_dir(core.DATA_DIR)
            path = Path(core.DATA_DIR) / (_SMART_FILENAME if kind == "smart" else _FILENAME)
            lock_path = str(path) + ".lock"
            descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            os.chmod(lock_path, 0o600)
            if core.fcntl is not None:
                core.fcntl.flock(descriptor, core.fcntl.LOCK_EX)
                locked = True
            yield path
        except OSError:
            raise RequestError() from None
        finally:
            if descriptor is not None:
                try:
                    try:
                        if locked:
                            core.fcntl.flock(descriptor, core.fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)
                except OSError:
                    raise RequestError() from None


def _eligible(username, account_id):
    try:
        users = core.load_users()
        user = users.get(username) if isinstance(users, dict) else None
        if (not isinstance(user, dict) or user.get("account_id") != account_id
                or user.get("approved") is not True
                or any(user.get(flag) for flag in ("paused", "pause_pending", "revoking"))):
            raise RequestError("ineligible")
    except RequestError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        raise RequestError() from None


def submit(username, account_id, domain, reason="", *, kind="dns"):
    """Queue an eligible account's proposal without reading or changing either list."""
    _require_active_kind(kind)
    if not _matches(_USERNAME, username) or not _matches(_ACCOUNT, account_id):
        raise RequestError("ineligible")
    try:
        normalized = _normalize_domain(domain, kind)
    except family_dns.FamilyDnsError:
        raise RequestError("invalid_domain") from None
    except (ValueError, OSError) as error:
        raise _smart_error(error) from None
    reason = _reason(reason)
    if reason is None:
        raise RequestError("invalid_reason")
    with _locked(kind=kind) as path:
        store = _read(path, kind=kind)
        _eligible(username, account_id)
        pending = [record for record in store["requests"]
                   if record["account_id"] == account_id and record["status"] in _ACTIVE]
        for record in pending:
            if record["domain"] == normalized:
                return copy.deepcopy(record), False
        if len(pending) >= MAX_PENDING_PER_ACCOUNT:
            raise RequestError("capacity")
        while len(store["requests"]) >= MAX_RECORDS:
            finished = [record for record in store["requests"] if record["status"] in _TERMINAL]
            if not finished:
                raise RequestError("capacity")
            store["requests"].remove(min(finished, key=lambda record: record["created_at"]))
        request_id = secrets.token_hex(16)
        if any(record["id"] == request_id for record in store["requests"]):
            raise RequestError()
        record = {"id": request_id, "username": username, "account_id": account_id,
                  "domain": normalized, "reason": reason, "status": "pending",
                  "created_at": _stamp(_now()), "reviewed_at": None, "reviewer": None,
                  "claim": None, "lease_until": None}
        store["requests"].append(record)
        _write(path, store, kind=kind)
        return copy.deepcopy(record), True


def list_requests(account_id=None, *, kind="dns"):
    """Return copies, newest first; an account filter never includes other accounts."""
    _kind(kind)
    if account_id is not None and not _matches(_ACCOUNT, account_id):
        raise RequestError("ineligible")
    with _locked(kind=kind) as path:
        records = _read(path, kind=kind)["requests"]
        return copy.deepcopy(sorted(
            (record for record in records if account_id is None or record["account_id"] == account_id),
            key=lambda record: (record["created_at"], record["id"]), reverse=True))


def _find(store, request_id):
    for record in store["requests"]:
        if record["id"] == request_id:
            return record
    raise RequestError("not_found")


def _claimed(store, request_id, claim):
    record = _find(store, request_id)
    if record["status"] != "applying" or record["claim"] != claim:
        raise RequestError("conflict")
    return record


def _refresh(request_id, claim, *, kind="dns"):
    with _locked(kind=kind) as path:
        store = _read(path, kind=kind)
        record = _claimed(store, request_id, claim)
        _eligible(record["username"], record["account_id"])
        if _date(record["lease_until"]) <= _now():
            raise RequestError("busy")
        record["lease_until"] = _stamp(_now() + timedelta(seconds=LEASE_SECONDS))
        _write(path, store, kind=kind)


def _finish(request_id, claim, reviewer, *, kind="dns"):
    with _locked(kind=kind) as path:
        store = _read(path, kind=kind)
        record = _claimed(store, request_id, claim)
        _eligible(record["username"], record["account_id"])
        record.update(status="approved", reviewed_at=_stamp(_now()), reviewer=reviewer,
                      claim=None, lease_until=None)
        _write(path, store, kind=kind)
        return copy.deepcopy(record)


def _release(request_id, claim, *, kind="dns"):
    with _locked(kind=kind) as path:
        store = _read(path, kind=kind)
        record = _find(store, request_id)
        if record["status"] == "applying" and record["claim"] == claim:
            record.update(status="pending", claim=None, lease_until=None)
            _write(path, store, kind=kind)


def review(request_id, decision, reviewer, *, kind="dns"):
    """Review once; approve only after confirming the live shared list is applied.

    DNS retries recheck live application before any generation-guarded add. Smart
    retries use its idempotent managed-list adapter, which confirms local application
    and queues publication. A kind always selects its own private store and adapter.
    """
    _require_active_kind(kind)
    if not _matches(_ID, request_id):
        raise RequestError("not_found")
    if (not isinstance(decision, str) or decision not in {"approve", "reject"}
            or not _safe_text(reviewer, 128, nonempty=True)):
        raise RequestError("invalid_request")
    reviewer = reviewer.strip()
    with _locked(kind=kind) as path:
        store = _read(path, kind=kind)
        record = _find(store, request_id)
        _eligible(record["username"], record["account_id"])
        target = "approved" if decision == "approve" else "rejected"
        if record["status"] in _TERMINAL:
            if record["status"] != target:
                raise RequestError("conflict")
            return copy.deepcopy(record)
        now = _now()
        if record["status"] == "applying" and _date(record["lease_until"]) > now:
            raise RequestError("busy")
        if decision == "reject":
            record.update(status="rejected", reviewed_at=_stamp(now), reviewer=reviewer,
                          claim=None, lease_until=None)
            _write(path, store, kind=kind)
            return copy.deepcopy(record)
        claim = secrets.token_hex(16)
        record.update(status="applying", claim=claim,
                      lease_until=_stamp(now + timedelta(seconds=LEASE_SECONDS)))
        _write(path, store, kind=kind)
        domain = record["domain"]
    try:
        if kind == "smart":
            _refresh(request_id, claim, kind=kind)
            try:
                happ_shared_rules.apply_proposed_domain(domain)
            except (ValueError, OSError) as error:
                raise _smart_error(error) from None
        else:
            state = family_dns.status()
            if not state.applied:
                raise family_dns.FamilyDnsError("apply_failed")
            if domain not in state.domains:
                _refresh(request_id, claim, kind=kind)
                state = family_dns.change("add", domain, state.generation)
            if not state.applied or domain not in state.domains:
                raise family_dns.FamilyDnsError("apply_failed")
        return _finish(request_id, claim, reviewer, kind=kind)
    except (family_dns.FamilyDnsError, RequestError):
        _release(request_id, claim, kind=kind)
        raise
    except Exception:  # noqa: BLE001 - release the lease and hide unexpected helper details.
        _release(request_id, claim, kind=kind)
        raise RequestError() from None
