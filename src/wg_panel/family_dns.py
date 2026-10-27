"""Bounded client for the server's shared family DNS exception list."""

import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 256 * 1024
# Leave enough time for validation, restart and smoke checks plus a failed-apply rollback.
HELPER_TIMEOUT_SECONDS = 200
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_ERROR_CODES = {
    "invalid_domain", "invalid_request", "stale_generation", "busy", "uninitialized",
    "unavailable", "apply_failed", "degraded",
}
_BACKUP_STATUSES = {"never", "updated", "unchanged", "error"}


class FamilyDnsError(RuntimeError):
    """Expose only a stable, non-sensitive error code to the interface."""

    def __init__(self, code="unavailable"):
        self.code = code if code in _ERROR_CODES | {"unconfigured"} else "unavailable"
        super().__init__(self.code)


@dataclass(frozen=True)
class BackupStatus:
    status: str
    last_attempt_at: int | None
    last_success_at: int | None
    commit: str | None
    generation: int | None = None


@dataclass(frozen=True)
class FamilyDnsState:
    domains: tuple[str, ...]
    generation: int
    applied: bool
    applied_at: int | None
    backup: BackupStatus


def normalize_domain(value):
    """Accept one domain, without URLs, wildcards, addresses or extra syntax."""
    if not isinstance(value, str) or len(value) > 1024:
        raise FamilyDnsError("invalid_domain")
    candidate = value.strip().removesuffix(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        raise FamilyDnsError("invalid_domain") from None
    labels = candidate.split(".")
    if len(candidate) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(x) for x in labels):
        raise FamilyDnsError("invalid_domain")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    raise FamilyDnsError("invalid_domain")


def _integer(value):
    return type(value) is int and value >= 0


def _timestamp(value):
    return value is None or _integer(value)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _state_from_response(raw, returncode):
    try:
        response = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise ValueError("invalid response")
        if not response["ok"]:
            code = response.get("error")
            raise FamilyDnsError(code if isinstance(code, str) else "unavailable")
        if returncode != 0:
            raise ValueError("unsuccessful helper")
        domains = response["domains"]
        if not isinstance(domains, list) or any(
            not isinstance(domain, str) or normalize_domain(domain) != domain
            for domain in domains
        ) or len(domains) != len(set(domains)):
            raise ValueError("invalid domains")
        if not _integer(response["generation"]) or type(response["applied"]) is not bool:
            raise ValueError("invalid state")
        if not _timestamp(response["applied_at"]):
            raise ValueError("invalid applied time")
        backup = response["backup"]
        if (
            not isinstance(backup, dict)
            or backup.get("status") not in _BACKUP_STATUSES
            or not _timestamp(backup["last_attempt_at"])
            or not _timestamp(backup["last_success_at"])
            or not (backup["commit"] is None or isinstance(backup["commit"], str)
                    and len(backup["commit"]) <= 128)
            or not (backup.get("generation") is None or _integer(backup["generation"]))
        ):
            raise ValueError("invalid backup state")
        return FamilyDnsState(
            tuple(domains), response["generation"], response["applied"], response["applied_at"],
            BackupStatus(
                backup["status"], backup["last_attempt_at"], backup["last_success_at"],
                backup["commit"], backup.get("generation"),
            ),
        )
    except FamilyDnsError as error:
        # Domain validation of helper output is a protocol fault, not a form error.
        if isinstance(locals().get("response"), dict) and response.get("ok") is False:
            raise
        raise FamilyDnsError() from error
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise FamilyDnsError() from None


def _invoke(payload):
    configured = os.getenv("WG_PANEL_FAMILY_DNS_HELPER", "").strip()
    if not configured:
        raise FamilyDnsError("unconfigured")
    helper = Path(configured)
    if not helper.is_absolute():
        raise FamilyDnsError()
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise FamilyDnsError("invalid_request")
    try:
        process = subprocess.Popen(
            [sys.executable, str(helper)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False,
        )
    except (OSError, ValueError):
        raise FamilyDnsError() from None

    output = []
    read_failed = []

    def read_output():
        try:
            # One extra byte distinguishes a full valid response from overflow.
            data = process.stdout.read(MAX_RESPONSE_BYTES + 1)
            output.append(data)
            if len(data) > MAX_RESPONSE_BYTES:
                process.kill()
        except OSError:
            read_failed.append(True)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    deadline = time.monotonic() + HELPER_TIMEOUT_SECONDS
    try:
        process.stdin.write(encoded)
        process.stdin.close()
        process.wait(timeout=max(0, deadline - time.monotonic()))
        reader.join(timeout=max(0, deadline - time.monotonic()))
        if reader.is_alive() or read_failed or not output or len(output[0]) > MAX_RESPONSE_BYTES:
            raise FamilyDnsError()
        return _state_from_response(output[0], process.returncode)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise FamilyDnsError() from None
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        reader.join(timeout=1)
        process.stdin.close()
        if not reader.is_alive():
            process.stdout.close()


def status():
    """Read status only; initialization and repair are never requested here."""
    return _invoke({"operation": "status"})


def change(operation, domain, expected_generation):
    """Submit one versioned change once; never retry an uncertain mutation."""
    if operation not in {"add", "remove"} or not _integer(expected_generation):
        raise FamilyDnsError("invalid_request")
    state = _invoke({
        "operation": operation, "domain": normalize_domain(domain),
        "expected_generation": expected_generation,
    })
    if not state.applied:
        raise FamilyDnsError("apply_failed")
    return state
