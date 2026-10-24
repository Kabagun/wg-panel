"""Permanent owner policy, independent of deletable accounts and devices."""

import json
import os
import re

from . import core

OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")


class AccountPolicyError(RuntimeError):
    pass


def account_policy_path():
    return os.path.join(core.DATA_DIR, "account_policy.json")


def load_account_policies():
    """Fail closed on malformed state; never silently discard permanent locks."""
    with core._wireguard_lock:
        path = account_policy_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            raise AccountPolicyError("Cannot read permanent account policy") from exc
        if (
            not isinstance(data, dict) or data.get("version") != 1
            or not isinstance(data.get("owners"), dict)
            or any(
                not isinstance(owner, str) or not OWNER_RE.fullmatch(owner)
                or record != {"safe_internet_locked": True}
                for owner, record in data.get("owners", {}).items()
            )
        ):
            raise AccountPolicyError("Invalid permanent account policy")
        return data["owners"]


def save_account_policies(policies):
    """Internal maintenance primitive; no web route can clear this registry."""
    with core._wireguard_lock:
        core.write_json_private(account_policy_path(), {"version": 1, "owners": policies})


def account_safe_internet_locked(owner, policies=None):
    if policies is None:
        policies = load_account_policies()
    return owner in policies


def effective_safe_internet(device, policies=None):
    return bool(
        device.get("safe_internet")
        or account_safe_internet_locked(device.get("owner"), policies)
    )
