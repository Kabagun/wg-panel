"""Account-wide VPN suspension, preserving device identities and configurations."""

import logging
import os

from . import traffic, wireguard
from .core import _wireguard_lock, load_users, mutate_users

logger = logging.getLogger(__name__)


def access_status(user):
    """Return a display/filter status without claiming a live VPN connection."""
    if user.get("role") == "admin":
        return "admin"
    if user.get("revoking"):
        return "revoking"
    if user.get("pause_pending"):
        return "attention"
    if user.get("paused"):
        return "paused"
    return "active" if user.get("approved") else "pending"


def _owned_devices(username):
    meta = traffic.load_device_meta()
    if os.path.isdir(wireguard.CLIENTS_DIR):
        for filename in os.listdir(wireguard.CLIENTS_DIR):
            if filename.endswith(".conf") and not meta.get(filename[:-5], {}).get("owner"):
                raise ValueError("Unowned client configurations require ownership recovery")
    names = []
    for name, item in sorted(meta.items()):
        if item.get("owner") != username or item.get("revoked"):
            continue
        if not wireguard.get_device(name):
            raise ValueError("An owned device configuration is missing; restore ownership/state")
        names.append(name)
    return names


def _pause_peers(names):
    failures = []
    for name in names:
        ok, error = wireguard._run_script("set-client-state.sh", name, 30, "pause")
        if not ok:
            logger.error("VPN pause failed for %s: %s", name, error)
            failures.append(name)
            continue
        # Removing/re-adding peers resets kernel counters, never monthly history.
        def reset_counters(records, key=name):
            if key in records:
                records[key]["last_rx"] = 0
                records[key]["last_tx"] = 0
        try:
            traffic.mutate_traffic(reset_counters)
        except (OSError, ValueError):
            logger.exception("Failed to checkpoint VPN counters for %s", name)
    return failures


def _checkpoint(username, *, paused, pending):
    def update(users):
        users[username]["paused"] = paused
        users[username]["pause_pending"] = pending
    mutate_users(update)


def set_user_paused(username, paused):
    """Pause/resume all owned peers; return (success, diagnostic).

    Persist the restrictive account state before touching peers. A failed resume
    re-pauses every peer; a failed pause remains explicit and retryable. The
    lifecycle lock excludes device creation, deletion and protected requests.
    """
    with _wireguard_lock:
        user = load_users().get(username)
        if not user or user.get("role") == "admin" or user.get("revoking"):
            return False, "User not found or protected"
        if not user.get("approved"):
            return False, "User is not approved"
        if not paused and not user.get("paused"):
            return True, ""
        try:
            _checkpoint(username, paused=True, pending=True)
        except (OSError, ValueError):
            logger.exception("Failed to persist VPN pause for %s", username)
            return False, "Could not save the pause request"
        try:
            names = _owned_devices(username)
        except (OSError, ValueError) as exc:
            logger.error("Cannot resolve VPN devices for %s: %s", username, exc)
            return False, str(exc)
        try:
            traffic.collect_traffic()
        except (OSError, ValueError):
            logger.exception("Could not collect final VPN counters for %s", username)
        if paused:
            failures = _pause_peers(names)
            if failures:
                return False, "Some devices could not be paused"
            try:
                _checkpoint(username, paused=True, pending=False)
            except (OSError, ValueError):
                logger.exception("Could not confirm VPN pause for %s", username)
                return False, "Peers paused, but the confirmation could not be saved"
            return True, ""

        try:
            # Safe internet must be enforced before the first peer is restored.
            wireguard.reconcile_safe_dns()
            for name in names:
                ok, error = wireguard._run_script("set-client-state.sh", name, 30, "resume")
                if not ok:
                    logger.error("VPN resume failed for %s: %s", name, error)
                    raise RuntimeError("A device could not be resumed")
            _checkpoint(username, paused=False, pending=False)
        except (OSError, ValueError, RuntimeError):
            logger.exception("VPN resume failed for %s; restoring pause", username)
            failures = _pause_peers(names)
            try:
                _checkpoint(username, paused=True, pending=bool(failures))
            except (OSError, ValueError):
                logger.exception("Could not persist VPN resume rollback for %s", username)
            return False, "Resume failed; pause restored" if not failures else "Resume and rollback incomplete"
        return True, ""


def reconcile_paused_users():
    """Reapply persisted pauses at startup; abort serving on unresolved access."""
    with _wireguard_lock:
        count = 0
        for username, user in load_users().items():
            if not user.get("paused") or user.get("revoking"):
                continue
            ok, error = set_user_paused(username, True)
            if not ok:
                raise RuntimeError(f"VPN pause reconciliation failed for {username}: {error}")
            count += 1
        return count
