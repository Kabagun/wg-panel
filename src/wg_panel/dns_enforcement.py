"""Server-side Safe internet DNS enforcement.

The panel deliberately delegates nftables changes to one installed, root-only
helper.  This module validates the managed client address set, invokes that
helper without a shell, and turns helper failures into an explicit exception
so callers can keep persisted Safe internet state unchanged.
"""

import ipaddress
import os
import subprocess

SAFE_DNS_HELPER_NAME = "safe-dns.sh"
SAFE_DNS_INTERFACE = "wg0"
SAFE_DNS_HELPER_TIMEOUT = 15
SAFE_CLIENT_NETWORK = ipaddress.IPv4Network("10.0.0.0/24")
SAFE_CLIENT_MIN = ipaddress.IPv4Address("10.0.0.2")
SAFE_CLIENT_MAX = ipaddress.IPv4Address("10.0.0.254")


class SafeDnsEnforcementError(RuntimeError):
    """Raised when the managed nftables policy cannot be applied."""


def normalize_safe_client_ips(client_ips):
    """Return sorted, unique safe-client IPv4 addresses.

    Only the IPv4 WireGuard pool used by ``wg0`` is accepted.  Rejecting all
    other forms before invoking the privileged helper prevents a malformed or
    future IPv6 address from broadening the nftables match scope.
    """

    normalized = set()
    for raw_ip in client_ips:
        try:
            address = ipaddress.ip_address(str(raw_ip).strip())
        except ValueError as exc:
            raise SafeDnsEnforcementError(f"Invalid safe internet client address: {raw_ip!r}") from exc
        if (
            not isinstance(address, ipaddress.IPv4Address)
            or address not in SAFE_CLIENT_NETWORK
            or address < SAFE_CLIENT_MIN
            or address > SAFE_CLIENT_MAX
        ):
            raise SafeDnsEnforcementError(
                "Safe internet client address must be in 10.0.0.2-10.0.0.254"
            )
        normalized.add(str(address))
    return tuple(sorted(normalized, key=lambda value: int(ipaddress.IPv4Address(value))))


def safe_dns_helper_path(wg_dir=None):
    """Return the configured installed helper path."""

    configured = os.getenv("WG_PANEL_SAFE_DNS_HELPER", "").strip()
    if configured:
        return configured
    directory = wg_dir or os.getenv("WG_PANEL_WG_DIR", "/etc/wireguard")
    return os.path.join(directory, SAFE_DNS_HELPER_NAME)


def sync_safe_dns(
    client_ips,
    *,
    wg_dir=None,
    helper_path=None,
    timeout=SAFE_DNS_HELPER_TIMEOUT,
    allow_unavailable=False,
    require_helper=True,
):
    """Atomically reconcile nftables with ``client_ips``.

    ``allow_unavailable`` exists only for non-Linux test/development runs. It
    is never enabled by production startup or request paths. ``require_helper``
    may be disabled for an empty startup set so a fresh install can start
    before the optional managed table has ever been created.
    """

    normalized = normalize_safe_client_ips(client_ips)
    helper = helper_path or safe_dns_helper_path(wg_dir)
    if not os.path.isfile(helper):
        if allow_unavailable or (not normalized and not require_helper):
            return normalized
        raise SafeDnsEnforcementError(f"Safe DNS helper is not installed: {helper}")

    command = [helper, "--sync", *normalized]
    environment = os.environ.copy()
    environment["WG_INTERFACE_NAME"] = SAFE_DNS_INTERFACE
    if wg_dir:
        environment["WG_DIR"] = wg_dir
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SafeDnsEnforcementError(f"Safe DNS helper failed to start: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "nftables reconciliation failed").strip()
        raise SafeDnsEnforcementError(detail[:500])
    return normalized
