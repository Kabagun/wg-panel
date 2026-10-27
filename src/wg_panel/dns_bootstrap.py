"""Reconcile Safe internet before WireGuard starts, without activating peers.

Run as root with the same environment as wg-panel.  Personal ownership must
already be prepared: this command validates a dry run and never migrates state.
It invokes only the managed DNS reconciler, not the panel's server or loops.
"""

import os
import sys

from .core import WG_DIR, _wireguard_lock
from .dns_enforcement import SafeDnsEnforcementError
from .infrastructure import assert_infrastructure_ready
from .safe_dns_settings import load_safe_dns_target
from .wireguard import migrate_device_metadata, reconcile_safe_dns


def bootstrap_safe_dns():
    """Validate ownership and reconcile DNS, returning nonsensitive counts."""
    with _wireguard_lock:
        infrastructure = assert_infrastructure_ready(wg_dir=WG_DIR)
        load_safe_dns_target(WG_DIR)
        ownership = migrate_device_metadata(dry_run=True)
        if ownership["ambiguous"] or ownership["unowned"] or ownership["migrated"]:
            raise SafeDnsEnforcementError("Safe DNS bootstrap requires prepared personal ownership")
        result = reconcile_safe_dns(require_helper=True, allow_unavailable=False)
    return {
        "personal_profiles": ownership["total"],
        "infrastructure_peers": len(infrastructure),
        "safe_devices": result["safe_devices"],
        "safe_addresses": len(result["ips"]),
    }


def main():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("Safe DNS bootstrap requires root", file=sys.stderr, flush=True)
        return 1
    try:
        counts = bootstrap_safe_dns()
    except Exception:  # noqa: BLE001 - boot logs must not expose deployment details.
        # Exceptions from configuration readers/helpers may contain paths,
        # client names, or command output.  Keep boot logs generic.
        print("Safe DNS bootstrap failed; operator preparation is required", file=sys.stderr,
              flush=True)
        return 1
    print(
        "[SAFE DNS BOOTSTRAP] "
        f"personal_profiles={counts['personal_profiles']} "
        f"infrastructure_peers={counts['infrastructure_peers']} "
        f"safe_devices={counts['safe_devices']} "
        f"safe_addresses={counts['safe_addresses']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
