"""Public connection parameters from the exact configuration offered for download."""

import base64
import subprocess


def connection_details(config, *, include_public_key=False):
    """Expose a fixed field list; never return either secret key."""
    sections = {"interface": {}, "peer": {}}
    section = None
    for raw in (config or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = sections.get(line[1:-1].lower())
        elif section is not None and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            key = key.lower()
            if key in {"address", "dns", "allowedips"} and section.get(key):
                section[key] += ", " + value
            else:
                section[key] = value
    interface, peer = sections["interface"], sections["peer"]
    details = {
        "address": interface.get("address", ""),
        "dns": interface.get("dns", ""),
        "listen_port": interface.get("listenport", ""),
        "mtu": interface.get("mtu", ""),
        "endpoint": peer.get("endpoint", ""),
        "allowed_ips": peer.get("allowedips", ""),
        "server_public_key": peer.get("publickey", ""),
        "preshared_key_enabled": bool(peer.get("presharedkey")),
        "keepalive": peer.get("persistentkeepalive", ""),
        "client_public_key": "",
    }
    if include_public_key:
        details["client_public_key"] = _public_key(interface.get("privatekey", ""))
    return details


def _public_key(private_key):
    try:
        if len(base64.b64decode(private_key, validate=True)) != 32:
            return ""
        result = subprocess.run(
            ["wg", "pubkey"], input=private_key + "\n", capture_output=True,
            text=True, timeout=2, check=True,
        )
        public_key = result.stdout.strip()
        return public_key if len(base64.b64decode(public_key, validate=True)) == 32 else ""
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""
