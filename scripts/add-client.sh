#!/bin/bash
# WG-PANEL-PREPARE-PROTOCOL v1
set -Eeuo pipefail
umask 077

CLIENT_NAME="${1:-}"
PREPARE_ONLY=0
DNS_SERVERS="1.1.1.1, 8.8.8.8"
if [ "${2:-}" = "--prepare" ] && [ "$#" -eq 2 ]; then
    PREPARE_ONLY=1
    DNS_SERVERS="1.1.1.3, 1.0.0.3"
elif [ "$#" -ne 1 ]; then
    echo "ERROR: Usage: add-client.sh NAME [--prepare]" >&2
    exit 2
fi
if [[ ! "$CLIENT_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,127}$ ]]; then
    echo "ERROR: Invalid client name" >&2
    exit 2
fi

WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENTS_DIR="${CLIENTS_DIR:-$WG_DIR/clients}"
INFRASTRUCTURE_CLIENTS_DIR="${INFRASTRUCTURE_CLIENTS_DIR:-$WG_DIR/infrastructure}"
INFRASTRUCTURE_REGISTRY="${INFRASTRUCTURE_REGISTRY:-${WG_PANEL_DATA_DIR:-/opt/wg-panel/data}/infrastructure_peers.json}"
INFRASTRUCTURE_ADOPTION_CHECKPOINT="${INFRASTRUCTURE_REGISTRY%/*}/infrastructure_adoption.json"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
WG_CONF="$WG_DIR/wg0.conf"

for command_name in wg flock ip awk grep mktemp; do
    command -v "$command_name" >/dev/null || {
        echo "ERROR: Required command '$command_name' is unavailable" >&2
        exit 3
    }
done
if [ "$PREPARE_ONLY" -eq 1 ]; then
    command -v python3 >/dev/null || {
        echo "ERROR: Required command 'python3' is unavailable" >&2
        exit 3
    }
fi

install -d -m 700 "$CLIENTS_DIR"
exec 9>"$WG_DIR/.wg-panel.lock"
flock -x 9

# The same operator file drives nftables DNAT and protected profile exports.
# WireGuard's DNS field takes an address only; the selected-source firewall
# redirects UDP/TCP 53 to the configured listener port. Never silently fall
# back when an existing target is malformed or cannot be read.
if [ "$PREPARE_ONLY" -eq 1 ]; then
    if ! DNS_SERVERS=$(python3 - "$WG_DIR/safe-dns-target" <<'PY'
import ipaddress
import os
import re
import stat
import sys

try:
    path = sys.argv[1]
    try:
        initial = os.lstat(path)
    except FileNotFoundError:
        print("1.1.1.3, 1.0.0.3")
        raise SystemExit(0)
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > 64:
        raise ValueError()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (not stat.S_ISREG(opened.st_mode) or not os.path.samestat(initial, opened)
                or not os.path.samestat(opened, os.lstat(path))):
            raise ValueError()
        content = handle.read(65)
    match = re.fullmatch(rb"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([1-9][0-9]{0,4})(?:\r?\n)?", content)
    if not match:
        raise ValueError()
    address = ipaddress.IPv4Address(match[1].decode("ascii"))
    if (address.is_loopback or address.is_multicast or address.is_unspecified
            or address.is_reserved or int(address) < 0x01000000 or int(match[2]) > 65535):
        raise ValueError()
    print(address)
except (OSError, ValueError):
    raise SystemExit("ERROR: Safe DNS target configuration is unavailable or invalid")
PY
    ); then
        exit 9
    fi
fi

FINAL_CONFIG="$CLIENTS_DIR/${CLIENT_NAME}.conf"
if [ -e "$FINAL_CONFIG" ]; then
    echo "ERROR: Client '$CLIENT_NAME' already exists" >&2
    exit 4
fi
if [ ! -f "$WG_CONF" ] || [ ! -f "$WG_DIR/server_public.key" ]; then
    echo "ERROR: WireGuard server configuration is incomplete" >&2
    exit 5
fi

# Read the root-only registry with the standard library, never the web package.
# Retained configs reserve infrastructure names/addresses even when the peer is
# paused (its persistent AllowedIPs are then inside a base64 envelope). Invalid
# state aborts before key generation or any WireGuard/configuration mutation.
INFRASTRUCTURE_RESERVED_OCTETS=""
if [ -e "$INFRASTRUCTURE_CLIENTS_DIR" ] || [ -L "$INFRASTRUCTURE_CLIENTS_DIR" ] \
        || [ -e "$INFRASTRUCTURE_REGISTRY" ] || [ -L "$INFRASTRUCTURE_REGISTRY" ] \
        || [ -e "$INFRASTRUCTURE_ADOPTION_CHECKPOINT" ] \
        || [ -L "$INFRASTRUCTURE_ADOPTION_CHECKPOINT" ]; then
    command -v python3 >/dev/null || {
        echo "ERROR: Infrastructure reservations require python3" >&2
        exit 3
    }
    if ! INFRASTRUCTURE_RESERVATIONS=$(python3 - "$INFRASTRUCTURE_CLIENTS_DIR" \
            "$INFRASTRUCTURE_REGISTRY" <<'PY'
import base64
import configparser
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys

directory, registry = sys.argv[1:]


def private(path, directory=False):
    info = os.lstat(path)
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError("Expected private owned infrastructure state")


def key(value):
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Invalid infrastructure identity")
    return value


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON field")
        result[name] = value
    return result


try:
    if os.path.lexists(os.path.join(os.path.dirname(registry), "infrastructure_adoption.json")):
        raise ValueError("Incomplete infrastructure adoption")
    if os.path.exists(os.path.dirname(registry)):
        private(os.path.dirname(registry), directory=True)
    peers = {}
    if os.path.lexists(registry):
        private(registry)
        with open(registry, encoding="utf-8") as handle:
            state = json.load(handle, object_pairs_hook=unique)
        if (not isinstance(state, dict) or set(state) != {"version", "peers"}
                or type(state["version"]) is not int or state["version"] != 1
                or not isinstance(state["peers"], dict)):
            raise ValueError("Invalid infrastructure registry")
        peers = state["peers"]
    files = set()
    if os.path.lexists(directory):
        private(directory, directory=True)
        files = set(os.listdir(directory))
    if files != {f"{name}.conf" for name in peers}:
        raise ValueError("Infrastructure registry/configuration mismatch")
    addresses, identities = set(), set()
    for name, record in peers.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", name)
                or not isinstance(record, dict)
                or set(record) != {"kind", "label", "public_key", "ipv4", "config_sha256"}
                or record["kind"] != "router" or not isinstance(record["label"], str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9 _-]{0,63}", record["label"])
                or not isinstance(record["config_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["config_sha256"])):
            raise ValueError("Invalid infrastructure peer")
        address = ipaddress.IPv4Address(record["ipv4"])
        if not ipaddress.IPv4Address("10.0.0.2") <= address <= ipaddress.IPv4Address("10.0.0.254"):
            raise ValueError("Invalid infrastructure address")
        if str(address) != record["ipv4"]:
            raise ValueError("Invalid infrastructure address")
        public_key = key(record["public_key"])
        if address in addresses or public_key in identities:
            raise ValueError("Duplicate infrastructure identity/address")
        addresses.add(address)
        identities.add(public_key)
        path = os.path.join(directory, f"{name}.conf")
        private(path)
        with open(path, "rb") as handle:
            content = handle.read()
        if hashlib.sha256(content).hexdigest() != record["config_sha256"]:
            raise ValueError("Infrastructure configuration changed")
        config = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
        config.read_string(content.decode("utf-8"))
        if config.sections() != ["Interface", "Peer"] or config.defaults():
            raise ValueError("Invalid infrastructure client sections")
        if config["Interface"]["Address"] != f"{address}/32":
            raise ValueError("Infrastructure address mismatch")
        key(config["Peer"]["PublicKey"])
        key(config["Peer"]["PresharedKey"])
        result = subprocess.run(["wg", "pubkey"], input=key(config["Interface"]["PrivateKey"]) + "\n",
                                capture_output=True, text=True, check=False, timeout=5)
        if result.returncode or key(result.stdout.strip()) != public_key:
            raise ValueError("Infrastructure identity mismatch")
        print(name, str(address).rsplit(".", 1)[1])
except (OSError, ValueError, TypeError, KeyError, configparser.Error, subprocess.SubprocessError):
    raise SystemExit("ERROR: Invalid infrastructure reservations; operator recovery required")
PY
    ); then
        exit 9
    fi
    while read -r infrastructure_name infrastructure_octet; do
        [ -n "$infrastructure_name" ] || continue
        if [ "$infrastructure_name" = "$CLIENT_NAME" ]; then
            echo "ERROR: Client name is reserved for infrastructure" >&2
            exit 4
        fi
        INFRASTRUCTURE_RESERVED_OCTETS+="$infrastructure_octet"$'\n'
    done <<<"$INFRASTRUCTURE_RESERVATIONS"
fi

SERVER_PUB=$(<"$WG_DIR/server_public.key")
IFACE="${WG_INTERFACE:-$(ip -o -4 route show to default | awk '{print $5; exit}')}"
SERVER_IP=$(ip -4 addr show "$IFACE" | awk '/inet / {sub("/.*", "", $2); print $2; exit}')
SERVER_ENDPOINT="${WG_ENDPOINT_HOST:-$SERVER_IP}"
SERVER_PORT="${WG_ENDPOINT_PORT:-51820}"
if [ -z "$SERVER_ENDPOINT" ]; then
    echo "ERROR: Cannot detect server endpoint; set WG_ENDPOINT_HOST" >&2
    exit 6
fi

USED_IPS=$({
    grep -h -oE '(AllowedIPs|Address)[[:space:]]*=[[:space:]]*10\.0\.0\.[0-9]+' \
        "$WG_CONF" 2>/dev/null || true
    # Paused peers are intentionally absent from active wg0.conf sections. Their
    # retained client configurations continue to reserve the assigned address.
    grep -h -oE '(AllowedIPs|Address)[[:space:]]*=[[:space:]]*10\.0\.0\.[0-9]+' \
        "$CLIENTS_DIR"/*.conf 2>/dev/null || true
    printf '%s' "$INFRASTRUCTURE_RESERVED_OCTETS"
} | grep -oE '[0-9]+$' | sort -un || true)
NEXT_IP=""
for candidate in $(seq 2 254); do
    if ! grep -qx "$candidate" <<<"$USED_IPS"; then
        NEXT_IP="$candidate"
        break
    fi
done
if [ -z "$NEXT_IP" ]; then
    echo "ERROR: WireGuard address pool is exhausted" >&2
    exit 7
fi

CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(printf '%s' "$CLIENT_PRIV" | wg pubkey)
CLIENT_PSK=$(wg genpsk)
CLIENT_TMP=$(mktemp "$CLIENTS_DIR/.${CLIENT_NAME}.conf.XXXXXX")
WG_TMP=$(mktemp "$WG_DIR/.wg0.conf.XXXXXX")
WG_BACKUP=$(mktemp "$WG_DIR/.wg0.backup.XXXXXX")
PSK_TMP=$(mktemp "$WG_DIR/.psk.XXXXXX")
LIVE_ADDED=0
WG_REPLACED=0
SUCCESS=0

cleanup() {
    status=$?
    if [ "$SUCCESS" -ne 1 ]; then
        if [ "$WG_REPLACED" -eq 1 ]; then
            install -m 600 "$WG_BACKUP" "$WG_CONF" || true
        fi
        if [ "$LIVE_ADDED" -eq 1 ]; then
            wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" remove || true
        fi
        rm -f -- "$FINAL_CONFIG"
    fi
    rm -f -- "$CLIENT_TMP" "$WG_TMP" "$WG_BACKUP" "$PSK_TMP"
    exit "$status"
}
trap cleanup EXIT

install -m 600 "$WG_CONF" "$WG_BACKUP"
install -m 600 "$WG_CONF" "$WG_TMP"
printf '%s' "$CLIENT_PSK" >"$PSK_TMP"

cat >"$CLIENT_TMP" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.0.0.$NEXT_IP/32
DNS = $DNS_SERVERS

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $CLIENT_PSK
Endpoint = $SERVER_ENDPOINT:$SERVER_PORT
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
PersistentKeepalive = 25
EOF

PEER_BLOCK=$(cat <<EOF

# $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $CLIENT_PSK
AllowedIPs = 10.0.0.$NEXT_IP/32
EOF
)

if [ "$PREPARE_ONLY" -eq 1 ]; then
    # Restart-safe comments keep this peer inactive until the panel has
    # installed account DNS enforcement and explicitly resumes it.
    PEER_DATA=$(printf '%s\n' "$PEER_BLOCK" | python3 -c \
        'import base64,sys; print(base64.b64encode(sys.stdin.buffer.read()).decode("ascii"))')
    printf '\n# WG-PANEL-PAUSED-BEGIN v1 %s\n# WG-PANEL-PAUSED-DATA %s\n# WG-PANEL-PAUSED-END v1 %s\n' \
        "$CLIENT_PUB" "$PEER_DATA" "$CLIENT_PUB" >>"$WG_TMP"
else
    printf '\n%s\n' "$PEER_BLOCK" >>"$WG_TMP"
    wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" preshared-key "$PSK_TMP" \
        allowed-ips "10.0.0.$NEXT_IP/32"
    LIVE_ADDED=1
fi
chmod 600 "$WG_TMP" "$CLIENT_TMP"
mv -f -- "$WG_TMP" "$WG_CONF"
WG_REPLACED=1
mv -f -- "$CLIENT_TMP" "$FINAL_CONFIG"
chmod 600 "$WG_CONF" "$FINAL_CONFIG"
SUCCESS=1

echo "Client '$CLIENT_NAME' created at 10.0.0.$NEXT_IP"
