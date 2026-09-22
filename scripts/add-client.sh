#!/bin/bash
set -Eeuo pipefail
umask 077

CLIENT_NAME="${1:-}"
if [[ ! "$CLIENT_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,127}$ ]]; then
    echo "ERROR: Invalid client name" >&2
    exit 2
fi

WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENTS_DIR="${CLIENTS_DIR:-$WG_DIR/clients}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
WG_CONF="$WG_DIR/wg0.conf"

for command_name in wg flock ip awk grep mktemp; do
    command -v "$command_name" >/dev/null || {
        echo "ERROR: Required command '$command_name' is unavailable" >&2
        exit 3
    }
done

install -d -m 700 "$CLIENTS_DIR"
exec 9>"$WG_DIR/.wg-panel.lock"
flock -x 9

FINAL_CONFIG="$CLIENTS_DIR/${CLIENT_NAME}.conf"
if [ -e "$FINAL_CONFIG" ]; then
    echo "ERROR: Client '$CLIENT_NAME' already exists" >&2
    exit 4
fi
if [ ! -f "$WG_CONF" ] || [ ! -f "$WG_DIR/server_public.key" ]; then
    echo "ERROR: WireGuard server configuration is incomplete" >&2
    exit 5
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
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $CLIENT_PSK
Endpoint = $SERVER_ENDPOINT:$SERVER_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

cat >>"$WG_TMP" <<EOF

# $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $CLIENT_PSK
AllowedIPs = 10.0.0.$NEXT_IP/32
EOF

wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" preshared-key "$PSK_TMP" \
    allowed-ips "10.0.0.$NEXT_IP/32"
LIVE_ADDED=1
chmod 600 "$WG_TMP" "$CLIENT_TMP"
mv -f -- "$WG_TMP" "$WG_CONF"
WG_REPLACED=1
mv -f -- "$CLIENT_TMP" "$FINAL_CONFIG"
chmod 600 "$WG_CONF" "$FINAL_CONFIG"
SUCCESS=1

echo "Client '$CLIENT_NAME' created at 10.0.0.$NEXT_IP"
