#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: ./add-client.sh <client-name>"
    echo "Example: ./add-client.sh phone-dad"
    exit 1
fi

CLIENT_NAME="$1"
WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENTS_DIR="${CLIENTS_DIR:-$WG_DIR/clients}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
SERVER_PUB=$(cat "$WG_DIR/server_public.key")
IFACE="${WG_INTERFACE:-$(ip -o -4 route show to default | awk '{print $5; exit}')}"
SERVER_IP=$(ip -4 addr show "$IFACE" | grep -oP "inet \K[0-9.]+" | head -n1 || true)
SERVER_ENDPOINT="${WG_ENDPOINT_HOST:-$SERVER_IP}"
SERVER_PORT="${WG_ENDPOINT_PORT:-51820}"
if [ -z "$SERVER_ENDPOINT" ]; then
    echo "ERROR: Cannot detect server endpoint. Set WG_ENDPOINT_HOST before running this script."
    exit 1
fi
mkdir -p "$CLIENTS_DIR"

# Check if client already exists
if [ -f "$CLIENTS_DIR/${CLIENT_NAME}.conf" ]; then
    echo "ERROR: Client '$CLIENT_NAME' already exists!"
    echo "Config: $CLIENTS_DIR/${CLIENT_NAME}.conf"
    exit 1
fi

# Find next available IP
USED_IPS=$(grep -oP 'AllowedIPs = 10\.0\.0\.\K[0-9]+' $WG_DIR/wg0.conf 2>/dev/null || echo "")
NEXT_IP=2
for i in $(seq 2 254); do
    if ! echo "$USED_IPS" | grep -qw "$i"; then
        NEXT_IP=$i
        break
    fi
done

echo "Assigning IP: 10.0.0.$NEXT_IP to $CLIENT_NAME"

# Generate client keys
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
CLIENT_PSK=$(wg genpsk)

# Create client config file
cat > "$CLIENTS_DIR/${CLIENT_NAME}.conf" << EOF
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

# Add peer to server config
cat >> "$WG_DIR/wg0.conf" << EOF

# $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $CLIENT_PSK
AllowedIPs = 10.0.0.$NEXT_IP/32
EOF

# Add peer live (no restart needed)
wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" preshared-key <(echo "$CLIENT_PSK") allowed-ips "10.0.0.$NEXT_IP/32"

echo ""
echo "============================================"
echo "Client '$CLIENT_NAME' created successfully!"
echo "============================================"
echo "Config file: $CLIENTS_DIR/${CLIENT_NAME}.conf"
echo "IP address:  10.0.0.$NEXT_IP"
echo ""
echo "=== QR Code (scan with WireGuard app) ==="
qrencode -t ansiutf8 < "$CLIENTS_DIR/${CLIENT_NAME}.conf"
echo ""
echo "=== Or copy this config to WireGuard app ==="
cat "$CLIENTS_DIR/${CLIENT_NAME}.conf"
echo ""
