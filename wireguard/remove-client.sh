#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: ./remove-client.sh <client-name>"
    echo ""
    echo "Active clients:"
    ls /etc/wireguard/clients/*.conf 2>/dev/null | xargs -I{} basename {} .conf || echo "  (none)"
    exit 1
fi

CLIENT_NAME="$1"
WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENTS_DIR="${CLIENTS_DIR:-$WG_DIR/clients}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"

if [ ! -f "$CLIENTS_DIR/${CLIENT_NAME}.conf" ]; then
    echo "ERROR: Client '$CLIENT_NAME' not found!"
    exit 1
fi

# Get client public key to remove from server
CLIENT_PRIV=$(grep "PrivateKey" "$CLIENTS_DIR/${CLIENT_NAME}.conf" | awk '{print $3}')
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

# Remove from live WireGuard
wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" remove

# Remove from server config (remove the peer block)
# Find and remove the block for this client
python3 -c "
import re
with open('$WG_DIR/wg0.conf') as f:
    content = f.read()
pattern = r'\n# ${CLIENT_NAME}\n\[Peer\][^\[]*'
content = re.sub(pattern, '', content)
with open('$WG_DIR/wg0.conf', 'w') as f:
    f.write(content.rstrip() + '\n')
"

# Remove client config
rm "$CLIENTS_DIR/${CLIENT_NAME}.conf"

echo "Client '$CLIENT_NAME' removed successfully!"
