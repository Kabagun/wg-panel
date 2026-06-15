#!/bin/bash
WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENTS_DIR="${CLIENTS_DIR:-$WG_DIR/clients}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"

echo "=== WireGuard Clients ==="
echo ""
if ls "$CLIENTS_DIR"/*.conf 1>/dev/null 2>&1; then
    for f in "$CLIENTS_DIR"/*.conf; do
        name=$(basename "$f" .conf)
        ip=$(grep "Address" "$f" | awk '{print $3}')
        echo "  $name  ->  $ip"
    done
    echo ""
    echo "Total: $(ls "$CLIENTS_DIR"/*.conf | wc -l) clients"
else
    echo "  No clients configured yet."
fi
echo ""
echo "=== Live connections ==="
wg show "$WG_INTERFACE_NAME" 2>/dev/null || echo "  WireGuard not running"
