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
CLIENT_CONFIG="$CLIENTS_DIR/${CLIENT_NAME}.conf"

for command_name in wg flock python3 mktemp; do
    command -v "$command_name" >/dev/null || {
        echo "ERROR: Required command '$command_name' is unavailable" >&2
        exit 3
    }
done

install -d -m 700 "$CLIENTS_DIR"
exec 9>"$WG_DIR/.wg-panel.lock"
flock -x 9

if [ ! -f "$CLIENT_CONFIG" ]; then
    echo "ERROR: Client '$CLIENT_NAME' not found" >&2
    exit 4
fi

CLIENT_PRIV=$(awk -F' = ' '$1 == "PrivateKey" {print $2; exit}' "$CLIENT_CONFIG")
CLIENT_PSK=$(awk -F' = ' '$1 == "PresharedKey" {print $2; exit}' "$CLIENT_CONFIG")
CLIENT_ADDRESS=$(awk -F' = ' '$1 == "Address" {print $2; exit}' "$CLIENT_CONFIG")
if [ -z "$CLIENT_PRIV" ] || [ -z "$CLIENT_PSK" ] || [ -z "$CLIENT_ADDRESS" ]; then
    echo "ERROR: Client configuration is incomplete" >&2
    exit 5
fi
CLIENT_PUB=$(printf '%s' "$CLIENT_PRIV" | wg pubkey)

WG_TMP=$(mktemp "$WG_DIR/.wg0.conf.XXXXXX")
WG_BACKUP=$(mktemp "$WG_DIR/.wg0.backup.XXXXXX")
PSK_TMP=$(mktemp "$WG_DIR/.psk.XXXXXX")
CLIENT_BACKUP=$(mktemp "$CLIENTS_DIR/.${CLIENT_NAME}.backup.XXXXXX")
LIVE_REMOVED=0
WG_REPLACED=0
SUCCESS=0

cleanup() {
    status=$?
    if [ "$SUCCESS" -ne 1 ]; then
        if [ "$WG_REPLACED" -eq 1 ]; then
            install -m 600 "$WG_BACKUP" "$WG_CONF" || true
        fi
        if [ "$LIVE_REMOVED" -eq 1 ]; then
            printf '%s' "$CLIENT_PSK" >"$PSK_TMP"
            wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" preshared-key "$PSK_TMP" \
                allowed-ips "$CLIENT_ADDRESS" || true
        fi
        if [ ! -e "$CLIENT_CONFIG" ]; then
            install -m 600 "$CLIENT_BACKUP" "$CLIENT_CONFIG" || true
        fi
    fi
    rm -f -- "$WG_TMP" "$WG_BACKUP" "$PSK_TMP" "$CLIENT_BACKUP"
    exit "$status"
}
trap cleanup EXIT

install -m 600 "$WG_CONF" "$WG_BACKUP"
install -m 600 "$CLIENT_CONFIG" "$CLIENT_BACKUP"
python3 - "$WG_CONF" "$WG_TMP" "$CLIENT_PUB" <<'PY'
import re
import sys

source, target, public_key = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    content = handle.read()
lines = content.splitlines(keepends=True)
headers = [
    index for index, line in enumerate(lines)
    if re.fullmatch(r"\s*\[[^\]\r\n]+\]\s*(?:#.*)?", line.rstrip("\r\n"))
]

def block_start(header):
    # Blank lines and comments before a header belong to that next section.
    start = header
    while start and (not lines[start - 1].strip() or lines[start - 1].lstrip().startswith("#")):
        start -= 1
    return start

matches = []
for position, header in enumerate(headers):
    if lines[header].split("#", 1)[0].strip() != "[Peer]":
        continue
    end = block_start(headers[position + 1]) if position + 1 < len(headers) else len(lines)
    keys = []
    for line in lines[header + 1:end]:
        key, separator, value = line.split("#", 1)[0].partition("=")
        if separator and key.strip() == "PublicKey":
            keys.append(value.strip())
    if public_key in keys:
        if keys != [public_key]:
            raise SystemExit("ERROR: Ambiguous persistent peer public keys")
        matches.append((block_start(header), end))
if len(matches) != 1:
    raise SystemExit(f"ERROR: Expected one persistent peer block, found {len(matches)}")
start, end = matches[0]
updated = "".join(lines[:start] + lines[end:])
with open(target, "w", encoding="utf-8") as handle:
    handle.write(updated)
PY

wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" remove
LIVE_REMOVED=1
chmod 600 "$WG_TMP"
mv -f -- "$WG_TMP" "$WG_CONF"
WG_REPLACED=1
rm -- "$CLIENT_CONFIG"

if wg show "$WG_INTERFACE_NAME" peers | grep -Fxq "$CLIENT_PUB"; then
    echo "ERROR: Live peer still exists after removal" >&2
    exit 6
fi
if awk '/^[[:space:]]*PublicKey[[:space:]]*=/ {value=$0; sub(/^[^=]*=/, "", value); sub(/#.*/, "", value); gsub(/[[:space:]]/, "", value); print value}' "$WG_CONF" | grep -Fxq "$CLIENT_PUB"; then
    echo "ERROR: Persistent peer still exists after removal" >&2
    exit 7
fi
if [ -e "$CLIENT_CONFIG" ]; then
    echo "ERROR: Client configuration still exists after removal" >&2
    exit 8
fi

chmod 600 "$WG_CONF"
SUCCESS=1
echo "Client '$CLIENT_NAME' removed successfully"
