#!/bin/bash
set -Eeuo pipefail
umask 077

CLIENT_NAME="${1:-}"
ACTION="${2:-}"
if [[ ! "$CLIENT_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,127}$ ]]; then
    echo "ERROR: Invalid client name" >&2
    exit 2
fi
if [ "$ACTION" != "pause" ] && [ "$ACTION" != "resume" ]; then
    echo "ERROR: State must be 'pause' or 'resume'" >&2
    exit 2
fi

WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENTS_DIR="${CLIENTS_DIR:-$WG_DIR/clients}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
WG_CONF="$WG_DIR/wg0.conf"
CLIENT_CONFIG="$CLIENTS_DIR/${CLIENT_NAME}.conf"

for command_name in wg flock python3 mktemp awk grep; do
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
if [ ! -f "$WG_CONF" ]; then
    echo "ERROR: WireGuard server configuration is missing" >&2
    exit 5
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
PSK_TMP=$(mktemp "$WG_DIR/.psk.XXXXXX")
ROLLBACK_LIVE_ON_FAILURE=0
SUCCESS=0

cleanup() {
    status=$?
    if [ "$SUCCESS" -ne 1 ] && [ "$ROLLBACK_LIVE_ON_FAILURE" -eq 1 ]; then
        wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" remove || true
    fi
    rm -f -- "$WG_TMP" "$PSK_TMP"
    exit "$status"
}
trap cleanup EXIT

PERSISTENT_STATE=$(python3 - "$WG_CONF" "$WG_TMP" "$CLIENT_PUB" "$ACTION" <<'PY'
import base64
import re
import sys

source, target, public_key, action = sys.argv[1:]
with open(source, encoding="utf-8", newline="") as handle:
    content = handle.read()
lines = content.splitlines(keepends=True)
begin_re = re.compile(r"# WG-PANEL-PAUSED-BEGIN v1 (\S+)\s*$")
data_re = re.compile(r"# WG-PANEL-PAUSED-DATA ([A-Za-z0-9+/]*={0,2})\s*$")
end_re = re.compile(r"# WG-PANEL-PAUSED-END v1 (\S+)\s*$")
paused_envelopes = []
paused_matches = []
protected_lines = set()
index = 0
while index < len(lines):
    stripped = lines[index].rstrip("\r\n")
    begin = begin_re.fullmatch(stripped)
    if begin:
        if index + 2 >= len(lines):
            raise SystemExit("ERROR: Incomplete paused peer envelope")
        data = data_re.fullmatch(lines[index + 1].rstrip("\r\n"))
        end_marker = end_re.fullmatch(lines[index + 2].rstrip("\r\n"))
        if not data or not end_marker or end_marker.group(1) != begin.group(1):
            raise SystemExit("ERROR: Invalid paused peer envelope")
        try:
            decoded = base64.b64decode(data.group(1), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SystemExit("ERROR: Invalid paused peer data") from exc
        if any(
            line.lstrip().startswith("# WG-PANEL-PAUSED-")
            for line in decoded.splitlines()
        ):
            raise SystemExit("ERROR: Nested paused peer envelope")
        decoded_headers = [
            line.split("#", 1)[0].strip()
            for line in decoded.splitlines()
            if re.fullmatch(r"\s*\[[^\]\r\n]+\]\s*(?:#.*)?", line)
        ]
        decoded_keys = re.findall(
            r"(?m)^\s*PublicKey\s*=\s*([^#\r\n]+?)\s*(?:#.*)?$", decoded
        )
        if decoded_headers != ["[Peer]"] or decoded_keys != [begin.group(1)]:
            raise SystemExit("ERROR: Paused peer data does not match its marker")
        paused_envelopes.append((index, index + 3, begin.group(1), decoded))
        protected_lines.update(range(index, index + 3))
        if begin.group(1) == public_key:
            paused_matches.append((index, index + 3, decoded))
        index += 3
        continue
    if stripped.startswith("# WG-PANEL-PAUSED-"):
        raise SystemExit("ERROR: Invalid paused peer envelope")
    index += 1

headers = [
    index for index, line in enumerate(lines)
    if re.fullmatch(r"\s*\[[^\]\r\n]+\]\s*(?:#.*)?", line.rstrip("\r\n"))
]


def block_start(header):
    start = header
    while (
        start
        and start - 1 not in protected_lines
        and (not lines[start - 1].strip() or lines[start - 1].lstrip().startswith("#"))
    ):
        start -= 1
    return start


header_starts = [block_start(header) for header in headers]
paused_starts = [start for start, _, _, _ in paused_envelopes]
active_matches = []
for position, header in enumerate(headers):
    later_boundaries = paused_starts + header_starts[position + 1:]
    end = min((boundary for boundary in later_boundaries if boundary > header), default=len(lines))
    section_name = lines[header].split("#", 1)[0].strip()
    if section_name.lower() == "[interface]":
        for line in lines[header + 1:end]:
            key, separator, value = line.split("#", 1)[0].partition("=")
            if separator and key.strip().lower() == "saveconfig" and value.strip().lower() == "true":
                raise SystemExit("ERROR: SaveConfig = true is unsupported")
    if section_name != "[Peer]":
        continue
    keys = []
    for line in lines[header + 1:end]:
        key, separator, value = line.split("#", 1)[0].partition("=")
        if separator and key.strip() == "PublicKey":
            keys.append(value.strip())
    if public_key in keys:
        if keys != [public_key]:
            raise SystemExit("ERROR: Ambiguous persistent peer public keys")
        active_matches.append((block_start(header), end))

matches = [("active", start, end, None) for start, end in active_matches]
matches.extend(("paused", start, end, decoded) for start, end, decoded in paused_matches)
if len(matches) != 1:
    raise SystemExit(f"ERROR: Expected one persistent peer block, found {len(matches)}")
state, start, end, decoded = matches[0]

if action == "pause" and state == "active":
    original = "".join(lines[start:end])
    encoded = base64.b64encode(original.encode("utf-8")).decode("ascii")
    replacement = (
        f"# WG-PANEL-PAUSED-BEGIN v1 {public_key}\n"
        f"# WG-PANEL-PAUSED-DATA {encoded}\n"
        f"# WG-PANEL-PAUSED-END v1 {public_key}\n"
    )
    updated = "".join(lines[:start]) + replacement + "".join(lines[end:])
elif action == "resume" and state == "paused":
    updated = "".join(lines[:start]) + decoded + "".join(lines[end:])
else:
    updated = content

with open(target, "w", encoding="utf-8", newline="") as handle:
    handle.write(updated)
print(state)
PY
)

if [ "$ACTION" = "pause" ]; then
    if [ "$PERSISTENT_STATE" = "active" ]; then
        chmod 600 "$WG_TMP"
        mv -f -- "$WG_TMP" "$WG_CONF"
    fi
    wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" remove
    if ! LIVE_PEERS=$(wg show "$WG_INTERFACE_NAME" peers); then
        echo "ERROR: Cannot verify live peers after pause" >&2
        exit 6
    fi
    if grep -Fxq "$CLIENT_PUB" <<<"$LIVE_PEERS"; then
        echo "ERROR: Live peer still exists after pause" >&2
        exit 6
    fi
    if ! grep -Fqx "# WG-PANEL-PAUSED-BEGIN v1 $CLIENT_PUB" "$WG_CONF"; then
        echo "ERROR: Paused persistent peer is missing" >&2
        exit 7
    fi
    chmod 600 "$WG_CONF" "$CLIENT_CONFIG"
    SUCCESS=1
    echo "Client '$CLIENT_NAME' paused successfully"
    exit 0
fi

printf '%s' "$CLIENT_PSK" >"$PSK_TMP"
if [ "$PERSISTENT_STATE" = "paused" ]; then
    ROLLBACK_LIVE_ON_FAILURE=1
fi
wg set "$WG_INTERFACE_NAME" peer "$CLIENT_PUB" preshared-key "$PSK_TMP" \
    allowed-ips "$CLIENT_ADDRESS"
if ! LIVE_PEERS=$(wg show "$WG_INTERFACE_NAME" peers); then
    echo "ERROR: Cannot verify live peers after resume" >&2
    exit 8
fi
if ! grep -Fxq "$CLIENT_PUB" <<<"$LIVE_PEERS"; then
    echo "ERROR: Live peer is missing after resume" >&2
    exit 8
fi
if [ "$PERSISTENT_STATE" = "paused" ]; then
    chmod 600 "$WG_TMP"
    mv -f -- "$WG_TMP" "$WG_CONF"
    ROLLBACK_LIVE_ON_FAILURE=0
fi
if grep -Fqx "# WG-PANEL-PAUSED-BEGIN v1 $CLIENT_PUB" "$WG_CONF"; then
    echo "ERROR: Paused persistent peer remains after resume" >&2
    exit 9
fi
if ! awk '/^[[:space:]]*PublicKey[[:space:]]*=/ {value=$0; sub(/^[^=]*=/, "", value); sub(/#.*/, "", value); gsub(/[[:space:]]/, "", value); print value}' "$WG_CONF" | grep -Fxq "$CLIENT_PUB"; then
    echo "ERROR: Active persistent peer is missing after resume" >&2
    exit 10
fi

chmod 600 "$WG_CONF" "$CLIENT_CONFIG"
SUCCESS=1
echo "Client '$CLIENT_NAME' resumed successfully"
