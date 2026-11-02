#!/bin/bash
set -Eeuo pipefail
umask 077

# This script owns only the table below.  It must never flush or replace an
# administrator-owned nftables table: the application passes the complete
# desired safe-client set and the generated nft batch touches this table only.
TABLE_FAMILY="inet"
TABLE_NAME="wg_panel_safe_dns"
SET_NAME="safe_clients"
DOH_SET_NAME="public_dns_v4"
WG_DIR="${WG_DIR:-/etc/wireguard}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
NFT_RULES_TMP=""

error() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ "$WG_INTERFACE_NAME" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || error "Invalid WireGuard interface name"

cleanup() {
    local status=$?
    if [ -n "${NFT_RULES_TMP}" ]; then
        rm -f -- "${NFT_RULES_TMP}"
    fi
    exit "$status"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || error "safe DNS firewall changes require root"
for command_name in nft flock mktemp sort; do
    command -v "$command_name" >/dev/null || error "Required command '$command_name' is unavailable"
done

install -d -m 700 "$WG_DIR"
exec 9>"$WG_DIR/.wg-panel-safe-dns.lock"
flock -x 9

# Optional operator-owned endpoint for a shared local filtering resolver.
# Without this file the existing Cloudflare Family behavior is preserved.
DNS_TARGET="1.1.1.3:53"
if [ -f "$WG_DIR/safe-dns-target" ]; then
    DNS_TARGET=$(<"$WG_DIR/safe-dns-target")
fi
if [[ ! "$DNS_TARGET" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,5})$ ]]; then
    error "Invalid safe DNS target; expected IPv4:port"
fi
for target_octet in "${BASH_REMATCH[@]:1:4}"; do
    (( 10#$target_octet <= 255 )) || error "Invalid safe DNS target address"
done
target_port="${DNS_TARGET##*:}"
(( 10#$target_port >= 1 && 10#$target_port <= 65535 )) || error "Invalid safe DNS target port"

if [ "${1:-}" != "--sync" ]; then
    echo "Usage: $0 --sync [10.0.0.2 ... 10.0.0.254]" >&2
    exit 2
fi
shift

declare -A seen_octets=()
safe_octets=()
for client_ip in "$@"; do
    if [[ ! "$client_ip" =~ ^10\.0\.0\.([1-9][0-9]{0,2})$ ]]; then
        error "Invalid WireGuard client address '$client_ip'"
    fi
    octet="${BASH_REMATCH[1]}"
    if (( octet < 2 || octet > 254 )); then
        error "WireGuard client address must be in 10.0.0.2-10.0.0.254"
    fi
    if [ -z "${seen_octets[$octet]+x}" ]; then
        seen_octets[$octet]=1
        safe_octets+=("$octet")
    fi
done

if [ "${#safe_octets[@]}" -gt 0 ]; then
    # Numeric sort makes repeated reconciliation produce byte-for-byte stable
    # input and keeps duplicate/ordering differences out of nft transactions.
    mapfile -t safe_octets < <(printf '%s\n' "${safe_octets[@]}" | sort -n)
fi

table_exists=0
if nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
    table_exists=1
fi

NFT_RULES_TMP=$(mktemp "${TMPDIR:-/tmp}/wg-panel-safe-dns.XXXXXX")
chmod 600 "$NFT_RULES_TMP"

if [ "${#safe_octets[@]}" -eq 0 ]; then
    # No enabled devices means no managed policy should remain.  Missing table
    # is already the desired state, so it is intentionally idempotent.
    if [ "$table_exists" -eq 1 ]; then
        printf 'delete table %s %s\n' "$TABLE_FAMILY" "$TABLE_NAME" >"$NFT_RULES_TMP"
        nft -f "$NFT_RULES_TMP"
    fi
    exit 0
fi

# Delete and recreate only the table owned by this helper. In an nft batch the
# delete/add sequence is one atomic transaction, so a failed parse or kernel
# commit leaves the previous managed policy intact and repeated syncs cannot
# collide with named sets/chains left by a table flush.
if [ "$table_exists" -eq 1 ]; then
    printf 'delete table %s %s\n' "$TABLE_FAMILY" "$TABLE_NAME" >"$NFT_RULES_TMP"
else
    : >"$NFT_RULES_TMP"
fi
printf 'add table %s %s\n' "$TABLE_FAMILY" "$TABLE_NAME" >>"$NFT_RULES_TMP"

cat >>"$NFT_RULES_TMP" <<EOF
add set $TABLE_FAMILY $TABLE_NAME $SET_NAME { type ipv4_addr; }
add element $TABLE_FAMILY $TABLE_NAME $SET_NAME {
EOF
for octet in "${safe_octets[@]}"; do
    printf '  10.0.0.%s,\n' "$octet" >>"$NFT_RULES_TMP"
done
cat >>"$NFT_RULES_TMP" <<EOF
}
# Dedicated public resolver addresses only; no shared Google/Apple/CDN ranges.
# Keep aligned with their documented DNS endpoints, not web-service addresses:
# developers.cloudflare.com/1.1.1.1/ip-addresses/
# developers.google.com/speed/public-dns/docs/using
# docs.quad9.net/services/ and adguard-dns.io/en/public-dns.html
add set $TABLE_FAMILY $TABLE_NAME $DOH_SET_NAME { type ipv4_addr; }
add element $TABLE_FAMILY $TABLE_NAME $DOH_SET_NAME {
    1.1.1.1, 1.0.0.1, 1.1.1.2, 1.0.0.2, 1.1.1.3, 1.0.0.3,
    8.8.8.8, 8.8.4.4,
    9.9.9.9, 149.112.112.112, 9.9.9.10, 149.112.112.10,
    9.9.9.11, 149.112.112.11, 9.9.9.12, 149.112.112.12,
    94.140.14.14, 94.140.15.15, 94.140.14.15, 94.140.15.16, 94.140.14.140, 94.140.14.141
}
add chain $TABLE_FAMILY $TABLE_NAME prerouting { type nat hook prerouting priority -100; policy accept; }
add rule $TABLE_FAMILY $TABLE_NAME prerouting iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME udp dport 53 dnat ip to $DNS_TARGET
add rule $TABLE_FAMILY $TABLE_NAME prerouting iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME tcp dport 53 dnat ip to $DNS_TARGET
add chain $TABLE_FAMILY $TABLE_NAME forward { type filter hook forward priority -200; policy accept; }
add rule $TABLE_FAMILY $TABLE_NAME forward iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME udp dport 853 counter drop
add rule $TABLE_FAMILY $TABLE_NAME forward iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME tcp dport 853 counter drop
# HTTPS/HTTP3, DNSCrypt, and Quad9's documented alternate DNS/DoT ports.
add rule $TABLE_FAMILY $TABLE_NAME forward iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME ip daddr @$DOH_SET_NAME tcp dport { 443, 5443, 8853, 9953 } counter drop
add rule $TABLE_FAMILY $TABLE_NAME forward iifname "$WG_INTERFACE_NAME" ip saddr @$SET_NAME ip daddr @$DOH_SET_NAME udp dport { 443, 5443, 8853, 9953 } counter drop
EOF

# IPv6 is not allocated to peers: generated profiles capture ::/0 and server
# peer AllowedIPs authorize only each IPv4 /32. Keep that boundary in place.
# These IPv4-scoped rules cannot control native/off-tunnel IPv6 or arbitrary
# HTTPS proxies/VPNs on unmanaged devices. Do not block wg0 IPv6 globally: the
# managed selection currently identifies peers by their IPv4 source address.

# nft applies a file as one transaction: if parsing, validation, or the
# kernel commit fails, the previous managed table remains intact.
nft -f "$NFT_RULES_TMP"
