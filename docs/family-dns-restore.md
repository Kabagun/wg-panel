# Restoring family DNS

This branch preserves the last family-DNS implementation and the public domain
exceptions at retirement on 2026-11-16. It contains no credentials or personal
client configurations. Keep private on-device retirement backups separately.

## Behavior to restore

- Family upstreams: Cloudflare 1.1.1.3 and 1.0.0.3.
- Exception domains in `archive/family-dns-allow-domains.txt` resolve through
  ordinary 1.1.1.1 and 8.8.8.8, including their subdomains.
- The account policy and per-device locks reside in private runtime data; they
  are not in Git and must be restored from the matching private backup.
- The home router uses its authenticated central DNS proxy, with family guard,
  failover and watchdog persistence. KVAS VPN routing domains are independent.

## Safe restoration order

1. Read the applicable access/runtime policies and inspect current private state.
   Back up the current version first; do not overwrite later accounts or keys.
2. Restore the central DNS backend's configuration, installed filtering rules,
   exception state and intended updater timers from the matching private backup.
   Validate the resolver configuration before a DNS-only restart. Check normal
   DNS answers and Cloudflare's harmless category-test sinkhole over UDP and TCP.
3. Restore the panel from this branch, or deliberately re-enable its archived
   implementation using operator setting `WG_PANEL_FAMILY_PROTECTION_ENABLED=1`
   on a retirement-aware version. Validate old account/device lock state and
   synchronize only the owned DNS firewall policy and modern runtime roster.
   Ordinary-account behavior and WG peer identity must remain intact.
4. Restore the router's selected private preimages using the saved on-device
   rollback script. Restore the central backend first: the router rollback
   verifies the family response. Re-enable only family-owned guards/updaters.
   Keep KVAS routing lists, interface configuration and VPN credentials unchanged.
5. Test a normal domain, a listed exception and the harmless family category-test
   domain on both networks/transports; verify unrelated HTTPS and active VPN.
   Wait through at least one scheduled reconciliation interval and check again.
6. Refresh Happ subscriptions and reconnect. Reimport classic client DNS settings
   only when necessary; do not rotate keys to change DNS. Never bulk replace live
   runtime/account files from an older backup without reconciling later changes.

## Portable configuration outline

Family backend (dnsmasq-style, substitute the private listener details):

```ini
port=<PRIVATE_BACKEND_PORT>
listen-address=<PRIVATE_LISTENER_IPV4>
no-resolv
no-hosts
server=1.1.1.3
server=1.0.0.3
```

For each validated exception, generate `server=/example.com/1.1.1.1` and
`server=/example.com/8.8.8.8` entries. The original compiler and tests on this
branch are the authoritative implementation for exception hierarchy and the
additional managed lists. Do not reuse private URLs, tokens or SSH keys in Git.

After retirement the legacy DNS endpoint may remain as an unfiltered forwarder
for already imported clients. Replacing that endpoint or deleting it before all
clients update would break those profiles. Preserve address compatibility.
