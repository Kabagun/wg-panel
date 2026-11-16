# Ordinary DNS by default

Family filtering is retired for all accounts. New WireGuard downloads and all
three Happ profiles use ordinary **1.1.1.1 and 8.8.8.8**. Stored protection flags
and permanent locks are retained privately for restoration but have no effect.
Family UI, DNS-exception requests and family administrator actions are unavailable.
Smart VPN domain proposals remain available and keep their administrator review.

Home-router DNS uses the same ordinary upstream pair. KVAS domain routing and
VPN tunnels are independent and remain unchanged. Family-only DNS guards and
scheduled reconcilers must be disabled as part of the operator migration; merely
changing the displayed DNS addresses is insufficient.

The former central DNS endpoint and family handlers are removed. There is no
compatibility bridge for previously imported profiles referencing that endpoint.
Update or recreate those profiles; do not add transitional resolver redirects.

Refresh the subscription and reconnect Happ to receive the ordinary profiles and
remove old client-side family restrictions. Never rewrite stored WG identities
just to change DNS: modern credential bindings include their raw configuration.

The implementation defaults to disabled. Its archived operator restore switch is
`WG_PANEL_FAMILY_PROTECTION_ENABLED=1`. Restoration also requires the matching
server/router filter configuration and scheduled jobs; changing this switch
alone is insufficient. No user-facing route can activate the archived feature.

The Git branch `backup/family-dns-2026-11-16` preserves the original implementation,
17 public domain exceptions and `docs/family-dns-restore.md`. Private configs,
credentials and account state remain solely in private on-device backups.
