# Private modern-transport pilot

Classic WireGuard remains independent. The experimental Happ service has no
Requires, BindsTo or PartOf relationship with WireGuard, DNS or the panel.
Restarting it never requires restarting those services.

Keep `data/happ_rollout.json` at `{"version":1,"enabled":false}`. Administrators
retain access. To admit selected approved ordinary accounts, create a private
`data/happ_pilot_access.json` with `version: 1` and an `account_ids` array of their
current immutable account IDs. Recreated accounts do not inherit admission.
These files, credentials, certificates and infrastructure addresses must never
be committed. There is no automatic public rollout or removal after seven days.

The panel's Safe internet setting governs Happ too. Protected accounts receive
the central family DNS. Ordinary accounts receive public unfiltered DNS.
Both receive all three routing modes: full tunnel, BY/RU IP addresses direct,
and Smart VPN using the administrator's list. Common encrypted DNS endpoints
are blocked in protected client profiles before direct routing is considered.
Every mode has its own bound WG identity; modern transports retain per-device
authentication across modes. Shared Smart VPN
rules keep their existing publication/update path. Subscription refresh remains
one hour. Changing account protection never silently unlocks its permanent policy.

Desktop subscriptions select Happ TUN, which passes traffic through the
configuration's SOCKS inbound with domain sniffing. Verify an actual listed
domain reaching the VPN server; a successful HTTP response alone is not proof
that split routing was applied. Current profiles use IPv4 for direct egress.
Sniffing rewrites the dialing destination to its hostname as well as selecting
the route, so TUN IPv6 literals do not bypass the outbound's IPv4 resolution.
All DNS query types are forwarded to the selected account resolver.

Provision the optional runtime only after testing an official Xray binary and
its release checksum. The reference unit uses `/root/Programs/wg-panel-happ/xray`
and a private generated `/opt/wg-panel/data/happ-xray.json`. It listens on
TCP8443 (VLESS REALITY/Vision) and UDP8443 (Hysteria2); StatsService is restricted
to loopback18012. Open only the two transport ports in the host firewall.
Keep the existing web server on443. Verify the TLS certificate, REALITY target,
ports, resources and automatic service startup before exposing profiles.

If a cloud firewall also protects the server, permit the same TCP and UDP
transport ports there. Opening UFW alone is insufficient. Preserve existing
SSH, web and WireGuard rules, and limit changes to the pilot's server. Verify
both protocols from a different machine or network before declaring them ready:
requests originating on the server do not test the cloud firewall's ingress.

`data/happ_runtime.json` contains `version:1`, `enabled:true`, an absolute
`binary` path, public `host`, certificate `tls_name`, `reality_public_key`, and
`server` options documented in `happ_transports.create_server_config`.
Server private keys and TLS file paths belong only in that private file.
The panel stores per-device credentials separately in
`data/happ_protocol_devices.json`; GET/export does not provision identities.
Explicit provisioning is `happ_runtime.provision(logical_device_name)`.

The service configuration is validated before replacement. Failure while
revoking access stops only the experimental service; it must never restore an
old roster that could admit a paused/deleted account. Pause, resume, deletion
and family policy changes synchronize the authenticated roster. Modern traffic
is attributed to its logical device using independent restart-aware counters.
Modern pilot devices are excluded from automatic inactivity cleanup until the
pilot's separate activity observation has been established.

Validate TCP and UDP end-to-end, authentication rejection, family DNS, concurrent
connections and pause/revoke behavior before enabling the runtime in a pilot.
Happ/client core compatibility and actual performance still require device tests;
a successful server test does not establish that a protocol is faster.
