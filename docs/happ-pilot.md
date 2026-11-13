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
the central family DNS and full-tunnel profiles. Ordinary accounts receive
public unfiltered DNS and the three existing routing modes. Shared Smart VPN
rules keep their existing publication/update path. Subscription refresh remains
one hour. Changing account protection never silently unlocks its permanent policy.

Provision the optional runtime only after testing an official Xray binary and
its release checksum. The reference unit uses `/root/Programs/wg-panel-happ/xray`
and a private generated `/opt/wg-panel/data/happ-xray.json`. It listens on
TCP8443 (VLESS REALITY/Vision) and UDP8443 (Hysteria2); StatsService is restricted
to loopback18012. Open only the two transport ports in the host firewall.
Keep the existing web server on443. Verify the TLS certificate, REALITY target,
ports, resources and automatic service startup before exposing profiles.

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
