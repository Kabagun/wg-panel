Happ subscriptions expose standard presentation metadata alongside their JSON:

- `subscription-userinfo`: measured client upload/download bytes and `total=0`
  for the current unlimited service. No quota or expiration date is invented.
- `profile-web-page-url`: the authenticated device page on the configured panel.
- `support-url`: the same panel's public site, without a subscription credential.
- `announce`: a compact UTF-8/base64 description of three normal routing modes
  or six DNS comparison entries, the measurement period, and unlimited usage.

The period starts when the new presentation counter is first sampled. Earlier
monthly history is preserved. That history combines legacy WireGuard and modern
transport columns with different direction conventions, so it is not imported
into new upload/download totals. The independent `happ_subscription_usage` entry
uses explicit Xray uplink/downlink counters and survives process generations.
Missing counters do not reset positive checkpoints or double-count later samples.

Collection stays in the existing background sampler. Public subscription GETs
read cached measurements without launching commands or calling the Xray API.
Happ displays fresh metadata when the subscription refreshes; its existing
one-hour interval is unchanged. The announced start date is displayed in Minsk.

A normal subscription reports its logical device. The private comparison sums
its two explicitly bound source devices once each, not once per mode. Usage of
those same credentials outside the comparison group is included in those device
counters. Other devices and account traffic are excluded.

Links preserve the trusted HTTPS panel origin and never contain subscription
tokens. Unknown or malformed presentation data omits the optional traffic status
instead of inventing usage or making VPN configuration unavailable.

Supported client fields follow the official Happ documentation:
https://github.com/HappDev/happ_su/blob/main/dev-docs/app-management.md
