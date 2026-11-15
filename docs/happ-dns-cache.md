# Account-scoped Happ DNS cache trial

The normal UDP export forwards application DNS questions to the account's
resolver. Xray's routing and `ForceIPv4` lookups use a separate internal cache.
This can require another network lookup for a name the application just resolved.

The private operator policy `data/happ_dns_cache.json` can opt a current account
identity into sharing the internal cache for A questions:

```json
{"version": 1, "accounts": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": true}}
```

The example identity is synthetic. The file is private runtime state and must
not be committed. Missing policy or an account not listed preserves the existing
export. Account recreation does not inherit an old identity's setting. Invalid
policy fails closed. Set the account entry to `false` to return its next export
to the baseline.

The trial changes only the DNS outbound's rules to hijack A questions into the
existing resolver/cache. AAAA and other types retain raw forwarding. Resolver
addresses, UDP transport, family filtering, routing, credentials and classic
WireGuard files are unchanged. Existing TCP DNS trials already use this A path.

The existing internal DNS tag must route to the VPN before the port-53
interception rule, preventing recursive interception. Native clients receive
the change after subscription refresh and reconnection. The policy does not
replace an already running client configuration.

Validate cache misses and repeats separately, alongside AAAA, MX/TXT, NXDOMAIN,
family sinkholes and certificate-verified HTTPS. A warm-cache improvement does
not prove that an intermittent cold lookup or an application's stalled state
has been fixed. Do not generalize a private trial to all accounts from that alone.
