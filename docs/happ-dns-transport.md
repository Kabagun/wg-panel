Happ's internal resolver can use TCP to the same account resolver for a scoped
transport trial. This does not change the resolver, family policy, domain list,
raw-DNS forwarding, TUN engine, or classic WireGuard configuration.

The private data file `happ_dns_transport.json` has this shape:

```json
{"version": 1, "accounts": {"<current-account-id>": "tcp"}}
```

Use the actual opaque account identifier only in private runtime data. Omitted
accounts retain UDP. Removing an entry restores UDP on the next subscription
refresh and reconnect; account recreation does not inherit the old entry.
Malformed policy fails the Happ export rather than falling back to a different
DNS server. Existing tunnels remain active while the export policy changes.

The generated Xray DNS server becomes `tcp://192.0.2.53` (or a bracketed IPv6
address), while the native Happ routing header retains a plain DNS IP. Internal
queries continue to follow the VPN routing rule. The user must refresh the
subscription and reconnect to apply an updated export.

A four-second `record not found` lookup indicates that Xray did not obtain a
matching record before its deadline. It does not identify which network hop
lost the response. A healthy TCP trial is a mitigation test, not proof that
UDP transport caused every reported application delay.
