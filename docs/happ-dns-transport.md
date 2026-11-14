The private account-scoped TCP DNS trial applies to both Xray's internal lookups
and plaintext DNS received from Happ's native TUN. The configured resolvers and
account family policy are preserved; there is no additional public fallback.

UDP is the normal transport and the preferred starting point. TCP is a diagnostic
fallback, not an unconditional performance improvement. Through a stream proxy,
fresh TCP DNS lookups can open new upstream connections for each query. The
internal cache helps repeated names but does not remove that first-query setup
cost. Compare both transports through the same native client and the same
resolver policy before retaining a TCP override.

The private data file `happ_dns_transport.json` has this shape:

```json
{"version": 1, "accounts": {"<current-account-id>": "tcp"}}
```

Use the actual opaque account identifier only in private runtime data. Omitted
accounts retain UDP. Removing an entry restores UDP on the next subscription
refresh and reconnect; account recreation does not inherit the old entry.
Malformed policy fails the Happ export rather than falling back to a different
DNS server. Existing tunnels remain active while the export policy changes.

Internal DNS servers use TCP URLs such as `tcp://192.0.2.53`, while the native
Happ routing header retains a plain DNS IP. Internal lookups follow the VPN rule.
Users must refresh the subscription and reconnect to apply updated exports.
Changing this private export policy requires no VPN, DNS, or web-service restart;
it does not modify stored WireGuard configurations or running tunnels.

For TCP exports, A queries enter the internal resolver cache. This lets an app's
DNS lookup and a later sniffed `ForceIPv4` connection share the same answer.
AAAA and other types remain transparent because the internal `UseIPv4` resolver
would otherwise suppress AAAA. Transparent forwarding rewrites its transport to
TCP, including when the application sends UDP to the native DNS address.

If a TCP export already contains multiple DNS servers, standard Xray parallel
querying starts them together. A positive answer can return without waiting for
the first server to time out. The server list and per-server deadlines remain
unchanged. Negative answers may still wait for the other selected server. A
single protected resolver stays single, and default UDP exports are unchanged.

This fixes duplicate uncached lookups and serial fallback overhead; it does not
prove that all bank, mail, or mobile TUN failures are DNS failures. An access-log
route marked `accepted` does not confirm TLS or application completion.

A four-second `record not found` lookup means Xray did not obtain a matching
record before its deadline. It does not identify which hop lost the response,
or prove that UDP caused every application delay.

Runtime verification uses the installed client core with synthetic loopback
DNS. Check UDP/TCP application input, cached A reuse, NXDOMAIN/NODATA/SERVFAIL,
AAAA/MX/TXT/HTTPS forwarding, a silent UDP backend, and a silent first TCP
resolver. Keep these tests separate from native TUN and authenticated app tests.

Protocol semantics follow the official Xray documentation:

- [DNS outbound](https://xtls.github.io/en/config/outbounds/dns.html)
- [Built-in DNS and parallel lookup](https://xtls.github.io/en/config/dns.html)

The private admin comparison binding also accepts optional `client_dns_only: true`.
This opt-in changes only the six copied comparison entries: `routeOnly: true`
retains the application's resolved destination, and `domainStrategy: AsIs` uses
that original IP for IP/country rules and the sniffed domain for domain rules.
The native Happ routing header uses the same strategy. Normal subscriptions and
the two source exports remain unchanged; disabling the flag restores the baseline.

This is client/system destination resolution, not a `localhost` resolver override.
All configured family/ordinary DNS addresses, plaintext DNS forwarding, policies,
and credentials remain intact. Requests submitted to a proxy as hostnames may
still need resolution to establish the connection. Numeric IPv6 destinations are
retained too; the existing `ForceIPv4` hostname setting does not translate them.
Verify actual phone IPv6 reachability before expanding this comparison-only pilot.

Native Happ Tunnel DNS and Xray's JSON DNS are separate settings. For JSON
subscriptions, Happ uses the provider routing profile's tunnel DNS locally;
those fields are not injected into the provider JSON. The app's "Use DNS from
JSON" option concerns the tunnel DNS source. Its disabled state alone is not
evidence that the JSON `dns` block was removed. See the official
[Happ routing documentation](https://github.com/HappDev/happ_su/blob/main/dev-docs/routing.md).

When the native client exposes a loopback SOCKS listener, compare a bounded
public resource through the current TUN and directly into that same core.
Keep the selected profile and core PID stable; do not start another tunnel or
core for this check. This separates the TUN front end from the shared core path
without disconnecting the VPN. TLS sniffing can replace a pinned IP, so retain
that limitation. A very short local TCP connect time may be tunnel interception,
not the remote server's RTT. Measure TLS completion, first byte and body transfer
separately, and do not treat previously cached browser/mail content as a fresh
application test.

An optional private `reference_control: true` requires `client_dns_only: true`.
It appends one ordinary Smart control to the admin comparison, preserving the
first six entries exactly. The control reverses the same two public resolvers,
uses UDP DNS with the A-query cache, and blocks QUIC after the DNS routing guards.
Its SOCKS/HTTP tags identify control activity in subsequent client logs. It uses
the same VLESS credentials and server; it does not change account filtering or
the original subscriptions. This compares a bundle of client behaviors inspired
by a working reference and cannot isolate their individual causal contributions.
