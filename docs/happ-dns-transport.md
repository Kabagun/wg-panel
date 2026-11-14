The private account-scoped TCP DNS trial applies to both Xray's internal lookups
and plaintext DNS received from Happ's native TUN. The configured resolvers and
account family policy are preserved; there is no additional public fallback.

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
