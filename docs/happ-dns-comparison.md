An administrator can opt one existing ordinary Happ device into a six-entry DNS
comparison subscription. All three routing modes are retained, each with family
DNS and ordinary DNS. Other subscriptions and single-mode downloads stay unchanged.

The private `happ_comparisons.json` data file explicitly binds the administrator
subscription and an already-provisioned protected source:

```json
{
  "version": 1,
  "devices": {
    "<ordinary-admin-device-id>": {
      "account_id": "<current-admin-account-id>",
      "family": {
        "wg_name": "<existing-family-device-id>",
        "account_id": "<current-family-account-id>"
      }
    }
  }
}
```

Keep actual device/account identifiers in private runtime data. A comparison
subscription contains credentials for both explicitly selected sources; share
its QR only with the authorized administrator. Family entries use the protected
source's authenticated server policy and accounting. Ordinary entries use the
ordinary administrator source. No new peers or server users are provisioned.

Current ownership, account identity, approval, pause/deletion state and family
policy are checked on every export. Only VLESS/REALITY sources are supported.
Stale bindings fail closed. A family-locked subscription cannot expose ordinary
variants through this feature.

Happ receives six complete JSON configurations with distinct names. Its shared
native-TUN routing header uses the family resolver as an anchor; each selected
JSON rewrites port 53 to its own resolver. Proxy IPs include both resolver sets,
and GeoIP tags cover the regional modes. Normal subscriptions retain their
same-DNS header validation. The comparison title is UTF-8/base64 encoded.

The ordinary device's subscription token/URL can remain stable while its display
name changes. Refresh the subscription after enabling the private comparison.
