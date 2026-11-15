# Happ subscription presentation

The standard subscription is named **🛡️ Kabagun VPN**. Its three entries describe
routing independently of the underlying transport:

| Entry | Caption |
| --- | --- |
| 🌐 Всё через VPN | Весь интернет через VPN |
| 🧠 Умный VPN | Сайты из списка через VPN |
| 🏡 РБ/РФ напрямую | РБ/РФ мимо · остальное VPN |

The announcement shows unlimited service, the device's DNS policy, the available
modes and the traffic accounting period. The website button opens the device's
panel page; the support button opens the panel homepage.

Traffic metadata contains actual recorded upload and download bytes. A zero total
means unlimited service, not a made-up quota. Missing or uncertain counters are
omitted. The presentation does not change traffic collection or refresh timing.

Happ receives the title and announcement as UTF-8 Base64 headers. Titles fit its
25-character limit, captions fit 30 characters, and announcements fit 200
characters. No provider-specific advanced banner or client controls are required.

In Happ desktop 4.7.2, rows still show transport details below their names rather
than the exported captions. The shared announcement remains visible above the
three entries. Its icon, names and status fit without clipping in the inspected
desktop layout.

Existing installations receive the presentation on their next subscription update,
or through the subscription's refresh button. Credentials, routing rules, DNS
settings and tunnel settings remain identical.

Reference: [Happ application management](https://github.com/HappDev/happ_su/blob/main/dev-docs/app-management.md).
