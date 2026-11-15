# Happ subscription presentation

The standard subscription is named **🛡️ Kabagun VPN**. Its three entries describe
routing independently of the underlying transport:

| Entry | Caption |
| --- | --- |
| 🌐 Всё через VPN | Весь интернет через VPN |
| 🧠 Умный VPN | AI и сервисы из списка → VPN |
| 🏡 РБ/РФ напрямую | РБ/РФ мимо · остальное VPN |

Exported server names start with `🇫🇮` before the mode emoji, so Happ renders the
Finnish server flag in its native icon position. The flag identifies the current
VPN exit, not the countries bypassed by regional routing. See [Happ's flag and
emoji convention](https://www.happ.su/main/ru/dev-docs/emoji).

The announcement shows unlimited service, explicit family protection on/off,
explanations of all three modes and the calendar month being counted. Smart VPN
sends AI and other services from the administrator's list through the VPN; other
destinations go directly.

Only `profile-web-page-url` is emitted. It opens device details without a sign-in
screen using a purpose-separated HMAC capability derived from the current account,
device and subscription nonce. It does not create or modify an account session.
The page is read-only: it shows the connection QR, import/download actions, mode
explanations and monthly usage. Other devices, account administration and destructive
actions remain behind normal authentication. Rotating the subscription link revokes
the page link as well. Paused, removed or unapproved identities fail closed.

Traffic metadata contains recorded upload and download bytes for the current
calendar month in Europe/Minsk. The next month starts at zero; up to 24 observed
months are retained. A zero quota total means unlimited service. Missing or uncertain
counters are omitted rather than inferred from legacy rx/tx history.

Version 2 adds monthly buckets while preserving cumulative totals and raw Xray
checkpoints. A v1 total can seed its start month only; older v1 trackers begin a new
monthly baseline at migration, with no invented backfill. Deltas at a month boundary
belong to the sample time, with approximately one polling interval of uncertainty.
Direct traffic and transport overhead are outside these Xray payload counters.

Happ receives the title and announcement as UTF-8 Base64 headers. Titles fit its
25-character limit, captions fit 30 characters, and announcements fit 200
characters. No provider-specific advanced banner or client controls are required.

In Happ desktop 4.7.2, rows still show transport details below their names rather
than the exported captions. The shared announcement carries the routing
explanations above the three entries.

Existing installations receive the presentation on their next subscription update,
or through the subscription's refresh button. Credentials, routing rules, DNS
settings and tunnel settings remain identical.

Reference: [Happ application management](https://github.com/HappDev/happ_su/blob/main/dev-docs/app-management.md).
