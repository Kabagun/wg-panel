# wg-panel

Minimal Flask web panel for a WireGuard server.

It supports user registration, admin approval, per-user device limits, device
creation/removal, QR/config download, traffic view, password reset links, and
optional Telegram notifications. New registrations require a public Telegram
username. Administrators can opt individual users into monthly payment
reminders without exposing payment data in customer dashboards.

Users can permanently enable **Safe internet for their entire account**. Every
current and future VPN profile then inherits protection. Downloaded configs and
QR codes use Cloudflare Family DNS (`1.1.1.3`, `1.0.0.3`) to block adult and
malicious domains. The installed nftables helper enforces each protected IPv4
WireGuard address: DNS TCP/UDP port 53 is redirected to Cloudflare Family and
DNS-over-TLS port 853 is blocked. Ordinary WireGuard clients are not matched by
the managed firewall set. Downloaded configs and QR codes continue to reflect
the selected DNS. Enabling server enforcement is immediate. After a
manual server reset, a device that previously imported the Family
DNS config must import the updated config to change its local DNS setting.

The dashboard and device pages show the account scope before confirmation. Both
`POST /account/safe-internet` and the existing authorized device policy endpoint
require `safe_internet=on` and `safe_internet_confirmed=on` for first activation.
The account entry is saved only after protection covers every current owner
address. Stale forms, direct POSTs, administrator roles and forged override fields
cannot disable it. Existing per-device opt-ins remain effective without silently
locking their accounts; **Protect all account profiles** confirms account policy
in place without any off interval. Other owners retain their existing choices.

Permanent policy lives independently in `data/account_policy.json`, keyed by
normalized login name, with schema `{"version":1,"owners":{"example":{"safe_internet_locked":true}}}`.
Deleting devices, changing profile names, deleting an account, or registering the
same login again does not clear this registry. Downloads, QR codes, startup,
pause/resume, deletion and future provisioning derive effective protection from
both this registry and legacy device preferences. Malformed policy fails closed.
Back up this file together with users, device metadata and configurations.
Resetting a policy requires deliberate manual server maintenance through SSH;
there is no browser reset path.

New protected profiles use `add-client.sh NAME --prepare`, which reserves the
address and writes a restart-safe paused peer envelope without a live peer.
The panel publishes an incomplete provisioning checkpoint, adds the allocated
address to server enforcement, then calls `set-client-state.sh NAME resume`.
Incomplete profiles cannot be viewed or downloaded. Failed provisioning removes
the peer before dropping its safe address; a failed cleanup retains the protected
checkpoint for manual recovery. The permanent owner policy is never rolled back
by a failed device creation. Install the updated helper **before** deploying the
account-policy application: the panel checks its version marker without running
an old helper and verifies the actual inactive envelope before resume.

These controls apply to one login identity and traffic through this VPN. An
administrator can still create a different unrelated identity. Removing the VPN
profile or using another connection also lies outside the panel's control and
requires managed-device controls. Some encrypted DNS services and proxies can
still bypass domain filtering.

## Interface

The panel uses a light, responsive interface in Russian or English, selected by
the browser language. It includes device cards, local device/user search,
QR/config setup, account-wide Safe internet controls, and administrator pages for
approval, limits, payment reminders and monthly traffic. Mobile tables become
labelled rows, while navigation collapses into a menu.

Administrators can pause an approved user's VPN on **all devices**, then resume
it with the same configurations, keys and addresses. The user list has access
status filters, explicit Pause/Resume actions and a separate error state for
incomplete pauses. A paused user can sign in and read/download saved configs,
but cannot create, modify or delete devices. Their dashboard and device pages
explain the pause; administrators remain able to manage or delete those devices.
Payment settings and reminder scheduling do not change when access is paused.

Templates are rendered once with Jinja autoescaping. Styles, icons and JavaScript
are served locally with the Python package; no CDN, frontend build or additional
runtime is required. Forms retain their existing POST/CSRF and ownership checks.
JavaScript adds search, password visibility, accessible deletion confirmation,
clipboard feedback and Safe internet confirmation. Canceling the first-enable
dialog leaves protection unchanged; confirming saves through the existing
CSRF-protected form and reloads the state, QR and configuration together. Locked
switches stay disabled for every web role. The switch requires JavaScript; other
forms and navigation remain available without it.

## What Is Versioned

- `src/wg_panel/` - Flask application package.
- `scripts/*.sh` - helper scripts used by the panel to add/list/remove peers.
- `pyproject.toml` - Python package metadata and `wg-panel` entry point.
- `requirements.txt` - simple deployment install wrapper.
- `.env.example` - environment file template.

Runtime data is intentionally not versioned:

- `/opt/wg-panel/data/` with users, traffic, device metadata, permanent account
  policies, and Flask secret.
- `/etc/wireguard/*.key`, `/etc/wireguard/wg0.conf`, and client configs.
- Runtime nftables state (including `inet wg_panel_safe_dns`).
- Web server, TLS, and systemd configuration.
- TLS private keys and certificates.
- Python virtual environments and caches.

## Install

Run as `root` on the VPN server.

```bash
apt-get update
apt-get install -y python3-venv wireguard nftables qrencode

git clone git@github.com:Kabagun/wg-panel.git /opt/wg-panel
python3 -m venv /opt/wg-panel/venv
/opt/wg-panel/venv/bin/pip install -r /opt/wg-panel/requirements.txt
```

Install helper scripts:

```bash
install -m 700 /opt/wg-panel/scripts/add-client.sh /etc/wireguard/add-client.sh
install -m 700 /opt/wg-panel/scripts/remove-client.sh /etc/wireguard/remove-client.sh
install -m 700 /opt/wg-panel/scripts/set-client-state.sh /etc/wireguard/set-client-state.sh
install -m 700 /opt/wg-panel/scripts/list-clients.sh /etc/wireguard/list-clients.sh
install -m 700 /opt/wg-panel/scripts/safe-dns.sh /etc/wireguard/safe-dns.sh
```

Create environment file:

```bash
install -d -m 700 /etc/wg-panel
cp /opt/wg-panel/.env.example /etc/wg-panel/wg-panel.env
nano /etc/wg-panel/wg-panel.env
chmod 600 /etc/wg-panel/wg-panel.env
```

At minimum set:

- `WG_PANEL_DOMAIN`
- `WG_PANEL_PUBLIC_IP`, optionally, to show VPN endpoint GeoIP when a registration comes from a private VPN/LAN address.
- `WG_PANEL_ADMIN_PASSWORD` before first startup
- `WG_PANEL_TRUST_PROXY=1` when the panel is served through nginx or another trusted reverse proxy.
- `WG_PANEL_TELEGRAM_BOT_TOKEN` and `WG_PANEL_TELEGRAM_CHAT_ID`, if Telegram notifications are needed.
- `WG_PANEL_TELEGRAM_WEBHOOK_SECRET`, a random secret used to authenticate Telegram callbacks.
- `WG_PANEL_PAYMENT_ACCOUNT` and `WG_PANEL_PAYMENT_ERIP_PATH` before payment reminders are enabled.
- `WG_PANEL_PAYMENT_TIME=09:00` and `WG_PANEL_PAYMENT_TIMEZONE=Europe/Minsk` for reminder scheduling.
- `WG_PANEL_PAYMENT_USER_DELAY_SECONDS=60` to separate complete reminder batches for different users.

New registration notifications use the ProxyFix-normalized client address,
browser metadata, and public IP details from the HTTPS `ipwho.is` API. Private or local client IPs cannot be
geolocated directly; in that case the notification can show the VPN endpoint
GeoIP from `WG_PANEL_PUBLIC_IP` or the resolved `WG_PANEL_DOMAIN`. Lookup
failures do not block registration.

Payment reminders are administrator-only. The configured day is a permanent
monthly anchor: a day that is absent from a short month uses that month's last
day, then returns to the original day in the next month. Prices are derived
from the configured device limit: 1–3 devices cost 5 BYN, 4–5 cost 7 BYN, and
unlimited costs 15 BYN. Existing users remain disabled until an administrator
sets a Telegram username and payment day and explicitly enables reminders.
When several users are due together, the two messages for one user are sent as
one batch, followed by the configured delay before the next user's batch.

On startup, the panel migrates legacy WireGuard filenames to exact owner/device
metadata. The migration aborts rather than guessing when one filename matches
multiple usernames. Generated `u<length>-<username>-<device>` names with missing
ownership are never interpreted as legacy filenames; restore their authoritative
metadata before startup. Ordinary device listing does not run migrations or
rewrite metadata. To inspect production safely before restarting, run:

```bash
/opt/wg-panel/venv/bin/python -c \
  'from wg_panel.wireguard import migrate_device_metadata; print(migrate_device_metadata(dry_run=True))'
```

Startup also reconciles the server-side Safe internet policy from persisted
device metadata and permanent account policy. If any profile is effectively safe but `/etc/wireguard/safe-dns.sh`
or nftables cannot apply the policy, startup aborts rather than serving an
unenforced configuration. With no safe devices, a fresh install may start
before the helper has ever created its managed table. The helper owns only
`inet wg_panel_safe_dns`; do not put unrelated rules in that table. It is
idempotent and atomically replaces only its own client set and rules. To inspect
the current managed state without changing it, run:

```bash
nft list table inet wg_panel_safe_dns
```

To use an operator-managed filtering DNS server instead of Cloudflare Family,
create the root-owned file `/etc/wireguard/safe-dns-target` containing one
`IPv4:port` endpoint, for example `10.0.0.1:18004`, then reconcile Safe internet.
The helper validates the entire endpoint before applying any nftables changes.
The resolver must be running and reachable through the host firewall first.
Only devices in the managed safe-client set are redirected; other clients retain
their existing DNS. Downloaded configurations still use the Family DNS addresses,
which the server redirects to the configured endpoint for opted-in devices.
Removing this file restores the default destination on the next reconciliation.

Install the helper before provisioning new devices. Provisioning reconciles the
managed table first so an address left fail-closed by an earlier cleanup error
cannot be reassigned to an ordinary client.

The implementation currently covers IPv4 clients in `10.0.0.2` through
`10.0.0.254` on `wg0`. IPv6 traffic and a production server's existing NAT or
forwarding policy are intentionally outside this repository's runtime state;
verify that the host already forwards and masquerades WireGuard IPv4 traffic
before enabling Safe internet.

Start the application through the server's deployment layer. Do not store
server-specific systemd, nginx, TLS, or domain configuration in this repository.
Run one application process: device lifecycle transactions and request limits
are coordinated within that process. Multiple WSGI workers are not supported.
The installed entry point is:

```bash
/opt/wg-panel/venv/bin/wg-panel
```

For ad-hoc local runs after installation:

```bash
/opt/wg-panel/venv/bin/python -m wg_panel
```

## Security lifecycle

Each account has an immutable random `account_id`; cookies must match that
identity and its password-reset session version. Existing accounts receive an
identity during startup or their first login. Cookies issued before this change
require a fresh login. Deleted usernames may be registered again without reusing
the previous account's sessions.

Account deletion disables the account before enumerating and revoking peers.
If revocation fails, the account remains disabled and cannot be approved again;
repair the reported helper/storage problem and retry deletion. Unowned client
configs or unresolved peer metadata block deletion until ownership is recovered.
Provisioning, migration, policy changes and protected device requests share the
same transaction boundary. Permanent Safe internet policy is inherited from the
owner registry, independently of account and device deletion.

VPN pause is separate from approval and deletion. Install the updated add/remove
helpers **and** `set-client-state.sh` together before using it. Pausing removes
each public key from the live WireGuard interface and wraps its exact persistent
peer block in a commented `WG-PANEL-PAUSED` envelope in `wg0.conf`. This envelope
contains base64-encoded configuration, not encryption; keep the file private and
do not discard these comments or overwrite the file with `wg showconf`/`wg-quick
save`. `SaveConfig=true` is not supported with these managed peer records.
Client files, device metadata and traffic history remain in place; retained
client addresses stay reserved in the allocator. Resuming restores the original
block and reconciles Safe internet before enabling any peer. It does not restart
WireGuard or disturb other users.

The account's restrictive state is saved before peer changes. A partial failure
keeps the account blocked for device changes and displays **Needs attention**;
the panel never reports that every device is disconnected without successful
helper results. Fix the logged helper/storage error and use **Retry pause**.
A failed resume attempts to pause every device again. Startup reapplies saved
pauses before serving requests and aborts if it cannot confirm enforcement.
After a completed pause, WireGuard restart reads the commented configuration
and does not restore paused peers, even if the panel is stopped.

Admin access actions are POST-only and CSRF-protected:

- `POST /admin/users/<username>/pause`: pause all existing devices; repeatable.
- `POST /admin/users/<username>/resume`: restore the retained peer identities.
- `GET /admin/users?status=paused`: filter by access status (`all`, `active`,
  `paused`, `pending`, `attention`, `revoking`).

Administrator accounts, accounts awaiting approval and accounts being deleted
cannot be paused or resumed through these actions. Changing a client's local
IP cannot bypass a removed public key or the server's per-peer `/32` constraint.

Login accepts at most 30 POST attempts per client IP in 60 seconds, in addition
to the existing per-IP/username cooldown. Full limiter storage rejects new keys
until existing restrictions expire instead of evicting active restrictions.

When the bundled HTTP redirect listener is enabled, it admits at most
`WG_PANEL_MAX_REDIRECT_CONNECTIONS` connections (default 32). Each connection
has an absolute `WG_PANEL_REDIRECT_SOCKET_TIMEOUT` deadline (default 5 seconds),
including clients that slowly send incomplete headers. Both settings must be
positive; the listener binds to `WG_PANEL_BIND_HOST`.

## Checks

```bash
systemctl is-active wg-panel
curl -fsS http://127.0.0.1:8080/healthz
wg show
journalctl -u wg-panel -n 100 --no-pager
```

## Code Layout

- `src/wg_panel/core.py` - Flask app object, environment config, user storage, shared helpers.
- `src/wg_panel/i18n.py` - UI strings and translation helper.
- `src/wg_panel/ui.py` - shared autoescaped page renderer and local SVG icons.
- `src/wg_panel/templates/` - shared layout, authentication, device and admin views.
- `src/wg_panel/static/` - local stylesheet, progressive enhancement and favicon.
- `src/wg_panel/auth.py` - login/admin decorators.
- `src/wg_panel/access.py` - account-wide pause/resume and startup reconciliation.
- `src/wg_panel/client_context.py` - registration IP, GeoIP, and browser metadata helpers.
- `src/wg_panel/wireguard.py` - WireGuard client config helpers.
- `src/wg_panel/dns_enforcement.py` - validated server-side Safe internet reconciliation.
- `src/wg_panel/traffic.py` - traffic counters and device metadata storage.
- `src/wg_panel/telegram.py` - Telegram notifications and callback helpers.
- `src/wg_panel/payments.py` - monthly payment dates, pricing, messages, and delivery checkpoints.
- `src/wg_panel/security.py` - CSRF, trusted client address, and request abuse controls.
- `src/wg_panel/routes/` - auth, device, Telegram, traffic, and admin routes.
- `src/wg_panel/runner.py` - startup reconciliation, redirect server, traffic collector, webhook, and Flask.
- `scripts/` - shell helpers installed into `/etc/wireguard`.
