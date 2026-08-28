# wg-panel

Minimal Flask web panel for a WireGuard server.

It supports user registration, admin approval, per-user device limits, device
creation/removal, QR/config download, traffic view, password reset links, and
optional Telegram notifications. New registrations require a public Telegram
username. Administrators can opt individual users into monthly payment
reminders without exposing payment data in customer dashboards.

Users can enable **Safe internet** separately for each device. Its downloaded
config and QR code then use Cloudflare Family DNS (`1.1.1.3`, `1.0.0.3`) to
block adult and malicious domains. The device must download and import the
updated config; this DNS preference is not server-enforced and can be changed
on the client.

## What Is Versioned

- `src/wg_panel/` - Flask application package.
- `scripts/*.sh` - helper scripts used by the panel to add/list/remove peers.
- `pyproject.toml` - Python package metadata and `wg-panel` entry point.
- `requirements.txt` - simple deployment install wrapper.
- `.env.example` - environment file template.

Runtime data is intentionally not versioned:

- `/opt/wg-panel/data/` with users, traffic, device metadata, and Flask secret.
- `/etc/wireguard/*.key`, `/etc/wireguard/wg0.conf`, and client configs.
- Web server, TLS, and systemd configuration.
- TLS private keys and certificates.
- Python virtual environments and caches.

## Install

Run as `root` on the VPN server.

```bash
apt-get update
apt-get install -y python3-venv wireguard qrencode

git clone git@github.com:Kabagun/wg-panel.git /opt/wg-panel
python3 -m venv /opt/wg-panel/venv
/opt/wg-panel/venv/bin/pip install -r /opt/wg-panel/requirements.txt
```

Install helper scripts:

```bash
install -m 700 /opt/wg-panel/scripts/add-client.sh /etc/wireguard/add-client.sh
install -m 700 /opt/wg-panel/scripts/remove-client.sh /etc/wireguard/remove-client.sh
install -m 700 /opt/wg-panel/scripts/list-clients.sh /etc/wireguard/list-clients.sh
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
multiple usernames. To inspect production safely before restarting, run:

```bash
/opt/wg-panel/venv/bin/python -c \
  'from wg_panel.wireguard import migrate_device_metadata; print(migrate_device_metadata(dry_run=True))'
```

Start the application through the server's deployment layer. Do not store
server-specific systemd, nginx, TLS, or domain configuration in this repository.
The installed entry point is:

```bash
/opt/wg-panel/venv/bin/wg-panel
```

For ad-hoc local runs after installation:

```bash
/opt/wg-panel/venv/bin/python -m wg_panel
```

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
- `src/wg_panel/ui.py` - inline HTML/CSS page builders.
- `src/wg_panel/auth.py` - login/admin decorators.
- `src/wg_panel/client_context.py` - registration IP, GeoIP, and browser metadata helpers.
- `src/wg_panel/wireguard.py` - WireGuard client config helpers.
- `src/wg_panel/traffic.py` - traffic counters and device metadata storage.
- `src/wg_panel/telegram.py` - Telegram notifications and callback helpers.
- `src/wg_panel/payments.py` - monthly payment dates, pricing, messages, and delivery checkpoints.
- `src/wg_panel/security.py` - CSRF, trusted client address, and request abuse controls.
- `src/wg_panel/routes/` - auth, device, Telegram, traffic, and admin routes.
- `src/wg_panel/runner.py` - startup code for redirect server, traffic collector, webhook, and Flask.
- `scripts/` - shell helpers installed into `/etc/wireguard`.
