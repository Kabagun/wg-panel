# wg-panel

Minimal Flask web panel for a WireGuard server.

It supports user registration, admin approval, per-user device limits, device
creation/removal, QR/config download, traffic view, password reset links, and
optional Telegram notifications.

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
- `WG_PANEL_ADMIN_PASSWORD` before first startup
- `WG_PANEL_TRUST_PROXY=1` when the panel is served through nginx or another trusted reverse proxy.
- `WG_PANEL_TELEGRAM_BOT_TOKEN` and `WG_PANEL_TELEGRAM_CHAT_ID`, if Telegram notifications are needed.

New registration notifications use the trusted proxy address, browser metadata,
and public IP details from `ip-api.com`. Private or local IPs skip the external
lookup, and lookup failures do not block registration.

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
- `src/wg_panel/routes/` - auth, device, Telegram, traffic, and admin routes.
- `src/wg_panel/runner.py` - startup code for redirect server, traffic collector, webhook, and Flask.
- `scripts/` - shell helpers installed into `/etc/wireguard`.
