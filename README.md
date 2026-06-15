# wg-panel

Minimal Flask web panel for a WireGuard server.

It supports user registration, admin approval, per-user device limits, device
creation/removal, QR/config download, traffic view, password reset links, and
optional Telegram notifications.

## What Is Versioned

- `app.py` - Flask application.
- `wireguard/*.sh` - helper scripts used by the panel to add/list/remove peers.
- `systemd/wg-panel.service` - systemd unit template.
- `nginx/*.conf` - nginx reverse proxy and rate-limit templates.
- `.env.example` - environment file template.

Runtime data is intentionally not versioned:

- `/opt/wg-panel/data/` with users, traffic, device metadata, and Flask secret.
- `/etc/wireguard/*.key`, `/etc/wireguard/wg0.conf`, and client configs.
- TLS private keys and certificates.
- Python virtual environments and caches.

## Install

Run as `root` on the VPN server.

```bash
apt-get update
apt-get install -y python3-venv wireguard qrencode nginx certbot

git clone git@github.com:Kabaye/wg-panel.git /opt/wg-panel
python3 -m venv /opt/wg-panel/venv
/opt/wg-panel/venv/bin/pip install -r /opt/wg-panel/requirements.txt
```

Install helper scripts:

```bash
install -m 700 /opt/wg-panel/wireguard/add-client.sh /etc/wireguard/add-client.sh
install -m 700 /opt/wg-panel/wireguard/remove-client.sh /etc/wireguard/remove-client.sh
install -m 700 /opt/wg-panel/wireguard/list-clients.sh /etc/wireguard/list-clients.sh
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
- `WG_PANEL_TELEGRAM_BOT_TOKEN` and `WG_PANEL_TELEGRAM_CHAT_ID`, if Telegram notifications are needed

Install and start the service:

```bash
cp /opt/wg-panel/systemd/wg-panel.service /etc/systemd/system/wg-panel.service
systemctl daemon-reload
systemctl enable --now wg-panel
systemctl status wg-panel --no-pager
```

## Nginx

Replace `vpn.example.com` in `nginx/wg-panel.conf` with the real domain, then:

```bash
cp /opt/wg-panel/nginx/wg-panel-limits.conf /etc/nginx/conf.d/wg-panel-limits.conf
cp /opt/wg-panel/nginx/wg-panel.conf /etc/nginx/sites-available/wg-panel
ln -sfn /etc/nginx/sites-available/wg-panel /etc/nginx/sites-enabled/wg-panel
nginx -t
systemctl reload nginx
```

Issue/renew TLS certificates with certbot or another ACME client before enabling
the HTTPS server block.

## Checks

```bash
systemctl is-active wg-panel
curl -fsS http://127.0.0.1:8080/healthz
wg show
journalctl -u wg-panel -n 100 --no-pager
```
