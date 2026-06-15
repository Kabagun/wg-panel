import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request

app = Flask("app", root_path=str(Path(__file__).resolve().parents[1]))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)

def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default

def _env_float(name, default):
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default

def _env_bool(name, default):
    raw = os.getenv(name, "1" if default else "0")
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}

# ─── Config ───────────────────────────────────────────────────────────────────
WG_DIR           = os.getenv("WG_PANEL_WG_DIR", "/etc/wireguard")
CLIENTS_DIR      = os.getenv("WG_PANEL_CLIENTS_DIR", f"{WG_DIR}/clients")
DATA_DIR         = os.getenv("WG_PANEL_DATA_DIR", "/opt/wg-panel/data")
USERS_FILE       = f"{DATA_DIR}/users.json"
TRAFFIC_FILE     = f"{DATA_DIR}/traffic.json"
DEVICE_META_FILE = f"{DATA_DIR}/device_meta.json"

# ─── Persistent secret key (survives restarts — sessions stay valid) ──────────
_SECRET_FILE = os.getenv("WG_PANEL_SECRET_FILE", f"{DATA_DIR}/.secret_key")
def _load_secret_key():
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(_SECRET_FILE, "w") as f:
        f.write(key)
    os.chmod(_SECRET_FILE, 0o600)
    return key
app.secret_key = _load_secret_key()

# ─── File locks (prevent race conditions between request threads) ─────────────
_users_lock       = threading.Lock()
_traffic_lock     = threading.Lock()
_device_meta_lock = threading.Lock()

MAX_CONCURRENT_REQUESTS = int(os.getenv("WG_PANEL_MAX_CONCURRENT_REQUESTS", "32"))
_request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

BIND_HOST                    = os.getenv("WG_PANEL_BIND_HOST", "0.0.0.0")
PORT                         = _env_int("WG_PANEL_PORT", 443)
ENABLE_INTERNAL_TLS          = _env_bool("WG_PANEL_ENABLE_INTERNAL_TLS", True)
ENABLE_HTTP_REDIRECT         = _env_bool("WG_PANEL_ENABLE_HTTP_REDIRECT", True)
HTTP_REDIRECT_PORT           = _env_int("WG_PANEL_HTTP_REDIRECT_PORT", 80)
REDIRECT_SOCKET_TIMEOUT_SECS = _env_float("WG_PANEL_REDIRECT_SOCKET_TIMEOUT", 5.0)

DOMAIN       = os.getenv("WG_PANEL_DOMAIN", "localhost")
ADMIN_USER   = os.getenv("WG_PANEL_ADMIN_USER", "admin")
ADMIN_PASS   = os.getenv("WG_PANEL_ADMIN_PASSWORD", "")
SSL_CERT     = os.getenv("WG_PANEL_SSL_CERT", f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem")
SSL_KEY      = os.getenv("WG_PANEL_SSL_KEY", f"/etc/letsencrypt/live/{DOMAIN}/privkey.pem")
TG_TOKEN     = os.getenv("WG_PANEL_TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID   = os.getenv("WG_PANEL_TELEGRAM_CHAT_ID", "")

# ─── Storage ──────────────────────────────────────────────────────────────────
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)

def save_users(users):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _users_lock:
        tmp = USERS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(users, f, indent=2)
        os.replace(tmp, USERS_FILE)

def ensure_admin():
    users = load_users()
    if ADMIN_USER not in users:
        if not ADMIN_PASS:
            raise RuntimeError("WG_PANEL_ADMIN_PASSWORD must be set before first startup")
        users[ADMIN_USER] = {
            "password_hash": _hash(ADMIN_PASS),
            "role": "admin",
            "approved": True,
            "max_devices": -1,
            "created_at": _now()
        }
        save_users(users)

def _hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def _check(pw, hashed):
    return hmac.compare_digest(_hash(pw), hashed)

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def _lang():
    """Returns 'ru' if browser prefers Russian, else 'en'."""
    accept = request.headers.get("Accept-Language", "")
    return "ru" if "ru" in accept.lower() else "en"
