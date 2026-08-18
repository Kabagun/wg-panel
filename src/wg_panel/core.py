import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

try:  # Linux production has fcntl; Windows development does not.
    import fcntl
except ImportError:  # pragma: no cover - platform specific
    fcntl = None


os.umask(0o077)


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


WG_DIR = os.getenv("WG_PANEL_WG_DIR", "/etc/wireguard")
CLIENTS_DIR = os.getenv("WG_PANEL_CLIENTS_DIR", f"{WG_DIR}/clients")
DATA_DIR = os.getenv("WG_PANEL_DATA_DIR", "/opt/wg-panel/data")
USERS_FILE = f"{DATA_DIR}/users.json"
TRAFFIC_FILE = f"{DATA_DIR}/traffic.json"
DEVICE_META_FILE = f"{DATA_DIR}/device_meta.json"

BIND_HOST = os.getenv("WG_PANEL_BIND_HOST", "0.0.0.0")
PORT = _env_int("WG_PANEL_PORT", 443)
ENABLE_INTERNAL_TLS = _env_bool("WG_PANEL_ENABLE_INTERNAL_TLS", True)
ENABLE_HTTP_REDIRECT = _env_bool("WG_PANEL_ENABLE_HTTP_REDIRECT", True)
HTTP_REDIRECT_PORT = _env_int("WG_PANEL_HTTP_REDIRECT_PORT", 80)
REDIRECT_SOCKET_TIMEOUT_SECS = _env_float("WG_PANEL_REDIRECT_SOCKET_TIMEOUT", 5.0)
TRUST_PROXY = _env_bool("WG_PANEL_TRUST_PROXY", False)

DOMAIN = os.getenv("WG_PANEL_DOMAIN", "localhost")
ADMIN_USER = os.getenv("WG_PANEL_ADMIN_USER", "admin").strip().lower()
ADMIN_PASS = os.getenv("WG_PANEL_ADMIN_PASSWORD", "")
SSL_CERT = os.getenv("WG_PANEL_SSL_CERT", f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem")
SSL_KEY = os.getenv("WG_PANEL_SSL_KEY", f"/etc/letsencrypt/live/{DOMAIN}/privkey.pem")
TG_TOKEN = os.getenv("WG_PANEL_TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("WG_PANEL_TELEGRAM_CHAT_ID", "")
TG_WEBHOOK_SECRET = os.getenv("WG_PANEL_TELEGRAM_WEBHOOK_SECRET", "")

PAYMENT_ERIP_PATH = os.getenv("WG_PANEL_PAYMENT_ERIP_PATH", "")
PAYMENT_ACCOUNT = os.getenv("WG_PANEL_PAYMENT_ACCOUNT", "")
PAYMENT_TIME = os.getenv("WG_PANEL_PAYMENT_TIME", "09:00")
PAYMENT_TIMEZONE = os.getenv("WG_PANEL_PAYMENT_TIMEZONE", "Europe/Minsk")

MAX_CONCURRENT_REQUESTS = _env_int("WG_PANEL_MAX_CONCURRENT_REQUESTS", 32)
MAX_REQUEST_BODY_BYTES = _env_int("WG_PANEL_MAX_REQUEST_BODY_BYTES", 16 * 1024)

app = Flask("app", root_path=str(Path(__file__).resolve().parents[2]))
app.config.update(
    MAX_CONTENT_LENGTH=MAX_REQUEST_BODY_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)
if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_users_lock = threading.RLock()
_traffic_lock = threading.RLock()
_device_meta_lock = threading.RLock()
_wireguard_lock = threading.RLock()
_request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)


def ensure_private_dir(path):
    """Create a directory and enforce owner-only access."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _load_json_unlocked(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_json_private(path, data):
    """Atomically write JSON with mode 0600 in an owner-only directory."""
    directory = os.path.dirname(path)
    ensure_private_dir(directory)
    temporary = f"{path}.tmp-{secrets.token_hex(6)}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def _user_file_lock():
    ensure_private_dir(DATA_DIR)
    lock_path = f"{USERS_FILE}.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _normalize_users(users):
    for username, user in users.items():
        user.setdefault("role", "user")
        user.setdefault("approved", False)
        user.setdefault("max_devices", 3)
        user.setdefault("created_at", _now())
        user.setdefault("telegram_username", "")
        user.setdefault("payment_enabled", False)
        user.setdefault("payment_day", None)
        user.setdefault("payment_last_notified_month", "")
        user.setdefault("payment_delivery", {"month": "", "parts": []})
        user.setdefault("session_version", 1)
        if user["role"] != "admin" and not user["approved"]:
            user.setdefault("approval_token", secrets.token_urlsafe(12))
        else:
            user.pop("approval_token", None)
        if username == ADMIN_USER:
            user["role"] = "admin"
            user["approved"] = True
            user["payment_enabled"] = False
    return users


def load_users():
    """Return normalized user state under process and OS-level locks."""
    with _users_lock, _user_file_lock():
        users = _load_json_unlocked(USERS_FILE, {})
        return _normalize_users(users)


def mutate_users(mutator):
    """Atomically load, mutate, and persist users; return the callback result."""
    with _users_lock, _user_file_lock():
        users = _normalize_users(_load_json_unlocked(USERS_FILE, {}))
        result = mutator(users)
        write_json_private(USERS_FILE, users)
        return result


def save_users(users):
    """Replace user state atomically. Prefer mutate_users for route updates."""
    with _users_lock, _user_file_lock():
        write_json_private(USERS_FILE, _normalize_users(users))


def _load_secret_key():
    ensure_private_dir(DATA_DIR)
    secret_file = os.getenv("WG_PANEL_SECRET_FILE", f"{DATA_DIR}/.secret_key")
    if os.path.exists(secret_file):
        os.chmod(secret_file, 0o600)
        with open(secret_file, encoding="utf-8") as handle:
            return handle.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(key)
    return key


app.secret_key = _load_secret_key()


def ensure_admin():
    def create_or_normalize(users):
        if ADMIN_USER not in users:
            if not ADMIN_PASS:
                raise RuntimeError("WG_PANEL_ADMIN_PASSWORD must be set before first startup")
            users[ADMIN_USER] = {
                "password_hash": _hash(ADMIN_PASS),
                "role": "admin",
                "approved": True,
                "max_devices": -1,
                "created_at": _now(),
                "session_version": 1,
                "telegram_username": "",
                "payment_enabled": False,
                "payment_day": None,
                "payment_last_notified_month": "",
                "payment_delivery": {"month": "", "parts": []},
            }

    mutate_users(create_or_normalize)


def _hash(password):
    """Return a salted scrypt password hash."""
    return generate_password_hash(password, method="scrypt")


def _is_legacy_hash(stored):
    return bool(re.fullmatch(r"[0-9a-f]{64}", str(stored or "")))


def verify_password(password, stored):
    """Return (valid, needs_upgrade) for current and legacy password hashes."""
    stored = str(stored or "")
    if _is_legacy_hash(stored):
        digest = hashlib.sha256(password.encode()).hexdigest()
        valid = hmac.compare_digest(digest, stored)
        return valid, valid
    try:
        return check_password_hash(stored, password), False
    except (ValueError, TypeError):
        return False, False


def _check(password, stored):
    return verify_password(password, stored)[0]


def _now():
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _lang():
    """Return Russian when the browser declares Russian preference."""
    accept = request.headers.get("Accept-Language", "")
    return "ru" if "ru" in accept.lower() else "en"
