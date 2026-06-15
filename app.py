#!/usr/bin/env python3
"""
WireGuard VPN Web Panel — Multi-user with admin approval.
Storage: JSON file (no database).
Clients: /etc/wireguard/clients/<username>-<device>.conf
"""

import os, json, secrets, hashlib, hmac, subprocess, base64, urllib.request, urllib.parse, threading
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import (Flask, request, render_template_string,
                   redirect, url_for, session, flash, Response, g)

app = Flask(__name__)
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

# ─── Translations ─────────────────────────────────────────────────────────────
STRINGS = {
    "en": {
        # nav
        "nav_devices":   "📋 My Devices",
        "nav_add":       "➕ Add Device",
        "nav_admin":     "⚙️ Admin",
        "nav_traffic":   "📊 Traffic",
        "nav_logout":    "Logout",
        # login
        "login_sub":     "Sign in to your account",
        "login_user":    "Username",
        "login_pass":    "Password",
        "login_btn":     "Sign In",
        "login_create":  "Create account",
        "login_forgot":  "Forgot password?",
        "login_err":     "Invalid username or password.",
        # register
        "reg_sub":       "Create an account — admin must approve before you can connect.",
        "reg_user":      "Username (letters, numbers, dashes)",
        "reg_pass":      "Password",
        "reg_confirm":   "Confirm password",
        "reg_terms":     "By registering, you confirm that you are an adult and <strong>you agree not to distribute prohibited content through this network</strong>.<br>You acknowledge that violations make the network owner liable for your actions toward third parties.<br><span style='color:#8b949e'>Your data is stored only within this service and is not shared with third parties.</span>",
        "reg_agree":     "I have read and accept the terms of use",
        "reg_btn":       "Register",
        "reg_back":      "Back to login",
        # pending
        "pend_title":    "Pending Approval",
        "pend_sub":      "Your account is waiting for admin approval.<br>Please check back later.",
        "pend_logout":   "Logout",
        # forgot
        "forgot_sub":    "Enter your username. The admin will receive a reset link via Telegram and forward it to you.",
        "forgot_btn":    "Send Reset Request",
        "forgot_back":   "Back to login",
        # reset
        "reset_title":   "Set New Password",
        "reset_new_pw":  "New password",
        "reset_conf_pw": "Confirm password",
        "reset_btn":     "Set Password",
        # dashboard
        "dash_title":    "📋 My Devices",
        "dash_logged":   "Logged in as",
        "dash_used":     "devices used",
        "dash_unlim":    "unlimited",
        "dash_col_dev":  "Device",
        "dash_col_act":  "Actions",
        "dash_view_qr":  "View / QR",
        "dash_remove":   "Remove",
        "dash_empty":    "No devices yet.",
        "dash_limit":    "Limit reached ({n} devices)",
        "dash_add_btn":  "➕ Add Device",
        # traffic
        "tr_sub":        "Monthly traffic per device (collected every 60 seconds)",
        "tr_total_dl":   "Total ↓ Download",
        "tr_total_ul":   "Total ↑ Upload",
        "tr_combined":   "Combined",
        "tr_col_owner":  "Owner",
        "tr_col_dev":    "Device",
        "tr_col_dl":     "Download",
        "tr_col_ul":     "Upload",
        "tr_col_hist":   "History",
        "tr_nodata":     "No data yet",
        "tr_nodiv":      "No devices.",
        "tr_warn":       "⚠️ Counters reset when WireGuard restarts. Monthly totals are cumulative.",
        # add device
        "add_sub":       "A new VPN config will be created for this device.",
        "add_label":     "Device name (e.g. phone, laptop, tablet)",
        "add_btn":       "Create",
        "add_tip":       "💡 Allowed: lowercase letters, numbers, dashes and underscores (e.g. pipyao-router, my_laptop)",
        # flash messages
        "flash_login_err":      "Invalid username or password.",
        "flash_reg_agree":      "You must accept the terms of use.",
        "flash_reg_user":       "Invalid username. Use lowercase letters, numbers, dashes.",
        "flash_reg_pass_len":   "Password must be at least 8 characters.",
        "flash_reg_pass_match": "Passwords do not match.",
        "flash_reg_taken":      "Username already taken.",
        "flash_reg_ok":         "Account created! Waiting for admin approval.",
        "flash_add_invalid":    "Invalid name. Use lowercase letters, numbers, dashes (-) and underscores (_).",
        "flash_add_limit":      "Device limit reached ({n}).",
        "flash_reset_len":      "Password must be at least 8 characters.",
        "flash_reset_match":    "Passwords do not match.",
        "flash_reset_ok":       "Password updated! You can now log in.",
    },
    "ru": {
        # nav
        "nav_devices":   "📋 Устройства",
        "nav_add":       "➕ Добавить",
        "nav_admin":     "⚙️ Админ",
        "nav_traffic":   "📊 Трафик",
        "nav_logout":    "Выйти",
        # login
        "login_sub":     "Войдите в свой аккаунт",
        "login_user":    "Имя пользователя",
        "login_pass":    "Пароль",
        "login_btn":     "Войти",
        "login_create":  "Создать аккаунт",
        "login_forgot":  "Забыли пароль?",
        "login_err":     "Неверное имя пользователя или пароль.",
        # register
        "reg_sub":       "Создайте аккаунт — администратор должен одобрить его перед подключением.",
        "reg_user":      "Имя пользователя (буквы, цифры, дефисы)",
        "reg_pass":      "Пароль",
        "reg_confirm":   "Подтвердите пароль",
        "reg_terms":     "Продолжая регистрацию, вы подтверждаете, что являетесь совершеннолетним, и <strong>обязуетесь не распространять запрещённый контент через данную сеть</strong>.<br>Вы осознаёте, что при нарушении этого условия владелец сети несёт ответственность за ваши действия перед третьими лицами.<br><span style='color:#8b949e'>Ваши данные хранятся только в пределах этого сервиса и не передаются третьим лицам.</span>",
        "reg_agree":     "Я прочитал(а) и принимаю условия использования сети",
        "reg_btn":       "Зарегистрироваться",
        "reg_back":      "Назад ко входу",
        # pending
        "pend_title":    "Ожидание одобрения",
        "pend_sub":      "Ваш аккаунт ожидает одобрения администратора.<br>Зайдите позже.",
        "pend_logout":   "Выйти",
        # forgot
        "forgot_sub":    "Введите имя пользователя. Администратор получит ссылку для сброса через Telegram.",
        "forgot_btn":    "Отправить запрос",
        "forgot_back":   "Назад ко входу",
        # reset
        "reset_title":   "Новый пароль",
        "reset_new_pw":  "Новый пароль",
        "reset_conf_pw": "Подтвердите пароль",
        "reset_btn":     "Установить пароль",
        # dashboard
        "dash_title":    "📋 Мои устройства",
        "dash_logged":   "Вы вошли как",
        "dash_used":     "устройств использовано",
        "dash_unlim":    "безлимит",
        "dash_col_dev":  "Устройство",
        "dash_col_act":  "Действия",
        "dash_view_qr":  "QR / Открыть",
        "dash_remove":   "Удалить",
        "dash_empty":    "Устройств пока нет.",
        "dash_limit":    "Лимит достигнут ({n} устройств)",
        "dash_add_btn":  "➕ Добавить устройство",
        # traffic
        "tr_sub":        "Месячный трафик на устройство (собирается каждые 60 секунд)",
        "tr_total_dl":   "Всего ↓ Загрузка",
        "tr_total_ul":   "Всего ↑ Отдача",
        "tr_combined":   "Суммарно",
        "tr_col_owner":  "Владелец",
        "tr_col_dev":    "Устройство",
        "tr_col_dl":     "Загрузка",
        "tr_col_ul":     "Отдача",
        "tr_col_hist":   "История",
        "tr_nodata":     "Нет данных",
        "tr_nodiv":      "Нет устройств.",
        "tr_warn":       "⚠️ Счётчики сбрасываются при перезапуске WireGuard. Месячные итоги суммируются.",
        # add device
        "add_sub":       "Для этого устройства будет создана конфигурация VPN.",
        "add_label":     "Название устройства (напр. phone, laptop, tablet)",
        "add_btn":       "Создать",
        "add_tip":       "💡 Разрешены: строчные буквы, цифры, дефисы и подчёркивания (напр. pipyao-router, my_laptop)",
        # flash messages
        "flash_login_err":      "Неверное имя пользователя или пароль.",
        "flash_reg_agree":      "Необходимо принять условия использования сети.",
        "flash_reg_user":       "Недопустимое имя. Только строчные буквы, цифры, дефисы.",
        "flash_reg_pass_len":   "Пароль должен быть не менее 8 символов.",
        "flash_reg_pass_match": "Пароли не совпадают.",
        "flash_reg_taken":      "Это имя пользователя уже занято.",
        "flash_reg_ok":         "Аккаунт создан! Ожидайте одобрения администратора.",
        "flash_add_invalid":    "Недопустимое название. Разрешены строчные буквы, цифры, дефисы (-) и подчёркивания (_).",
        "flash_add_limit":      "Достигнут лимит устройств ({n}).",
        "flash_reset_len":      "Пароль должен быть не менее 8 символов.",
        "flash_reset_match":    "Пароли не совпадают.",
        "flash_reset_ok":       "Пароль обновлён! Теперь вы можете войти.",
    }
}

def t(key, lang):
    """Return translated string for key; fallback to English."""
    return STRINGS.get(lang, STRINGS["en"]).get(key) or STRINGS["en"].get(key, key)

def telegram_configured(require_chat=True):
    if not TG_TOKEN:
        return False
    return bool(TG_CHAT_ID) if require_chat else True

def _tg_send_async(fn, *args, **kwargs):
    """Run a Telegram function in a background thread (non-blocking)."""
    threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True).start()

def send_telegram(text, silent=False):
    """Fire-and-forget Telegram message (non-blocking). silent=True disables notification sound."""
    if not telegram_configured():
        return
    def _send():
        try:
            url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
            payload = {
                "chat_id": TG_CHAT_ID,
                "text": text,
                "parse_mode": "Markdown",
                "disable_notification": "true" if silent else "false"
            }
            data = urllib.parse.urlencode(payload).encode()
            urllib.request.urlopen(url, data=data, timeout=10)
        except Exception as e:
            import sys
            print(f"[TG ERROR] {e}", file=sys.stderr, flush=True)
    _tg_send_async(_send)

@app.before_request
def limit_concurrent_requests():
    if not _request_slots.acquire(blocking=False):
        return "Server is busy. Please retry in a moment.", 503, {"Retry-After": "5"}
    g._request_slot_acquired = True

@app.teardown_request
def release_concurrent_requests(_exc):
    if getattr(g, "_request_slot_acquired", False):
        g._request_slot_acquired = False
        _request_slots.release()

def fmt_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} B"
        b /= 1024
    return f"{b:.2f} PB"

def load_traffic():
    if not os.path.exists(TRAFFIC_FILE):
        return {}
    try:
        with open(TRAFFIC_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_traffic(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _traffic_lock:
        tmp = TRAFFIC_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, TRAFFIC_FILE)

def load_device_meta():
    if not os.path.exists(DEVICE_META_FILE):
        return {}
    try:
        with open(DEVICE_META_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_device_meta(meta):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _device_meta_lock:
        tmp = DEVICE_META_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(meta, f, indent=2)
        os.replace(tmp, DEVICE_META_FILE)

def get_device_type(wg_name):
    """Returns device VPN type."""
    return "wireguard"

def set_device_type(wg_name, vpn_type):
    meta = load_device_meta()
    meta.setdefault(wg_name, {})["vpn_type"] = vpn_type
    save_device_meta(meta)

def remove_device_meta(wg_name):
    meta = load_device_meta()
    if wg_name in meta:
        del meta[wg_name]
        save_device_meta(meta)

def get_wg_peer_stats():
    """Returns dict: {ip: (rx_bytes, tx_bytes)} from wg show all dump."""
    stats = {}
    try:
        r = subprocess.run(["wg", "show", "all", "dump"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 8:
                try:
                    ip = parts[4].split("/")[0]
                    rx = int(parts[6])
                    tx = int(parts[7])
                    stats[ip] = (rx, tx)
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return stats

def get_client_ip(wg_name):
    """Get client VPN IP from their conf file."""
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            for line in f:
                if line.strip().startswith("Address"):
                    addr = line.split("=", 1)[1].strip()
                    return addr.split("/")[0]
    except Exception:
        pass
    return None

def collect_traffic():
    """Collect current WireGuard stats and accumulate into monthly totals."""
    peer_stats = get_wg_peer_stats()
    if not peer_stats:
        return
    traffic = load_traffic()
    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    for owner, device, wg_name in get_all_devices():
        ip = get_client_ip(wg_name)
        if not ip or ip not in peer_stats:
            continue
        rx_now, tx_now = peer_stats[ip]
        if wg_name not in traffic:
            traffic[wg_name] = {"last_rx": 0, "last_tx": 0, "monthly": {}}
        entry = traffic[wg_name]
        last_rx = entry.get("last_rx", 0)
        last_tx = entry.get("last_tx", 0)
        if month_key not in entry["monthly"]:
            entry["monthly"][month_key] = {"rx": 0, "tx": 0}
        delta_rx = rx_now - last_rx if rx_now >= last_rx else rx_now
        delta_tx = tx_now - last_tx if tx_now >= last_tx else tx_now
        entry["monthly"][month_key]["rx"] += delta_rx
        entry["monthly"][month_key]["tx"] += delta_tx
        entry["last_rx"] = rx_now
        entry["last_tx"] = tx_now
    save_traffic(traffic)

def send_telegram_buttons(text, buttons):
    """Send Telegram message with inline keyboard (non-blocking)."""
    if not telegram_configured():
        return
    def _send():
        try:
            url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
            payload = {
                "chat_id": TG_CHAT_ID,
                "text": text,
                "parse_mode": "Markdown",
                "reply_markup": json.dumps({"inline_keyboard": buttons})
            }
            data = urllib.parse.urlencode(payload).encode()
            urllib.request.urlopen(url, data=data, timeout=10)
        except Exception as e:
            import sys
            print(f"[TG ERROR] {e}", file=sys.stderr, flush=True)
    _tg_send_async(_send)

def answer_callback(callback_id, text=""):
    if not telegram_configured(require_chat=False):
        return
    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/answerCallbackQuery"
        data = urllib.parse.urlencode({"callback_query_id": callback_id, "text": text}).encode()
        urllib.request.urlopen(url, data=data, timeout=5)
    except Exception:
        pass

def edit_tg_message(chat_id, msg_id, text):
    if not telegram_configured(require_chat=False):
        return
    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/editMessageText"
        data = urllib.parse.urlencode({
            "chat_id": chat_id, "message_id": msg_id,
            "text": text, "parse_mode": "Markdown"
        }).encode()
        urllib.request.urlopen(url, data=data, timeout=5)
    except Exception:
        pass

def set_tg_webhook():
    if not telegram_configured(require_chat=False) or DOMAIN == "localhost":
        return
    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/setWebhook"
        data = urllib.parse.urlencode({
            "url": f"https://{DOMAIN}/tg_webhook",
            "allowed_updates": '["callback_query"]'
        }).encode()
        urllib.request.urlopen(url, data=data, timeout=10)
    except Exception as e:
        import sys
        print(f"[TG WEBHOOK] Failed to register: {e}", file=sys.stderr, flush=True)

# ─── WireGuard helpers────────────────────────────────────────────────────────
def client_name(username, device):
    return f"{username}-{device}"

def get_user_devices(username):
    """Return list of device names belonging to a user."""
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    prefix = f"{username}-"
    return sorted([
        f.replace(".conf", "").replace(prefix, "", 1)
        for f in os.listdir(CLIENTS_DIR)
        if f.startswith(prefix) and f.endswith(".conf")
    ])

def get_all_devices():
    """Return list of (username, device, wg_name) tuples for all clients."""
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    users = load_users()
    result = []
    for f in sorted(os.listdir(CLIENTS_DIR)):
        if not f.endswith(".conf"):
            continue
        name = f.replace(".conf", "")
        # Match against known usernames (handles dashes in usernames correctly)
        for username in users:
            prefix = f"{username}-"
            if name.startswith(prefix) and len(name) > len(prefix):
                device = name[len(prefix):]
                result.append((username, device, name))
                break
    return result

def get_config(wg_name):
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None

def create_device(wg_name):
    try:
        script = f"{WG_DIR}/add-client.sh"
        r = subprocess.run(
            [script, wg_name],
            capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0, r.stderr
    except Exception as e:
        return False, str(e)

def delete_device(wg_name):
    try:
        script = f"{WG_DIR}/remove-client.sh"
        subprocess.run([script, wg_name], capture_output=True, timeout=15)
    except Exception:
        pass
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if os.path.exists(path):
        os.remove(path)
    remove_device_meta(wg_name)

def qr_svg_b64(wg_name):
    path = f"{CLIENTS_DIR}/{wg_name}.conf"
    if not os.path.exists(path):
        return None
    try:
        r = subprocess.run(
            ["qrencode", "-t", "SVG", "-r", path, "-o", "-"],
            capture_output=True, timeout=10
        )
        if r.returncode == 0:
            return "data:image/svg+xml;base64," + base64.b64encode(r.stdout).decode()
    except Exception:
        pass
    return None

# ─── Auth decorators ──────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def deco(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return deco

def approved_required(f):
    @wraps(f)
    def deco(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login"))
        users = load_users()
        u = users.get(session["user"], {})
        if not u.get("approved"):
            return render_template_string(pending_page(_lang()))
        return f(*a, **kw)
    return deco

def admin_required(f):
    @wraps(f)
    def deco(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login"))
        users = load_users()
        if users.get(session["user"], {}).get("role") != "admin":
            flash("Access denied.", "error")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return deco

# ─── CSS / Base ───────────────────────────────────────────────────────────────
FAVICON = '<link rel="icon" href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'><text y=\'.9em\' font-size=\'90\'>🔒</text></svg>">'

def page_head(title="VPN Panel"):
    return f'<title>{title} | VPN Panel</title>\n{FAVICON}\n'

CSS = """
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* ── Reset ── */
*{box-sizing:border-box;margin:0;padding:0}

/* ── Dark theme (default) ── */
:root{
  --bg:#0d1117;--card:#161b22;--border:#30363d;--border2:#21262d;
  --text:#c9d1d9;--text2:#8b949e;--head:#e6edf3;
  --accent:#58a6ff;--input-bg:#0d1117;
  --ok-bg:#0d4429;--ok:#3fb950;
  --err-bg:#3d0c0c;--err:#f85149;
  --pend-bg:#3d2b00;--pend:#d29922;
  --admin-bg:#1a2f5e;--admin:#79c0ff;
  --stat-bg:#0d1117;
  --btn-s-bg:#21262d;--btn-s-border:#30363d;
}

/* ── Light theme ── */
@media(prefers-color-scheme:light){
  :root{
    --bg:#f6f8fa;--card:#ffffff;--border:#d0d7de;--border2:#eaeef2;
    --text:#1f2328;--text2:#656d76;--head:#1f2328;
    --accent:#0969da;--input-bg:#ffffff;
    --ok-bg:#dafbe1;--ok:#1a7f37;
    --err-bg:#ffebe9;--err:#cf222e;
    --pend-bg:#fff8c5;--pend:#9a6700;
    --admin-bg:#ddf4ff;--admin:#0550ae;
    --stat-bg:#f6f8fa;
    --btn-s-bg:#f6f8fa;--btn-s-border:#d0d7de;
  }
}

body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:var(--bg);color:var(--text);min-height:100vh;padding:24px 16px;
     overflow-x:hidden}
.wrap{max-width:560px;margin:0 auto;min-width:0}
.wide{max-width:860px;margin:0 auto;min-width:0}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;
      padding:28px;margin-bottom:20px;overflow:hidden}
h1{color:var(--accent);font-size:22px;margin-bottom:4px}
h2{color:var(--head);font-size:17px;margin-bottom:14px}
.sub{color:var(--text2);font-size:13px;margin-bottom:20px}
input[type=text],input[type=password],input[type=number],select{
  width:100%;padding:10px 12px;background:var(--input-bg);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-size:16px;margin-bottom:14px;
  -webkit-appearance:none}
input:focus,select:focus{border-color:var(--accent);outline:none}
label{display:block;color:var(--text2);font-size:13px;margin-bottom:5px}
.btn{display:inline-block;padding:10px 18px;border:none;border-radius:6px;
     font-size:14px;cursor:pointer;text-decoration:none;text-align:center;
     color:#fff;transition:opacity .15s;
     -webkit-tap-highlight-color:transparent}
.btn:hover{opacity:.85}
.g{background:#238636}.b{background:#1f6feb}.r{background:#da3633}
.y{background:#9e6a03}.s{background:var(--btn-s-bg);border:1px solid var(--btn-s-border);color:var(--text)}
.btn-full{width:100%;display:block;padding:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;align-items:center}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}
.tag-ok{background:var(--ok-bg);color:var(--ok)}
.tag-pend{background:var(--pend-bg);color:var(--pend)}
.tag-admin{background:var(--admin-bg);color:var(--admin)}
.msg-ok{color:var(--ok);font-size:13px;margin-bottom:12px;padding:8px 12px;
        background:var(--ok-bg);border-radius:6px}
.msg-err{color:var(--err);font-size:13px;margin-bottom:12px;padding:8px 12px;
         background:var(--err-bg);border-radius:6px}
.conf{background:var(--stat-bg);border:1px solid var(--border);border-radius:6px;padding:12px;
      font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;
      max-height:260px;overflow-y:auto;margin:12px 0;color:var(--text)}
.qr{text-align:center;margin:16px 0}
.qr img{max-width:260px;width:100%;background:#fff;padding:10px;border-radius:8px}
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:0 -4px}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:340px}
th{text-align:left;color:var(--text2);font-weight:500;padding:8px 10px;
   border-bottom:1px solid var(--border)}
td{padding:8px 10px;border-bottom:1px solid var(--border2);vertical-align:middle}
tr:last-child td{border-bottom:none}
.nav{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}
hr{border:none;border-top:1px solid var(--border);margin:20px 0}
.stat-box{text-align:center;padding:16px 20px;background:var(--stat-bg);
          border:1px solid var(--border);border-radius:8px;flex:1;min-width:90px}
.stat-num{font-size:28px;font-weight:700;color:var(--accent)}
.stat-lbl{color:var(--text2);font-size:12px;margin-top:2px}

/* ── Mobile ── */
@media(max-width:600px){
  body{padding:16px 12px}
  .card{padding:18px 14px}
  .nav{gap:6px;overflow-x:auto;flex-wrap:wrap;-webkit-overflow-scrolling:touch}
  .nav .btn{font-size:13px;padding:9px 12px;flex:0 0 auto;white-space:nowrap}
  h1{font-size:20px}
  .stat-box{padding:12px 10px}
  .stat-num{font-size:22px}
  td,th{padding:7px 6px}
  .btn{padding:8px 12px;font-size:13px}
}
</style>
"""

def flash_html():
    msgs = ""
    for cat, msg in (session.pop("_flashes", None) or []):
        cls = "msg-ok" if cat == "ok" else "msg-err"
        msgs += f'<div class="{cls}">{msg}</div>'
    return msgs

# ─── Pages ────────────────────────────────────────────────────────────────────
def login_page(lang):
    return page_head("VPN Panel") + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>🔒 VPN Panel</h1>
  <p class="sub">{t("login_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST" id="login-form" autocomplete="on">
    <label for="username">{t("login_user", lang)}</label>
    <input type="text" id="username" name="u" autocomplete="username" required autofocus>
    <label for="password">{t("login_pass", lang)}</label>
    <input type="password" id="password" name="p" autocomplete="current-password" required>
    <button class="btn g btn-full" type="submit">{t("login_btn", lang)}</button>
  </form>
  <hr>
  <div style="text-align:center;display:flex;gap:8px;justify-content:center">
    <a href="/register" class="btn s">{t("login_create", lang)}</a>
    <a href="/forgot" class="btn s">{t("login_forgot", lang)}</a>
  </div>
</div></div>
"""

def register_page(lang):
    return page_head("Register") + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>📝 Register</h1>
  <p class="sub">{t("reg_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST" autocomplete="on">
    <label>{t("reg_user", lang)}</label>
    <input type="text" id="username" name="u" pattern="[a-z0-9-]+" required autofocus
           autocomplete="username" title="Lowercase letters, numbers, dashes only">
    <label>{t("reg_pass", lang)}</label>
    <input type="password" id="new-password" name="p" minlength="8" required autocomplete="new-password">
    <label>{t("reg_confirm", lang)}</label>
    <input type="password" name="p2" required autocomplete="new-password">
    <div style="background:rgba(255,200,0,0.07);border:1px solid rgba(255,200,0,0.25);border-radius:8px;padding:12px 14px;margin:12px 0;font-size:12px;color:var(--fg);line-height:1.6">
      {t("reg_terms", lang)}
    </div>
    <label style="display:flex;align-items:flex-start;gap:8px;font-size:13px;cursor:pointer;margin-bottom:4px">
      <input type="checkbox" name="agree" required style="margin-top:3px;flex-shrink:0">
      <span>{t("reg_agree", lang)}</span>
    </label>
    <button class="btn g btn-full" type="submit">{t("reg_btn", lang)}</button>
  </form>
  <hr>
  <div style="text-align:center">
    <a href="/login" class="btn s">{t("reg_back", lang)}</a>
  </div>
</div></div>
"""

def pending_page(lang):
    return page_head(t("pend_title", lang)) + CSS + f"""
<div class="wrap" style="padding-top:80px">
<div class="card" style="text-align:center">
  <h1>⏳ {t("pend_title", lang)}</h1>
  <p class="sub" style="margin-bottom:20px">{t("pend_sub", lang)}</p>
  <a href="/logout" class="btn r">{t("pend_logout", lang)}</a>
</div></div>
"""

def nav_bar(is_admin=False):
    lang = _lang()
    admin_link = (f'<a href="/admin" class="btn b">{t("nav_admin", lang)}</a>'
                  f'<a href="/traffic" class="btn b">{t("nav_traffic", lang)}</a>') if is_admin else ''
    return f"""<div class="nav">
  <a href="/dashboard" class="btn b">{t("nav_devices", lang)}</a>
  <a href="/add" class="btn g">{t("nav_add", lang)}</a>
  {admin_link}
  <a href="/logout" class="btn r" style="margin-left:auto;flex-shrink:0">{t("nav_logout", lang)}</a>
</div>"""

# ─── Routes: Auth ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/healthz")
def healthz():
    return {"status": "ok", "time": _now()}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("u", "").strip().lower()
        p = request.form.get("p", "")
        users = load_users()
        usr = users.get(u)
        if usr and _check(p, usr["password_hash"]):
            session["user"] = u
            session["role"] = usr["role"]
            return redirect(url_for("dashboard"))
        flash(t("flash_login_err", _lang()), "error")
    lang = _lang()
    tmpl = login_page(lang).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("u", "").strip().lower()
        p  = request.form.get("p", "")
        p2 = request.form.get("p2", "")
        users = load_users()
        if not request.form.get("agree"):
            flash(t("flash_reg_agree", _lang()), "error")
        elif not u or not all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in u):
            flash(t("flash_reg_user", _lang()), "error")
        elif len(p) < 8:
            flash(t("flash_reg_pass_len", _lang()), "error")
        elif p != p2:
            flash(t("flash_reg_pass_match", _lang()), "error")
        elif u in users:
            flash(t("flash_reg_taken", _lang()), "error")
        else:
            users[u] = {
                "password_hash": _hash(p),
                "role": "user",
                "approved": False,
                "max_devices": 3,
                "created_at": _now()
            }
            save_users(users)
            reg_time = _now()
            send_telegram_buttons(
                f"\U0001f514 *New VPN registration*\n\n"
                f"\U0001f464 Username: `{u}`\n"
                f"\U0001f552 Time: {reg_time}\n"
                f"\U0001f310 IP: {request.remote_addr}\n"
                f"\U0001f4f1 Browser: {request.user_agent.string[:60]}",
                [
                    [
                        {"text": "\u2705 Approve 3 devices", "callback_data": f"approve:{u}:3"},
                        {"text": "\u274c Reject", "callback_data": f"reject:{u}"}
                    ],
                    [
                        {"text": "\u2705 Approve 5 devices", "callback_data": f"approve:{u}:5"},
                        {"text": "\u2705 Approve unlimited", "callback_data": f"approve:{u}:-1"}
                    ]
                ]
            )
            flash(t("flash_reg_ok", _lang()), "ok")
            return redirect(url_for("login"))
    lang = _lang()
    tmpl = register_page(lang).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def forgot_page(lang):
    return page_head("Forgot Password") + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>🔑 Forgot Password</h1>
  <p class="sub">{t("forgot_sub", lang)}</p>
  {{{{flash}}}}
  <form method="POST">
    <label>{t("login_user", lang)}</label>
    <input type="text" name="u" required autofocus>
    <button class="btn g btn-full" type="submit">{t("forgot_btn", lang)}</button>
  </form>
  <hr>
  <div style="text-align:center"><a href="/login" class="btn s">{t("forgot_back", lang)}</a></div>
</div></div>
"""

def reset_page(lang, username):
    if lang == "ru":
        sub = f"Выберите новый пароль для <b>{username}</b>."
    else:
        sub = f"Choose a new password for <b>{username}</b>."
    return page_head(t("reset_title", lang)) + CSS + f"""
<div class="wrap" style="padding-top:60px">
<div class="card">
  <h1>🔑 {t("reset_title", lang)}</h1>
  <p class="sub">{sub}</p>
  {{{{flash}}}}
  <form method="POST">
    <label>{t("reset_new_pw", lang)}</label>
    <input type="password" name="p" minlength="8" required autofocus>
    <label>{t("reset_conf_pw", lang)}</label>
    <input type="password" name="p2" required>
    <button class="btn g btn-full" type="submit">{t("reset_btn", lang)}</button>
  </form>
</div></div>
"""

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        u = request.form.get("u", "").strip().lower()
        users = load_users()
        usr = users.get(u)
        if usr and usr.get("role") != "admin":
            token = secrets.token_urlsafe(32)
            expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            users[u]["reset_token"] = token
            users[u]["reset_token_expiry"] = expiry
            save_users(users)
            reset_url = f"https://{DOMAIN}/reset/{token}"
            send_telegram(
                f"🔑 *Password reset request*\n\n"
                f"👤 Username: `{u}`\n"
                f"🕐 Requested: {_now()}\n"
                f"⏰ Expires in: 1 hour\n\n"
                f"Forward this link to the user:\n{reset_url}"
            )
        # Always show success to prevent username enumeration
        flash("If that username exists, the admin has been notified via Telegram and will send you a reset link.", "ok")
        return redirect(url_for("login"))
    tmpl = forgot_page(_lang()).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    users = load_users()
    # Find user with this token
    matched = None
    for u, d in users.items():
        if d.get("reset_token") == token:
            expiry = d.get("reset_token_expiry", "")
            try:
                if datetime.fromisoformat(expiry) > datetime.now(timezone.utc):
                    matched = u
            except Exception:
                pass
            break

    if not matched:
        flash("Reset link is invalid or has expired.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        p  = request.form.get("p", "")
        p2 = request.form.get("p2", "")
        if len(p) < 8:
            flash(t("flash_reset_len", _lang()), "error")
        elif p != p2:
            flash(t("flash_reset_match", _lang()), "error")
        else:
            users[matched]["password_hash"] = _hash(p)
            users[matched].pop("reset_token", None)
            users[matched].pop("reset_token_expiry", None)
            save_users(users)
            send_telegram(f"✅ Password successfully reset for user: `{matched}`")
            flash(t("flash_reset_ok", _lang()), "ok")
            return redirect(url_for("login"))

    tmpl = reset_page(_lang(), matched).replace("{{flash}}", flash_html())
    return render_template_string(tmpl)

# ─── Routes: User ─────────────────────────────────────────────────────────────
@app.route("/dashboard")
@approved_required
def dashboard():
    u = session["user"]
    users = load_users()
    usr = users.get(u, {})
    is_admin = usr.get("role") == "admin"
    devices = get_user_devices(u)
    max_d = usr.get("max_devices", 3)
    limit_str = "unlimited" if max_d == -1 else str(max_d)
    used = len(devices)
    can_add = max_d == -1 or used < max_d
    lang = _lang()
    limit_str = t("dash_unlim", lang) if max_d == -1 else str(max_d)

    rows = ""
    for d in devices:
        wg = client_name(u, d)
        rows += f"""<tr>
          <td><span style="font-family:monospace;color:#58a6ff">{d}</span></td>
          <td><a href="/device/{wg}" class="btn b" style="padding:4px 10px;font-size:12px">{t("dash_view_qr", lang)}</a>
              <a href="/device/{wg}/delete" class="btn r" style="padding:4px 10px;font-size:12px"
                 onclick="return confirm('{d}?')">{t("dash_remove", lang)}</a></td>
        </tr>"""

    empty = f'<tr><td colspan="2" style="color:#8b949e;padding:16px">{t("dash_empty", lang)}</td></tr>' if not rows else ""
    add_btn = f'<a href="/add" class="btn g">{t("dash_add_btn", lang)}</a>' if can_add else \
              f'<span style="color:#8b949e;font-size:13px">{t("dash_limit", lang).format(n=max_d)}</span>'

    html = page_head(t("dash_title", lang)) + CSS + f"""
<div class="wide">
  {nav_bar(is_admin)}
  <div class="card">
    <h1>{t("dash_title", lang)}</h1>
    <p class="sub">{t("dash_logged", lang)} <b>{u}</b> &nbsp;·&nbsp;
       {used} / {limit_str} {t("dash_used", lang)}</p>
    {flash_html()}
    <div class="tbl-wrap">
    <table><thead><tr><th>{t("dash_col_dev", lang)}</th><th>{t("dash_col_act", lang)}</th></tr></thead>
    <tbody>{rows}{empty}</tbody></table>
    </div>
    <hr>
    {add_btn}
  </div>
</div>"""
    return render_template_string(html)

@app.route("/add", methods=["GET", "POST"])
@approved_required
def add_device():
    u = session["user"]
    users = load_users()
    usr = users.get(u, {})
    is_admin = usr.get("role") == "admin"
    max_d = usr.get("max_devices", 3)

    if request.method == "POST":
        device = request.form.get("device", "").strip().lower()
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        if not device or not all(c in allowed for c in device) or device[0] in "-_" or device[-1] in "-_":
            flash(t("flash_add_invalid", _lang()), "error")
        else:
            devices = get_user_devices(u)
            if max_d != -1 and len(devices) >= max_d:
                flash(t("flash_add_limit", _lang()).format(n=max_d), "error")
            elif device in devices:
                return redirect(url_for("view_device", wg_name=client_name(u, device)))
            else:
                wg = client_name(u, device)
                ok, err = create_device(wg)
                if ok:
                    send_telegram(
                        f"📱 *Device added*\n\n"
                        f"👤 User: `{u}`\n"
                        f"🔌 Device: `{device}`\n"
                        f"🕐 Time: {_now()}",
                        silent=True
                    )
                    return redirect(url_for("view_device", wg_name=wg))
                else:
                    flash(f"Failed to create device: {err}", "error")

    lang = _lang()
    html = page_head("Add Device") + CSS + f"""
<div class="wrap">
  {nav_bar(is_admin)}
  <div class="card">
    <h1>➕ Add Device</h1>
    <p class="sub">{t("add_sub", lang)}</p>
    {flash_html()}
    <form method="POST">
      <label>{t("add_label", lang)}</label>
      <input type="text" name="device" pattern="[a-z0-9][a-z0-9_-]*[a-z0-9]|[a-z0-9]"
             placeholder="phone, pipyao-router, my_laptop" title="Lowercase letters, numbers, dashes and underscores" required autofocus>
      <button class="btn g btn-full" type="submit">{t("add_btn", lang)}</button>
    </form>
    <p style="color:var(--text2);font-size:12px;margin-top:12px">
      {t("add_tip", lang)}
    </p>
  </div>
</div>"""
    return render_template_string(html)

@app.route("/device/<wg_name>")
@approved_required
def view_device(wg_name):
    u = session["user"]
    users = load_users()
    is_admin = users.get(u, {}).get("role") == "admin"

    # Users can only see their own devices (admin can see all)
    if not is_admin and not wg_name.startswith(f"{u}-"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    config = get_config(wg_name)
    if not config:
        flash("Device not found.", "error")
        return redirect(url_for("dashboard"))

    qr = qr_svg_b64(wg_name)
    lang = _lang()
    display_name = wg_name.split("-", 1)[1] if "-" in wg_name else wg_name
    qr_block = f'<div class="qr"><img src="{qr}" alt="QR"></div>' if qr else \
               '<p style="color:#8b949e">QR unavailable</p>'

    type_badge = ""
    app_hint = ""
    app_links = """<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
      <a href="https://apps.apple.com/app/wireguard/id1441195209" target="_blank" rel="noopener"
         class="btn b" style="font-size:12px;padding:5px 12px;text-decoration:none">
        📱 iOS / macOS
      </a>
      <a href="https://www.wireguard.com/install/" target="_blank" rel="noopener"
         class="btn b" style="font-size:12px;padding:5px 12px;text-decoration:none">
        💻 Windows / Linux / macOS
      </a>
    </div>"""
    config_hint = ("WireGuard → + → Сканировать QR код" if lang == "ru"
                   else "WireGuard app → + → Scan from QR code")
    ios_tip = ("💡 <b>iOS:</b> Откройте WireGuard → ➕ → <b>Сканировать QR</b> — без скачивания!"
               if lang == "ru" else
               "💡 <b>iOS:</b> Open WireGuard → ➕ → <b>Scan from QR code</b> — no download needed!")
    dl_btn_text = ("⬇️ Скачать или открыть в WireGuard (iOS · macOS)"
                   if lang == "ru" else "⬇️ Download or Open in WireGuard (iOS · macOS)")

    conf_section_title = "Текст конфига" if lang == "ru" else "Config Text"
    conf_section_hint  = ("Скопируйте и вставьте в приложение → Добавить туннель"
                          if lang == "ru" else "Copy and paste into the app → Add Tunnel → Add empty tunnel")
    remove_label   = "🗑️ Удалить устройство" if lang == "ru" else "🗑️ Remove this device"
    remove_confirm = "Удалить {d}? Это действие необратимо.".format(d=display_name) if lang == "ru" else f"Remove {display_name}? This cannot be undone."
    sub_text       = f"Конфигурация VPN для <b>{display_name}</b>" if lang == "ru" else f"VPN config for <b>{display_name}</b>"
    qr_heading     = "QR-код" if lang == "ru" else "QR Code"
    copy_hint      = "👆 Нажмите, чтобы скопировать" if lang == "ru" else "👆 Click to copy"
    copied_msg     = "✅ Скопировано!" if lang == "ru" else "✅ Copied!"

    html = page_head(display_name) + CSS + f"""
<div class="wrap">
  {nav_bar(is_admin)}
  <div class="card">
    <h1>📱 {display_name}{type_badge}</h1>
    <p class="sub">{sub_text}</p>
    {flash_html()}
    <h2>{qr_heading}</h2>
    {app_hint}
    <p style="color:#8b949e;font-size:12px;margin-bottom:4px">{config_hint}</p>
    <p style="color:#58a6ff;font-size:12px;margin-bottom:8px">{ios_tip}</p>
    {app_links}
    {qr_block}
    <hr>
    <h2>{conf_section_title}</h2>
    <p style="color:#8b949e;font-size:12px;margin-bottom:4px">{conf_section_hint}</p>
    <p style="color:#58a6ff;font-size:12px;margin-bottom:8px">{copy_hint}</p>
    <div class="conf" id="conf-block" onclick="copyConf(this)" title="{copy_hint}"
         style="cursor:pointer;position:relative;user-select:all">{config}</div>
    <div id="copy-toast" style="display:none;color:#3fb950;font-size:13px;margin:4px 0 8px">{copied_msg}</div>
    <a href="/device/{wg_name}/download" class="btn b btn-full" style="margin-bottom:8px">
       {dl_btn_text}
    </a>
    <a href="/device/{wg_name}/delete" class="btn r btn-full"
       onclick="return confirm('{remove_confirm}')">
       {remove_label}
    </a>
  </div>
</div>
<script>
function copyConf(el) {{
  const text = el.innerText;
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(showToast, fallback);
  }} else {{ fallback(); }}
  function fallback() {{
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    showToast();
  }}
  function showToast() {{
    const t = document.getElementById('copy-toast');
    t.style.display = 'block';
    setTimeout(() => t.style.display = 'none', 2000);
  }}
}}
</script>"""
    return render_template_string(html)

@app.route("/device/<wg_name>/download")
@approved_required
def download_device(wg_name):
    u = session["user"]
    users = load_users()
    is_admin = users.get(u, {}).get("role") == "admin"
    if not is_admin and not wg_name.startswith(f"{u}-"):
        return "Access denied", 403
    config = get_config(wg_name)
    if not config:
        return "Device not found", 404
    display_name = wg_name.split("-", 1)[1] if "-" in wg_name else wg_name
    return Response(
        config,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'inline; filename="{display_name}.conf"'}
    )

@app.route("/device/<wg_name>/delete")
@approved_required
def delete_device_route(wg_name):
    u = session["user"]
    users = load_users()
    is_admin = users.get(u, {}).get("role") == "admin"

    if not is_admin and not wg_name.startswith(f"{u}-"):
        flash("Access denied.", "error")
        return redirect(url_for("dashboard"))

    delete_device(wg_name)
    send_telegram(
        f"🗑️ *Device removed*\n\n"
        f"👤 By: `{u}`\n"
        f"🔌 Device: `{wg_name}`\n"
        f"🕐 Time: {_now()}",
        silent=True
    )
    flash(f"Device '{wg_name}' removed.", "ok")

    if is_admin and request.referrer and "/admin" in request.referrer:
        return redirect(url_for("admin_devices"))
    return redirect(url_for("dashboard"))

@app.route("/tg_webhook", methods=["POST"])
def tg_webhook():
    """Handle Telegram inline button callbacks for approve/reject."""
    try:
        data = request.get_json(silent=True) or {}
        cq = data.get("callback_query")
        if not cq:
            return "ok"
        callback_id = cq["id"]
        cb_data = cq.get("data", "")
        msg = cq.get("message", {})
        msg_id = msg.get("message_id")
        chat_id = msg.get("chat", {}).get("id")
        parts = cb_data.split(":", 2)
        if len(parts) < 2:
            answer_callback(callback_id, "Invalid")
            return "ok"
        action, username = parts[0], parts[1]
        max_dev = int(parts[2]) if len(parts) > 2 else 3
        users = load_users()
        if username not in users:
            answer_callback(callback_id, "User not found")
            edit_tg_message(chat_id, msg_id, f"\u2753 User `{username}` not found (already processed?)")
            return "ok"
        if action == "approve":
            users[username]["approved"] = True
            users[username]["max_devices"] = max_dev
            save_users(users)
            limit_str = "\u221e" if max_dev == -1 else str(max_dev)
            answer_callback(callback_id, f"\u2705 {username} approved!")
            edit_tg_message(chat_id, msg_id,
                f"\u2705 *Approved:* `{username}`\nDevice limit: {limit_str}")
        elif action == "reject":
            del users[username]
            save_users(users)
            answer_callback(callback_id, f"\u274c {username} rejected")
            edit_tg_message(chat_id, msg_id,
                f"\u274c *Rejected:* `{username}` \u2014 account deleted")
    except Exception as e:
        import sys
        print(f"[TG WEBHOOK ERROR] {e}", file=sys.stderr, flush=True)
    return "ok"

@app.route("/traffic")
@admin_required
def traffic_page():
    try:
        collect_traffic()
    except Exception:
        pass
    traffic = load_traffic()
    month_key = datetime.now(timezone.utc).strftime("%Y-%m")
    all_devices = get_all_devices()
    lang = _lang()
    # First pass: totals only
    total_rx = total_tx = 0
    for owner, device, wg_name in all_devices:
        curr = traffic.get(wg_name, {}).get("monthly", {}).get(month_key, {"rx": 0, "tx": 0})
        total_rx += curr["rx"]
        total_tx += curr["tx"]
    nodata_label = f'<span style="color:#8b949e;font-size:11px">{t("tr_nodata", lang)}</span>'
    rows = ""
    for owner, device, wg_name in all_devices:
        entry = traffic.get(wg_name, {})
        monthly = entry.get("monthly", {})
        curr = monthly.get(month_key, {"rx": 0, "tx": 0})
        history = ""
        for mk in sorted(monthly.keys(), reverse=True)[:3]:
            m = monthly[mk]
            history += f'<span style="color:#8b949e;font-size:11px">{mk}: ↓{fmt_bytes(m["tx"])} ↑{fmt_bytes(m["rx"])}</span><br>'
        rows += f"""<tr>
          <td><span style="font-family:monospace;color:#8b949e">{owner}</span></td>
          <td><span style="font-family:monospace;color:#58a6ff">{device}</span></td>
          <td style="color:#3fb950">↓ {fmt_bytes(curr["tx"])}</td>
          <td style="color:#f78166">↑ {fmt_bytes(curr["rx"])}</td>
          <td>{history if history else nodata_label}</td>
        </tr>"""
    empty = f'<tr><td colspan="5" style="color:#8b949e;padding:16px">{t("tr_nodiv", lang)}</td></tr>' if not rows else ""
    html = page_head(f"Traffic {month_key}") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>📊 Traffic — {month_key}</h1>
    <p class="sub">{t("tr_sub", lang)}</p>
    <div style="display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap">
      <div class="stat-box"><div class="stat-num" style="color:#3fb950">{fmt_bytes(total_tx)}</div><div class="stat-lbl">{t("tr_total_dl", lang)}</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#f78166">{fmt_bytes(total_rx)}</div><div class="stat-lbl">{t("tr_total_ul", lang)}</div></div>
      <div class="stat-box"><div class="stat-num">{fmt_bytes(total_rx + total_tx)}</div><div class="stat-lbl">{t("tr_combined", lang)}</div></div>
    </div>
    <div class="tbl-wrap">
    <table><thead><tr><th>{t("tr_col_owner", lang)}</th><th>{t("tr_col_dev", lang)}</th><th>{t("tr_col_dl", lang)}</th><th>{t("tr_col_ul", lang)}</th><th>{t("tr_col_hist", lang)}</th></tr></thead>
    <tbody>{rows}{empty}</tbody></table>
    </div>
    <p style="color:#8b949e;font-size:12px;margin-top:12px">{t("tr_warn", lang)}</p>
  </div>
</div>"""
    return render_template_string(html)

# ─── Routes: Admin────────────────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin_panel():
    users = load_users()
    pending = [u for u, d in users.items() if not d["approved"] and d["role"] != "admin"]
    all_devices = get_all_devices()

    pending_rows = ""
    for u in pending:
        pending_rows += f"""<tr>
          <td><span style="font-family:monospace">{u}</span></td>
          <td>{users[u]['created_at']}</td>
          <td>
            <form method="POST" action="/admin/users/{u}/approve" style="display:inline">
              <input type="number" name="max_devices" value="3" min="1" max="50"
                     style="width:60px;margin:0 4px 0 0;padding:4px">
              <button class="btn g" style="padding:4px 10px;font-size:12px">Approve</button>
            </form>
            <a href="/admin/users/{u}/delete" class="btn r"
               style="padding:4px 10px;font-size:12px"
               onclick="return confirm('Delete user {u}?')">Delete</a>
          </td>
        </tr>"""

    html = page_head("Admin") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>⚙️ Admin Panel</h1>
    <p class="sub">Overview</p>
    <div class="row" style="gap:12px;margin-bottom:0">
      <div class="stat-box">
        <div class="stat-num" style="color:var(--accent)">{len(users)}</div>
        <div class="stat-lbl">Total users</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:var(--pend)">{len(pending)}</div>
        <div class="stat-lbl">Pending</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:var(--ok)">{len(all_devices)}</div>
        <div class="stat-lbl">Total devices</div>
      </div>
    </div>
  </div>

  {"" if not pending else f'''
  <div class="card">
    <h2>⏳ Pending Approvals ({len(pending)})</h2>
    <div class="tbl-wrap">
    <table><thead><tr><th>Username</th><th>Registered</th><th>Actions</th></tr></thead>
    <tbody>{pending_rows}</tbody></table>
    </div>
  </div>'''}

  <div class="card">
    <div class="row">
      <a href="/admin/users" class="btn b">👥 Manage Users</a>
      <a href="/admin/devices" class="btn b">📱 All Devices</a>
    </div>
  </div>
</div>"""
    return render_template_string(html)

@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    rows = ""
    for u, d in sorted(users.items()):
        devices = get_user_devices(u)
        max_d = d.get("max_devices", 3)
        limit = "∞" if max_d == -1 else str(max_d)
        amount = "∞ / ∞" if d["role"] == "admin" else f"{len(devices)} / {limit}"
        role_tag = '<span class="tag tag-admin">admin</span>' if d["role"] == "admin" \
                   else ('<span class="tag tag-ok">active</span>' if d["approved"]
                         else '<span class="tag tag-pend">pending</span>')
        edit_btn = "" if d["role"] == "admin" else f"""
          <form method="POST" action="/admin/users/{u}/edit" style="display:inline;gap:4px">
            <input type="number" name="max_devices" value="{max_d if max_d != -1 else ''}"
                   placeholder="∞" min="1" max="100"
                   style="width:55px;margin:0 4px 0 0;padding:3px 6px;font-size:12px">
            <button class="btn y" style="padding:4px 8px;font-size:11px">Save</button>
          </form>"""
        del_btn = "" if d["role"] == "admin" else \
            f'<a href="/admin/users/{u}/delete" class="btn r" style="padding:4px 8px;font-size:11px" onclick="return confirm(\'Delete {u} and all their devices?\')">Delete</a>'
        approve_btn = "" if d["approved"] else \
            f'<form method="POST" action="/admin/users/{u}/approve" style="display:inline"><input type="hidden" name="max_devices" value="3"><button class="btn g" style="padding:4px 8px;font-size:11px">Approve</button></form>'

        rows += f"""<tr>
          <td><span style="font-family:monospace">{u}</span></td>
          <td>{role_tag}</td>
          <td>{amount}</td>
          <td>{d['created_at']}</td>
          <td>{approve_btn} {edit_btn} {del_btn}</td>
        </tr>"""

    html = page_head("Users") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>👥 Users</h1>
    <p class="sub">Manage accounts and device limits</p>
    {flash_html()}
    <div class="tbl-wrap">
    <table>
      <thead><tr><th>Username</th><th>Status</th><th>Amount</th>
             <th>Registered</th><th>Actions</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>
  </div>
</div>"""
    return render_template_string(html)

@app.route("/admin/users/<username>/approve", methods=["POST"])
@admin_required
def admin_approve(username):
    users = load_users()
    if username in users and users[username]["role"] != "admin":
        try:
            max_d = int(request.form.get("max_devices", 3))
        except ValueError:
            max_d = 3
        users[username]["approved"] = True
        users[username]["max_devices"] = max_d
        save_users(users)
        flash(f"User '{username}' approved with {max_d} device limit.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/edit", methods=["POST"])
@admin_required
def admin_edit(username):
    users = load_users()
    if username in users and users[username]["role"] != "admin":
        val = request.form.get("max_devices", "").strip()
        try:
            users[username]["max_devices"] = -1 if not val else int(val)
        except ValueError:
            flash("Invalid device limit value.", "error")
            return redirect(url_for("admin_users"))
        save_users(users)
        flash(f"User '{username}' updated.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<username>/delete")
@admin_required
def admin_delete_user(username):
    users = load_users()
    if username in users and users[username]["role"] != "admin":
        # Delete all their devices
        for device in get_user_devices(username):
            delete_device(client_name(username, device))
        del users[username]
        save_users(users)
        flash(f"User '{username}' and all their devices deleted.", "ok")
    return redirect(url_for("admin_users"))

@app.route("/admin/devices")
@admin_required
def admin_devices():
    all_devices = get_all_devices()
    rows = ""
    for owner, device, wg_name in all_devices:
        rows += f"""<tr>
          <td><span style="font-family:monospace;color:#8b949e">{owner}</span></td>
          <td><span style="font-family:monospace;color:#58a6ff">{device}</span></td>
          <td>
            <a href="/device/{wg_name}" class="btn b" style="padding:4px 10px;font-size:12px">View</a>
            <a href="/device/{wg_name}/delete" class="btn r" style="padding:4px 10px;font-size:12px"
               onclick="return confirm('Remove {wg_name}?')">Remove</a>
          </td>
        </tr>"""
    empty = '<tr><td colspan="3" style="color:#8b949e;padding:16px">No devices.</td></tr>' if not rows else ""

    html = page_head("All Devices") + CSS + f"""
<div class="wide">
  {nav_bar(True)}
  <div class="card">
    <h1>📱 All Devices ({len(all_devices)})</h1>
    <p class="sub">Every WireGuard client across all users</p>
    {flash_html()}
    <div class="tbl-wrap">
    <table><thead><tr><th>Owner</th><th>Device</th><th>Actions</th></tr></thead>
    <tbody>{rows}{empty}</tbody></table>
    </div>
  </div>
</div>"""
    return render_template_string(html)

# ─── Start ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class HTTPSRedirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(301)
            self.send_header("Location", f"https://{DOMAIN}{self.path}")
            self.end_headers()
        def do_POST(self):
            self.do_GET()
        def log_message(self, *a):
            pass

    def run_redirect():
        from socketserver import ThreadingMixIn

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True
            def get_request(self):
                sock, addr = super().get_request()
                try:
                    sock.settimeout(REDIRECT_SOCKET_TIMEOUT_SECS)
                except Exception:
                    pass
                return sock, addr

        try:
            ThreadingHTTPServer(("0.0.0.0", HTTP_REDIRECT_PORT), HTTPSRedirect).serve_forever()
        except OSError as e:
            import sys
            print(f"[HTTP REDIRECT] Failed to bind on :{HTTP_REDIRECT_PORT}: {e}", file=sys.stderr, flush=True)

    if ENABLE_HTTP_REDIRECT:
        threading.Thread(target=run_redirect, daemon=True).start()

    def traffic_loop():
        import time
        time.sleep(10)  # wait for app to fully start
        while True:
            try:
                collect_traffic()
            except Exception:
                pass
            time.sleep(60)

    threading.Thread(target=traffic_loop, daemon=True).start()
    set_tg_webhook()

    os.makedirs(CLIENTS_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    ensure_admin()
    cert_ready = os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY)
    ssl_ctx = (SSL_CERT, SSL_KEY) if ENABLE_INTERNAL_TLS and cert_ready else None
    if ENABLE_INTERNAL_TLS and not cert_ready:
        import sys
        print("[TLS] Cert files missing, starting without internal TLS", file=sys.stderr, flush=True)
    app.run(host=BIND_HOST, port=PORT, debug=False, ssl_context=ssl_ctx, threaded=True)
