import calendar
import html
import re
import threading
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .core import (
    PAYMENT_ACCOUNT,
    PAYMENT_ERIP_PATH,
    PAYMENT_TIME,
    PAYMENT_TIMEZONE,
    load_users,
    mutate_users,
)
from .telegram import send_telegram_sync

TELEGRAM_USERNAME_RE = re.compile(r"^[a-z0-9_]{5,32}$", re.IGNORECASE)
_payment_run_lock = threading.Lock()


def normalize_telegram_username(value):
    username = str(value or "").strip()
    username = username.removeprefix("@")
    username = username.lower()
    return username if TELEGRAM_USERNAME_RE.fullmatch(username) else ""


def payment_price(max_devices):
    if max_devices == -1:
        return 15
    if 1 <= max_devices <= 3:
        return 5
    if 4 <= max_devices <= 5:
        return 7
    return None


def effective_due_date(year, month, payment_day):
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, min(payment_day, last_day))


def next_effective_due_date(payment_day, today=None):
    today = today or datetime.now(_payment_zone()).date()
    current = effective_due_date(today.year, today.month, payment_day)
    if today <= current:
        return current
    first_next = (current.replace(day=1) + timedelta(days=32)).replace(day=1)
    return effective_due_date(first_next.year, first_next.month, payment_day)


def payment_today():
    return datetime.now(_payment_zone()).date()


def _payment_zone():
    try:
        return ZoneInfo(PAYMENT_TIMEZONE)
    except ZoneInfoNotFoundError:
        return ZoneInfo("Europe/Minsk")


def _payment_start_time():
    try:
        hour, minute = (int(part) for part in PAYMENT_TIME.split(":", 1))
        return time(hour, minute)
    except (TypeError, ValueError):
        return time(9, 0)


def _is_due(user, now):
    if not user.get("payment_enabled") or not user.get("approved"):
        return False
    day = user.get("payment_day")
    if not isinstance(day, int) or not 1 <= day <= 31:
        return False
    if not normalize_telegram_username(user.get("telegram_username")):
        return False
    if payment_price(user.get("max_devices")) is None:
        return False
    due = effective_due_date(now.year, now.month, day)
    if now.date() < due:
        return False
    if now.date() == due and now.time().replace(tzinfo=None) < _payment_start_time():
        return False
    return user.get("payment_last_notified_month") != now.strftime("%Y-%m")


def build_payment_messages(username, user, due):
    telegram_username = normalize_telegram_username(user.get("telegram_username"))
    price = payment_price(user.get("max_devices"))
    limit = "Безлимит" if user.get("max_devices") == -1 else str(user.get("max_devices"))
    due_text = due.strftime("%d.%m.%Y")
    summary = (
        "💳 <b>Напоминание об оплате VPN</b>\n\n"
        f"👤 Аккаунт: <code>{html.escape(username)}</code>\n"
        f"✈️ Telegram: @{html.escape(telegram_username)}\n"
        f"📱 Лимит устройств: {html.escape(limit)}\n"
        f"💰 К оплате: <b>{price} BYN</b>\n"
        f"📅 Дата оплаты: <b>{due_text}</b>"
    )
    forward_text = (
        f"Здравствуйте! Напоминаю об оплате VPN-доступа — <b>{price} BYN</b>.\n\n"
        "🏦 <b>Оплата через ЕРИП:</b>\n"
        f"{html.escape(PAYMENT_ERIP_PATH)}\n\n"
        "💳 <b>Данные для пополнения:</b>\n"
        f"<code>{html.escape(PAYMENT_ACCOUNT)}</code>\n\n"
        "Чек об оплате отправлять не нужно. Спасибо!"
    )
    buttons = [[{"text": f"Написать @{telegram_username}", "url": f"https://t.me/{telegram_username}"}]]
    return summary, forward_text, buttons


def _prepare_delivery(username, month):
    def prepare(users):
        user = users.get(username)
        if (
            not user
            or not user.get("payment_enabled")
            or user.get("payment_last_notified_month") == month
        ):
            return None
        delivery = user.get("payment_delivery")
        if not isinstance(delivery, dict) or delivery.get("month") != month:
            delivery = {"month": month, "parts": []}
            user["payment_delivery"] = delivery
        parts = delivery.get("parts")
        if not isinstance(parts, list):
            parts = []
            delivery["parts"] = parts
        return list(parts)

    return mutate_users(prepare)


def _checkpoint(username, month, part):
    def checkpoint(users):
        user = users.get(username)
        if not user or not user.get("payment_enabled"):
            return False
        delivery = user.setdefault("payment_delivery", {"month": month, "parts": []})
        if delivery.get("month") != month:
            delivery.clear()
            delivery.update({"month": month, "parts": []})
        if part not in delivery["parts"]:
            delivery["parts"].append(part)
        if {"summary", "forward"}.issubset(delivery["parts"]):
            user["payment_last_notified_month"] = month
            user["payment_delivery"] = {"month": "", "parts": []}
        return True

    return mutate_users(checkpoint)


def process_payment_reminders(now=None, sender=send_telegram_sync):
    """Send all currently due reminders and return per-user delivery results."""
    if not PAYMENT_ACCOUNT or not PAYMENT_ERIP_PATH:
        return []
    if not _payment_run_lock.acquire(blocking=False):
        return []
    try:
        zone = _payment_zone()
        if now is None:
            now = datetime.now(zone)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=zone)
        else:
            now = now.astimezone(zone)
        month = now.strftime("%Y-%m")
        results = []
        for username, user in sorted(load_users().items()):
            if user.get("role") == "admin" or not _is_due(user, now):
                continue
            due = effective_due_date(now.year, now.month, user["payment_day"])
            summary, forward_text, buttons = build_payment_messages(username, user, due)
            parts = _prepare_delivery(username, month)
            if parts is None:
                continue
            if "summary" not in parts:
                if not sender(summary, False, "HTML", buttons):
                    results.append((username, "summary_failed"))
                    continue
                if not _checkpoint(username, month, "summary"):
                    results.append((username, "disabled"))
                    continue
            if "forward" not in parts:
                if not sender(forward_text, False, "HTML"):
                    results.append((username, "forward_failed"))
                    continue
                if not _checkpoint(username, month, "forward"):
                    results.append((username, "disabled"))
                    continue
            results.append((username, "sent"))
        return results
    finally:
        _payment_run_lock.release()
