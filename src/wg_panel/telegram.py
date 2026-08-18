import json
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .core import DOMAIN, TG_CHAT_ID, TG_TOKEN, TG_WEBHOOK_SECRET

_EXECUTOR_WORKERS = 4
_EXECUTOR_QUEUE = 64
_executor = ThreadPoolExecutor(max_workers=_EXECUTOR_WORKERS, thread_name_prefix="wg-panel-bg")
_executor_slots = threading.BoundedSemaphore(_EXECUTOR_WORKERS + _EXECUTOR_QUEUE)


def telegram_configured(require_chat=True):
    if not TG_TOKEN:
        return False
    return bool(TG_CHAT_ID) if require_chat else True


def submit_background(function, *args, **kwargs):
    """Submit bounded background work; return False when backpressure is active."""
    if not _executor_slots.acquire(blocking=False):
        return False
    try:
        future = _executor.submit(function, *args, **kwargs)
    except RuntimeError:
        _executor_slots.release()
        return False
    def completed(done_future):
        _executor_slots.release()
        exception = done_future.exception()
        if exception is not None:
            print(f"[BACKGROUND ERROR] {exception}", file=sys.stderr, flush=True)

    future.add_done_callback(completed)
    return True


def _telegram_api(method, payload, timeout=10):
    if not telegram_configured(require_chat=False):
        return None
    url = f"https://api.telegram.org/bot{TG_TOKEN}/{method}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError("Telegram response exceeded 128 KiB")
        decoded = json.loads(raw.decode("utf-8"))
        if decoded.get("ok") is not True:
            raise ValueError(f"Telegram API rejected {method}")
        return decoded.get("result")
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
        print(f"[TG ERROR] {method}: {exc}", file=sys.stderr, flush=True)
        return None


def send_telegram_sync(text, silent=False, parse_mode="Markdown", buttons=None):
    """Send one administrator message and return whether Telegram acknowledged it."""
    if not telegram_configured():
        return False
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": text,
        "disable_notification": bool(silent),
        "disable_web_page_preview": True,
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": buttons}
    return _telegram_api("sendMessage", payload) is not None


def send_telegram(text, silent=False):
    """Queue one Markdown Telegram message without creating unbounded threads."""
    if not telegram_configured():
        return False
    return submit_background(send_telegram_sync, text, silent, "Markdown")


def send_telegram_buttons(text, buttons):
    """Queue one Markdown Telegram message with an inline keyboard."""
    if not telegram_configured():
        return False
    return submit_background(send_telegram_sync, text, False, "Markdown", buttons)


def answer_callback(callback_id, text=""):
    if not telegram_configured(require_chat=False):
        return False
    return _telegram_api(
        "answerCallbackQuery",
        {"callback_query_id": callback_id, "text": text},
        timeout=5,
    ) is not None


def edit_tg_message(chat_id, message_id, text):
    if not telegram_configured(require_chat=False):
        return False
    return _telegram_api(
        "editMessageText",
        {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        },
        timeout=5,
    ) is not None


def set_tg_webhook():
    """Register an authenticated callback-only Telegram webhook."""
    if not telegram_configured(require_chat=False) or DOMAIN == "localhost":
        return False
    if not TG_WEBHOOK_SECRET:
        print("[TG WEBHOOK] WG_PANEL_TELEGRAM_WEBHOOK_SECRET is required", file=sys.stderr, flush=True)
        return False
    return _telegram_api(
        "setWebhook",
        {
            "url": f"https://{DOMAIN}/tg_webhook",
            "secret_token": TG_WEBHOOK_SECRET,
            "allowed_updates": ["callback_query"],
            "drop_pending_updates": False,
        },
    ) is not None
