import json
import threading
import urllib.parse
import urllib.request

from .core import DOMAIN, TG_CHAT_ID, TG_TOKEN

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
