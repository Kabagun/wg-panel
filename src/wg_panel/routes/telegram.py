import hmac

from flask import request

from ..core import TG_CHAT_ID, TG_WEBHOOK_SECRET, app, mutate_users
from ..telegram import answer_callback, edit_tg_message


def _authorized_webhook():
    supplied = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    return bool(
        TG_WEBHOOK_SECRET
        and supplied
        and hmac.compare_digest(TG_WEBHOOK_SECRET, supplied)
    )


@app.route("/tg_webhook", methods=["POST"])
def tg_webhook():
    """Handle authenticated, one-time administrator approval callbacks."""
    if not _authorized_webhook():
        return "forbidden", 403

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return "invalid", 400
    callback = data.get("callback_query")
    if not isinstance(callback, dict):
        return "ok"

    callback_id = str(callback.get("id") or "")
    message = callback.get("message") if isinstance(callback.get("message"), dict) else {}
    chat = message.get("chat") if isinstance(message.get("chat"), dict) else {}
    actor = callback.get("from") if isinstance(callback.get("from"), dict) else {}
    chat_id = str(chat.get("id") or "")
    actor_id = str(actor.get("id") or "")
    if not TG_CHAT_ID or chat_id != str(TG_CHAT_ID) or actor_id != str(TG_CHAT_ID):
        return "forbidden", 403

    parts = str(callback.get("data") or "").split(":")
    action = parts[0] if parts else ""
    token = parts[1] if len(parts) > 1 else ""
    if action not in {"approve", "reject"} or not token or len(parts) not in {2, 3}:
        answer_callback(callback_id, "Invalid action")
        return "ok"

    max_devices = None
    if action == "approve":
        if len(parts) != 3:
            answer_callback(callback_id, "Invalid limit")
            return "ok"
        try:
            max_devices = int(parts[2])
        except ValueError:
            max_devices = None
        if max_devices not in {3, 5, -1}:
            answer_callback(callback_id, "Invalid limit")
            return "ok"

    def apply(users):
        match = next(
            (
                (username, user)
                for username, user in users.items()
                if user.get("role") != "admin"
                and not user.get("revoking")
                and not user.get("approved")
                and hmac.compare_digest(str(user.get("approval_token", "")), token)
            ),
            None,
        )
        if not match:
            return None
        username, user = match
        if action == "approve":
            user["approved"] = True
            user["max_devices"] = max_devices
            user.pop("approval_token", None)
        else:
            del users[username]
        return username

    username = mutate_users(apply)
    message_id = message.get("message_id")
    if not username:
        answer_callback(callback_id, "Already processed")
        edit_tg_message(chat_id, message_id, "❓ Registration already processed or expired.")
        return "ok"

    if action == "approve":
        limit = "∞" if max_devices == -1 else str(max_devices)
        answer_callback(callback_id, f"✅ {username} approved")
        edit_tg_message(chat_id, message_id, f"✅ *Approved:* `{username}`\nDevice limit: {limit}")
    else:
        answer_callback(callback_id, f"❌ {username} rejected")
        edit_tg_message(chat_id, message_id, f"❌ *Rejected:* `{username}` — account deleted")
    return "ok"
