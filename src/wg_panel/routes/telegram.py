from flask import request

from ..core import app, load_users, save_users
from ..telegram import answer_callback, edit_tg_message

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
