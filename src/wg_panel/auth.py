from functools import wraps

from flask import flash, redirect, render_template_string, session, url_for

from .core import _lang, load_users
from .ui import pending_page


def _current_user():
    username = session.get("user")
    if not username:
        return None, None
    user = load_users().get(username)
    if not user or session.get("session_version") != user.get("session_version", 1):
        session.clear()
        return None, None
    return username, user

def login_required(f):
    @wraps(f)
    def deco(*a, **kw):
        username, _user = _current_user()
        if not username:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return deco

def approved_required(f):
    @wraps(f)
    def deco(*a, **kw):
        _username, user = _current_user()
        if not user:
            return redirect(url_for("login"))
        if not user.get("approved"):
            return render_template_string(pending_page(_lang()))
        return f(*a, **kw)
    return deco

def admin_required(f):
    @wraps(f)
    def deco(*a, **kw):
        _username, user = _current_user()
        if not user:
            return redirect(url_for("login"))
        if user.get("role") != "admin":
            flash("Access denied.", "error")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return deco
