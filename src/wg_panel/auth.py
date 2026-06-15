from functools import wraps

from flask import flash, redirect, render_template_string, session, url_for

from .core import _lang, load_users
from .ui import pending_page

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
