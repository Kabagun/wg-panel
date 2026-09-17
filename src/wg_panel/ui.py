"""Shared, autoescaped page rendering and local interface assets."""

from flask import render_template, session
from markupsafe import Markup

from .core import _lang, load_users
from .i18n import t
from .security import csrf_input
from .traffic import fmt_bytes

ICONS = {
    "shield": '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z"/><path d="m8 12 3 3 5-6"/>',
    "grid": '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
    "devices": '<rect x="3" y="4" width="14" height="11" rx="2"/><path d="M7 20h7m-4-5v5"/><rect x="16" y="10" width="6" height="11" rx="1.5"/>',
    "phone": '<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 5h4m-3 14h2"/>',
    "laptop": '<rect x="4" y="3" width="16" height="13" rx="2"/><path d="m4 16-2 4h20l-2-4M9 20h6"/>',
    "router": '<rect x="3" y="12" width="18" height="8" rx="2"/><path d="M6 12V4m12 8V4M7 16h.01M11 16h.01"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "arrow": '<path d="M5 12h14m-5-5 5 5-5 5"/>',
    "back": '<path d="M19 12H5m5-5-5 5 5 5"/>',
    "chevron": '<path d="m9 5 7 7-7 7"/>',
    "down": '<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
    "upload": '<path d="M12 18V4m-5 5 5-5 5 5M4 17v4h16v-4"/>',
    "users": '<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3m1-16a3 3 0 0 1 0 6m2 4a5 5 0 0 1 3 4v2"/>',
    "chart": '<path d="M4 3v17h17M8 15v-4m5 4V7m5 8V4"/>',
    "logout": '<path d="M9 4H4v16h5m5-12 4 4-4 4M8 12h13"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "check": '<path d="m5 12 4 4L19 6"/>',
    "lock": '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4m-4 5v2"/>',
    "key": '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-5-5 3-3m-6 0 3-3"/>',
    "eye": '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12"/><circle cx="12" cy="12" r="3"/>',
    "copy": '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
    "trash": '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "close": '<path d="m6 6 12 12M6 18 18 6"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
    "qr": '<path d="M3 3h6v6H3zm12 0h6v6h-6zM3 15h6v6H3zm12 0h2v2h-2zm4 0h2v6h-6v-2m-3-7h3m-3-8v4M3 12h5"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
}


def icon(name, size=20):
    """Render a decorative icon from the fixed local SVG collection."""
    paths = ICONS.get(name, ICONS["devices"])
    return Markup(
        f'<svg width="{int(size)}" height="{int(size)}" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.65" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{paths}</svg>'
    )


def device_icon(name):
    """Choose a decorative device icon using its user-provided name."""
    name = name.lower()
    if any(part in name for part in ("phone", "iphone", "ipad", "tablet", "pixel")):
        return "phone"
    if any(part in name for part in ("router", "keenetic", "home")):
        return "router"
    return "laptop"


def render_page(template, title_key, *, lang=None, auth_view=False, **context):
    """Render user content as autoescaped data, never as Jinja source."""
    lang = lang or _lang()
    username = session.get("user", "")
    user = load_users().get(username, {}) if username and not auth_view else {}
    return render_template(
        template,
        lang=lang,
        title=t(title_key, lang),
        tr=lambda key: t(key, lang),
        icon=icon,
        device_icon=device_icon,
        csrf=lambda: Markup(csrf_input()),
        fmt_bytes=fmt_bytes,
        current_username=username,
        is_admin=user.get("role") == "admin",
        auth_view=auth_view,
        **context,
    )


def login_page(lang):
    """Render the sign-in page."""
    return render_page("auth.html", "ui_login_title", lang=lang, auth_view=True, mode="login")


def register_page(lang):
    """Render account registration."""
    return render_page("auth.html", "auth_create", lang=lang, auth_view=True, mode="register")


def pending_page(lang):
    """Render the approval gate without application navigation."""
    return render_page("auth.html", "pend_title", lang=lang, auth_view=True, mode="pending")


def forgot_page(lang):
    """Render the password recovery request."""
    return render_page("auth.html", "auth_recovery", lang=lang, auth_view=True, mode="forgot")


def reset_page(lang, username):
    """Render password replacement for the validated account."""
    return render_page(
        "auth.html", "reset_title", lang=lang, auth_view=True, mode="reset", username=username
    )
