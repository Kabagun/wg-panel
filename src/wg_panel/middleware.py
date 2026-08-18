from flask import g, request

from .core import _request_slots, app
from .security import validate_csrf


@app.before_request
def limit_concurrent_requests():
    if not _request_slots.acquire(blocking=False):
        return "Server is busy. Please retry in a moment.", 503, {"Retry-After": "5"}
    g._request_slot_acquired = True
    return None


@app.before_request
def enforce_csrf():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.endpoint != "tg_webhook":
        validate_csrf()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("Cache-Control", "no-store, private, max-age=0")
    response.headers.setdefault("Pragma", "no-cache")
    response.headers.setdefault("Expires", "0")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'",
    )
    return response

@app.teardown_request
def release_concurrent_requests(_exc):
    if getattr(g, "_request_slot_acquired", False):
        g._request_slot_acquired = False
        _request_slots.release()
