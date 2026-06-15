from flask import g

from .core import app, _request_slots

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
