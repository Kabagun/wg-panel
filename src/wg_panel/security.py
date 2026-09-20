import hmac
import secrets
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from flask import abort, request, session
from markupsafe import Markup


class WindowRateLimiter:
    """Bounded in-memory sliding-window limiter for a single-process service."""

    def __init__(self, max_keys=2048, clock=time.monotonic):
        self._events = {}
        self._expires = {}
        self._max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()

    def consume(self, namespace, key, limit, window_seconds):
        now = self._clock()
        bucket_key = (namespace, str(key))
        with self._lock:
            if bucket_key not in self._events:
                for existing, expiry in list(self._expires.items()):
                    if expiry <= now:
                        self._events.pop(existing, None)
                        self._expires.pop(existing, None)
                if len(self._events) >= self._max_keys:
                    return False, max(1, int(min(self._expires.values()) - now))
                self._events[bucket_key] = deque()
            events = self._events[bucket_key]
            cutoff = now - window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(window_seconds - (now - events[0])))
                return False, retry_after
            events.append(now)
            self._expires[bucket_key] = now + window_seconds
            return True, 0

    def reset(self, namespace, key):
        with self._lock:
            self._events.pop((namespace, str(key)), None)
            self._expires.pop((namespace, str(key)), None)


class LoginFailureLimiter:
    """Apply a cooldown after repeated failed authentication attempts."""

    def __init__(
        self,
        threshold=5,
        window_seconds=300,
        cooldown_seconds=900,
        max_keys=2048,
        clock=time.monotonic,
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._failures = {}
        self._blocked_until = {}
        self._lock = threading.Lock()

    def check(self, key):
        now = self._clock()
        key = str(key)
        with self._lock:
            self._prune_expired(now)
            blocked_until = self._blocked_until.get(key, 0)
            if blocked_until > now:
                return False, max(1, int(blocked_until - now))
            if key not in self._failures and len(self._failures) >= self.max_keys:
                expiry = min(
                    max(events[-1] + self.window_seconds if events else 0,
                        self._blocked_until.get(existing, 0))
                    for existing, events in self._failures.items()
                )
                return False, max(1, int(expiry - now))
            return True, 0

    def record_failure(self, key):
        now = self._clock()
        key = str(key)
        with self._lock:
            self._prune_expired(now)
            if self._blocked_until.get(key, 0) > now:
                return
            if key not in self._failures and len(self._failures) >= self.max_keys:
                return
            failures = self._failures.setdefault(key, deque(maxlen=self.threshold))
            failures.append(now)
            if len(failures) >= self.threshold:
                self._blocked_until[key] = now + self.cooldown_seconds

    def reset(self, key):
        key = str(key)
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)

    def _prune_expired(self, now):
        cutoff = now - self.window_seconds
        for key, failures in list(self._failures.items()):
            while failures and failures[0] <= cutoff:
                failures.popleft()
            if self._blocked_until.get(key, 0) <= now:
                self._blocked_until.pop(key, None)
                if not failures:
                    self._failures.pop(key, None)


public_rate_limiter = WindowRateLimiter()
login_request_limiter = WindowRateLimiter()
login_failure_limiter = LoginFailureLimiter()


def client_ip():
    """Return the ProxyFix-normalized peer address, never a raw forwarding header."""
    return (request.remote_addr or "unknown").strip()


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def csrf_input():
    return Markup(f'<input type="hidden" name="csrf_token" value="{csrf_token()}">')


def validate_csrf():
    supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="Invalid CSRF token")

    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if origin:
        parsed = urlsplit(origin)
        if parsed.netloc and parsed.netloc.lower() != request.host.lower():
            abort(400, description="Cross-origin request rejected")


def rate_limited_response(retry_after):
    return (
        "Too many requests. Please try again later.",
        429,
        {"Retry-After": str(retry_after)},
    )
