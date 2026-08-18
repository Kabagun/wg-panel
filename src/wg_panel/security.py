import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

from flask import abort, request, session
from markupsafe import Markup


class WindowRateLimiter:
    """Bounded in-memory sliding-window limiter for a single-process service."""

    def __init__(self, max_keys=2048, clock=time.monotonic):
        self._events = defaultdict(deque)
        self._max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()

    def consume(self, namespace, key, limit, window_seconds):
        now = self._clock()
        bucket_key = (namespace, str(key))
        with self._lock:
            events = self._events[bucket_key]
            cutoff = now - window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                retry_after = max(1, int(window_seconds - (now - events[0])))
                return False, retry_after
            events.append(now)
            self._trim()
            return True, 0

    def reset(self, namespace, key):
        with self._lock:
            self._events.pop((namespace, str(key)), None)

    def _trim(self):
        while len(self._events) > self._max_keys:
            self._events.pop(next(iter(self._events)))


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
        self._failures = defaultdict(deque)
        self._blocked_until = {}
        self._lock = threading.Lock()

    def check(self, key):
        now = self._clock()
        key = str(key)
        with self._lock:
            blocked_until = self._blocked_until.get(key, 0)
            if blocked_until > now:
                return False, max(1, int(blocked_until - now))
            self._blocked_until.pop(key, None)
            self._prune(key, now)
            return True, 0

    def record_failure(self, key):
        now = self._clock()
        key = str(key)
        with self._lock:
            self._prune(key, now)
            failures = self._failures[key]
            failures.append(now)
            if len(failures) >= self.threshold:
                self._blocked_until[key] = now + self.cooldown_seconds
            while len(self._failures) > self.max_keys:
                oldest = next(iter(self._failures))
                self._failures.pop(oldest, None)
                self._blocked_until.pop(oldest, None)

    def reset(self, key):
        key = str(key)
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)

    def _prune(self, key, now):
        failures = self._failures[key]
        cutoff = now - self.window_seconds
        while failures and failures[0] <= cutoff:
            failures.popleft()
        if not failures:
            self._failures.pop(key, None)


public_rate_limiter = WindowRateLimiter()
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
