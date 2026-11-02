"""Short-lived, one-use device deletion challenges.

Only opaque random nonces reach the browser. Device fingerprints (including a
hash of the raw config) remain in process memory. A restart invalidates every
pending confirmation. All callers hold the device lifecycle lock.
"""

import secrets
import time
from dataclasses import dataclass

CHALLENGE_TTL_SECONDS = 300
MAX_CHALLENGES = 512


@dataclass(frozen=True)
class _Challenge:
    actor: tuple
    identity: tuple
    expires_at: float


_challenges: dict[str, _Challenge] = {}


def issue(actor, identity):
    now = time.monotonic()
    for nonce, challenge in list(_challenges.items()):
        if challenge.expires_at <= now:
            _challenges.pop(nonce, None)
    while len(_challenges) >= MAX_CHALLENGES:
        _challenges.pop(next(iter(_challenges)))
    nonce = secrets.token_urlsafe(32)
    _challenges[nonce] = _Challenge(actor, identity, now + CHALLENGE_TTL_SECONDS)
    return nonce


def consume(nonce, actor, identity):
    # Pop before validation so every submitted challenge is one-use, including
    # incorrect names and failed helper calls. The lifecycle lock serializes it.
    challenge = _challenges.pop(nonce, None)
    return bool(
        challenge
        and challenge.expires_at > time.monotonic()
        and challenge.actor == actor
        and challenge.identity == identity
    )
