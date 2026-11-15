"""Purpose-separated, revocable read access to one Happ device."""
import base64
import hmac

from . import core, happ_pilot


def device_access_token(device, user):
    """Bind the page capability to the current device, account and subscription nonce.

    A page token cannot authenticate as a subscription token or create a session.
    Rotating the subscription nonce revokes both independently derived tokens.
    """
    subscription = happ_pilot.subscription_token(device, user)
    key = core.app.secret_key
    if isinstance(key, str):
        key = key.encode()
    message = b'happ-device-page-v1\0' + subscription.encode('ascii')
    return base64.urlsafe_b64encode(hmac.digest(key, message, 'sha256')).decode().rstrip('=')
