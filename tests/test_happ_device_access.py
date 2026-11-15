"""A device capability is not an account login; monthly counters stay directional."""
# Pytest shares the imported runtime fixture across acceptance modules.
# ruff: noqa: F811
import base64
import copy
from datetime import UTC, datetime
from urllib.parse import urlsplit

import pytest
from test_happ_routes import (  # noqa: F401
    ADMIN,
    CLASSIC,
    FOREIGN,
    OTHER,
    PILOT,
    PRIVATE,
    ROUTER,
    SECOND,
    browser,
    runtime,
    subscription,
)

from wg_panel import core, happ_pilot, traffic, wireguard
from wg_panel.happ_device_access import device_access_token
from wg_panel.happ_subscription_usage import record_sample
from wg_panel.routes import happ as routes


def page(name=PILOT, token=None):
    device = wireguard.get_device(name)
    token = token or device_access_token(device, core.load_users()[device['owner']])
    return f'/device/{name}/happ/access/{token}'


@pytest.fixture
def frozen(monkeypatch):
    class Clock(datetime):
        current = datetime(2026, 11, 15, 12, tzinfo=UTC)

        @classmethod
        def now(cls, tz=None):
            return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)

    monkeypatch.setattr(routes, 'datetime', Clock)
    return Clock


def test_single_subscription_link_opens_device_without_login_or_an_account_session(runtime):
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200 and 'support-url' not in response.headers
    link = urlsplit(response.headers['profile-web-page-url'])
    assert link.path == page()
    client = browser(None)
    details = client.get(link.path)
    assert details.status_code == 200
    text = details.get_data(as_text=True)
    assert 'Kabagun VPN' in text and 'Подключите устройство' in text
    assert 'AI и другие сервисы из списка администратора' in text
    assert 'Беларуси и России' in text and 'ПОМЕСЯЧНЫЙ УЧЁТ' in text
    assert 'Не передавайте ссылку и QR' in text
    assert PRIVATE not in text and FOREIGN not in text
    assert 'Set-Cookie' not in details.headers
    with client.session_transaction() as session:
        assert 'user' not in session and 'account_id' not in session
    assert client.get('/dashboard').status_code == 302
    assert 'no-store' in details.headers['Cache-Control']
    assert details.headers['Referrer-Policy'] == 'no-referrer'
    assert details.headers['X-Robots-Tag'] == 'noindex, nofollow, noarchive'
    assert 'frame-ancestors' in details.headers['Content-Security-Policy']


def test_purpose_and_device_bound_tokens_cannot_authenticate_other_resources(runtime):
    device = wireguard.get_device(PILOT)
    user = core.load_users()[ADMIN]
    token = device_access_token(device, user)
    sub_token = happ_pilot.subscription_token(device, user)
    assert token != sub_token and len(token) == 43
    client = browser(None)
    assert client.get(page(token=sub_token)).status_code == 404
    assert client.get(subscription(mode='bundle', token=token)).status_code == 404
    assert client.get(page(SECOND, token)).status_code == 404
    assert client.get(page(FOREIGN, token)).status_code == 404


def test_link_rotation_and_account_identity_change_revoke_existing_page(runtime):
    original = page()
    happ_pilot.rotate_subscription(PILOT)
    assert browser(None).get(original).status_code == 404
    replacement = page()
    assert browser(None).get(replacement).status_code == 200
    core.mutate_users(lambda users: users[ADMIN].update(account_id='c' * 64))
    assert browser(None).get(replacement).status_code == 404


@pytest.mark.parametrize('scope,flag', [
    ('account', 'paused'), ('account', 'pause_pending'), ('account', 'revoking'),
    ('device', 'happ_transport_deleting'), ('device', 'deletion_protected'),
])
def test_lifecycle_gates_are_enforced_before_returning_a_capability_page(runtime, scope, flag):
    link = page()
    if scope == 'account':
        core.mutate_users(lambda users: users[ADMIN].update({flag: True}))
    else:
        traffic.mutate_device_meta(lambda meta: meta[PILOT].update({flag: True}))
    assert browser(None).get(link).status_code == 404


def test_unapproved_deleted_and_classic_devices_cannot_use_page(runtime):
    link = page()
    for name in (CLASSIC, ROUTER):
        assert browser(None).get(f'/device/{name}/happ/access/' + 'a' * 43).status_code == 404
    core.mutate_users(lambda users: users[ADMIN].update(approved=False))
    assert browser(None).get(link).status_code == 404
    core.mutate_users(lambda users: users[ADMIN].update(approved=True))
    traffic.mutate_device_meta(lambda meta: meta.pop(PILOT))
    assert browser(None).get(link).status_code == 404


def test_public_read_cannot_mutate_a_device_or_change_existing_login(runtime):
    client = browser(OTHER)
    before = copy.deepcopy(traffic.load_device_meta())
    details = client.get(page())
    assert details.status_code == 200
    assert 'data-delete-open' not in details.get_data(as_text=True)
    assert '<form' not in details.get_data(as_text=True)
    with client.session_transaction() as session:
        assert session['user'] == OTHER
    assert client.post(page(), data={'name': 'injected'}).status_code in (400, 405)
    assert traffic.load_device_meta() == before


def test_device_label_is_autoescaped_on_public_page(runtime):
    monkey_name = '<img src=x onerror=alert(1)>'
    # The visible label is derived from the immutable config filename in production.
    original = wireguard.get_device
    from unittest.mock import patch
    def get_device(name):
        device = original(name)
        if name == PILOT:
            device = {**device, 'device': monkey_name}
        return device
    with patch.object(wireguard, 'get_device', get_device):
        response = browser(None).get(page())
    assert response.status_code == 200
    assert monkey_name not in response.get_data(as_text=True)
    assert '&lt;img' in response.get_data(as_text=True)


def test_month_rollover_resets_header_and_page_without_modifying_history(runtime, frozen):
    entry = {'monthly': {'2026-11': {'rx': 10**12, 'tx': 10**12}}}
    record_sample(entry, generation='test', upload_bytes=100, download_bytes=200,
                  sampled_at=datetime(2026, 11, 15, 9, tzinfo=UTC))
    record_sample(entry, generation='test', upload_bytes=223, download_bytes=656,
                  sampled_at=datetime(2026, 11, 15, 10, tzinfo=UTC))
    traffic.save_traffic({PILOT: entry})
    before = traffic.load_traffic()
    client = browser(None)
    assert client.get(subscription()).headers['subscription-userinfo'] == 'upload=123; download=456; total=0'
    november = client.get(page()).get_data(as_text=True)
    assert '11.2026' in november and '15.11.2026' in november
    frozen.current = datetime(2026, 11, 30, 21, tzinfo=UTC)  # Midnight in Minsk.
    response = client.get(subscription())
    assert response.headers['subscription-userinfo'] == 'upload=0; download=0; total=0'
    banner = base64.b64decode(response.headers['announce'].removeprefix('base64:')).decode()
    assert '12.2026' in banner and 'с 01.12' not in banner
    december = client.get(page()).get_data(as_text=True)
    assert '12.2026' in december and '01.12.2026' in december
    assert traffic.load_traffic() == before


def test_capability_page_is_rate_limited(runtime):
    client = browser(None)
    link = page()
    statuses = [client.get(link).status_code for _ in range(31)]
    assert statuses[:30] == [200] * 30
    assert statuses[-1] == 429
