"""Reference-control delivery retains family comparison and truthful UI metadata."""
import base64
import json

import pytest
from test_happ_routes import (  # noqa: F401
    FOREIGN,
    PILOT,
    browser,
    runtime,
    subscription,
)
from test_happ_transports import VLESS

from wg_panel import core, happ_runtime, traffic
from wg_panel.happ_subscription_info import build_headers

pytestmark = pytest.mark.family_archive


def test_public_control_bundle_header_and_page_report_seven_entries(runtime, monkeypatch):  # noqa: F811
    traffic.mutate_device_meta(lambda meta: meta[FOREIGN].update(safe_internet=True))
    core.write_json_private(str(runtime.data / 'happ_comparisons.json'), {
        'version': 1, 'devices': {PILOT: {'account_id': 'a' * 64,
            'family': {'wg_name': FOREIGN, 'account_id': 'b' * 64},
            'client_dns_only': True, 'reference_control': True}}})
    core.write_json_private(str(runtime.data / 'happ_dns_transport.json'), {
        'version': 1, 'accounts': {'a' * 64: 'tcp', 'b' * 64: 'tcp'}})
    monkeypatch.setattr(happ_runtime, 'transport_options', lambda _device: [
        {'id': 'vless-reality', 'title': 'VLESS / REALITY', 'available': True}])
    monkeypatch.setattr(happ_runtime, 'client_settings', lambda _device, _transport: VLESS)
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    configs = response.get_json()
    assert len(configs) == 7 and configs[-1]['remarks'] == '🇫🇮 🧪 Контроль · UDP без QUIC'
    assert all(c['routing']['domainStrategy'] == 'AsIs' for c in configs)
    routing = json.loads(base64.b64decode(response.headers['routing'].removeprefix('happ://routing/onadd/')))
    assert routing['DomainStrategy'] == 'AsIs'
    assert routing['RemoteDNSIP'] == routing['DomesticDNSIP'] == '10.8.0.1'
    assert set(routing['ProxyIp']) == {'10.8.0.1', '1.1.1.1', '8.8.8.8'}
    announcement = base64.b64decode(response.headers['announce'].removeprefix('base64:')).decode()
    assert '7 профилей' in announcement and 'контроль UDP без QUIC' in announcement
    page = browser().get(f'/device/{PILOT}/happ', headers={'Accept-Language': 'ru'}).get_data(as_text=True)
    assert 'Семь профилей' in page and 'диагностический тест без семейной фильтрации' in page
    assert 'один из шести' not in page
    assert len(browser(None).get(subscription(name=FOREIGN, mode='bundle')).get_json()) == 3


@pytest.mark.parametrize('comparison,control', [(False, True), (True, 1), (True, 'true')])
def test_control_announcement_flag_requires_a_real_comparison_and_boolean(comparison, control):
    with pytest.raises(ValueError, match='Invalid subscription presentation data'):
        build_headers(upload_bytes=0, download_bytes=0, panel_base_url='https://panel.example.test',
                      device_path='/device/synthetic/happ', usage_scope='sources', usage_month='2026-11',
                      comparison=comparison, comparison_control=control)
