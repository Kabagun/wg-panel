"""Closed pilot acceptance with synthetic identities, keys and resolver state."""

import base64
import hashlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from flask import url_for
from werkzeug.datastructures import MultiDict

from wg_panel import (
    account_policy,
    app,
    core,
    happ_peers,
    happ_pilot,
    happ_shared_rules,
    infrastructure,
    security,
    traffic,
    wireguard,
)
from wg_panel.dns_enforcement import SafeDnsEnforcementError
from wg_panel.happ_config import MODES
from wg_panel.routes import devices as device_routes
from wg_panel.routes import happ as happ_routes

ADMIN = "pilotadmin"
OTHER = "otheradmin"
PILOT = "u10-pilotadmin-pilot"
SECOND = "u10-pilotadmin-second"
FOREIGN = "u10-otheradmin-pilot"
CLASSIC = "u5-alice-phone"
ROUTER = "u10-pilotadmin-router"
PRIVATE = base64.b64encode(bytes(32)).decode()
PUBLIC = base64.b64encode(bytes([1]) * 32).decode()
PSK = base64.b64encode(bytes([2]) * 32).decode()
CSRF = "synthetic-csrf"


def config(address="10.0.0.2", private=PRIVATE, psk=PSK):
    return (
        f"[Interface]\nPrivateKey = {private}\nAddress = {address}/32\n"
        "DNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\n"
        f"PublicKey = {PUBLIC}\nPresharedKey = {psk}\n"
        "Endpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )


def browser(username=ADMIN):
    client = app.test_client()
    if username:
        user = core.load_users()[username]
        with client.session_transaction() as session:
            session.update(user=username, account_id=user["account_id"], session_version=1,
                           _csrf_token=CSRF)
    return client


def subscription(name=PILOT, mode="custom", token=None):
    device = wireguard.get_device(name)
    if token is None:
        token = happ_pilot.subscription_token(device, core.load_users()[device["owner"]])
    with app.test_request_context():
        return url_for("happ_subscription", wg_name=name, token=token, mode=mode)


def rules_form(**changes):
    return {"csrf_token": CSRF, "wg_name": PILOT, "mode": "custom", "revision": "0",
            "rules": "Example.ORG\n192.0.2.12/24", **changes}


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    wg = tmp_path / "wireguard"
    clients = wg / "clients"
    clients.mkdir(parents=True)
    for module, attribute, value in (
        (core, "DATA_DIR", data), (core, "WG_DIR", wg), (core, "CLIENTS_DIR", clients),
        (core, "USERS_FILE", data / "users.json"),
        (core, "DEVICE_META_FILE", data / "device_meta.json"),
        (core, "TRAFFIC_FILE", data / "traffic.json"),
        (traffic, "DEVICE_META_FILE", data / "device_meta.json"),
        (traffic, "TRAFFIC_FILE", data / "traffic.json"), (traffic, "CLIENTS_DIR", clients),
        (wireguard, "CLIENTS_DIR", clients), (wireguard, "WG_DIR", wg),
    ):
        monkeypatch.setattr(module, attribute, str(value))
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", True)
    monkeypatch.setitem(app.config, "HAPP_ROLLOUT_ENABLED", False)
    monkeypatch.setitem(app.config, "HAPP_PUBLIC_BASE_URL", "https://vpn.example.test")
    monkeypatch.setattr(app, "secret_key", b"synthetic-happ-test-signing-key-32-bytes")
    monkeypatch.setattr(happ_pilot, "qr_for_link", lambda _link: None)
    monkeypatch.setattr(device_routes, "qr_svg_b64", lambda _name: None)
    monkeypatch.setattr(device_routes, "send_telegram", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(wireguard, "_run_script",
                        lambda *_args, **_kwargs: pytest.fail("unexpected peer mutation"))
    clock = [1000.0]
    monkeypatch.setattr(happ_routes, "public_rate_limiter",
                        security.WindowRateLimiter(clock=lambda: clock[0]))
    core.save_users({
        ADMIN: {"role": "admin", "approved": True, "max_devices": -1,
                "session_version": 1, "account_id": "a" * 64},
        OTHER: {"role": "admin", "approved": True, "max_devices": -1,
                "session_version": 1, "account_id": "b" * 64},
        "alice": {"role": "user", "approved": True, "max_devices": 3,
                  "session_version": 1, "account_id": "c" * 64},
    })
    metadata = {}
    for index, (name, owner, label, pilot) in enumerate((
        (PILOT, ADMIN, "pilot", True), (SECOND, ADMIN, "second", True),
        (FOREIGN, OTHER, "pilot", True), (CLASSIC, "alice", "phone", False),
        (ROUTER, ADMIN, "router", False),
    ), 2):
        (clients / f"{name}.conf").write_text(config(f"10.0.0.{index}"), encoding="utf-8", newline="\n")
        metadata[name] = {"owner": owner, "device": label, "vpn_type": "wireguard",
                          "safe_internet": False, "happ_pilot": pilot}
        if pilot:
            metadata[name]["happ_subscription_nonce"] = str(index) * 64
    metadata[ROUTER]["deletion_protected"] = True
    # Route tests exercise delivery and authorization. The transport module's
    # own tests cover durable provisioning, binding and rollback separately.
    mappings = {}
    for parent_index, parent in enumerate((PILOT, SECOND, FOREIGN)):
        mappings[parent] = {'all': parent}
        for mode_index, mode in enumerate(('custom', 'by-ru-direct')):
            child = f'{parent}-transport-{mode_index}'
            mappings[parent][mode] = child
            private = base64.b64encode(bytes([4 + parent_index * 2 + mode_index]) * 32).decode()
            psk = base64.b64encode(bytes([20 + parent_index * 2 + mode_index]) * 32).decode()
            (clients / f'{child}.conf').write_text(
                config(f'10.0.0.{100 + parent_index * 2 + mode_index}', private, psk), encoding='utf-8')
            metadata[child] = {'owner': metadata[parent]['owner'], 'device': mode,
                'vpn_type': 'wireguard', 'happ_pilot': True, 'happ_transport_internal': True,
                'happ_parent': parent, 'happ_mode': mode, 'safe_internet': False}
    monkeypatch.setattr(happ_peers, 'mode_mapping', lambda parent: dict(mappings[parent]))
    traffic.save_device_meta(metadata)
    account_policy.save_account_policies({})
    target = wg / "safe-dns-target"
    target.write_text("10.8.0.1:18004\n", encoding="ascii")
    return SimpleNamespace(data=data, wg=wg, clients=clients, target=target, clock=clock,
                           mappings=mappings)


def test_disabled_pilot_hides_entry_choice_and_all_exports(runtime, monkeypatch):
    (runtime.data / "happ_pilot.json").write_text('{"version":1,"enabled":true}')
    path = subscription()
    monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", False)
    admin = browser()
    for url in ("/admin/happ-pilot", f"/device/{PILOT}/happ",
                f"/device/{PILOT}/happ/custom/download", path):
        assert admin.get(url).status_code == 404
    for url in ("/dashboard", "/add"):
        page = admin.get(url).get_data(as_text=True)
        assert 'href="/admin/happ-pilot"' not in page
        assert 'name="client_app"' not in page
    assert admin.post("/add", data={"csrf_token": CSRF, "device": "new",
                                          "client_app": "happ"}).status_code == 403
    assert admin.get(f"/device/{PILOT}/download").status_code == 200


@pytest.mark.parametrize("username", [None, "alice", OTHER])
def test_private_pilot_device_allows_approved_owner_or_managing_admin(runtime, username):
    client = browser(username)
    for url in (f"/device/{PILOT}/happ", f"/device/{PILOT}/happ/custom/download"):
        response = client.get(url)
        if username == OTHER:
            assert response.status_code == 200
            assert response.mimetype == ("application/json" if url.endswith("/download") else "text/html")
        else:
            assert response.status_code in {302, 404}
            assert response.mimetype != "application/json"
    if username != OTHER:
        assert client.get("/admin/happ-pilot").status_code == 302
    else:
        page = client.get("/admin/happ-pilot").get_data(as_text=True)
        assert f'href="/device/{FOREIGN}/happ"' in page
        assert f'href="/device/{PILOT}/happ"' not in page


@pytest.mark.parametrize("mode", MODES)
def test_ordinary_public_subscription_exports_public_dns_and_hourly_import_headers(runtime, mode):
    response = browser(None).get(subscription(mode=mode))
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert "attachment;" in response.headers["Content-Disposition"]
    assert response.headers["tun-enable"] == "1"
    assert response.headers['tun-type'] == 'default'
    assert response.headers["profile-update-interval"] == "1"
    assert response.headers["Cache-Control"].startswith("no-store")
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "Set-Cookie" not in response.headers
    exported = response.get_json()
    assert exported["dns"]["servers"] == ["1.1.1.1", "8.8.8.8"]
    vpn, = [item for item in exported["outbounds"] if item["tag"] == "vpn"]
    assert vpn["protocol"] == "wireguard"
    expected_mode = mode if mode in happ_pilot.BUNDLE_MODES else 'by-ru-direct'
    mapped = happ_peers.mode_mapping(PILOT)[expected_mode]
    expected_key = re.search(r'PrivateKey = (\S+)',
                            (runtime.clients / f'{mapped}.conf').read_text()).group(1)
    expected_psk = re.search(r'PresharedKey = (\S+)',
                            (runtime.clients / f'{mapped}.conf').read_text()).group(1)
    assert vpn["settings"]["secretKey"] == expected_key
    assert vpn["settings"]["remoteDNS"] == ["1.1.1.1", "8.8.8.8"]
    peer, = vpn["settings"]["peers"]
    assert peer["endpoint"] == "vpn.example.test:51820"
    assert peer["publicKey"] == PUBLIC and peer["preSharedKey"] == expected_psk
    prefix = "happ://routing/onadd/"
    assert response.headers["routing"].startswith(prefix)
    routing = json.loads(base64.b64decode(response.headers["routing"].removeprefix(prefix)))
    assert routing["RemoteDNSIP"] == routing["DomesticDNSIP"] == "1.1.1.1"
    assert routing["RemoteDNSType"] == routing["DomesticDNSType"] == "DoU"


def test_subscription_presentation_uses_new_trusted_usage_without_collecting_or_leaking_history(
        runtime, monkeypatch):
    from wg_panel import happ_runtime
    from wg_panel.happ_subscription_usage import record_sample

    entry = {'monthly': {'2026-11': {'rx': 999_000, 'tx': 123_000}}}
    start = datetime(2026, 11, 14, 22, tzinfo=UTC)
    record_sample(entry, generation='test', upload_bytes=100, download_bytes=200, sampled_at=start)
    record_sample(entry, generation='test', upload_bytes=223, download_bytes=656,
                  sampled_at=start + timedelta(minutes=1))
    traffic.save_traffic({PILOT: entry, SECOND: {'monthly': {'2026-11': {'rx': 10**12, 'tx': 10**12}}}})
    before = traffic.load_traffic()
    monkeypatch.setattr(happ_runtime, 'collect_traffic', lambda: pytest.fail('public request collected traffic'))
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    assert response.headers['subscription-userinfo'] == 'upload=123; download=456; total=0'
    assert response.headers['profile-web-page-url'] == f'https://vpn.example.test/device/{PILOT}/happ'
    assert response.headers['support-url'] == 'https://vpn.example.test/'
    announcement = base64.b64decode(response.headers['announce'].removeprefix('base64:')).decode()
    assert '15.11.2026' in announcement  # 22:00 UTC is the next day in Minsk.
    assert 'Безлимит' in announcement and '3 режима' in announcement
    assert len(announcement) <= 200 and 'expire' not in response.headers['subscription-userinfo']
    assert traffic.load_traffic() == before


@pytest.mark.parametrize('history', [[], {PILOT: []}, {PILOT: {'happ_subscription_usage': {'version': 999}}}])
def test_invalid_optional_usage_never_blocks_subscription(runtime, history):
    traffic.save_traffic(history)
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200 and len(response.get_json()) == 3
    assert 'subscription-userinfo' not in response.headers
    assert response.headers['support-url'] == 'https://vpn.example.test/'


def test_bundle_contains_three_distinct_transport_identities_and_shared_dns(runtime):
    identity = core.load_users()[ADMIN]['account_id']
    happ_pilot.save_rules(identity, 'ai.example.org\n192.0.2.0/24', 0)
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    assert response.headers['Cache-Control'].startswith('no-store')
    assert response.headers['profile-title'] == 'VPN modes'
    assert response.headers['tun-enable'] == '1'
    assert response.headers['tun-type'] == 'default'
    assert 'Set-Cookie' not in response.headers
    bundle = response.get_json()
    assert isinstance(bundle, list) and len(bundle) == 3
    assert len({item['remarks'] for item in bundle}) == 3
    assert happ_pilot.BUNDLE_MODES == ('all', 'custom', 'by-ru-direct')
    for mode, item in zip(happ_pilot.BUNDLE_MODES, bundle, strict=True):
        assert item == browser(None).get(subscription(mode=mode)).get_json()
        assert item['dns']['servers'] == ['1.1.1.1', '8.8.8.8']
        assert item['meta']['serverDescription']
    settings = [next(o for o in item['outbounds'] if o['tag'] == 'vpn')['settings']
                for item in bundle]
    assert len({item['secretKey'] for item in settings}) == 3
    assert len({tuple(item['address']) for item in settings}) == 3
    assert len({item['peers'][0]['preSharedKey'] for item in settings}) == 3
    assert len({(item['peers'][0]['publicKey'], item['peers'][0]['endpoint'])
                for item in settings}) == 1
    assert bundle[0]['routing']['rules'][-1]['outboundTag'] == 'vpn'
    assert bundle[1]['routing']['rules'][-1]['outboundTag'] == 'direct'
    assert bundle[2]['routing']['rules'][-1]['outboundTag'] == 'vpn'
    assert any(rule.get('domain') == ['domain:ai.example.org']
               and rule['outboundTag'] == 'vpn' for rule in bundle[1]['routing']['rules'])
    assert any(rule.get('ip') == ['geoip:by', 'geoip:ru']
               and rule['outboundTag'] == 'direct' for rule in bundle[2]['routing']['rules'])
    routing = json.loads(base64.b64decode(
        response.headers['routing'].removeprefix('happ://routing/onadd/')))
    assert {'geoip:by', 'geoip:ru'} <= set(routing['DirectIp'])
    assert len(routing['DirectIp']) == len(set(routing['DirectIp']))
    assert routing['RemoteDNSIP'] == routing['DomesticDNSIP'] == '1.1.1.1'
    assert routing['ProxyIp'] == ['1.1.1.1']
    assert routing['Geoipurl'].endswith('/geoip.dat')
    assert browser().get(f'/device/{PILOT}/happ/bundle/download').get_json() == bundle


@pytest.mark.parametrize('family', [False, True])
def test_account_scoped_tcp_dns_bundle_preserves_policy_headers_and_stored_configs(runtime, family):
    if family:
        account_policy.save_account_policies({ADMIN: {'safe_internet_locked': True}})
    before = {path.name: path.read_bytes() for path in runtime.clients.glob('*.conf')}
    identity = core.load_users()[ADMIN]['account_id']
    core.write_json_private(str(runtime.data / 'happ_dns_transport.json'),
                            {'version': 1, 'accounts': {identity: 'tcp'}})
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    bundle = response.get_json()
    resolver = '10.8.0.1' if family else '1.1.1.1'
    expected = ['tcp://10.8.0.1'] if family else ['tcp://1.1.1.1', 'tcp://8.8.8.8']
    assert all(item['dns']['servers'] == expected for item in bundle)
    assert [item['routing']['rules'][-1]['outboundTag'] for item in bundle] == [
        'vpn', 'direct', 'vpn']
    assert all(item['routing']['rules'][0] == {
        'type': 'field', 'inboundTag': ['dns-internal'], 'outboundTag': 'vpn'} for item in bundle)
    routing = json.loads(base64.b64decode(
        response.headers['routing'].removeprefix('happ://routing/onadd/')))
    assert routing['RemoteDNSIP'] == routing['DomesticDNSIP'] == resolver
    assert routing['RemoteDNSType'] == routing['DomesticDNSType'] == 'DoU'
    assert response.headers['profile-update-interval'] == '1'
    assert all(not server.startswith('tcp://') for server in
               browser(None).get(subscription(name=FOREIGN, mode='all')).get_json()['dns']['servers'])
    assert {path.name: path.read_bytes() for path in runtime.clients.glob('*.conf')} == before


def test_admin_comparison_bundle_has_six_named_modes_and_keeps_other_subscriptions(runtime, monkeypatch):
    from test_happ_transports import VLESS

    from wg_panel import happ_runtime
    traffic.mutate_device_meta(lambda meta: meta[FOREIGN].update(safe_internet=True))
    core.write_json_private(str(runtime.data / 'happ_comparisons.json'), {
        'version': 1, 'devices': {PILOT: {
            'account_id': 'a' * 64,
            'family': {'wg_name': FOREIGN, 'account_id': 'b' * 64}}}})
    core.write_json_private(str(runtime.data / 'happ_dns_transport.json'), {
        'version': 1, 'accounts': {'a' * 64: 'tcp', 'b' * 64: 'tcp'}})
    monkeypatch.setattr(happ_runtime, 'transport_options', lambda _device: [
        {'id': 'vless-reality', 'title': 'VLESS / REALITY', 'available': True}])
    monkeypatch.setattr(happ_runtime, 'client_settings', lambda item, _transport: {
        **VLESS, 'uuid': ('d4a79772-9db8-4bdc-a146-63fdd4709975' if item['wg_name'] == PILOT
                         else 'd4a79772-9db8-4bdc-a146-63fdd4709976')})
    from wg_panel.happ_subscription_usage import record_sample
    usage_history = {}
    for name, upload, download in [(PILOT, 123, 456), (FOREIGN, 7, 8), (SECOND, 10**9, 10**9)]:
        entry = {}
        record_sample(entry, generation='test', upload_bytes=0, download_bytes=0,
                      sampled_at=datetime(2026, 11, 14, tzinfo=UTC))
        record_sample(entry, generation='test', upload_bytes=upload, download_bytes=download,
                      sampled_at=datetime(2026, 11, 14, 1, tzinfo=UTC))
        usage_history[name] = entry
    traffic.save_traffic(usage_history)
    before = {path.name: path.read_bytes() for path in runtime.clients.glob('*.conf')}
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    bundle = response.get_json()
    assert len(bundle) == 6
    assert len({item['remarks'] for item in bundle}) == 6
    assert [item['routing']['rules'][-1]['outboundTag'] for item in bundle] == [
        'vpn', 'vpn', 'direct', 'direct', 'vpn', 'vpn']
    for index, item in enumerate(bundle):
        assert item['dns']['servers'] == (
            ['tcp://10.8.0.1'] if index % 2 == 0 else ['tcp://1.1.1.1', 'tcp://8.8.8.8'])
        assert next(out for out in item['outbounds'] if out['tag'] == 'vpn')['protocol'] == 'vless'
    title = response.headers['profile-title']
    assert title.startswith('base64:')
    assert base64.b64decode(title.removeprefix('base64:')).decode() == 'Сравнение DNS'
    routing = json.loads(base64.b64decode(
        response.headers['routing'].removeprefix('happ://routing/onadd/')))
    assert routing['RemoteDNSIP'] == routing['DomesticDNSIP'] == '10.8.0.1'
    assert set(routing['ProxyIp']) == {'10.8.0.1', '1.1.1.1', '8.8.8.8'}
    assert {'geoip:by', 'geoip:ru'} <= set(routing['DirectIp'])
    assert response.headers['profile-update-interval'] == '1'
    assert response.headers['subscription-userinfo'] == 'upload=130; download=464; total=0'
    assert '6 профилей' in base64.b64decode(response.headers['announce'].removeprefix('base64:')).decode()
    assert len(browser(None).get(subscription(name=FOREIGN, mode='bundle')).get_json()) == 3
    assert browser(None).get(subscription(mode='all')).get_json()['dns']['servers'] == [
        'tcp://1.1.1.1', 'tcp://8.8.8.8']
    page = browser().get(f'/device/{PILOT}/happ', headers={'Accept-Language': 'ru'}).get_data(as_text=True)
    assert 'Шесть профилей в одной подписке' in page
    assert 'Одиночная конфигурация ниже' in page
    assert {path.name: path.read_bytes() for path in runtime.clients.glob('*.conf')} == before


def test_normal_bundle_rejects_mixed_dns_and_comparison_rejects_nonadmin(runtime):
    configs = [{'dns': {'servers': ['1.1.1.1']}, 'routing': {'rules': []}},
               {'dns': {'servers': ['10.8.0.1']}, 'routing': {'rules': []}}]
    device = wireguard.get_device(PILOT)
    with pytest.raises(ValueError):
        happ_pilot.routing_header(device, 'bundle', configs)
    with pytest.raises(ValueError):
        happ_pilot.comparison_routing_header({**device, 'owner': 'alice'}, configs * 3)


def test_protected_bundle_exports_all_three_modes_with_same_family_dns(runtime):
    account_policy.save_account_policies({ADMIN: {'safe_internet_locked': True}})
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    bundle = response.get_json()
    assert len(bundle) == 3
    for mode,config in zip(happ_pilot.BUNDLE_MODES,bundle,strict=True):
        assert config == browser(None).get(subscription(mode=mode)).get_json()
        assert config['dns']['servers'] == ['10.8.0.1']
        vpn, = [item for item in config['outbounds'] if item['tag'] == 'vpn']
        assert vpn['settings']['remoteDNS'] == ['10.8.0.1']
        assert any(rule.get('port')=='853' and rule['outboundTag']=='block' for rule in config['routing']['rules'])
    assert len({config['outbounds'][0]['settings']['secretKey'] for config in bundle}) == 3
    assert bundle[1]['routing']['rules'][-1]['outboundTag'] == 'direct'
    assert response.headers['profile-update-interval'] == '1'
    routing = json.loads(base64.b64decode(
        response.headers['routing'].removeprefix('happ://routing/onadd/')))
    assert {'geoip:by','geoip:ru'} <= set(routing['DirectIp'])
    assert routing['GlobalProxy'] == 'true'
    assert routing['RemoteDNSIP'] == routing['DomesticDNSIP'] == '10.8.0.1'


@pytest.mark.parametrize('family', [False, True])
@pytest.mark.parametrize('transport,protocol', [('hysteria2','hysteria'),('vless-reality','vless')])
def test_modern_subscription_delivers_only_selected_transport_for_all_modes(
        runtime, monkeypatch, family, transport, protocol):
    from test_happ_transports import HYS, VLESS

    from wg_panel import happ_runtime
    if family:
        account_policy.save_account_policies({ADMIN: {'safe_internet_locked': True}})
    monkeypatch.setattr(happ_runtime, 'transport_options', lambda _device: [
        {'id': transport, 'title': 'Selected transport', 'available': True}])
    monkeypatch.setattr(happ_runtime, 'client_settings',
                        lambda _device, selected: HYS if selected=='hysteria2' else VLESS)
    before = (runtime.clients/f'{PILOT}.conf').read_bytes()
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    bundle = response.get_json()
    assert len(bundle) == 3 and len({config['remarks'] for config in bundle}) == 3
    for mode, config in zip(happ_pilot.BUNDLE_MODES, bundle, strict=True):
        assert config['outbounds'][0]['protocol'] == protocol
        assert config['dns']['servers'] == (['10.8.0.1'] if family else ['1.1.1.1','8.8.8.8'])
        assert not any(label in config['remarks'] for label in ('Hysteria','VLESS','WireGuard'))
        assert browser(None).get(subscription(mode=mode)).get_json() == config
        assert browser().get(f'/device/{PILOT}/happ/{mode}/download').get_json() == config
    assert (runtime.clients/f'{PILOT}.conf').read_bytes() == before
    assert browser().get(f'/device/{PILOT}/happ').status_code == 200
    assert browser().get(f'/device/{PILOT}/happ?transport=wireguard').status_code == 404
    other = 'vless-reality' if transport=='hysteria2' else 'hysteria2'
    assert browser(None).get(subscription()+'?transport='+other).status_code == 404
    assert browser(None).get(subscription()+'?transport='+transport+'&transport='+transport).status_code == 404


def test_preview_mode_does_not_change_bundle_import_or_advertise_retired_modes(runtime):
    admin = browser()
    url = 'https://vpn.example.test' + subscription(mode='bundle')
    for mode in happ_pilot.BUNDLE_MODES:
        page = admin.get(f'/device/{PILOT}/happ?mode={mode}').get_data(as_text=True)
        assert url in page and f'happ://add/{url}' in page
        assert f'/device/{PILOT}/happ/bundle/download' in page
        assert 'value="by-direct"' not in page and 'value="ru-direct"' not in page


def test_bundle_token_rotation_revokes_all_presets_without_replacing_peer(runtime):
    old = subscription(mode='bundle')
    before = (runtime.clients / f'{PILOT}.conf').read_bytes()
    assert browser(None).get(old).status_code == 200
    assert browser().post(f'/device/{PILOT}/happ/rotate',
                          data={'csrf_token': CSRF, 'mode': 'custom'}).status_code == 303
    assert browser(None).get(old).status_code == 404
    assert browser(None).get(subscription(mode='bundle')).status_code == 200
    assert (runtime.clients / f'{PILOT}.conf').read_bytes() == before


SHARED_SOURCE = 'https://raw.githubusercontent.com/example/policy/main/routing-domains.txt'


def enable_shared_rules(runtime, monkeypatch, text=b'shared.example.org\nsecond.example.org\n'):
    happ_shared_rules.sync(runtime.data, SHARED_SOURCE,
                           fetch=lambda *_args, **_kwargs: text, now=datetime.now(UTC))
    monkeypatch.setitem(app.config, 'HAPP_RULES_URL', SHARED_SOURCE)


def test_shared_list_is_exported_for_all_pilots_and_cannot_be_edited_per_account(runtime, monkeypatch):
    identity = core.load_users()[ADMIN]['account_id']
    happ_pilot.save_rules(identity, 'old-private.example.org', 0)
    original = (runtime.data / 'happ_rules.json').read_bytes()
    enable_shared_rules(runtime, monkeypatch)
    for device in (PILOT, FOREIGN):
        response = browser(None).get(subscription(name=device, mode='bundle'))
        assert response.status_code == 200
        for config in response.get_json():
            domains = [rule.get('domain', []) for rule in config['routing']['rules']]
            assert ['domain:second.example.org', 'domain:shared.example.org'] in domains
            assert not any('domain:old-private.example.org' in group for group in domains)
    assert browser().post('/account/happ-rules', data=rules_form()).status_code == 403
    with pytest.raises(ValueError):
        happ_pilot.save_rules(identity, 'different.example.org', 1)
    page = browser().get(f'/device/{PILOT}/happ').get_data(as_text=True)
    assert 'name="rules"' not in page
    assert 'https://github.com/example/policy/blob/main/routing-domains.txt' in page
    assert (runtime.data / 'happ_rules.json').read_bytes() == original
    assert happ_pilot.shared_rules_context()['shared_rules_status'] == 'current'


@pytest.mark.parametrize('state', ['missing', 'corrupt', 'wrong_source'])
def test_unusable_shared_cache_never_falls_back_to_personal_or_empty_rules(runtime, monkeypatch, state):
    enable_shared_rules(runtime, monkeypatch)
    cache = runtime.data / 'happ_shared_rules.json'
    if state == 'missing':
        cache.unlink()
    elif state == 'corrupt':
        cache.write_text('{broken')
    else:
        monkeypatch.setitem(app.config, 'HAPP_RULES_URL', SHARED_SOURCE.replace('main/', 'other/'))
    assert browser(None).get(subscription(mode='bundle')).status_code == 503
    assert browser().get(f'/device/{PILOT}/happ').status_code == 503
    assert browser('alice').get(f'/device/{CLASSIC}/download').status_code == 200


def test_failed_refresh_retains_shared_routes_and_shows_delayed_status(runtime, monkeypatch):
    enable_shared_rules(runtime, monkeypatch)
    before = browser(None).get(subscription(mode='bundle')).get_json()
    def failed(*_args, **_kwargs):
        raise OSError('synthetic failure')
    happ_shared_rules.sync(runtime.data, SHARED_SOURCE, fetch=failed, now=datetime.now(UTC))
    assert browser(None).get(subscription(mode='bundle')).get_json() == before
    assert happ_pilot.shared_rules_context()['shared_rules_status'] == 'delayed'


def test_old_successful_shared_check_is_marked_delayed_without_losing_rules(runtime, monkeypatch):
    happ_shared_rules.sync(runtime.data, SHARED_SOURCE,
                           fetch=lambda *_args, **_kwargs: b'shared.example.org\n',
                           now=datetime.now(UTC) - timedelta(minutes=16))
    monkeypatch.setitem(app.config, 'HAPP_RULES_URL', SHARED_SOURCE)
    assert happ_pilot.shared_rules_context()['shared_rules_status'] == 'delayed'
    assert browser(None).get(subscription(mode='bundle')).status_code == 200


def test_shared_gets_preserve_cached_list_account_state_and_wireguard(runtime, monkeypatch):
    enable_shared_rules(runtime, monkeypatch)
    files = [*runtime.clients.glob('*.conf'), *runtime.data.glob('*.json')]
    before = {str(path): path.read_bytes() for path in files}
    for path in (f'/device/{PILOT}/happ', f'/device/{PILOT}/happ/bundle/download',
                 subscription(mode='bundle')):
        assert browser().get(path).status_code == 200
    assert {str(path): path.read_bytes() for path in files} == before


@pytest.mark.parametrize("token", ["x" * 43, "short", "z" * 100, "é" * 43])
def test_wrong_or_malformed_subscription_credentials_fail_closed(runtime, token):
    assert browser(None).get(subscription(token=token)).status_code == 404


@pytest.mark.parametrize("mode", MODES[1:])
def test_protected_device_allows_split_modes_without_downgrading_dns_policy(runtime, mode):
    account_policy.save_account_policies({ADMIN: {"safe_internet_locked": True}})
    before = account_policy.load_account_policies()
    for response in (browser().get(f"/device/{PILOT}/happ/{mode}/download"),
                     browser(None).get(subscription(mode=mode))):
        assert response.status_code == 200
        config = response.get_json()
        assert config['dns']['servers'] == ['10.8.0.1']
        assert config['outbounds'][0]['settings']['remoteDNS'] == ['10.8.0.1']
    assert browser(None).get(subscription(mode="all")).status_code == 200
    assert account_policy.load_account_policies() == before


def test_subscription_rotation_requires_csrf_and_revokes_old_link_only(runtime):
    admin = browser()
    old = subscription()
    original_config = (runtime.clients / f"{PILOT}.conf").read_bytes()
    nonce = traffic.load_device_meta()[PILOT]["happ_subscription_nonce"]
    url = f"/device/{PILOT}/happ/rotate"
    assert admin.get(url).status_code == 405
    assert admin.post(url, data={"mode": "custom"}).status_code == 400
    assert traffic.load_device_meta()[PILOT]["happ_subscription_nonce"] == nonce
    assert browser(None).get(old).status_code == 200
    assert admin.post(url, data={"csrf_token": CSRF, "mode": "custom"}).status_code == 303
    assert browser(None).get(old).status_code == 404
    assert browser(None).get(subscription()).status_code == 200
    assert (runtime.clients / f"{PILOT}.conf").read_bytes() == original_config


@pytest.mark.parametrize("mode", ["custom", "bundle"])
@pytest.mark.parametrize("change", ["paused", "pause_pending", "unapproved", "revoking",
                                   "demoted", "account_deleted", "account_recreated",
                                   "device_revoked", "device_deleted", "config_deleted"])
def test_public_subscription_obeys_live_account_and_device_lifecycle(runtime, change, mode):
    path = subscription(mode=mode)
    assert browser(None).get(path).status_code == 200
    if change in {"paused", "pause_pending", "revoking"}:
        core.mutate_users(lambda users: users[ADMIN].update({change: True}))
    elif change == "unapproved":
        core.mutate_users(lambda users: users[ADMIN].update(approved=False))
    elif change == "demoted":
        core.mutate_users(lambda users: users[ADMIN].update(role="user"))
    elif change == "account_deleted":
        core.mutate_users(lambda users: users.pop(ADMIN))
    elif change == "account_recreated":
        core.mutate_users(lambda users: users[ADMIN].update(account_id="d" * 64))
    elif change == "device_revoked":
        traffic.mutate_device_meta(lambda meta: meta[PILOT].update(revoked=True))
    elif change == "device_deleted":
        traffic.mutate_device_meta(lambda meta: meta.pop(PILOT))
    else:
        (runtime.clients / f"{PILOT}.conf").unlink()
    assert browser(None).get(path).status_code == 404


def test_gets_preserve_raw_wireguard_files_metadata_users_and_permanent_policy(runtime):
    admin = browser()
    paths = [*runtime.clients.glob("*.conf"), runtime.data / "device_meta.json",
             runtime.data / "users.json", runtime.data / "account_policy.json", runtime.target]
    before = {path: path.read_bytes() for path in paths}
    for path in ("/admin/happ-pilot", f"/device/{PILOT}/happ", "/dashboard", "/add",
                 f"/device/{PILOT}/happ/custom/download", subscription(),
                 f"/device/{PILOT}/happ/bundle/download", subscription(mode="bundle")):
        assert admin.get(path).status_code == 200
    classic = browser("alice").get(f"/device/{CLASSIC}/download")
    assert classic.status_code == 200
    assert classic.get_data() == before[runtime.clients / f"{CLASSIC}.conf"]
    assert b"DNS = 1.1.1.1, 8.8.8.8" in classic.get_data()
    assert admin.get(f"/device/{PILOT}/download").get_data() == before[
        runtime.clients / f"{PILOT}.conf"
    ]
    assert {path: path.read_bytes() for path in paths} == before
    assert admin.get(f"/device/{PILOT}").location.endswith(f"/device/{PILOT}/happ")


def test_rules_save_is_csrf_checked_canonical_and_shared_by_account_identity(runtime):
    admin = browser()
    identity = core.load_users()[ADMIN]["account_id"]
    assert admin.post("/account/happ-rules", data=rules_form(csrf_token="bad")).status_code == 400
    assert happ_pilot.get_rules(identity) == (0, [])
    assert admin.post("/account/happ-rules", data=rules_form()).status_code == 303
    assert happ_pilot.get_rules(identity) == (1, ["domain:example.org", "192.0.2.0/24"])
    page = admin.get(f"/device/{SECOND}/happ").get_data(as_text=True)
    assert "domain:example.org" in page and 'name="revision" value="1"' in page
    other_identity = core.load_users()[OTHER]["account_id"]
    assert happ_pilot.get_rules(other_identity) == (0, [])
    core.mutate_users(lambda users: users[ADMIN].update(account_id="d" * 64))
    assert happ_pilot.get_rules("d" * 64) == (0, [])
    assert browser().post("/account/happ-rules", data=rules_form(rules="new.example")).status_code == 303
    assert happ_pilot.get_rules("d" * 64) == (1, ["domain:new.example"])
    assert happ_pilot.get_rules(identity) == (1, ["domain:example.org", "192.0.2.0/24"])


@pytest.mark.parametrize("change", ["stale", "invalid_rule", "script", "bad_revision",
                                   "duplicate_revision", "duplicate_rules", "foreign_target"])
def test_failed_rules_updates_never_overwrite_current_owner_list(runtime, change):
    admin = browser()
    identity = core.load_users()[ADMIN]["account_id"]
    assert admin.post("/account/happ-rules", data=rules_form()).status_code == 303
    before = (runtime.data / "happ_rules.json").read_bytes()
    form = MultiDict(rules_form(revision="1", rules="replacement.example"))
    if change == "stale":
        form["revision"] = "0"
    elif change == "invalid_rule":
        form["rules"] = "regexp:.*"
    elif change == "script":
        form["rules"] = "<script>synthetic()</script>"
    elif change == "bad_revision":
        form["revision"] = "-1"
    elif change == "duplicate_revision":
        form.add("revision", "1")
    elif change == "duplicate_rules":
        form.add("rules", "second.example")
    else:
        form["wg_name"] = FOREIGN
    response = admin.post("/account/happ-rules", data=form)
    assert response.status_code == (404 if change == "foreign_target" else 303)
    assert (runtime.data / "happ_rules.json").read_bytes() == before
    assert happ_pilot.get_rules(identity)[0] == 1
    if change == "script":
        page = admin.get(response.location).get_data(as_text=True)
        assert "<script>synthetic()</script>" not in page


def test_device_label_is_escaped_in_happ_page_and_json_stays_collapsed(runtime):
    label = "test <script>synthetic()</script>"
    traffic.mutate_device_meta(lambda meta: meta[PILOT].update(device=label))
    page = browser().get(f"/device/{PILOT}/happ").get_data(as_text=True)
    assert "test &lt;script&gt;synthetic()&lt;/script&gt;" in page
    assert "<script>synthetic()</script>" not in page
    details = re.findall(r'<details class="happ-private-details"([^>]*)>(.*?)</details>',
                         page, re.DOTALL)
    assert len(details) == 2 and all("open" not in attrs for attrs, _body in details)
    assert any('id="happ-config-block"' in body for _attrs, body in details)
    assert page.count("data-copy-status") == 2


@pytest.mark.parametrize("target_state", ["missing", "invalid"])
def test_missing_or_invalid_central_dns_fails_closed_without_affecting_classic_download(
    runtime, target_state,
):
    account_policy.save_account_policies({ADMIN: {'safe_internet_locked': True}})
    path = subscription(mode='all')
    before = {file.name: file.read_bytes() for file in runtime.clients.glob("*.conf")}
    if target_state == "missing":
        runtime.target.unlink()
    else:
        runtime.target.write_text("invalid-target\n", encoding="ascii")
    for url in (f"/device/{PILOT}/happ", f"/device/{PILOT}/happ/all/download", path):
        response = browser().get(url)
        assert response.status_code == 503
        assert response.mimetype != "application/json"
        assert "routing" not in response.headers
        assert PRIVATE not in response.get_data(as_text=True)
    assert browser("alice").get(f"/device/{CLASSIC}/download").status_code == 200
    assert {name: (runtime.clients / name).read_bytes() for name in before} == before


def test_ordinary_happ_export_does_not_depend_on_family_resolver(runtime):
    runtime.target.unlink()
    before = {file.name:file.read_bytes() for file in runtime.clients.glob('*.conf')}
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    assert all(item['dns']['servers'] == ['1.1.1.1','8.8.8.8'] for item in response.get_json())
    assert wireguard._safe_dns_ips(traffic.load_device_meta()) == []
    assert {name:(runtime.clients/name).read_bytes() for name in before} == before


def test_corrupted_rule_storage_fails_closed_on_private_and_public_exports(runtime):
    path = subscription()
    (runtime.data / "happ_rules.json").write_text('{"version":1,"accounts":"invalid"}')
    for url in (f"/device/{PILOT}/happ", f"/device/{PILOT}/happ/custom/download", path):
        response = browser().get(url)
        assert response.status_code == 503
        assert response.mimetype != "application/json"
        assert PRIVATE not in response.get_data(as_text=True)


def test_classic_or_ordinary_owner_device_is_not_a_pilot_export(runtime):
    assert browser().get(f"/device/{CLASSIC}/happ").status_code == 404
    traffic.mutate_device_meta(lambda meta: meta[CLASSIC].update(
        happ_pilot=True, happ_subscription_nonce="f" * 64,
    ))
    assert browser().get(f"/device/{CLASSIC}/happ/all/download").status_code == 404
    assert browser(None).get(subscription(CLASSIC)).status_code == 404


def test_forged_happ_choice_is_denied_but_classic_creation_remains_available(runtime, monkeypatch):
    calls = []
    monkeypatch.setattr(wireguard, "create_device", lambda *_args: pytest.fail("forged pilot"))
    monkeypatch.setattr(device_routes, "create_device",
                        lambda owner, name: calls.append((owner, name)) or (True, "classic-new", ""))
    alice = browser("alice")
    response = alice.post("/add", data={"csrf_token": CSRF, "device": "new", "client_app": "happ"})
    assert response.status_code == 403 and not calls
    response = alice.post("/add", data={"csrf_token": CSRF, "device": "new"})
    assert response.status_code == 302 and response.location.endswith("/device/classic-new")
    assert calls == [("alice", "new")]


@pytest.mark.parametrize("path", ["/admin/happ-pilot", "/add"])
def test_creating_fresh_pilot_marks_only_new_device_and_preserves_existing_profiles(
    runtime, monkeypatch, path,
):
    before = {file.name: file.read_bytes() for file in runtime.clients.glob("*.conf")}
    calls = []
    reconciled = []

    def create(owner, name, *, happ=False):
        assert happ is True
        calls.append((owner, name))
        wg_name = f"u{len(owner)}-{owner}-{name}"
        (runtime.clients / f"{wg_name}.conf").write_text(config("10.0.0.20"), encoding="utf-8")
        traffic.set_device_meta(wg_name, owner, name)
        return True, wg_name, ""

    monkeypatch.setattr(wireguard, "create_device", create)
    monkeypatch.setattr(happ_peers, 'ensure_mode_peers', lambda name: {'all': name})
    monkeypatch.setattr(wireguard, "_sync_safe_dns",
                        lambda ips, **_kwargs: reconciled.append(tuple(ips)) or tuple(ips))
    monkeypatch.setattr(device_routes, "create_device",
                        lambda *_args: pytest.fail("pilot must not call classic route creator"))
    admin = browser()
    form = {"csrf_token": CSRF, "device": "fresh", "client_app": "happ"}
    assert admin.post(path, data={**form, "csrf_token": "bad"}).status_code == 400
    assert not calls
    response = admin.post(path, data=form)
    assert response.status_code in {302, 303}
    name = "u10-pilotadmin-fresh"
    assert response.location.endswith(f"/device/{name}/happ")
    assert calls == [(ADMIN, "fresh")]
    item = traffic.load_device_meta()[name]
    assert item["happ_pilot"] is True
    assert re.fullmatch(r"[0-9a-f]{64}", item["happ_subscription_nonce"])
    assert reconciled == [()]
    assert {name: (runtime.clients / name).read_bytes() for name in before} == before


@pytest.mark.parametrize("device_name", ["pilot", "router"])
def test_existing_or_router_profile_cannot_be_adopted_as_pilot(runtime, monkeypatch, device_name):
    paths = [*runtime.clients.glob("*.conf"), runtime.data / "device_meta.json"]
    before = {path: path.read_bytes() for path in paths}
    monkeypatch.setattr(wireguard, "create_device",
                        lambda *_args: pytest.fail("existing identity must not be reprovisioned"))
    response = browser().post("/admin/happ-pilot", data={"csrf_token": CSRF, "device": device_name})
    assert response.status_code == 303
    assert {path: path.read_bytes() for path in paths} == before


@pytest.mark.parametrize("name", ["../router", "bad name", "x" * 65, "__"])
def test_invalid_pilot_names_cannot_reach_provisioning(runtime, monkeypatch, name):
    before = traffic.load_device_meta()
    monkeypatch.setattr(wireguard, "create_device",
                        lambda *_args: pytest.fail("invalid name reached provisioning"))
    response = browser().post("/admin/happ-pilot", data={"csrf_token": CSRF, "device": name})
    assert response.status_code == 303
    assert traffic.load_device_meta() == before


def test_protected_router_and_registered_infrastructure_are_never_exported(runtime, monkeypatch):
    traffic.mutate_device_meta(lambda meta: meta[ROUTER].update(
        happ_pilot=True, happ_subscription_nonce="f" * 64,
    ))
    assert browser().get(f"/device/{ROUTER}/happ").status_code == 404
    assert browser(None).get(subscription(ROUTER)).status_code == 404
    directory = runtime.wg / "infrastructure"
    directory.mkdir(mode=0o700)
    source = config("10.0.0.50").encode()
    profile = directory / "opaque-router.conf"
    profile.write_bytes(source)
    profile.chmod(0o600)
    monkeypatch.setattr(infrastructure, "_public_key", lambda _key: PUBLIC)
    core.write_json_private(str(runtime.data / "infrastructure_peers.json"), {
        "version": 1, "peers": {"opaque-router": {
            "kind": "router", "label": "synthetic-router", "public_key": PUBLIC,
            "ipv4": "10.0.0.50", "config_sha256": hashlib.sha256(source).hexdigest(),
        }},
    })
    before = profile.read_bytes()
    assert browser().get("/device/opaque-router/happ").status_code == 404
    assert browser().get("/device/opaque-router/happ/all/download").status_code == 404
    assert browser(None).get("/happ/sub/opaque-router/" + "x" * 43 + "/all").status_code == 404
    assert profile.read_bytes() == before


def test_public_subscription_is_rate_limited_and_recovers_after_window(runtime):
    client = browser(None)
    invalid = subscription(token="x" * 43)
    for _ in range(60):
        assert client.get(invalid).status_code == 404
    response = client.get(subscription())
    assert response.status_code == 429 and int(response.headers["Retry-After"]) > 0
    assert client.get(subscription(), environ_base={"REMOTE_ADDR": "198.51.100.20"}).status_code == 200
    runtime.clock[0] += 61
    assert client.get(subscription()).status_code == 200


def test_happ_marker_alone_does_not_enable_family_dns_redirect_or_lock_account(runtime):
    selected = set(wireguard._safe_dns_ips(traffic.load_device_meta()))
    assert selected == set()
    assert account_policy.load_account_policies() == {}
    assert wireguard.get_device(PILOT)["safe_internet"] is False
    assert wireguard.get_device(CLASSIC)["safe_internet"] is False
    traffic.mutate_device_meta(lambda meta: meta[PILOT].update(safe_internet=True))
    assert set(wireguard._safe_dns_ips(traffic.load_device_meta())) == {'10.0.0.2','10.0.0.100','10.0.0.101'}
    account_policy.save_account_policies({ADMIN: {'safe_internet_locked': True}})
    assert set(wireguard._safe_dns_ips(traffic.load_device_meta())) == {
        '10.0.0.2', '10.0.0.3', '10.0.0.6', *(f'10.0.0.{value}' for value in range(100,104)),
    }


def test_failed_pilot_dns_reconciliation_cannot_leave_exportable_new_peer(runtime, monkeypatch):
    name = "u10-pilotadmin-fresh"

    def create(owner, label, *, happ=False):
        assert happ is True
        (runtime.clients / f"{name}.conf").write_text(config("10.0.0.20"), encoding="utf-8")
        traffic.set_device_meta(name, owner, label)
        return True, name, ""

    def unavailable(**_kwargs):
        raise SafeDnsEnforcementError("synthetic DNS helper failure")

    def remove(wg_name):
        assert wg_name == name
        (runtime.clients / f"{name}.conf").unlink()
        traffic.mutate_device_meta(lambda meta: meta.pop(name))
        return True

    monkeypatch.setattr(wireguard, "create_device", create)
    monkeypatch.setattr(wireguard, "reconcile_safe_dns", unavailable)
    monkeypatch.setattr(wireguard, "delete_device", remove)
    response = browser().post("/admin/happ-pilot", data={"csrf_token": CSRF, "device": "fresh"})
    assert response.status_code in {303, 503}
    assert name not in traffic.load_device_meta()
    assert not (runtime.clients / f"{name}.conf").exists()


def test_access_log_redacts_subscription_device_and_credential(runtime, caplog):
    path = subscription()
    token = path.split("/")[-2]
    with caplog.at_level(logging.INFO, logger="werkzeug"):
        logging.getLogger("werkzeug").info('"GET %s HTTP/1.1" 200', path)
    assert "/happ/sub/[redacted]" in caplog.text
    assert token not in caplog.text and PILOT not in caplog.text


def test_rollout_allows_approved_owner_and_preserves_classic_export(runtime, monkeypatch):
    def transfer(meta):
        for name in runtime.mappings[PILOT].values():
            meta[name]['owner'] = 'alice'
    traffic.mutate_device_meta(transfer)
    classic = (runtime.clients / f'{CLASSIC}.conf').read_bytes()
    owner = browser('alice')
    assert owner.get(f'/device/{PILOT}/happ').status_code == 404
    monkeypatch.setitem(app.config, 'HAPP_ROLLOUT_ENABLED', True)
    assert owner.get(f'/device/{PILOT}/happ').status_code == 200
    assert owner.get(f'/device/{PILOT}').location.endswith(f'/device/{PILOT}/happ')
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200 and len(response.get_json()) == 3
    assert owner.get(f'/device/{CLASSIC}/download').data == classic
    core.mutate_users(lambda users: users['alice'].update(paused=True))
    assert browser(None).get(subscription(mode='bundle')).status_code == 404


def test_family_owner_rollout_exports_three_modes_with_account_dns(runtime, monkeypatch):
    monkeypatch.setitem(app.config, 'HAPP_ROLLOUT_ENABLED', True)
    account_policy.save_account_policies({ADMIN: {'safe_internet_locked': True}})
    bundle = browser(None).get(subscription(mode='bundle'))
    assert bundle.status_code == 200 and len(bundle.get_json()) == 3
    assert all(config['dns']['servers']==['10.8.0.1'] for config in bundle.get_json())
    assert browser(None).get(subscription(mode='custom')).status_code == 200


def test_internal_transports_cannot_be_opened_downloaded_or_deleted_in_panel(runtime):
    for child in list(runtime.mappings[PILOT].values())[1:]:
        for path in (f'/device/{child}', f'/device/{child}/download',
                     f'/device/{child}/happ', f'/device/{child}/delete/confirm'):
            response = browser().get(path)
            assert response.status_code in {302, 403, 404}
            assert PRIVATE not in response.get_data(as_text=True)
        assert browser().post(f'/device/{child}/delete', data={'csrf_token': CSRF}).status_code == 302


@pytest.mark.parametrize('family',[False,True])
def test_unprepared_bundle_get_fails_without_provisioning_and_full_tunnel_stays_available(
    runtime, monkeypatch, family,
):
    if family:
        account_policy.save_account_policies({ADMIN:{'safe_internet_locked':True}})
    def unavailable(_parent):
        raise ValueError('unavailable')
    monkeypatch.setattr(happ_peers, 'mode_mapping', unavailable)
    paths = [*runtime.clients.glob('*.conf'), runtime.data / 'device_meta.json']
    before = {path: path.read_bytes() for path in paths}
    assert browser(None).get(subscription(mode='bundle')).status_code == 503
    assert browser(None).get(subscription(mode='custom')).status_code == 503
    assert browser(None).get(subscription(mode='all')).status_code == 200
    assert {path: path.read_bytes() for path in paths} == before
