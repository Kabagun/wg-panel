"""DNS transport trials preserve the resolver, account boundary and routing policy."""
import base64
import copy
import json

import pytest

from wg_panel import core
from wg_panel.happ_config import build_happ_config
from wg_panel.happ_dns import client_dns_transport, resolver_ip


def test_transport_policy_is_opt_in_by_current_account_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'DATA_DIR', str(tmp_path))
    users = {'tester': {'account_id': 'a' * 64}, 'other': {'account_id': 'b' * 64}}
    monkeypatch.setattr(core, 'load_users', lambda: users)
    assert client_dns_transport('tester') == 'udp'
    policy = tmp_path / 'happ_dns_transport.json'
    policy.write_text(json.dumps({'version': 1, 'accounts': {'a' * 64: 'tcp'}}))
    assert client_dns_transport('tester') == 'tcp'
    assert client_dns_transport('other') == 'udp'
    users['tester']['account_id'] = 'c' * 64
    assert client_dns_transport('tester') == 'udp'


@pytest.mark.parametrize('value', [[], {'version': True, 'accounts': {}},
                                 {'version': 1, 'accounts': {'a' * 64: 'localhost'}},
                                 {'version': 1, 'accounts': {'tester': 'tcp'}}])
def test_invalid_transport_policy_fails_closed(tmp_path, monkeypatch, value):
    monkeypatch.setattr(core, 'DATA_DIR', str(tmp_path))
    (tmp_path / 'happ_dns_transport.json').write_text(json.dumps(value))
    with pytest.raises(ValueError, match='Invalid Happ DNS transport policy'):
        client_dns_transport('tester')


@pytest.mark.parametrize(('value', 'expected'), [('192.0.2.53', '192.0.2.53'),
    ('tcp://192.0.2.53', '192.0.2.53'), ('tcp://[2001:db8::53]', '2001:db8::53')])
def test_routing_header_resolver_remains_an_ip(value, expected):
    assert resolver_ip(value) == expected


@pytest.mark.parametrize('value', ['tcp://resolver.example', 'tcp://user@192.0.2.53',
                                 'tcp://192.0.2.53:853', 'tcp://192.0.2.53/path', None])
def test_resolver_parser_rejects_non_exported_forms(value):
    with pytest.raises(ValueError, match='Invalid Happ DNS resolver'):
        resolver_ip(value)


@pytest.mark.parametrize('mode', ['all', 'custom', 'by-ru-direct'])
def test_tcp_changes_only_internal_dns_transport(mode):
    secret = base64.b64encode(bytes([1]) * 32).decode()
    public = base64.b64encode(bytes([2]) * 32).decode()
    config = (f'[Interface]\nPrivateKey = {secret}\nAddress = 10.8.0.2/32, fd00::2/128\n'
              'DNS = 192.0.2.53, 2001:db8::53\n\n[Peer]\n'
              f'PublicKey = {public}\nAllowedIPs = 0.0.0.0/0, ::/0\n'
              'Endpoint = vpn.example.test:51820\n')
    baseline = build_happ_config(config, mode, ['domain:example.test'],
                                 safe_internet=True, remarks='Test')
    tcp = build_happ_config(config, mode, ['domain:example.test'],
                           safe_internet=True, remarks='Test', dns_transport='tcp')
    assert tcp['dns']['servers'] == ['tcp://192.0.2.53', 'tcp://[2001:db8::53]']
    normalized = copy.deepcopy(tcp)
    normalized['dns']['servers'] = baseline['dns']['servers']
    assert normalized == baseline
