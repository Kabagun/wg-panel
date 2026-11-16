"""Account-scoped DNS A-cache trials preserve every other export behavior."""
import base64
import copy
import json

import pytest

from wg_panel import core, happ_dns
from wg_panel.happ_config import build_happ_config

ACCOUNT_A = 'a' * 64
ACCOUNT_B = 'b' * 64
ACCOUNT_C = 'c' * 64
POLICY_ERROR = 'Invalid Happ DNS cache policy'


@pytest.fixture
def policy_state(tmp_path, monkeypatch):
    users = {'tester': {'account_id': ACCOUNT_A}, 'other': {'account_id': ACCOUNT_B}}
    monkeypatch.setattr(core, 'DATA_DIR', str(tmp_path))
    monkeypatch.setattr(core, 'load_users', lambda: users)
    return tmp_path / 'happ_dns_cache.json', users


def write_policy(path, accounts):
    path.write_text(json.dumps({'version': 1, 'accounts': accounts}), encoding='utf-8')


def test_cache_policy_missing_is_disabled_for_every_account(policy_state):
    assert happ_dns.client_dns_cache_a('tester') is False
    assert happ_dns.client_dns_cache_a('other') is False
    assert happ_dns.client_dns_cache_a('missing') is False


def test_opt_in_follows_current_account_identity_not_login(policy_state):
    path, users = policy_state
    write_policy(path, {ACCOUNT_A: True})
    assert happ_dns.client_dns_cache_a('tester') is True
    assert happ_dns.client_dns_cache_a('other') is False
    assert happ_dns.client_dns_cache_a('missing') is False

    # A renamed login retains the same account; a recreated login does not.
    users['renamed'] = users.pop('tester')
    assert happ_dns.client_dns_cache_a('renamed') is True
    assert happ_dns.client_dns_cache_a('tester') is False
    users['tester'] = {'account_id': ACCOUNT_C}
    assert happ_dns.client_dns_cache_a('tester') is False
    assert happ_dns.client_dns_cache_a('renamed') is True


def test_rotated_or_deleted_identity_loses_old_opt_in(policy_state):
    path, users = policy_state
    write_policy(path, {ACCOUNT_A: True})
    users['tester']['account_id'] = ACCOUNT_C
    assert happ_dns.client_dns_cache_a('tester') is False
    del users['tester']
    assert happ_dns.client_dns_cache_a('tester') is False


def test_explicit_false_and_policy_updates_are_not_truthy_or_cached(policy_state):
    path, _ = policy_state
    write_policy(path, {ACCOUNT_A: False, ACCOUNT_B: True})
    assert happ_dns.client_dns_cache_a('tester') is False
    assert happ_dns.client_dns_cache_a('other') is True
    write_policy(path, {ACCOUNT_A: True, ACCOUNT_B: False})
    assert happ_dns.client_dns_cache_a('tester') is True
    assert happ_dns.client_dns_cache_a('other') is False
    path.unlink()
    assert happ_dns.client_dns_cache_a('tester') is False


def test_global_default_covers_existing_and_new_account_identities(policy_state):
    path, users = policy_state
    path.write_text(json.dumps({'version': 1, 'default': True, 'accounts': {}}))
    assert happ_dns.client_dns_cache_a('tester') is True
    assert happ_dns.client_dns_cache_a('other') is True
    users['new'] = {'account_id': ACCOUNT_C}
    assert happ_dns.client_dns_cache_a('new') is True
    assert happ_dns.client_dns_cache_a('missing') is False
    users['invalid'] = {'account_id': 'invalid'}
    assert happ_dns.client_dns_cache_a('invalid') is False


def test_account_override_wins_over_global_default_after_account_rotation(policy_state):
    path, users = policy_state
    path.write_text(json.dumps({'version': 1, 'default': True,
                                'accounts': {ACCOUNT_A: False}}))
    assert happ_dns.client_dns_cache_a('tester') is False
    assert happ_dns.client_dns_cache_a('other') is True
    users['tester']['account_id'] = ACCOUNT_C
    assert happ_dns.client_dns_cache_a('tester') is True
    path.write_text(json.dumps({'version': 1, 'default': False,
                                'accounts': {ACCOUNT_A: True}}))
    assert happ_dns.client_dns_cache_a('other') is False
    users['tester']['account_id'] = ACCOUNT_A
    assert happ_dns.client_dns_cache_a('tester') is True


@pytest.mark.parametrize('value', [None, 0, 1, 'true', [], {}])
def test_global_default_must_be_a_boolean(policy_state, value):
    path, _ = policy_state
    path.write_text(json.dumps({'version': 1, 'accounts': {}, 'default': value}))
    with pytest.raises(ValueError, match=POLICY_ERROR):
        happ_dns.client_dns_cache_a('tester')


@pytest.mark.parametrize('value', [
    [], None, True, 1,
    {}, {'version': 1}, {'accounts': {}},
    {'version': 1, 'accounts': {}, 'extra': True},
    {'version': True, 'accounts': {}},
    {'version': 1.0, 'accounts': {}},
    {'version': '1', 'accounts': {}},
    {'version': 2, 'accounts': {}},
    {'version': 1, 'accounts': []},
    {'version': 1, 'accounts': None},
    {'version': 1, 'accounts': {'tester': True}},
    {'version': 1, 'accounts': {'a' * 63: True}},
    {'version': 1, 'accounts': {'a' * 65: True}},
    {'version': 1, 'accounts': {'A' * 64: True}},
    {'version': 1, 'accounts': {'g' * 64: True}},
    {'version': 1, 'accounts': {ACCOUNT_A: 1}},
    {'version': 1, 'accounts': {ACCOUNT_A: 0}},
    {'version': 1, 'accounts': {ACCOUNT_A: 'true'}},
    {'version': 1, 'accounts': {ACCOUNT_A: None}},
    {'version': 1, 'accounts': {ACCOUNT_A: []}},
    {'version': 1, 'accounts': {ACCOUNT_A: True, ACCOUNT_B: 'false'}},
])
def test_invalid_policy_fails_closed_with_generic_error(policy_state, value):
    path, _ = policy_state
    path.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises(ValueError) as error:
        happ_dns.client_dns_cache_a('tester')
    assert str(error.value) == POLICY_ERROR


@pytest.mark.parametrize('raw', [b'{', b'not-json', b'\xff\xfe', b''])
def test_malformed_policy_bytes_fail_closed(policy_state, raw):
    path, _ = policy_state
    path.write_bytes(raw)
    with pytest.raises(ValueError) as error:
        happ_dns.client_dns_cache_a('tester')
    assert str(error.value) == POLICY_ERROR


def test_policy_size_boundary_is_bytes_and_oversize_fails_closed(policy_state):
    path, _ = policy_state
    raw = json.dumps({'version': 1, 'accounts': {ACCOUNT_A: True}}).encode('utf-8')
    path.write_bytes(raw + b' ' * (20000 - len(raw)))
    assert happ_dns.client_dns_cache_a('tester') is True
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError) as error:
        happ_dns.client_dns_cache_a('tester')
    assert str(error.value) == POLICY_ERROR


def synthetic_wg(*, family):
    secret = base64.b64encode(bytes([1]) * 32).decode()
    public = base64.b64encode(bytes([2]) * 32).decode()
    psk = base64.b64encode(bytes([3]) * 32).decode()
    resolvers = '192.0.2.53, 2001:db8::53' if family else '198.51.100.53, 2001:db8:1::53'
    return (
        f'[Interface]\nPrivateKey = {secret}\nAddress = 10.8.0.2/32, fd00::2/128\n'
        f'DNS = {resolvers}\nMTU = 1380\n\n[Peer]\nPublicKey = {public}\n'
        f'PresharedKey = {psk}\nAllowedIPs = 0.0.0.0/0, ::/0\n'
        'Endpoint = vpn.example.test:51820\nPersistentKeepalive = 25\n'
    )


def build(mode, family, **kwargs):
    return build_happ_config(
        synthetic_wg(family=family), mode,
        ['https://Example.TEST/path', '192.0.2.128/25'],
        safe_internet=family, remarks='Synthetic cache trial', **kwargs,
    )


def dns_out(config):
    return next(out for out in config['outbounds'] if out['tag'] == 'dns-out')


@pytest.mark.parametrize('mode', ['all', 'custom', 'by-ru-direct'])
@pytest.mark.parametrize('family', [False, True], ids=['ordinary', 'family'])
def test_udp_cache_changes_only_a_rules_preserving_identity_dns_and_routing(mode, family):
    baseline = build(mode, family)
    enabled = build(mode, family, dns_cache_a=True)
    assert dns_out(baseline)['settings']['rules'] == [{'action': 'direct'}]
    assert dns_out(enabled)['settings']['rules'] == [
        {'qType': 1, 'action': 'hijack'}, {'action': 'direct'},
    ]
    assert 'rewriteNetwork' not in dns_out(enabled)['settings']
    assert enabled['dns']['queryStrategy'] == 'UseIPv4'
    assert dns_out(enabled)['streamSettings']['sockopt']['dialerProxy'] == 'vpn'

    # Whole-config equality after replacing just the A rule catches resolver,
    # identity, IPv6/AAAA, input, filtering and route drift together.
    normalized = copy.deepcopy(enabled)
    dns_out(normalized)['settings']['rules'] = copy.deepcopy(dns_out(baseline)['settings']['rules'])
    assert normalized == baseline


@pytest.mark.parametrize('mode', ['all', 'custom', 'by-ru-direct'])
@pytest.mark.parametrize('family', [False, True], ids=['ordinary', 'family'])
def test_explicit_false_is_identical_to_default_export(mode, family):
    assert build(mode, family, dns_cache_a=False) == build(mode, family)


@pytest.mark.parametrize('mode', ['all', 'custom', 'by-ru-direct'])
@pytest.mark.parametrize('family', [False, True], ids=['ordinary', 'family'])
def test_tcp_existing_behavior_is_identical_with_trial_enabled_or_disabled(mode, family):
    baseline = build(mode, family, dns_transport='tcp')
    assert build(mode, family, dns_transport='tcp', dns_cache_a=False) == baseline
    assert build(mode, family, dns_transport='tcp', dns_cache_a=True) == baseline
    assert dns_out(baseline)['settings']['rules'] == [
        {'qType': 1, 'action': 'hijack'}, {'action': 'direct'},
    ]
    assert dns_out(baseline)['settings']['rewriteNetwork'] == 'tcp'


@pytest.mark.parametrize('value', [None, 0, 1, 0.0, '', 'true', [], {}])
@pytest.mark.parametrize('transport', ['udp', 'tcp'])
def test_cache_argument_rejects_non_bool_even_for_tcp(value, transport):
    with pytest.raises(ValueError):
        build('custom', True, dns_transport=transport, dns_cache_a=value)
