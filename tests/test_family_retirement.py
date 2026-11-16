"""Retirement defaults, compatibility and archived-state isolation."""
import pytest
from test_happ_transports import OPTIONS, USERS

from wg_panel import account_policy, core, family_dns_requests, happ_comparison, wireguard
from wg_panel.happ_transports import create_server_config


@pytest.fixture(autouse=True)
def retired(monkeypatch):
    monkeypatch.setitem(core.app.config, 'FAMILY_PROTECTION_ENABLED', False)


@pytest.mark.parametrize('setting', [None, False, 1, 'true', '1', {}])
def test_only_explicit_boolean_restore_enables_family(monkeypatch, setting):
    monkeypatch.setitem(core.app.config, 'FAMILY_PROTECTION_ENABLED', setting)
    assert not account_policy.family_protection_enabled()


def test_archived_locks_do_not_require_reading_legacy_policy(monkeypatch):
    def unavailable():
        raise AssertionError('Retired policy must not be read')
    monkeypatch.setattr(account_policy, 'load_account_policies', unavailable)
    assert not account_policy.account_safe_internet_locked('sample')
    assert not account_policy.effective_safe_internet({'owner': 'sample', 'safe_internet': True})
    assert not wireguard.set_account_safe_internet('sample', confirmed=True)
    assert not wireguard.set_device_safe_internet('sample-phone', True, confirmed=True)


def test_retired_startup_only_clears_owned_firewall(monkeypatch):
    calls = []
    monkeypatch.setattr(wireguard, 'sync_safe_dns', lambda ips, **kwargs: calls.append(tuple(ips)))
    monkeypatch.setattr(wireguard, 'load_safe_dns_target',
                        lambda *_: (_ for _ in ()).throw(AssertionError('Archived target read')))
    assert wireguard.reconcile_safe_dns() == {'safe_devices': 0, 'ips': []}
    assert calls == [()]


def test_formerly_protected_download_is_ordinary_without_rewriting_identity(monkeypatch, tmp_path):
    raw = '[Interface]\nPrivateKey=synthetic\nDNS=10.8.0.1\n[Peer]\nPublicKey=synthetic\n'
    (tmp_path/'sample-phone.conf').write_text(raw)
    monkeypatch.setattr(wireguard, 'CLIENTS_DIR', str(tmp_path))
    monkeypatch.setattr(wireguard, 'assert_infrastructure_ready', lambda **_: {})
    monkeypatch.setattr(wireguard, 'load_device_meta', lambda: {
        'sample-phone': {'owner': 'sample', 'device': 'phone', 'safe_internet': True,
                         'safe_internet_locked': True}})
    device = wireguard.get_device('sample-phone')
    assert device['safe_internet'] is False
    assert device['account_safe_internet_locked'] is False
    assert 'DNS = 1.1.1.1, 8.8.8.8' in wireguard.get_config('sample-phone')
    assert (tmp_path/'sample-phone.conf').read_text() == raw


def test_retired_comparison_and_old_dns_requests_do_not_touch_state():
    assert happ_comparison.export_bundle({'wg_name': 'sample'}) is None
    for operation in (
        lambda: family_dns_requests.submit('sample', 'a'*64, 'example.com'),
        lambda: family_dns_requests.review('a'*32, 'approve', 'admin'),
    ):
        with pytest.raises(family_dns_requests.RequestError, match='ineligible'):
            operation()


def test_ordinary_server_has_no_family_or_legacy_dns_handlers():
    users = [{**user, 'family': False} for user in USERS]
    config = create_server_config(users, OPTIONS)
    rules = config['routing']['rules']
    assert not any(rule.get('port') in ('853', '443') for rule in rules)
    assert not any(rule.get('outboundTag') == 'central-dns' for rule in rules)
    assert not any(outbound.get('tag') == 'central-dns' for outbound in config['outbounds'])
    assert config['inbounds'][0]['settings']['clients'][0]['id'] == USERS[0]['id']


def test_legacy_compatibility_option_is_not_supported():
    with pytest.raises(ValueError):
        create_server_config(USERS, {**OPTIONS, 'compat_dns_ips': ['10.8.0.1']})
