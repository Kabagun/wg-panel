"""Modern pilot identity, revocation, DNS policy and byte-accounting acceptance."""
import base64
import json
from datetime import UTC, datetime

import pytest

from wg_panel import core, happ_pilot, happ_runtime, traffic, wireguard
from wg_panel.device_cleanup import _eligible


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    clients = tmp_path / 'clients'
    clients.mkdir()
    (clients / 'test-phone.conf').write_text('synthetic identity')
    monkeypatch.setattr(core, 'DATA_DIR', str(tmp_path))
    monkeypatch.setattr(wireguard, 'CLIENTS_DIR', str(clients))
    monkeypatch.setattr(traffic, 'DEVICE_META_FILE', str(tmp_path / 'meta.json'))
    monkeypatch.setattr(traffic, 'TRAFFIC_FILE', str(tmp_path / 'traffic.json'))
    user = {'role': 'user', 'approved': True, 'account_id': 'a' * 64}
    device = {'wg_name': 'test-phone', 'owner': 'tester', 'device': 'phone',
              'happ_pilot': True, 'safe_internet': True}
    monkeypatch.setattr(core, 'load_users', lambda: {'tester': user})
    monkeypatch.setattr(wireguard, 'get_device', lambda name: device if name == 'test-phone' else None)
    monkeypatch.setitem(core.app.config, 'HAPP_PILOT_ENABLED', True)
    monkeypatch.setitem(core.app.config, 'HAPP_ROLLOUT_ENABLED', False)
    core.write_json_private(str(tmp_path / 'happ_pilot_access.json'),
                            {'version': 1, 'account_ids': [user['account_id']]})
    key = base64.urlsafe_b64encode(bytes([8]) * 32).decode().rstrip('=')
    cfg = {'version': 1, 'enabled': True, 'binary': str(tmp_path / 'xray'),
           'host': 'vpn.example.org', 'tls_name': 'vpn.example.org', 'reality_public_key': key,
           'server': {'reality_private_key': key, 'reality_short_ids': ['1234567890abcdef'],
                      'reality_target': 'www.microsoft.com:443',
                      'reality_server_names': ['www.microsoft.com'],
                      'certificate_file': str(tmp_path / 'cert.pem'), 'key_file': str(tmp_path / 'key.pem')}}
    core.write_json_private(str(tmp_path / 'happ_runtime.json'), cfg)
    traffic.save_device_meta({'test-phone': device.copy()})
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if 'statsquery' in args:
            return '{}'
        return 'active' if 'is-active' in args else 'generation-a'
    monkeypatch.setattr(happ_runtime, '_run', run)
    return tmp_path, user, device, calls


def test_private_ordinary_pilot_does_not_open_other_members(runtime):
    _path, user, _device, _calls = runtime
    assert happ_pilot.available_for_user(user)
    assert not happ_pilot.available_for_user({**user, 'account_id': 'b' * 64})
    assert happ_pilot.available_for_user({**user, 'role': 'admin', 'account_id': 'c' * 64})
    assert not happ_pilot.available_for_user({**user, 'paused': True})


def test_provision_is_idempotent_bound_and_only_restarts_pilot(runtime):
    path, user, device, calls = runtime
    happ_runtime.provision('test-phone')
    before = (path / 'happ_protocol_devices.json').read_bytes()
    happ_runtime.provision('test-phone')
    assert (path / 'happ_protocol_devices.json').read_bytes() == before
    assert [item['id'] for item in happ_runtime.transport_options(device)] == [
        'hysteria2']
    assert [call for call in calls if 'restart' in call] == [
        ['systemctl', 'restart', 'wg-panel-happ.service']]
    user['account_id'] = 'd' * 64
    with pytest.raises(ValueError):
        happ_runtime.client_settings(device, 'hysteria2')


def test_family_toggle_updates_authenticated_server_routes(runtime):
    path, _user, device, _calls = runtime
    happ_runtime.provision('test-phone')
    config = json.loads((path / 'happ-xray.json').read_text())
    assert any(rule.get('outboundTag') == 'central-dns' for rule in config['routing']['rules'])
    device['safe_internet'] = False
    happ_runtime.sync()
    config = json.loads((path / 'happ-xray.json').read_text())
    assert not any(rule.get('outboundTag') == 'central-dns' for rule in config['routing']['rules'])


def test_pause_and_revoke_remove_public_authentication(runtime):
    path, user, device, calls = runtime
    happ_runtime.provision('test-phone')
    user['paused'] = True
    happ_runtime.sync()
    config = json.loads((path / 'happ-xray.json').read_text())
    assert all(item['listen'] == '127.0.0.1' for item in config['inbounds'])
    happ_runtime.revoke('test-phone')
    assert json.loads((path / 'happ_protocol_devices.json').read_text())['devices'] == {}
    with pytest.raises(ValueError, match='unavailable'):
        happ_runtime.transport_options(device)
    assert all('wg-quick' not in ' '.join(call) for call in calls)


def test_bad_candidate_stops_only_pilot_without_resurrecting_credentials(runtime, monkeypatch):
    _path, _user, _device, calls = runtime
    original = happ_runtime._run
    def fail(args, **kwargs):
        if '-test' in args:
            raise ValueError('bad config')
        return original(args, **kwargs)
    monkeypatch.setattr(happ_runtime, '_run', fail)
    with pytest.raises(ValueError):
        happ_runtime.provision('test-phone')
    assert ['systemctl', 'stop', 'wg-panel-happ.service'] in calls
    assert not any('restart' in call for call in calls)


def test_stats_roll_up_once_and_restart_does_not_subtract_history(runtime, monkeypatch):
    path, _user, _device, _calls = runtime
    happ_runtime.provision('test-phone')
    record = json.loads((path / 'happ_protocol_devices.json').read_text())['devices']['test-phone']
    generation = ['a']
    def run(args, **kwargs):
        if 'statsquery' in args:
            return json.dumps({'stat': [{'name': 'user>>>' + record['email'] + '>>>traffic>>>downlink',
                                         'value': 120}]})
        return generation[0]
    monkeypatch.setattr(happ_runtime, '_run', run)
    happ_runtime.collect_traffic()
    happ_runtime.collect_traffic()
    month = datetime.now(UTC).strftime('%Y-%m')
    assert traffic.load_traffic()['test-phone']['monthly'][month]['rx'] == 120
    generation[0] = 'b'
    happ_runtime.collect_traffic()
    assert traffic.load_traffic()['test-phone']['monthly'][month]['rx'] == 240


def test_pilot_modern_activity_is_never_deleted_as_idle_wireguard(runtime):
    _path, user, device, _calls = runtime
    assert not _eligible({**device, 'happ_protocols': True}, user)


def test_boot_guard_rejects_stale_roster_after_pause_before_config_repair(runtime):
    _path, user, _device, _calls = runtime
    happ_runtime.provision('test-phone')
    happ_runtime.validate_persisted_config()
    user['paused'] = True
    with pytest.raises(ValueError, match='roster'):
        happ_runtime.validate_persisted_config()
    happ_runtime.sync()
    happ_runtime.validate_persisted_config()


def test_changing_export_transport_preserves_listener_and_identity(runtime):
    path, _user, device, calls = runtime
    happ_runtime.provision('test-phone')
    listener = (path/'happ-xray.json').read_bytes()
    identity = (path/'happ_protocol_devices.json').read_bytes()
    calls.clear()
    config = json.loads((path/'happ_runtime.json').read_bytes())
    config['client_transport'] = 'vless-reality'
    core.write_json_private(str(path/'happ_runtime.json'), config)
    assert happ_runtime.selected_transport(device) == 'vless-reality'
    assert [item['id'] for item in happ_runtime.transport_options(device)] == ['vless-reality']
    happ_runtime.sync()
    happ_runtime.validate_persisted_config()
    assert (path/'happ-xray.json').read_bytes() == listener
    assert (path/'happ_protocol_devices.json').read_bytes() == identity
    assert not any('restart' in call or 'stop' in call for call in calls)


@pytest.mark.parametrize('value', ['wireguard', 'unknown', None, [], True])
def test_bad_export_preference_fails_without_stopping_existing_clients(runtime, value):
    path, _user, device, calls = runtime
    happ_runtime.provision('test-phone')
    config = json.loads((path/'happ_runtime.json').read_bytes())
    config['client_transport'] = value
    core.write_json_private(str(path/'happ_runtime.json'), config)
    calls.clear()
    with pytest.raises(ValueError, match='^Happ transport unavailable$'):
        happ_runtime.transport_options(device)
    happ_runtime.validate_persisted_config()
    happ_runtime.sync()
    assert not any('restart' in call or 'stop' in call for call in calls)
