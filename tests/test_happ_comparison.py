"""Synthetic acceptance for the explicitly bound, read-only DNS comparison."""
import copy
import json

import pytest

from wg_panel import core, happ_comparison, happ_pilot, happ_runtime, wireguard

ORDINARY = 'test-admin-ordinary'
FAMILY = 'test-member-family'


@pytest.fixture
def comparison(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'DATA_DIR', str(tmp_path))
    monkeypatch.setitem(core.app.config, 'HAPP_PILOT_ENABLED', True)
    monkeypatch.setitem(core.app.config, 'HAPP_ROLLOUT_ENABLED', True)
    users = {
        'testadmin': {'account_id': 'a' * 64, 'role': 'admin', 'approved': True},
        'testmember': {'account_id': 'b' * 64, 'role': 'user', 'approved': True},
    }
    devices = {
        ORDINARY: {'wg_name': ORDINARY, 'owner': 'testadmin', 'device': 'ordinary',
                   'happ_pilot': True, 'safe_internet': False},
        FAMILY: {'wg_name': FAMILY, 'owner': 'testmember', 'device': 'family',
                 'happ_pilot': True, 'safe_internet': True},
    }
    binding = {'version': 1, 'devices': {ORDINARY: {
        'account_id': 'a' * 64,
        'family': {'wg_name': FAMILY, 'account_id': 'b' * 64},
    }}}
    path = tmp_path / 'happ_comparisons.json'
    path.write_text(json.dumps(binding), encoding='utf-8')
    monkeypatch.setattr(core, 'load_users', lambda: users)
    monkeypatch.setattr(wireguard, 'get_device', devices.get)
    calls = []
    monkeypatch.setattr(happ_runtime, 'selected_transport', lambda _device: 'vless-reality')
    monkeypatch.setattr(happ_pilot, 'get_rules', lambda account: (1, [account[:1] + '.example']))
    configs = {}
    def export(source, mode, rules):
        calls.append((source['wg_name'], mode, list(rules)))
        config = {'remarks': 'source title', 'meta': {'source': 'retained'},
                  'dns': {'servers': ['family.example' if source['safe_internet']
                                      else 'ordinary.example']},
                  'outbounds': [{'tag': 'vpn', 'protocol': 'vless',
                                 'streamSettings': {'security': 'reality'},
                                 'settings': {'synthetic_id': source['wg_name']}}]}
        configs[(source['wg_name'], mode)] = config
        return config
    monkeypatch.setattr(happ_pilot, 'exported_config', export)
    return path, binding, users, devices, calls, configs


def test_no_opt_in_does_not_touch_sources(comparison, monkeypatch):
    path, _binding, _users, devices, calls, _configs = comparison
    path.unlink()
    monkeypatch.setattr(core, 'load_users', lambda: pytest.fail('no opt-in must return early'))
    assert happ_comparison.export_bundle(devices[ORDINARY]) is None
    assert calls == []


def test_six_named_entries_use_each_current_source_and_rules_without_mutation(comparison):
    path, _binding, users, devices, calls, source_configs = comparison
    before = copy.deepcopy((users, devices))
    file_before = path.read_bytes()
    result = happ_comparison.export_bundle(devices[ORDINARY])
    assert result['title'] == 'Сравнение DNS'
    configs = result['configs']
    assert [item['remarks'] for item in configs] == [
        f'{mode} · {dns}' for mode in ('Всё через VPN', 'Умный VPN', 'РБ/РФ напрямую')
        for dns in ('семейный DNS', 'обычный DNS')]
    assert len({item['remarks'] for item in configs}) == 6
    assert calls == [(name, mode, [rule])
                     for mode in ('all', 'custom', 'by-ru-direct')
                     for name, rule in ((FAMILY, 'b.example'), (ORDINARY, 'a.example'))]
    assert [item['dns']['servers'][0] for item in configs] == [
        'family.example', 'ordinary.example'] * 3
    assert all(item['meta']['source'] == 'retained' for item in configs)
    assert all(item['remarks'].split(' · ')[1] in item['meta']['serverDescription']
               for item in configs)
    assert all(item['remarks'] == 'source title' for item in source_configs.values())
    assert (users, devices) == before
    assert path.read_bytes() == file_before


def test_other_subscriptions_are_not_composed(comparison):
    _path, _binding, _users, devices, calls, _configs = comparison
    assert happ_comparison.export_bundle(devices[FAMILY]) is None
    assert happ_comparison.export_bundle({'wg_name': 'unlisted-test'}) is None
    assert calls == []


@pytest.mark.parametrize('name,flag,value', [
    (ORDINARY, 'safe_internet', True), (FAMILY, 'safe_internet', False),
    (ORDINARY, 'happ_pilot', False), (FAMILY, 'happ_pilot', False),
    (ORDINARY, 'deletion_protected', True), (FAMILY, 'deletion_protected', True),
    (ORDINARY, 'happ_transport_internal', True), (FAMILY, 'happ_parent', 'synthetic-parent'),
    (ORDINARY, 'vpn_type', 'amneziawg'), (FAMILY, 'vpn_type', 'amneziawg'),
    *[(name, flag, True) for name in (ORDINARY, FAMILY) for flag in (
        'paused', 'pause_pending', 'revoking', 'deleting', 'revoked', 'provisioning',
        'happ_transport_provisioning', 'happ_transport_deleting')],
])
def test_ineligible_device_fails_closed(comparison, name, flag, value):
    _path, _binding, _users, devices, calls, _configs = comparison
    devices[name][flag] = value
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
    assert calls == []


@pytest.mark.parametrize('owner,field,value', [
    ('testadmin', 'role', 'user'), ('testadmin', 'approved', False),
    ('testmember', 'approved', False), ('testmember', 'role', 'unknown'),
    ('testadmin', 'account_id', 'c' * 64), ('testmember', 'account_id', 'c' * 64),
    *[(owner, flag, True) for owner in ('testadmin', 'testmember')
      for flag in ('paused', 'pause_pending', 'revoking', 'deleting')],
])
def test_current_user_binding_and_state_are_authoritative(comparison, owner, field, value):
    _path, _binding, users, devices, calls, _configs = comparison
    users[owner][field] = value
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
    assert calls == []


@pytest.mark.parametrize('name', [ORDINARY, FAMILY])
def test_missing_or_reassigned_source_fails_closed(comparison, name):
    _path, _binding, _users, devices, calls, _configs = comparison
    request_device = copy.deepcopy(devices[ORDINARY])
    devices.pop(name)
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(request_device)
    assert calls == []


@pytest.mark.parametrize('name,owner', [(ORDINARY, 'testmember'), (FAMILY, 'testadmin')])
def test_current_owner_cannot_be_replaced_by_the_bound_owner(comparison, name, owner):
    _path, _binding, _users, devices, calls, _configs = comparison
    request_device = copy.deepcopy(devices[ORDINARY])
    devices[name]['owner'] = owner
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(request_device)
    assert calls == []


def test_family_source_requires_current_pilot_availability(comparison, monkeypatch):
    _path, _binding, _users, devices, calls, _configs = comparison
    monkeypatch.setitem(core.app.config, 'HAPP_ROLLOUT_ENABLED', False)
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
    assert calls == []


@pytest.mark.parametrize('transport', ['wireguard', 'hysteria2'])
@pytest.mark.parametrize('name', [ORDINARY, FAMILY])
def test_unsupported_transport_never_exports_credentials(comparison, monkeypatch, name, transport):
    _path, _binding, _users, devices, calls, _configs = comparison
    monkeypatch.setattr(happ_runtime, 'selected_transport',
                        lambda device: transport if device['wg_name'] == name else 'vless-reality')
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
    assert calls == []


@pytest.mark.parametrize('raw', [
    '', '[]', '{}', '{"version":1,"version":1,"devices":{}}',
    json.dumps({'version': True, 'devices': {}}),
    json.dumps({'version': 2, 'devices': {}}),
    json.dumps({'version': 1, 'devices': {}, 'extra': True}),
    json.dumps({'version': 1, 'devices': []}),
    ' ' * 65537,
], ids=['empty', 'array', 'missing', 'duplicate-key', 'bool-version', 'wrong-version',
        'extra-field', 'devices-array', 'oversize'])
def test_malformed_private_file_fails_closed(comparison, raw):
    path, _binding, _users, devices, calls, _configs = comparison
    path.write_text(raw, encoding='utf-8')
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
    assert calls == []


@pytest.mark.parametrize('change', [
    lambda record: record.update(extra=True),
    lambda record: record.update(account_id='A' * 64),
    lambda record: record.update(account_id='a' * 63),
    lambda record: record['family'].update(account_id=123),
    lambda record: record['family'].update(wg_name='../private'),
    lambda record: record['family'].update(wg_name=ORDINARY),
    lambda record: record['family'].update(extra=True),
    lambda record: record.update(family=None),
])
def test_exact_private_binding_schema(comparison, change):
    path, binding, _users, devices, calls, _configs = comparison
    change(binding['devices'][ORDINARY])
    path.write_text(json.dumps(binding), encoding='utf-8')
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
    assert calls == []


@pytest.mark.parametrize('records', [
    {'../invalid': {}}, {ORDINARY: None}, {ORDINARY: []},
    {f'synthetic-{index}': {} for index in range(129)},
])
def test_device_mapping_names_shapes_and_count_are_bounded(comparison, records):
    path, _binding, _users, devices, calls, _configs = comparison
    path.write_text(json.dumps({'version': 1, 'devices': records}), encoding='utf-8')
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
    assert calls == []


def test_export_validation_failure_is_propagated_generically(comparison, monkeypatch):
    _path, _binding, _users, devices, _calls, _configs = comparison
    def reject(*_args):
        raise ValueError('synthetic private configuration detail')
    monkeypatch.setattr(happ_pilot, 'exported_config', reject)
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])


@pytest.mark.parametrize('protocol,security', [('wireguard', None), ('vless', 'tls')])
def test_changed_export_transport_fails_closed(comparison, monkeypatch, protocol, security):
    _path, _binding, _users, devices, _calls, _configs = comparison
    monkeypatch.setattr(happ_pilot, 'exported_config', lambda *_args: {
        'outbounds': [{'tag': 'vpn', 'protocol': protocol,
                       'streamSettings': {'security': security}}]})
    with pytest.raises(ValueError, match='^Happ comparison unavailable$'):
        happ_comparison.export_bundle(devices[ORDINARY])
