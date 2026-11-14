"""Private read-only composition of already provisioned family/ordinary exports."""
import copy
import json
import re
from pathlib import Path

from . import core

_ERROR = 'Happ comparison unavailable'
_ACCOUNT = re.compile(r'[0-9a-f]{64}')
_MAX_BYTES = 65536
_MODES = (
    ('all', 'Всё через VPN'),
    ('custom', 'Умный VPN'),
    ('by-ru-direct', 'РБ/РФ напрямую'),
)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_ERROR)
        result[key] = value
    return result


def _fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(_ERROR)


def _account(value):
    if not isinstance(value, str) or not _ACCOUNT.fullmatch(value):
        raise ValueError(_ERROR)


def _bindings():
    from .wireguard import SAFE_NAME_RE

    try:
        with (Path(core.DATA_DIR) / 'happ_comparisons.json').open('rb') as handle:
            raw = handle.read(_MAX_BYTES + 1)
    except FileNotFoundError:
        return {}
    if len(raw) > _MAX_BYTES:
        raise ValueError(_ERROR)
    data = json.loads(raw, object_pairs_hook=_object)
    _fields(data, ('version', 'devices'))
    if type(data['version']) is not int or data['version'] != 1:
        raise ValueError(_ERROR)
    devices = data['devices']
    if not isinstance(devices, dict) or len(devices) > 128:
        raise ValueError(_ERROR)
    for name, record in devices.items():
        if not SAFE_NAME_RE.fullmatch(name):
            raise ValueError(_ERROR)
        _fields(record, ('account_id', 'family'))
        _account(record['account_id'])
        family = record['family']
        _fields(family, ('wg_name', 'account_id'))
        _account(family['account_id'])
        if (not isinstance(family['wg_name'], str)
                or not SAFE_NAME_RE.fullmatch(family['wg_name'])
                or family['wg_name'] == name):
            raise ValueError(_ERROR)
    return devices


def _source(name, account_id, users, *, family):
    from . import happ_peers, happ_pilot, wireguard

    device = wireguard.get_device(name)
    if (not isinstance(device, dict) or device.get('wg_name') != name
            or not happ_pilot.is_pilot_device(device) or happ_peers.is_internal(device)
            or device.get('deletion_protected')
            or device.get('vpn_type', 'wireguard') != 'wireguard'
            or device.get('safe_internet') is not family
            or any(device.get(flag) for flag in (
                'paused', 'pause_pending', 'revoking', 'deleting', 'revoked', 'provisioning',
                'happ_transport_provisioning', 'happ_transport_deleting'))):
        raise ValueError(_ERROR)
    user = users.get(device.get('owner'))
    if (not isinstance(user, dict) or user.get('account_id') != account_id
            or not happ_pilot.available_for_user(user)
            or any(user.get(flag) for flag in ('paused', 'pause_pending', 'revoking', 'deleting'))
            or (not family and (user.get('role') != 'admin'
                                or user.get('approved') is not True))):
        raise ValueError(_ERROR)
    return device, user


def export_bundle(device):
    """Return an explicit six-entry comparison, or None for an ordinary subscription.

    Configured bindings always fail closed. No credentials, source names or account
    identities are included in validation errors or comparison display metadata.
    """
    from . import happ_pilot, happ_runtime

    try:
        with core._wireguard_lock:
            bindings = _bindings()
            record = bindings.get(device.get('wg_name'))
            if record is None:
                return None
            users = core.load_users()
            ordinary, ordinary_user = _source(
                device['wg_name'], record['account_id'], users, family=False)
            family, family_user = _source(
                record['family']['wg_name'], record['family']['account_id'], users, family=True)
            sources = ((family, family_user, 'семейный DNS'),
                       (ordinary, ordinary_user, 'обычный DNS'))
            if any(happ_runtime.selected_transport(source) != 'vless-reality'
                   for source, _user, _label in sources):
                raise ValueError(_ERROR)
            rules = [happ_pilot.get_rules(user['account_id'])[1]
                     for _source_device, user, _label in sources]
            configs = []
            for mode, title in _MODES:
                for index, (source, _user, label) in enumerate(sources):
                    config = copy.deepcopy(happ_pilot.exported_config(source, mode, rules[index]))
                    vpns = [out for out in config['outbounds'] if out.get('tag') == 'vpn']
                    if (len(vpns) != 1 or vpns[0].get('protocol') != 'vless'
                            or vpns[0].get('streamSettings', {}).get('security') != 'reality'):
                        raise ValueError(_ERROR)
                    config['remarks'] = f'{title} · {label}'
                    config.setdefault('meta', {})['serverDescription'] = (
                        f'{title}. DNS: {label}.')
                    configs.append(config)
            return {'configs': configs, 'title': 'Сравнение DNS',
                    'usage_sources': [source['wg_name'] for source, _user, _label in sources]}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ValueError(_ERROR) from None
