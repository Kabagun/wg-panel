"""A one-device trial using the existing Smart VPN transport and server geofiles."""

import base64
import copy
import hashlib
import hmac
import json
import re
from pathlib import Path

from . import core
from .happ_subscription_info import server_profile_label

STATE = 'happ_geosite_pilot.json'
SECOND_ASSET = 'happ_geosite_pilot_v2.dat'
GEOIP_ASSET = 'happ_geosite_pilot_geoip.dat'
GEOIP_MAX_BYTES = 1024 * 1024
PROFILE_LABEL = '🇫🇮 Умный VPN · GeoSite (тест)'
CATEGORY = 'geosite:smart-vpn'
_HEX_ID = re.compile(r'[0-9a-f]{32}')
_DIGEST = re.compile(r'[0-9a-f]{64}')
_ROUTING_PREFIX = 'happ://routing/onadd/'
_STATE_KEYS = {'device', 'nonce_sha256', 'asset_id', 'phase', 'updated_at'}


def state():
    """Read operator state; malformed or missing state leaves the trial off."""
    try:
        path = Path(core.DATA_DIR) / STATE
        with path.open('rb') as handle:
            data = handle.read(2049)
        if len(data) > 2048:
            return None
        record = json.loads(data)
        if (not isinstance(record, dict)
                or set(record) not in (_STATE_KEYS, _STATE_KEYS | {'geoip_sha256'})
                or not isinstance(record['device'], str)
                or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,127}', record['device'])
                or not isinstance(record['nonce_sha256'], str)
                or not _DIGEST.fullmatch(record['nonce_sha256'])
                or ('geoip_sha256' in record and (not isinstance(record['geoip_sha256'], str)
                                                  or not _DIGEST.fullmatch(record['geoip_sha256'])))
                or not isinstance(record['asset_id'], str) or not _HEX_ID.fullmatch(record['asset_id'])
                or type(record['phase']) is not int or record['phase'] not in (1, 2)
                or type(record['updated_at']) is not int or record['updated_at'] <= 0):
            return None
        return record
    except (OSError, ValueError):
        return None


def append_profile(device, configs, rules):
    record = state()
    nonce = device.get('happ_subscription_nonce')
    if (record is None or device.get('wg_name') != record['device'] or device.get('safe_internet')
            or not isinstance(nonce, str) or not _DIGEST.fullmatch(nonce)
            or not hmac.compare_digest(hashlib.sha256(nonce.encode()).hexdigest(), record['nonce_sha256'])):
        return configs, None

    prototype = next((config for config in configs
                      if config.get('remarks') == server_profile_label('custom')
                      and any(out.get('tag') == 'vpn' and out.get('protocol') == 'vless'
                              for out in config.get('outbounds', ()))), None)
    if prototype is None:
        return configs, None

    sample = copy.deepcopy(prototype)
    domains = {rule for rule in rules if rule.startswith('domain:')}
    matches = [rule for rule in sample['routing']['rules']
               if rule.get('outboundTag') == 'vpn' and domains and set(rule.get('domain', [])) == domains]
    if len(matches) != 1:
        return configs, None
    matches[0]['domain'] = [CATEGORY]
    sample['remarks'] = PROFILE_LABEL
    sample['meta'] = {**sample.get('meta', {}), 'serverDescription': 'Тест внешнего файла GeoSite'}
    return [*configs, sample], record


def apply_routing_header(header, record):
    if record is None:
        return header
    profile = json.loads(base64.b64decode(header.removeprefix(_ROUTING_PREFIX), validate=True))
    origin = core.app.config.get('HAPP_PUBLIC_BASE_URL', f'https://{core.DOMAIN}').rstrip('/')
    if record['phase'] == 1:
        profile['Geositeurl'] = f"{origin}/happ/assets/geosite.dat?pilot={record['asset_id']}&rev=1"
    else:
        profile['Geositeurl'] = f"{origin}/happ/assets/geosite-pilot/{record['asset_id']}/2/geosite.dat"
    if 'geoip_sha256' in record:
        profile['Geoipurl'] = f"{origin}/happ/assets/geoip-by-ru/{record['geoip_sha256']}/geoip.dat"
    profile['LastUpdated'] = str(record['updated_at'])
    return _ROUTING_PREFIX + base64.b64encode(
        json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode()
    ).decode('ascii')


def second_asset(asset_id):
    record = state()
    if record is None or record['phase'] != 2 or asset_id != record['asset_id']:
        return None
    try:
        with (Path(core.DATA_DIR) / SECOND_ASSET).open('rb') as handle:
            data = handle.read(262145)
        return data if 0 < len(data) <= 262144 else None
    except OSError:
        return None


def geoip_asset(digest):
    record = state()
    if record is None or record.get('geoip_sha256') != digest:
        return None
    try:
        with (Path(core.DATA_DIR) / GEOIP_ASSET).open('rb') as handle:
            data = handle.read(GEOIP_MAX_BYTES + 1)
    except OSError:
        return None
    if not 0 < len(data) <= GEOIP_MAX_BYTES or hashlib.sha256(data).hexdigest() != digest:
        return None
    return data
