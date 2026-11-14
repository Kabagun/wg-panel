"""Opt-in pilot state. Reads never change peers, account policy or DNS services."""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from . import core, wireguard
from .dns_enforcement import SafeDnsEnforcementError
from .happ_config import GEOIP_URL, MODES, build_happ_config, normalize_proxy_rules
from .happ_dns import client_dns_transport, resolver_ip
from .happ_shared_rules import load_snapshot, managed_mode, publication_status
from .i18n import t
from .safe_dns_settings import load_safe_dns_target
from .traffic import mutate_device_meta

_lock = threading.RLock()
_SUB_PATH = re.compile(r"/happ/sub/[^\s\"'<>]*")
_NONCE = re.compile(r"[0-9a-f]{64}")
BUNDLE_MODES = ('all', 'custom', 'by-ru-direct')


class HappStateError(ValueError):
    pass


class SubscriptionLogFilter(logging.Filter):
    def filter(self, record):
        record.msg = _SUB_PATH.sub('/happ/sub/[redacted]', record.getMessage())
        record.args = ()
        return True


logging.getLogger('werkzeug').addFilter(SubscriptionLogFilter())


def pilot_enabled():
    override = core.app.config.get('HAPP_PILOT_ENABLED')
    if override is not None:
        return override is True
    try:
        data = (Path(core.DATA_DIR) / 'happ_pilot.json').read_bytes()
        return len(data) < 256 and json.loads(data) == {'version': 1, 'enabled': True}
    except (OSError, ValueError):
        return False


def is_pilot_device(device):
    from .happ_peers import is_internal
    return bool(pilot_enabled() and device and device.get('happ_pilot') is True
                and not is_internal(device) and not device.get('happ_transport_deleting'))


def public_enabled():
    override = core.app.config.get('HAPP_ROLLOUT_ENABLED')
    if override is not None:
        return override is True
    try:
        raw = (Path(core.DATA_DIR) / 'happ_rollout.json').read_bytes()
        value = json.loads(raw)
        return (len(raw) < 256 and isinstance(value, dict) and set(value) == {'version', 'enabled'}
                and type(value['version']) is int and value['version'] == 1 and value['enabled'] is True)
    except (OSError, ValueError, TypeError):
        return False


def available_for_user(user):
    return bool(pilot_enabled() and isinstance(user, dict) and user.get('approved') is True
                and user.get('role') in ('admin', 'user') and user.get('account_id')
                and not any(user.get(flag) for flag in ('paused', 'pause_pending', 'revoking'))
                and (user.get('role') == 'admin' or _allowed_account(user) or public_enabled()))


def _allowed_account(user):
    """An optional private allowlist adds ordinary test accounts, never credentials in Git."""
    try:
        raw = (Path(core.DATA_DIR) / 'happ_pilot_access.json').read_bytes()
        data = json.loads(raw)
        return (len(raw) < 20000 and data.get('version') == 1
                and isinstance(data.get('account_ids'), list)
                and user['account_id'] in data['account_ids'])
    except (OSError, ValueError, TypeError, KeyError):
        return False


def shared_rules_url():
    return core.app.config.get('HAPP_RULES_URL', os.getenv('WG_PANEL_HAPP_RULES_URL', ''))


def shared_rules_context():
    source = shared_rules_url()
    if not source:
        return {'shared_rules': False}
    snapshot = load_snapshot(core.DATA_DIR, source)
    checked = datetime.fromisoformat(snapshot['last_checked'])
    managed = managed_mode()
    delayed = not managed and (bool(snapshot['error']) or (datetime.now(UTC) - checked).total_seconds() > 900)
    parts = urlsplit(source)
    source_link = None
    # Show public GitHub file URLs, never arbitrary configured endpoints.
    if (parts.hostname == 'raw.githubusercontent.com' and not parts.username
            and not parts.password and not parts.query and not parts.fragment):
        path = parts.path.strip('/').split('/')
        if len(path) >= 4 and all(re.fullmatch(r'[A-Za-z0-9_.-]+', part) for part in path):
            source_link = f'https://github.com/{path[0]}/{path[1]}/blob/' + '/'.join(path[2:])
    return {'shared_rules': True, 'shared_rules_status': 'delayed' if delayed else 'current',
            'shared_rules_checked': snapshot['last_checked'],
            'shared_rules_updated': snapshot['last_success'],
            'shared_rules_revision': snapshot['revision'][:12],
            'shared_rules_source_link': source_link, 'shared_rules_managed': managed,
            'shared_rules_publication': publication_status(core.DATA_DIR, snapshot['revision']) if managed else None}


@contextmanager
def _rules_lock():
    with core._wireguard_lock, _lock:
        core.ensure_private_dir(core.DATA_DIR)
        path = Path(core.DATA_DIR) / 'happ_rules.json.lock'
        with open(path, 'a', encoding='utf-8') as handle:
            if core.fcntl:
                core.fcntl.flock(handle, core.fcntl.LOCK_EX)
            try:
                yield
            finally:
                if core.fcntl:
                    core.fcntl.flock(handle, core.fcntl.LOCK_UN)


def _load_rules():
    path = Path(core.DATA_DIR) / 'happ_rules.json'
    if not path.exists():
        return {'version': 1, 'accounts': {}}
    try:
        raw = path.read_bytes()
        if len(raw) > 2_000_000:
            raise ValueError
        data = json.loads(raw)
        if set(data) != {'version', 'accounts'} or data['version'] != 1:
            raise ValueError
        if not isinstance(data['accounts'], dict):
            raise TypeError
        for identity, record in data['accounts'].items():
            if not isinstance(identity, str) or not _NONCE.fullmatch(identity):
                raise ValueError
            if set(record) != {'revision', 'rules'} or type(record['revision']) is not int:
                raise ValueError
            if record['revision'] < 1 or not isinstance(record['rules'], list):
                raise ValueError
            if normalize_proxy_rules('\n'.join(record['rules'])) != record['rules']:
                raise ValueError
        return data
    except (OSError, TypeError, ValueError):
        raise HappStateError('invalid_state') from None


def get_rules(account_id):
    if shared_rules_url():
        snapshot = load_snapshot(core.DATA_DIR, shared_rules_url())
        return snapshot['revision'], snapshot['rules']
    with _rules_lock():
        record = _load_rules()['accounts'].get(account_id, {'revision': 0, 'rules': []})
        return record['revision'], list(record['rules'])


def save_rules(account_id, text, expected_revision):
    if shared_rules_url():
        raise HappStateError('shared_rules_managed')
    if not isinstance(account_id, str) or not _NONCE.fullmatch(account_id):
        raise HappStateError('invalid_state')
    rules = normalize_proxy_rules(text)
    with _rules_lock():
        data = _load_rules()
        previous = data['accounts'].get(account_id, {'revision': 0, 'rules': []})
        if type(expected_revision) is not int or expected_revision != previous['revision']:
            raise HappStateError('stale_revision')
        data['accounts'][account_id] = {'revision': previous['revision'] + 1, 'rules': rules}
        core.write_json_private(str(Path(core.DATA_DIR) / 'happ_rules.json'), data)


def create_pilot_device(owner, name):
    """Provision a fresh peer; never adopt an existing/router identity."""
    with core._wireguard_lock:
        user = core.load_users().get(owner, {})
        if not available_for_user(user):
            return False, '', 'unavailable'
        if name in wireguard.get_user_devices(owner):
            return False, '', 'already_exists'
        ok, wg_name, _error = wireguard.create_device(owner, name, happ=True)
        if not ok:
            return False, '', 'provision_failed'
        try:
            def mark(meta):
                device = meta.get(wg_name, {})
                if (device.get('owner') != owner or device.get('deletion_protected')
                        or device.get('revoked') or device.get('provisioning')):
                    raise ValueError
                device.update(happ_pilot=True, happ_subscription_nonce=secrets.token_hex(32))
            mutate_device_meta(mark)
            # Reuse the existing per-peer DNS redirect to the central target's
            # configured port. This does not lock the administrator's account.
            wireguard.reconcile_safe_dns()
            from .happ_peers import ensure_mode_peers
            ensure_mode_peers(wg_name)
            from .happ_runtime import provision
            provision(wg_name)
            return True, wg_name, ''
        except (OSError, ValueError, SafeDnsEnforcementError):
            # Keep the Happ binding while cascading fresh children. Removing
            # the marker first could leave active orphan transports on failure.
            wireguard.delete_device(wg_name)
            return False, '', 'provision_failed'


def subscription_token(device, user):
    nonce = device.get('happ_subscription_nonce', '')
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise HappStateError('invalid_state')
    key = core.app.secret_key
    if isinstance(key, str):
        key = key.encode()
    if not key or len(key) < 32:
        raise HappStateError('invalid_state')
    message = json.dumps(['happ-pilot-v1', device['wg_name'], user['account_id'], nonce],
                         separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(hmac.digest(key, message, 'sha256')).decode().rstrip('=')


def rotate_subscription(wg_name):
    def update(meta):
        if meta.get(wg_name, {}).get('happ_pilot') is not True:
            raise HappStateError('unavailable')
        meta[wg_name]['happ_subscription_nonce'] = secrets.token_hex(32)
    mutate_device_meta(update)


def subscription_modes(device):
    return BUNDLE_MODES


def _central_config(device, transport_name=None, *, dns=None):
    config = wireguard.get_config(transport_name or device['wg_name'])
    if not config:
        raise HappStateError('unavailable')
    # Only the Happ export uses the existing central resolver. No stored .conf,
    # DNS policy, account flag or authoritative exception list is rewritten.
    if dns is None:
        if device['safe_internet']:
            target = load_safe_dns_target(wireguard.WG_DIR)
            if not target.custom:
                raise HappStateError('central_dns_unavailable')
            dns = target.client_dns_servers
        else:
            dns = '1.1.1.1, 8.8.8.8'
    return wireguard._render_config_dns(config, dns)


def _export_config(device, mode, rules, config, transport='wireguard'):
    key = 'happ_mode_' + mode.replace('-', '_')
    exported = build_happ_config(config, mode, rules, safe_internet=device['safe_internet'],
                                 remarks=t(key, 'ru'),
                                 dns_transport=client_dns_transport(device['owner']))
    exported['meta'] = {'serverDescription': t(key + '_help', 'ru')}
    from .happ_runtime import client_settings
    from .happ_transports import overlay_transport
    exported = overlay_transport(exported, transport, client_settings(device, transport))
    return exported


def exported_config(device, mode, rules, transport=None):
    from . import happ_peers
    if happ_peers.is_internal(device) or device.get('happ_transport_deleting'):
        raise HappStateError('unavailable')
    if transport is None:
        from .happ_runtime import selected_transport
        transport = selected_transport(device)
    peer_name = device['wg_name']
    if mode != 'all':
        mapping = happ_peers.mode_mapping(device['wg_name'])
        peer_name = mapping['custom' if mode == 'custom' else 'by-ru-direct']
    return _export_config(device, mode, rules, _central_config(device, peer_name), transport)


def exported_bundle(device, rules):
    from . import happ_peers
    with core._wireguard_lock:
        if happ_peers.is_internal(device) or device.get('happ_transport_deleting'):
            raise HappStateError('unavailable')
        modes = subscription_modes(device)
        mapping = happ_peers.mode_mapping(device['wg_name'])
        from .happ_runtime import transport_options
        return [_export_config(device, mode, rules, _central_config(device, mapping[mode]), option['id'])
                for option in transport_options(device) if option['available'] for mode in modes]


def routing_header(device, mode, config):
    if mode not in (*MODES, 'bundle'):
        raise HappStateError('unavailable')
    configs = config if mode == 'bundle' else [config]
    if not configs:
        raise HappStateError('invalid_state')
    direct_ips = []
    for item in configs:
        for rule in item['routing']['rules']:
            if rule.get('outboundTag') == 'direct':
                direct_ips.extend(rule.get('ip', []))
    dns = configs[0]['dns']['servers'][0]
    if (not isinstance(dns, str)
            or any(item['dns']['servers'] != configs[0]['dns']['servers'] for item in configs)):
        raise HappStateError('invalid_state')
    dns = resolver_ip(dns)
    # JSON subscriptions allow only one routing profile. Include every entry's
    # GeoIP tags so Happ's trimmed database can run either BY or RU preset.
    direct_ips = list(dict.fromkeys(direct_ips))
    profile = {
        'Name': 'Pilot-' + hashlib.sha256((device['wg_name'] + mode).encode()).hexdigest()[:12],
        'GlobalProxy': 'false' if mode == 'custom' else 'true',
        'RemoteDNSType': 'DoU', 'RemoteDNSDomain': '', 'RemoteDNSIP': dns,
        'DomesticDNSType': 'DoU', 'DomesticDNSDomain': '', 'DomesticDNSIP': dns,
        'Geoipurl': GEOIP_URL, 'Geositeurl': '', 'DirectIp': direct_ips,
        'DirectSites': [], 'ProxySites': [], 'ProxyIp': [dns],
        'DomainStrategy': 'IPOnDemand', 'FakeDNS': 'false',
    }
    return 'happ://routing/onadd/' + base64.b64encode(
        json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode()).decode()


def comparison_routing_header(device, configs):
    """One native TUN DNS anchor; each validated JSON retains its own resolver."""
    user = core.load_users().get(device.get('owner'), {})
    if (user.get('role') != 'admin' or device.get('safe_internet')
            or not isinstance(configs, list) or len(configs) != 6):
        raise HappStateError('invalid_state')
    # The family entry anchors native TUN DNS. Every selected JSON rewrites
    # port 53 through its own dns-out before private-IP/direct rules apply.
    # Only header inputs are normalized; returned source configs are untouched.
    servers = configs[0]['dns']['servers']
    header_configs = [{**item, 'dns': {**item['dns'], 'servers': servers}}
                      for item in configs]
    link = routing_header(device, 'bundle', header_configs)
    prefix = 'happ://routing/onadd/'
    profile = json.loads(base64.b64decode(link.removeprefix(prefix)))
    profile['Name'] = 'DNS-comparison-' + hashlib.sha256(device['wg_name'].encode()).hexdigest()[:12]
    profile['ProxyIp'] = list(dict.fromkeys(
        resolver_ip(server) for item in configs for server in item['dns']['servers']))
    return prefix + base64.b64encode(
        json.dumps(profile, ensure_ascii=False, separators=(',', ':')).encode()).decode()


def qr_for_link(link):
    try:
        result = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=link.encode(),
                                capture_output=True, timeout=5, check=True)
        return 'data:image/svg+xml;base64,' + base64.b64encode(result.stdout).decode()
    except (OSError, subprocess.SubprocessError):
        return None
