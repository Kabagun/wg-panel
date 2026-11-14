"""Private, opt-in modern transports. Never restart WireGuard or the DNS stack."""
import hashlib
import json
import logging
import secrets
import subprocess
import time
import uuid
from pathlib import Path

from . import core
from .happ_transports import create_server_config

logger = logging.getLogger(__name__)
UNIT = 'wg-panel-happ.service'
_CLIENT_TRANSPORTS = {'vless-reality': 'VLESS / REALITY', 'hysteria2': 'Hysteria2 / QUIC'}
_DEFAULT_CLIENT_TRANSPORT = 'hysteria2'


def _path(name):
    return Path(core.DATA_DIR) / name


def settings():
    path = _path('happ_runtime.json')
    if not path.exists():
        return None
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
        if len(raw) > 20000 or data['version'] != 1 or data['enabled'] is not True:
            raise ValueError
        if not Path(data['binary']).is_absolute():
            raise ValueError
        return data
    except (OSError, KeyError, TypeError, ValueError):
        raise ValueError('Happ runtime requires recovery') from None


def _registry():
    path = _path('happ_protocol_devices.json')
    if not path.exists():
        return {'version': 1, 'devices': {}}
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
        if len(raw) > 2000000 or data['version'] != 1 or not isinstance(data['devices'], dict):
            raise ValueError
        return data
    except (OSError, KeyError, TypeError, ValueError):
        raise ValueError('Happ credentials require recovery') from None


def _binding(name, user):
    from . import wireguard
    # Use the stored identity, independent of rendered DNS or policy changes.
    raw = (Path(wireguard.CLIENTS_DIR) / (name + '.conf')).read_bytes()
    return hashlib.sha256(raw + b'\0' + user['account_id'].encode()).hexdigest()


def _active(name, record):
    from . import happ_pilot, wireguard
    device = wireguard.get_device(name)
    if not device or not happ_pilot.is_pilot_device(device):
        return None
    user = core.load_users().get(device['owner'], {})
    if not happ_pilot.available_for_user(user):
        return None
    if record['account_id'] != user['account_id'] or record['binding'] != _binding(name, user):
        raise ValueError('Happ identity changed')
    return device


def transport_options(device):
    """Expose one server-selected transport, never a protocol/mode matrix."""
    cfg = settings()
    if not cfg:
        # Preserve installations using the original WG-only Happ exporter.
        return [{'id': 'wireguard', 'title': 'WireGuard', 'available': True}]
    record = _registry()['devices'].get(device['wg_name'])
    if not record or not _active(device['wg_name'], record):
        raise ValueError('Happ transport unavailable')
    transport = cfg.get('client_transport', _DEFAULT_CLIENT_TRANSPORT)
    if not isinstance(transport, str) or transport not in _CLIENT_TRANSPORTS:
        # An export preference must not invalidate the independent listener's
        # boot guard or revocation sync for already connected clients.
        raise ValueError('Happ transport unavailable')
    return [{'id': transport, 'title': _CLIENT_TRANSPORTS[transport], 'available': True}]


def selected_transport(device):
    return transport_options(device)[0]['id']


def client_settings(device, transport):
    if transport == 'wireguard':
        return {}
    cfg = settings()
    record = _registry()['devices'].get(device['wg_name'])
    if not cfg or not record or not _active(device['wg_name'], record):
        raise ValueError('Happ transport unavailable')
    common = {'host': cfg['host'], 'port': cfg['server'].get('port', 8443)}
    if transport == 'vless-reality':
        return {**common, 'uuid': record['id'], 'public_key': cfg['reality_public_key'],
                'short_id': cfg['server']['reality_short_ids'][0],
                'server_name': cfg['server']['reality_server_names'][0]}
    if transport == 'hysteria2':
        return {**common, 'password': record['password'], 'server_name': cfg['tls_name']}
    raise ValueError('Happ transport unavailable')


def _run(args, *, timeout=15):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode:
            raise ValueError('Happ service action failed')
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise ValueError('Happ service action failed') from None


def sync():
    try:
        return _sync()
    except (OSError, ValueError, TypeError, KeyError):
        try:
            _run(['systemctl', 'stop', UNIT])
        except ValueError:
            logger.critical('Experimental Happ listener could not be stopped')
        raise ValueError('Happ runtime requires recovery') from None


def _desired_config(cfg):
    users = []
    for name, record in _registry()['devices'].items():
        device = _active(name, record)
        if device:
            users.append({key: record[key] for key in ('id', 'email', 'password')} |
                         {'family': device['safe_internet']})
    return create_server_config(users, cfg['server'])


def validate_persisted_config():
    """Read-only boot guard: stale credentials may never reappear after a reboot."""
    with core._wireguard_lock:
        cfg = settings()
        if not cfg or json.loads(_path('happ-xray.json').read_bytes()) != _desired_config(cfg):
            raise ValueError('Happ runtime roster is not current')


def _sync():
    """Validate before replacing configuration. Failed revocation stops only this pilot."""
    cfg = settings()
    if not cfg:
        return
    with core._wireguard_lock:
        config = _desired_config(cfg)
        target = _path('happ-xray.json')
        candidate = _path('happ-xray.candidate.json')
        unchanged = target.exists() and json.loads(target.read_bytes()) == config
        if unchanged:
            try:
                if _run(['systemctl', 'is-active', UNIT]).strip() == 'active':
                    return
            except ValueError:
                pass
        try:
            collect_traffic()
            core.write_json_private(str(candidate), config)
            _run([cfg['binary'], 'run', '-test', '-config', str(candidate)])
            candidate.replace(target)
            _run(['systemctl', 'restart', UNIT], timeout=25)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                try:
                    _run([cfg['binary'], 'api', 'statsquery', '-s=127.0.0.1:18012'], timeout=2)
                    break
                except ValueError:
                    time.sleep(.2)
            else:
                raise ValueError('Happ service is not ready')
        except ValueError:
            # Never restore stale credentials after a failed removal/pause.
            _run(['systemctl', 'stop', UNIT])
            raise
        finally:
            candidate.unlink(missing_ok=True)


def provision(name):
    if not settings():
        return
    from . import traffic, wireguard
    with core._wireguard_lock:
        device = wireguard.get_device(name)
        if not device or not device.get('happ_pilot'):
            raise ValueError('Happ device unavailable')
        user = core.load_users()[device['owner']]
        data = _registry()
        if name not in data['devices']:
            data['devices'][name] = {'account_id': user['account_id'], 'binding': _binding(name, user),
                'id': str(uuid.uuid4()), 'password': secrets.token_urlsafe(32),
                'email': 'device-' + secrets.token_hex(12) + '@pilot.invalid'}
            core.write_json_private(str(_path('happ_protocol_devices.json')), data)
        traffic.mutate_device_meta(lambda meta: meta[name].update(happ_protocols=True))
        sync()


def revoke(name):
    """Remove modern credentials before any WG parent/metadata is removed."""
    if not settings():
        return
    with core._wireguard_lock:
        data = _registry()
        if name not in data['devices']:
            return
        collect_traffic()
        del data['devices'][name]
        core.write_json_private(str(_path('happ_protocol_devices.json')), data)
        sync()


def collect_traffic():
    cfg = settings()
    if not cfg or not _path('happ-xray.json').exists():
        return
    from datetime import UTC, datetime

    from . import traffic
    from .happ_subscription_usage import record_sample
    try:
        raw = _run([cfg['binary'], 'api', 'statsquery', '-s=127.0.0.1:18012'])
        values = json.loads(raw).get('stat', [])
        counters = {item['name']: int(item['value']) for item in values}
        # A process restart resets counters even if a new sample already exceeds the old one.
        generation = _run(['systemctl', 'show', UNIT, '-p', 'InvocationID', '--value']).strip()
        if not generation or any(value < 0 for value in counters.values()):
            raise ValueError
        month = datetime.now(UTC).strftime('%Y-%m')
        sampled_at = datetime.now(UTC)
        records = _registry()['devices']
        def apply(history):
            for name, record in records.items():
                if not _active(name, record):
                    continue
                # Retain legacy rx/tx history; presentation below uses explicit client directions.
                rx = counters.get('user>>>' + record['email'] + '>>>traffic>>>downlink', 0)
                tx = counters.get('user>>>' + record['email'] + '>>>traffic>>>uplink', 0)
                entry = history.setdefault(name, {'last_rx': 0, 'last_tx': 0, 'monthly': {}})
                checkpoint = entry.setdefault('happ_protocols', {})
                previous = checkpoint if checkpoint.get('generation') == generation else {}
                total = entry.setdefault('monthly', {}).setdefault(month, {'rx': 0, 'tx': 0})
                for field, value in (('rx', rx), ('tx', tx)):
                    old = previous.get(field, 0)
                    total[field] += value - old if value >= old else value
                checkpoint.update(generation=generation, rx=rx, tx=tx)
                record_sample(entry, generation=generation,
                              upload_bytes=counters.get('user>>>' + record['email'] + '>>>traffic>>>uplink'),
                              download_bytes=counters.get('user>>>' + record['email'] + '>>>traffic>>>downlink'),
                              sampled_at=sampled_at)
        traffic.mutate_traffic(apply)
    except (ValueError, TypeError, KeyError, OSError):
        logger.warning('Happ transport counters unavailable; classic accounting is unchanged')


if __name__ == '__main__':
    import sys
    if sys.argv[1:] != ['--check-config']:
        raise SystemExit('Expected --check-config')
    validate_persisted_config()
