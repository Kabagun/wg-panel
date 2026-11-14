"""Pure subscription presentation; callers own usage provenance and authorization."""
import base64
import ipaddress
import re
from datetime import date
from urllib.parse import urlsplit, urlunsplit

_ERROR = 'Invalid subscription presentation data'
_MAX_BYTES = (1 << 63) - 1
_DEVICE_PATH = re.compile(r'/device/[a-z0-9][a-z0-9_-]{0,127}(?:/happ)?')
_PATH_PART = re.compile(r'[A-Za-z0-9_.-]{1,128}')
_MONTH = re.compile(r'[0-9]{4}-(?:0[1-9]|1[0-2])')
_SCOPE = {'device': 'это устройство', 'account': 'все устройства аккаунта',
          'sources': 'устройства подписки'}


def _count(value):
    if type(value) is not int or not 0 <= value <= _MAX_BYTES:
        raise ValueError(_ERROR)
    return value


def _panel_links(base_url, device_path):
    if (not isinstance(base_url, str) or not 1 <= len(base_url) <= 2048
            or any(ord(char) <= 32 or ord(char) >= 127 for char in base_url)
            or any(char in base_url for char in ('\\', '?', '#', '%', '@'))
            or not isinstance(device_path, str) or not _DEVICE_PATH.fullmatch(device_path)):
        raise ValueError(_ERROR)
    parts = urlsplit(base_url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise ValueError(_ERROR)
    host = parts.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split('.')
        if (len(labels) < 2 or len(host) > 253 or labels[-1].isdigit()
                or host.endswith(('.localhost', '.local', '.internal', '.lan'))
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                       for label in labels)):
            raise ValueError(_ERROR)
    else:
        if not address.is_global:
            raise ValueError(_ERROR)
    port = parts.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(_ERROR)
    base_path = parts.path.rstrip('/')
    segments = base_path.split('/')[1:]
    if (any(not _PATH_PART.fullmatch(part) or part in ('.', '..') for part in segments)
            or any(segments[index:index + 2] == ['happ', 'sub']
                   for index in range(len(segments)))):
        raise ValueError(_ERROR)
    site = urlunsplit(('https', parts.netloc, base_path + '/', '', ''))
    device = urlunsplit(('https', parts.netloc, base_path + device_path, '', ''))
    return device, site


def build_headers(*, upload_bytes, download_bytes, panel_base_url, device_path,
                  usage_scope, usage_month=None, comparison=False, usage_started_at=None):
    """Build up to four standard Happ headers, without expiry or core controls.

    Paths are application paths relative to the trusted panel base, including when
    they start with '/'. Both counts may be None to omit uncertain traffic data;
    otherwise explicit client-direction byte counts are required. Historical rx/tx
    direction, current time, account ownership and traffic collection are not inferred.
    A validated explicit usage start date takes precedence over the legacy month label.
    """
    try:
        if (not isinstance(usage_scope, str) or usage_scope not in _SCOPE
                or type(comparison) is not bool):
            raise ValueError(_ERROR)
        if usage_started_at is not None:
            if (not isinstance(usage_started_at, str)
                    or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', usage_started_at)):
                raise ValueError(_ERROR)
            started = date.fromisoformat(usage_started_at)
            period = f'Учёт с {started:%d.%m.%Y}'
        else:
            if (not isinstance(usage_month, str) or not _MONTH.fullmatch(usage_month)
                    or usage_month.startswith('0000-')):
                raise ValueError(_ERROR)
            period = f'Трафик за {usage_month}'
        device_url, support_url = _panel_links(panel_base_url, device_path)
        profiles = ('6 профилей: 3 режима × семейный/обычный DNS.' if comparison else
                    '3 режима: всё через VPN, умный VPN, РБ/РФ напрямую.')
        announce = f'{profiles} {period}: {_SCOPE[usage_scope]}. Безлимит.'
        if len(announce) > 200:
            raise ValueError(_ERROR)
        headers = {
            'profile-web-page-url': device_url,
            'support-url': support_url,
            'announce': 'base64:' + base64.b64encode(announce.encode('utf-8')).decode('ascii'),
        }
        if upload_bytes is not None or download_bytes is not None:
            upload, download = _count(upload_bytes), _count(download_bytes)
            headers['subscription-userinfo'] = f'upload={upload}; download={download}; total=0'
        return headers
    except (ValueError, TypeError, OverflowError):
        raise ValueError(_ERROR) from None
