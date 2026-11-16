"""Pure subscription presentation; callers own usage provenance and authorization."""
import base64
import ipaddress
import re
from datetime import date
from urllib.parse import urlsplit, urlunsplit

_ERROR = 'Invalid subscription presentation data'
_MAX_BYTES = (1 << 63) - 1
_DEVICE_PATH = re.compile(
    r'/device/[a-z0-9][a-z0-9_-]{0,127}(?:/happ(?:/access/[A-Za-z0-9_-]{43})?)?')
_PATH_PART = re.compile(r'[A-Za-z0-9_.-]{1,128}')
_MONTH = re.compile(r'[0-9]{4}-(?:0[1-9]|1[0-2])')
_SCOPE = {'device': 'это устройство', 'account': 'все устройства аккаунта',
          'sources': 'устройства подписки'}
_SCOPE_SHORT = {'device': '', 'account': ' · аккаунт', 'sources': ' · подписка'}
_RECONNECT_NOTICE = '🔄 Периодически выключайте и включайте VPN для обновления настроек.'
_RECONNECT_NOTICE_SHORT = '🔄 Периодически выключайте и включайте VPN.'
_PROFILES = {
    'all': ('🌐 Всё через VPN', 'Весь интернет через VPN'),
    'custom': ('🧠 Умный VPN', 'AI и сервисы из списка → VPN'),
    'by-ru-direct': ('🏡 РБ/РФ напрямую', 'РБ/РФ мимо · остальное VPN'),
    'by-direct': ('🇧🇾 Беларусь напрямую', 'Беларусь мимо · остальное VPN'),
    'ru-direct': ('🇷🇺 Россия напрямую', 'Россия мимо · остальное VPN'),
}
_TITLE_LABELS = {
    'all': '🌐 Всё',
    'custom': '🧠 Умный',
    'by-ru-direct': '🏡 РБ/РФ',
    'by-direct': '🇧🇾 РБ',
    'ru-direct': '🇷🇺 РФ',
}


def _profile(mode):
    if not isinstance(mode, str) or mode not in _PROFILES:
        raise ValueError(_ERROR)
    return _PROFILES[mode]


def profile_label(mode):
    """Return the compact, Unicode routing-mode name shown in Happ."""
    return _profile(mode)[0]


def server_profile_label(mode):
    """Put the current node's flag first so Happ uses its native server icon."""
    return '🇫🇮 ' + profile_label(mode)


def profile_caption(mode):
    """Describe routing behavior in at most 30 Unicode characters."""
    return _profile(mode)[1]


def subscription_title(mode, *, comparison=False):
    """Return a Unicode title within Happ's 25-character limit; callers encode it."""
    if type(comparison) is not bool or not isinstance(mode, str):
        raise ValueError(_ERROR)
    if mode == 'bundle':
        return 'Kabagun VPN · 🧪 DNS' if comparison else '🛡️ Kabagun VPN'
    _profile(mode)
    return 'Kabagun VPN · ' + _TITLE_LABELS[mode]


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
    device = urlunsplit(('https', parts.netloc, base_path + device_path, '', ''))
    return device


def build_headers(*, upload_bytes, download_bytes, panel_base_url, device_path,
                  usage_scope, usage_month=None, comparison=False, usage_started_at=None,
                  comparison_control=False, safe_internet=None):
    """Build up to three standard Happ headers, without expiry or core controls.

    Paths are application paths relative to the trusted panel base, including when
    they start with '/'. Both counts may be None to omit uncertain traffic data;
    otherwise explicit client-direction byte counts are required. Historical rx/tx
    direction, current time, account ownership and traffic collection are not inferred.
    Counts and the optional observed start date belong to the explicit usage month.
    DNS status is explicit: None omits it; comparisons describe both DNS variants.
    """
    try:
        if (not isinstance(usage_scope, str) or usage_scope not in _SCOPE
                or type(comparison) is not bool or type(comparison_control) is not bool
                or safe_internet is not None and type(safe_internet) is not bool
                or comparison_control and not comparison):
            raise ValueError(_ERROR)
        if (not isinstance(usage_month, str) or not _MONTH.fullmatch(usage_month)
                or usage_month.startswith('0000-')):
            raise ValueError(_ERROR)
        if usage_started_at is not None:
            if (not isinstance(usage_started_at, str)
                    or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', usage_started_at)):
                raise ValueError(_ERROR)
            date.fromisoformat(usage_started_at)
            if usage_started_at[:7] != usage_month:
                raise ValueError(_ERROR)
        month_label = usage_month[5:] + '.' + usage_month[:4]
        period = f'📊 Трафик {month_label}{_SCOPE_SHORT[usage_scope]}'
        device_url = _panel_links(panel_base_url, device_path)
        status = '♾️ Безлимит'
        if comparison:
            count = 7 if comparison_control else 6
            status += f' · {count} профилей · семейный/обычный DNS'
            if comparison_control:
                status += ' + контроль UDP без QUIC'
        elif safe_internet is not None:
            status += (' · 🛡️ Семейная защита включена' if safe_internet
                       else ' · 🛡️ Семейная защита выключена')
        explanation = (['🧠 Умный VPN: AI и сервисы из списка → VPN, остальное напрямую']
                       if comparison else [
                           '🌐 Всё через VPN: весь интернет',
                           '🧠 Умный VPN: AI и список админа → VPN, остальное напрямую',
                           '🏡 РБ/РФ напрямую, остальное → VPN'])
        notice = _RECONNECT_NOTICE
        announce = '\n'.join([status, notice, *explanation, period])
        if len(announce.encode('utf-16-le')) // 2 > 200:
            explanation = (['🧠 AI и список админа → VPN, остальное напрямую']
                           if comparison else [
                               '🌐 Всё через VPN',
                               '🧠 AI и список админа → VPN, остальное напрямую',
                               '🏡 РБ/РФ напрямую, остальное → VPN'])
            announce = '\n'.join([status, notice, *explanation, period])
        if len(announce.encode('utf-16-le')) // 2 > 200:
            period = f'📊 {month_label}{_SCOPE_SHORT[usage_scope]}'
            announce = '\n'.join([status, notice, *explanation, period])
        if len(announce.encode('utf-16-le')) // 2 > 200:
            notice = _RECONNECT_NOTICE_SHORT
            announce = '\n'.join([status, notice, *explanation, period])
        if len(announce.encode('utf-16-le')) // 2 > 200:
            explanation = (['🧠 AI и список → VPN, остальное напрямую'] if comparison else [
                '🌐 Всё → VPN',
                '🧠 AI и список → VPN, остальное напрямую',
                '🏡 РБ/РФ напрямую, остальное → VPN'])
            announce = '\n'.join([status, notice, *explanation, period])
        if len(announce.encode('utf-16-le')) // 2 > 200:
            raise ValueError(_ERROR)
        headers = {
            'profile-web-page-url': device_url,
            'announce': 'base64:' + base64.b64encode(announce.encode('utf-8')).decode('ascii'),
        }
        if upload_bytes is not None or download_bytes is not None:
            upload, download = _count(upload_bytes), _count(download_bytes)
            headers['subscription-userinfo'] = f'upload={upload}; download={download}; total=0'
        return headers
    except (ValueError, TypeError, OverflowError):
        raise ValueError(_ERROR) from None
