"""Private, account-scoped DNS transport trials for Happ exports only."""

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from . import core


def client_dns_transport(owner):
    path = Path(core.DATA_DIR) / 'happ_dns_transport.json'
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return 'udp'
    try:
        value = json.loads(raw)
        if (len(raw) > 20000 or not isinstance(value, dict)
                or set(value) != {'version', 'accounts'}
                or type(value['version']) is not int or value['version'] != 1
                or not isinstance(value['accounts'], dict)
                or any(not isinstance(key, str) or not re.fullmatch(r'[0-9a-f]{64}', key)
                       or transport not in ('udp', 'tcp')
                       for key, transport in value['accounts'].items())):
            raise ValueError
        identity = core.load_users().get(owner, {}).get('account_id')
        return value['accounts'].get(identity, 'udp')
    except (TypeError, ValueError):
        raise ValueError('Invalid Happ DNS transport policy') from None


def resolver_ip(value):
    """Keep the native Happ routing header's DNS field an IP, never a TCP URL."""
    try:
        if not isinstance(value, str):
            raise TypeError
        if value.startswith('tcp://'):
            parsed = urlsplit(value)
            if (parsed.username or parsed.password or parsed.port is not None
                    or parsed.path or parsed.query or parsed.fragment):
                raise ValueError
            value = parsed.hostname
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        raise ValueError('Invalid Happ DNS resolver') from None
