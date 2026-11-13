"""Pure Xray 26.10.31 transport overlays and an authenticated pilot server.

No credentials are generated, files opened, or peers/services changed here.
The caller supplies private runtime credentials and retains lifecycle authority.
"""

import base64
import binascii
import copy
import ipaddress
import math
import re
import uuid
from pathlib import PurePosixPath, PureWindowsPath

TRANSPORTS = ("wireguard", "vless-reality", "hysteria2")
_ERROR = "Invalid Happ transport configuration"
_PRIVATE = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
    "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)
# Known public resolver endpoints, not an exhaustive arbitrary-DoH detector.
_DOH_IPS = (
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
    "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9",
)


def _invalid():
    raise ValueError(_ERROR)


def _text(value, maximum=256):
    if (not isinstance(value, str) or not value or len(value) > maximum
            or value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _invalid()
    return value


def _fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) <= set(required) | set(optional):
        _invalid()


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        _invalid()
    return value


def _domain(value):
    value = _text(value, 253)
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        _invalid()
    labels = name.split(".")
    if (len(name) > 253 or len(labels) < 2
            or labels[-1] in {"local", "localhost", "internal", "lan", "home", "invalid", "test"}
            or labels[-2:] == ["home", "arpa"] or labels[-1].isdecimal()
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in labels)):
        _invalid()
    return name


def _host(value):
    value = _text(value, 253)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return _domain(value)
    if not address.is_global or "%" in value:
        _invalid()
    return str(address)


def _uuid(value):
    value = _text(value, 36)
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        _invalid()
    if str(parsed) != value or parsed.int == 0:
        _invalid()
    return value


def _key(value):
    value = _text(value, 43)
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        _invalid()
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        _invalid()
    if len(raw) != 32 or not any(raw) or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        _invalid()
    return value


def _short_id(value):
    value = _text(value, 16)
    if not re.fullmatch(r"(?:[0-9a-f]{2}){1,8}", value):
        _invalid()
    return value


def _password(value):
    value = _text(value)
    if len(value) < 16 or any(ord(c) > 126 for c in value):
        _invalid()
    return value


def _json(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            _json(item)
    elif isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _json(item)
    else:
        _invalid()


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)


def overlay_transport(base_xray_config, transport, settings):
    """Replace only the sole ``vpn`` outbound; retain routing/DNS and input data.

    VLESS settings: host, port, uuid, public_key, short_id, server_name.
    Hysteria2 settings: host, port, password, server_name. WireGuard takes {}.
    ``base_xray_config`` must be the validated WireGuard generator result.
    """
    if transport not in TRANSPORTS or not isinstance(base_xray_config, dict):
        _invalid()
    _json(base_xray_config)
    outbounds = base_xray_config.get("outbounds")
    if (not isinstance(outbounds, list) or any(not isinstance(out, dict) for out in outbounds)
            or sum(out.get("tag") == "vpn" for out in outbounds) != 1):
        _invalid()
    index = next(i for i, out in enumerate(outbounds) if out.get("tag") == "vpn")
    if outbounds[index].get("protocol") != "wireguard":
        _invalid()
    result = copy.deepcopy(base_xray_config)
    if transport == "wireguard":
        _fields(settings, ())
        return result
    required = {"host", "port", "server_name"}
    required |= ({"uuid", "public_key", "short_id"} if transport == "vless-reality" else {"password"})
    _fields(settings, required)
    host, port, name = _host(settings["host"]), _port(settings["port"]), _domain(settings["server_name"])
    if transport == "vless-reality":
        outbound = {
            "tag": "vpn", "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [{
                "id": _uuid(settings["uuid"]), "encryption": "none",
                # Preserve QUIC; plain Vision intentionally rejects UDP443.
                "flow": "xtls-rprx-vision-udp443",
            }]}]},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "fingerprint": "chrome", "serverName": name,
                "publicKey": _key(settings["public_key"]), "shortId": _short_id(settings["short_id"]),
            }},
        }
    else:
        outbound = {
            "tag": "vpn", "protocol": "hysteria",
            "settings": {"version": 2, "address": host, "port": port},
            "streamSettings": {"network": "hysteria", "security": "tls",
                               "hysteriaSettings": {"version": 2, "auth": _password(settings["password"])},
                               "tlsSettings": {"serverName": name, "allowInsecure": False, "alpn": ["h3"]}},
        }
    result["outbounds"][index] = outbound
    # A validated generator has WG key material only in the replaced outbound.
    if any(out.get("protocol") == "wireguard" for out in result["outbounds"]):
        _invalid()
    old_settings = outbounds[index].get("settings", {})
    old_keys = [old_settings.get("secretKey")]
    for peer in old_settings.get("peers", []):
        old_keys.extend((peer.get("publicKey"), peer.get("preSharedKey")))
    strings = list(_strings(result))
    if any(isinstance(key, str) and key and any(key in text for text in strings) for key in old_keys):
        _invalid()
    return result


def _path(value):
    value = _text(value, 4096)
    if not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        _invalid()
    return value


def _target(value):
    value = _text(value, 300)
    match = re.fullmatch(r"(?:\[([^]]+)\]|([^:]+)):([0-9]{1,5})", value)
    if not match:
        _invalid()
    host = _host(match[1] or match[2])
    port = _port(int(match[3]))
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _loopback(value):
    try:
        ip = ipaddress.ip_address(_text(value))
    except ValueError:
        _invalid()
    if not ip.is_loopback:
        _invalid()
    return str(ip)


def create_server_config(users, server_options):
    """Build one authenticated TCP REALITY / UDP Hysteria2 server on port8443.

    Each user is {id: canonical UUID, email: opaque-label@pilot.invalid,
    password: Hysteria secret, family: optional bool defaulting to True}.
    Only family users get central DNS rewriting / known encrypted-DNS blocks.
    Options require reality_private_key,
    reality_short_ids, reality_target, reality_server_names, certificate_file,
    key_file. Optional listen/port/dns_host/dns_port/api_listen/api_port override
    defaults. api_port=None disables the API. An empty roster opens no public
    proxy listeners. Callers own credential files and roster synchronization.
    """
    required = {"reality_private_key", "reality_short_ids", "reality_target",
                "reality_server_names", "certificate_file", "key_file"}
    _fields(server_options, required, {"listen", "port", "dns_host", "dns_port", "api_listen", "api_port"})
    if not isinstance(users, list) or len(users) > 256:
        _invalid()
    clients, hys_users, seen_ids, seen_emails, seen_passwords = [], [], set(), set(), set()
    family_users = []
    for user in users:
        _fields(user, {"id", "email", "password"}, {"family"})
        family = user.get("family", True)
        if type(family) is not bool:
            _invalid()
        identifier, password = _uuid(user["id"]), _password(user["password"])
        email = _text(user["email"], 128)
        if (not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,95}@pilot\.invalid", email)
                or identifier in seen_ids or email in seen_emails or password in seen_passwords):
            _invalid()
        seen_ids.add(identifier)
        seen_emails.add(email)
        seen_passwords.add(password)
        if family:
            family_users.append(email)
        clients.append({"id": identifier, "email": email, "flow": "xtls-rprx-vision", "level": 0})
        hys_users.append({"auth": password, "email": email, "level": 0})
    opts = server_options
    try:
        listen = str(ipaddress.ip_address(_text(opts.get("listen", "0.0.0.0"))))
    except ValueError:
        _invalid()
    port = _port(opts.get("port", 8443))
    dns_host, dns_port = _loopback(opts.get("dns_host", "127.0.0.1")), _port(opts.get("dns_port", 18004))
    if dns_port == port:
        _invalid()
    api_host, api_port = _loopback(opts.get("api_listen", "127.0.0.1")), opts.get("api_port", 18012)
    if api_port is not None:
        _port(api_port)
        if api_port in (port, dns_port):
            _invalid()
    names, short_ids = opts["reality_server_names"], opts["reality_short_ids"]
    if (not isinstance(names, list) or not 1 <= len(names) <= 16
            or not isinstance(short_ids, list) or not 1 <= len(short_ids) <= 256):
        _invalid()
    names = [_domain(name) for name in names]
    short_ids = [_short_id(value) for value in short_ids]
    if len(set(names)) != len(names) or len(set(short_ids)) != len(short_ids):
        _invalid()
    reality = {"show": False, "target": _target(opts["reality_target"]), "xver": 0,
               "serverNames": names, "privateKey": _key(opts["reality_private_key"]), "shortIds": short_ids}
    certificate, key = _path(opts["certificate_file"]), _path(opts["key_file"])
    inbounds = []
    if clients:
        inbounds = [
            {"tag": "vless-in", "listen": listen, "port": port, "protocol": "vless",
             "settings": {"clients": clients, "decryption": "none"},
             "streamSettings": {"network": "raw", "security": "reality", "realitySettings": reality}},
            {"tag": "hysteria-in", "listen": listen, "port": port, "protocol": "hysteria",
             "settings": {"version": 2, "users": hys_users},
             "streamSettings": {"network": "hysteria", "security": "tls",
                                "hysteriaSettings": {"version": 2},
                                "tlsSettings": {"alpn": ["h3"], "minVersion": "1.3",
                                                "certificates": [{"certificateFile": certificate, "keyFile": key}]}}},
        ]
    rules = []
    result = {
        "log": {"loglevel": "warning"}, "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "central-dns", "protocol": "freedom", "settings": {
                "redirect": f"[{dns_host}]:{dns_port}" if ":" in dns_host else f"{dns_host}:{dns_port}",
                # Server Freedom's default private-IP guard also checks the
                # rewritten target. Allow only this fixed local resolver.
                "finalRules": [{"action": "allow", "network": "tcp,udp", "ip": [dns_host],
                                "port": str(dns_port)}]}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "stats": {},
    }
    if api_port is not None:
        result["api"] = {"tag": "api", "services": ["StatsService"]}
        inbounds.append({"tag": "api-in", "listen": api_host, "port": api_port,
                         "protocol": "dokodemo-door", "settings": {"address": api_host}})
        rules.append({"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"})
    if family_users:
        # An empty user matcher means unrestricted matching in Xray. Omit
        # these rules entirely when there are no protected users.
        rules.extend([
            {"type": "field", "user": family_users, "network": "tcp,udp", "port": "53", "outboundTag": "central-dns"},
            {"type": "field", "user": family_users, "network": "tcp,udp", "port": "853", "outboundTag": "block"},
            {"type": "field", "user": family_users, "network": "tcp,udp", "port": "443", "ip": list(_DOH_IPS), "outboundTag": "block"},
        ])
    rules.extend([
        {"type": "field", "ip": list(_PRIVATE), "outboundTag": "block"},
        {"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
    ])
    return result
