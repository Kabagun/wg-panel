"""Pure, deliberately narrow WireGuard-to-Xray export for the Happ pilot.

This emits an Xray configuration, not a client-specific routing import schema.
Country modes require a full geoip.dat containing the BY/RU country sets.
No network, filesystem, key generation, or peer mutation takes place here.
"""

import base64
import binascii
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

MODES = ("all", "custom", "by-direct", "ru-direct", "by-ru-direct")
GEOIP_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
MAX_PROXY_RULES = 256

# Literal LAN ranges avoid depending on geoip.dat in all/custom modes. Do not use
# ipaddress.is_private: it includes special-use public ranges, not only LANs.
_LAN_NETWORKS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
)
_COUNTRIES = {
    "by-direct": ["geoip:by"],
    "ru-direct": ["geoip:ru"],
    "by-ru-direct": ["geoip:by", "geoip:ru"],
}
_DNS_TAG = "dns-internal"
_WG_ERROR = "Invalid or unsupported WireGuard configuration"
_RULE_ERROR = "Invalid proxy rule; use domains, HTTP(S) URLs, or IP networks"


def _has_control(value: str, *, multiline: bool = False) -> bool:
    return any(
        unicodedata.category(char).startswith("C") and not (multiline and char in "\r\n")
        for char in value
    )


def _domain(value: str) -> str:
    if not value or value != value.strip() or _has_control(value):
        raise ValueError(_RULE_ERROR)
    value = value.removesuffix(".")
    ascii_name = value.encode("idna").decode("ascii").lower()
    if len(ascii_name) > 253 or not ascii_name or ascii_name.isdecimal():
        raise ValueError(_RULE_ERROR)
    labels = ascii_name.split(".")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s) for s in labels):
        raise ValueError(_RULE_ERROR)
    # A malformed dotted IPv4 address must not become a domain rule.
    if all(label.isdecimal() for label in labels):
        raise ValueError(_RULE_ERROR)
    return ascii_name


def _proxy_rule(value: str) -> str:
    domain_prefix = value.lower().startswith("domain:")
    if domain_prefix:
        value = value[7:]
    elif "://" in value:
        url = urlsplit(value)
        if (
            url.scheme.lower() not in {"http", "https"}
            or not url.netloc
            or url.username is not None
            or url.password is not None
            or "\\" in value
            or not url.hostname
        ):
            raise ValueError(_RULE_ERROR)
        # Accessing port validates bracket syntax and the numeric port range.
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError(_RULE_ERROR)
        value = url.hostname
    if not value or "%" in value or any(char.isspace() for char in value):
        raise ValueError(_RULE_ERROR)
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        if "/" in value or ":" in value:
            raise ValueError(_RULE_ERROR) from None
        return "domain:" + _domain(value)
    if domain_prefix:
        raise ValueError(_RULE_ERROR)
    return str(network)


def normalize_proxy_rules(text: str) -> list[str]:
    """Normalize newline/comma-separated rules; domains include their subdomains.

    HTTP(S) URL paths are discarded, but userinfo, regexes, arbitrary Xray
    matchers, wildcard syntax and control characters are never accepted.
    The limit applies before deduplication as well as to the result.
    """
    if not isinstance(text, str) or len(text) > 65536 or _has_control(text, multiline=True):
        raise ValueError(_RULE_ERROR)
    # Commas in a pasted URL belong to its path/query, not to a second rule.
    values = [
        value.strip()
        for line in text.splitlines()
        for value in ([line] if "://" in line else line.split(","))
    ]
    values = [value for value in values if value]
    if len(values) > MAX_PROXY_RULES:
        raise ValueError("Too many proxy rules")
    try:
        return list(dict.fromkeys(_proxy_rule(value) for value in values))
    except (ValueError, UnicodeError):
        raise ValueError(_RULE_ERROR) from None


@dataclass(frozen=True)
class _WireGuard:
    secret_key: str
    addresses: list[str]
    dns: list[str]
    peer: dict
    mtu: int | None


def _csv(values: list[str]) -> list[str]:
    result = [item.strip() for value in values for item in value.split(",")]
    if not result or any(not item for item in result):
        raise ValueError(_WG_ERROR)
    return result


def _key(value: str) -> str:
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(_WG_ERROR)
    return value


def _integer(value: str, minimum: int, maximum: int) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError(_WG_ERROR)
    number = int(value)
    if not minimum <= number <= maximum:
        raise ValueError(_WG_ERROR)
    return number


def _endpoint(value: str) -> str:
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:([0-9]+)", value)
        if not match or "%" in match[1]:
            raise ValueError(_WG_ERROR)
        address = ipaddress.IPv6Address(match[1])
        return f"[{address}]:{_integer(match[2], 1, 65535)}"
    host, separator, port = value.rpartition(":")
    if not separator or not host or ":" in host:
        raise ValueError(_WG_ERROR)
    try:
        host = str(ipaddress.IPv4Address(host))
    except ValueError:
        host = _domain(host)
    return f"{host}:{_integer(port, 1, 65535)}"


def _parse_wireguard(text: str) -> _WireGuard:
    try:
        if (
            not isinstance(text, str)
            or len(text) > 65536
            or _has_control(text.replace("\t", ""), multiline=True)
        ):
            raise ValueError(_WG_ERROR)
        sections: dict[str, dict[str, list[str]]] = {}
        section = None
        allowed = {
            "interface": {"privatekey", "address", "dns", "mtu"},
            "peer": {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"},
        }
        repeated = {"address", "dns", "allowedips"}
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("["):
                name = line[1:-1].lower() if line.endswith("]") else ""
                if name not in allowed or name in sections:
                    raise ValueError(_WG_ERROR)
                if name == "peer" and "interface" not in sections:
                    raise ValueError(_WG_ERROR)
                sections[name] = section = {}
                section_name = name
                continue
            if section is None or "=" not in line:
                raise ValueError(_WG_ERROR)
            field, value = (item.strip() for item in line.split("=", 1))
            field = field.lower()
            if field not in allowed[section_name] or not value:
                raise ValueError(_WG_ERROR)
            if field in section and field not in repeated:
                raise ValueError(_WG_ERROR)
            section.setdefault(field, []).append(value)
        if set(sections) != {"interface", "peer"}:
            raise ValueError(_WG_ERROR)
        interface, peer = sections["interface"], sections["peer"]
        secret_key = _key(interface["privatekey"][0])
        addresses = [str(ipaddress.ip_interface(value)) for value in _csv(interface["address"])]
        if any("/" not in value for value in _csv(interface["address"])):
            raise ValueError(_WG_ERROR)
        dns_addresses = [ipaddress.ip_address(value) for value in _csv(interface["dns"])]
        if any(ip.is_unspecified or ip.is_multicast or "%" in str(ip) for ip in dns_addresses):
            raise ValueError(_WG_ERROR)
        networks = [ipaddress.ip_network(value, strict=False) for value in _csv(peer["allowedips"])]
        address_families = {ipaddress.ip_interface(value).version for value in addresses}
        if any(
            ip.version not in address_families
            or not any(ip.version == net.version and ip in net for net in networks)
            for ip in dns_addresses
        ):
            raise ValueError(_WG_ERROR)
        if any("%" in value for value in addresses):
            raise ValueError(_WG_ERROR)
        result_peer = {
            "endpoint": _endpoint(peer["endpoint"][0]),
            "publicKey": _key(peer["publickey"][0]),
            "allowedIPs": [str(network) for network in networks],
            "keepAlive": 0,
        }
        if "presharedkey" in peer:
            result_peer["preSharedKey"] = _key(peer["presharedkey"][0])
        if "persistentkeepalive" in peer:
            value = peer["persistentkeepalive"][0]
            result_peer["keepAlive"] = 0 if value.lower() == "off" else _integer(value, 0, 65535)
        mtu = _integer(interface["mtu"][0], 68, 65535) if "mtu" in interface else None
        return _WireGuard(
            secret_key, addresses, [str(ip) for ip in dns_addresses], result_peer, mtu
        )
    except (ValueError, UnicodeError, KeyError, binascii.Error):
        # Never include source lines, keys, endpoint credentials or parser details.
        raise ValueError(_WG_ERROR) from None


def _routing(mode: str, proxy_rules: list[str], dns: list[str], *, safe_internet=False) -> dict:
    def rule(tag: str, **conditions) -> dict:
        return {"type": "field", **conditions, "outboundTag": tag}

    rules = [
        rule("vpn", inboundTag=[_DNS_TAG]),
        rule("dns-out", network="tcp,udp", port="53"),
        rule("vpn", ip=[str(ipaddress.ip_network(ip)) for ip in dns]),
    ]
    if safe_internet:
        # Split traffic still resolves through the account's family DNS.
        # Keep common encrypted-resolver bypasses ahead of every direct rule.
        from .happ_transports import _DOH_IPS
        rules.extend([
            rule('block', network='tcp,udp', port='853'),
            rule('block', network='tcp,udp', port='443', ip=list(_DOH_IPS)),
            rule('block', domain=['domain:' + host for host in (
                'dns.google', 'cloudflare-dns.com', 'mozilla.cloudflare-dns.com',
                'dns.quad9.net', 'doh.opendns.com', 'dns.nextdns.io',
                'dns.adguard-dns.com', 'dns.adguard.com')]),
        ])
    domains = [value for value in proxy_rules if value.startswith("domain:")]
    networks = [value for value in proxy_rules if not value.startswith("domain:")]
    if domains:
        rules.append(rule("vpn", domain=domains))
    if networks:
        rules.append(rule("vpn", ip=networks))
    rules.append(rule("direct", ip=list(_LAN_NETWORKS)))
    if mode in _COUNTRIES:
        rules.append(rule("direct", ip=list(_COUNTRIES[mode])))
    rules.append(rule("direct" if mode == "custom" else "vpn", network="tcp,udp"))
    # IPIfNonMatch cannot resolve country/IP rules when the final catch-all wins.
    return {"domainStrategy": "IPOnDemand", "rules": rules}


def build_happ_config(
    wg_config: str,
    mode: str,
    proxy_rules: list[str],
    *,
    safe_internet: bool,
    remarks: str,
) -> dict:
    """Build a standalone Xray configuration without altering the WG identity.

    Safe internet keeps the same protected resolver in every routing mode.
    DNS and WireGuard failures have no direct/public resolver fallback. Raw
    plaintext DNS is rewritten to the first exported resolver through the VPN;
    callers supply the central server resolver in the rendered WG DNS field.
    """
    if mode not in MODES:
        raise ValueError("Unsupported routing mode")
    if not isinstance(safe_internet, bool):
        raise ValueError("Invalid Safe internet setting")  # noqa: TRY004 - public ValueError API
    if (
        not isinstance(proxy_rules, list)
        or len(proxy_rules) > MAX_PROXY_RULES
        or any(
            not isinstance(value, str) or "\n" in value or "\r" in value or "," in value
            for value in proxy_rules
        )
    ):
        raise ValueError(_RULE_ERROR)
    normalized = normalize_proxy_rules("\n".join(proxy_rules))
    if not isinstance(remarks, str) or len(remarks) > 256 or _has_control(remarks):
        raise ValueError("Invalid profile name")
    wg = _parse_wireguard(wg_config)
    if safe_internet:
        networks = [ipaddress.ip_network(value) for value in wg.peer["allowedIPs"]]
        for family in {ipaddress.ip_interface(value).version for value in wg.addresses}:
            family_networks = [net for net in networks if net.version == family]
            collapsed = list(ipaddress.collapse_addresses(family_networks))
            if len(collapsed) != 1 or collapsed[0].prefixlen != 0:
                raise ValueError("Safe internet requires full-tunnel WireGuard allowed IPs")
    settings = {
        "secretKey": wg.secret_key,
        "address": wg.addresses,
        "peers": [wg.peer],
        "remoteDNS": list(wg.dns),
    }
    if wg.mtu is not None:
        settings["mtu"] = wg.mtu
    # Happ TUN can pass a literal IPv6 destination into SOCKS. Retain the
    # sniffed hostname for dialing too, so ForceIPv4 resolves it through the
    # account DNS instead of leaving an unusable IPv6 literal unchanged.
    sniffing = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {"servers": list(wg.dns), "queryStrategy": "UseIPv4", "tag": _DNS_TAG},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": dict(sniffing),
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {},
                "sniffing": dict(sniffing),
            },
        ],
        "outbounds": [
            {"tag": "vpn", "protocol": "wireguard", "settings": settings},
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
                # UseIPv4 may fall back to OS DNS when the exported DNS fails.
                "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv4"}},
            },
            {"tag": "block", "protocol": "blackhole", "settings": {}},
            {
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {
                    "rewriteAddress": wg.dns[0],
                    "rewritePort": 53,
                    # Preserve every query type through the account resolver.
                    "rules": [{"action": "direct"}],
                },
                "streamSettings": {"sockopt": {"dialerProxy": "vpn"}},
            },
        ],
        "routing": _routing(mode, normalized, wg.dns, safe_internet=safe_internet),
    }
