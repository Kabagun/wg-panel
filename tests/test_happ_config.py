"""Synthetic, secret-safe fixtures for the closed Happ/Xray export pilot."""

import base64
import copy
import ipaddress
import json

import pytest

from wg_panel.happ_config import GEOIP_URL, MODES, build_happ_config, normalize_proxy_rules

PRIVATE = base64.b64encode(bytes([1]) * 32).decode()
PUBLIC = base64.b64encode(bytes([2]) * 32).decode()
PSK = base64.b64encode(bytes([3]) * 32).decode()
WG = (
    f"[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.8.0.2/32\n"
    "DNS = 9.9.9.9, 149.112.112.112\nMTU = 1380\n\n"
    f"[Peer]\nPublicKey = {PUBLIC}\nPresharedKey = {PSK}\n"
    "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.test:51820\n"
    "PersistentKeepalive = 25 # seconds\n"
)


def build(config=WG, mode="all", rules=None, safe=False):
    return build_happ_config(
        config,
        mode,
        [] if rules is None else rules,
        safe_internet=safe,
        remarks="Pilot",
    )


def test_preserves_wireguard_identity_transport_and_dns():
    output = build()
    settings = output["outbounds"][0]["settings"]
    assert settings == {
        "secretKey": PRIVATE,
        "address": ["10.8.0.2/32"],
        "mtu": 1380,
        "remoteDNS": ["9.9.9.9", "149.112.112.112"],
        "peers": [
            {
                "endpoint": "vpn.example.test:51820",
                "publicKey": PUBLIC,
                "preSharedKey": PSK,
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "keepAlive": 25,
            }
        ],
    }
    assert output["dns"]["servers"] == settings["remoteDNS"]
    assert output["dns"]["queryStrategy"] == "UseIPv4"
    assert output["remarks"] == "Pilot"
    assert output["log"] == {"loglevel": "warning"}
    assert [
        (inbound["listen"], inbound["port"], inbound["protocol"]) for inbound in output["inbounds"]
    ] == [
        ("127.0.0.1", 10808, "socks"),
        ("127.0.0.1", 10809, "http"),
    ]
    assert output["inbounds"][0]["settings"]["udp"] is True
    # The SOCKS destination must become the sniffed hostname as well: a TUN
    # IPv6 literal cannot be converted by the direct outbound's ForceIPv4.
    assert all(inbound["sniffing"]["routeOnly"] is False for inbound in output["inbounds"])
    assert [(out["tag"], out["protocol"]) for out in output["outbounds"]] == [
        ("vpn", "wireguard"),
        ("direct", "freedom"),
        ("block", "blackhole"),
        ("dns-out", "dns"),
    ]
    assert output["outbounds"][1]["streamSettings"]["sockopt"]["domainStrategy"] == "ForceIPv4"


def test_optional_psk_mtu_and_keepalive_are_not_invented():
    config = WG.replace(f"PresharedKey = {PSK}\n", "").replace("MTU = 1380\n", "")
    config = config.replace("PersistentKeepalive = 25 # seconds\n", "")
    settings = build(config)["outbounds"][0]["settings"]
    assert "mtu" not in settings
    assert "preSharedKey" not in settings["peers"][0]
    assert settings["peers"][0]["keepAlive"] == 0


@pytest.mark.parametrize(
    "endpoint,expected",
    [
        ("198.51.100.10:51820", "198.51.100.10:51820"),
        ("[2001:db8:0::10]:51820", "[2001:db8::10]:51820"),
        ("VPN.Example.TEST:443", "vpn.example.test:443"),
        ("туннель.example:443", "xn--e1ameaxg1e.example:443"),
    ],
)
def test_endpoint_forms(endpoint, expected):
    config = WG.replace("vpn.example.test:51820", endpoint)
    assert build(config)["outbounds"][0]["settings"]["peers"][0]["endpoint"] == expected


def test_repeated_list_fields_and_ipv6_dns_preserved():
    config = WG.replace("Address = 10.8.0.2/32", "Address = 10.8.0.2/32\nAddress = fd00::2/128")
    config = config.replace(
        "DNS = 9.9.9.9, 149.112.112.112", "DNS = 9.9.9.9\nDNS = 2001:4860::8888"
    )
    config = config.replace("0.0.0.0/0, ::/0", "0.0.0.0/1, 128.0.0.0/1\nAllowedIPs = ::/0")
    settings = build(config, safe=True)["outbounds"][0]["settings"]
    assert settings["address"] == ["10.8.0.2/32", "fd00::2/128"]
    assert settings["remoteDNS"] == ["9.9.9.9", "2001:4860::8888"]
    assert settings["peers"][0]["allowedIPs"] == ["0.0.0.0/1", "128.0.0.0/1", "::/0"]


def test_rule_normalization_and_idempotence():
    result = normalize_proxy_rules(
        " Example.COM.\r\nhttps://example.com:443/path?query=yes#fragment\n"
        "DOMAIN:домен.рф\n192.0.2.37/24, 2001:db8::abcd/64\n192.0.2.1\n"
        "https://[2001:db8::1]:443/a\n"
    )
    assert result == [
        "domain:example.com",
        "domain:xn--d1acufc.xn--p1ai",
        "192.0.2.0/24",
        "2001:db8::/64",
        "192.0.2.1/32",
        "2001:db8::1/128",
    ]
    assert normalize_proxy_rules("\n".join(result)) == result


@pytest.mark.parametrize(
    "text",
    [
        "regexp:.*",
        "geosite:example",
        "geoip:ru",
        "full:example.com",
        "keyword:example",
        "*.example.com",
        ".example.com",
        "example.*",
        "example.com/path",
        "user@example.com",
        "https://user:password@example.com/path",
        "https://@example.com",
        "ftp://example.com",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:abc",
        "https://example.com\\@elsewhere.test",
        "https://[2001:db8::1/path",
        "file:///etc/passwd",
        "example.com\x00",
        "exam\tple.com",
        "example.com\x7f",
        "exam\u200bple.com",
        "example com",
        "999.999.1.1",
        "192.0.2.1/99",
        "domain:192.0.2.1",
        "::invalid",
        "https://%65xample.com",
        '{"outboundTag":"direct"}',
        "example.com:443",
    ],
)
def test_rejects_untrusted_rule_syntax(text):
    with pytest.raises(ValueError, match="Invalid proxy rule"):
        normalize_proxy_rules(text)


def test_rule_limits_before_deduplication():
    assert len(normalize_proxy_rules("\n".join(f"host{i}.test" for i in range(256)))) == 256
    with pytest.raises(ValueError, match="Too many"):
        normalize_proxy_rules("\n".join(["example.test"] * 257))
    assert normalize_proxy_rules("\n, \r\n") == []


def test_url_path_cannot_add_another_rule():
    assert normalize_proxy_rules("https://example.test/path,elsewhere.test?a,b") == [
        "domain:example.test",
    ]


@pytest.mark.parametrize(
    "mode,countries,default",
    [
        ("all", [], "vpn"),
        ("custom", [], "direct"),
        ("by-direct", ["geoip:by"], "vpn"),
        ("ru-direct", ["geoip:ru"], "vpn"),
        ("by-ru-direct", ["geoip:by", "geoip:ru"], "vpn"),
    ],
)
def test_modes_and_rule_priority(mode, countries, default):
    output = build(mode=mode, rules=["example.test", "10.8.0.0/16", "192.0.2.0/24"])
    routing = output["routing"]
    assert routing["domainStrategy"] == "IPOnDemand"
    rules = routing["rules"]
    assert rules[0]["inboundTag"] == [output["dns"]["tag"]]
    assert rules[1]["port"] == "53"
    assert rules[2]["ip"] == ["9.9.9.9/32", "149.112.112.112/32"]
    assert [rule["outboundTag"] for rule in rules[:5]] == [
        "vpn",
        "dns-out",
        "vpn",
        "vpn",
        "vpn",
    ]
    assert rules[3]["domain"] == ["domain:example.test"]
    assert rules[4]["ip"] == ["10.8.0.0/16", "192.0.2.0/24"]
    assert "10.0.0.0/8" in rules[5]["ip"] and rules[5]["outboundTag"] == "direct"
    country_rules = [
        rule for rule in rules if any(ip.startswith("geoip:") for ip in rule.get("ip", []))
    ]
    assert [ip for rule in country_rules for ip in rule["ip"]] == countries
    assert all(rule["outboundTag"] == "direct" for rule in country_rules)
    assert rules[-1]["outboundTag"] == default
    assert rules[-1]["network"] == "tcp,udp"
    assert not any("domain" in rule and "ip" in rule for rule in rules)


@pytest.mark.parametrize("mode", MODES)
def test_family_dns_is_protected_before_lan_bypass_without_public_fallback(mode):
    config = WG.replace("9.9.9.9, 149.112.112.112", "10.8.0.1")
    output = build(config, mode=mode, safe=True)
    assert output["dns"]["servers"] == ["10.8.0.1"]
    assert output["outbounds"][0]["settings"]["remoteDNS"] == ["10.8.0.1"]
    rules = output["routing"]["rules"]
    assert rules[2]["ip"] == ["10.8.0.1/32"] and rules[2]["outboundTag"] == "vpn"
    lan_index = next(i for i,r in enumerate(rules) if '10.0.0.0/8' in r.get('ip',[]))
    assert lan_index > 2 and rules[lan_index]['outboundTag'] == 'direct'
    dns_out = next(out for out in output['outbounds'] if out['tag']=='dns-out')
    assert dns_out['settings']['rewriteAddress'] == '10.8.0.1'
    assert dns_out['settings']['rules'] == [{'action': 'direct'}]
    assert dns_out['streamSettings']['sockopt']['dialerProxy'] == 'vpn'
    # Public resolver IPs in block rules are not DNS fallbacks.
    assert output['dns']['servers'] == [dns_out['settings']['rewriteAddress']]


@pytest.mark.parametrize("mode", MODES)
def test_raw_dns_is_rewritten_to_exported_resolver_for_every_mode(mode):
    output = build(mode=mode)
    dns_outbound = next(out for out in output["outbounds"] if out["tag"] == "dns-out")
    assert dns_outbound["protocol"] == "dns"
    assert dns_outbound["settings"] == {
        "rewriteAddress": "9.9.9.9",
        "rewritePort": 53,
        "rules": [{"action": "direct"}],
    }
    assert dns_outbound["streamSettings"]["sockopt"]["dialerProxy"] == "vpn"
    # Preserve both transports and all query types without synthesizing replies.
    assert "rewriteNetwork" not in dns_outbound["settings"]
    rules = output["routing"]["rules"]
    assert rules[0]["inboundTag"] == [output["dns"]["tag"]]
    assert rules[0]["outboundTag"] == "vpn"
    assert rules[1] == {
        "type": "field",
        "network": "tcp,udp",
        "port": "53",
        "outboundTag": "dns-out",
    }


def first_route(output, *, host, port, domain=None, network='tcp'):
    """Evaluate only literal/domain rules relevant to DNS guard priority."""
    for rule in output['routing']['rules']:
        if 'inboundTag' in rule:
            continue
        if 'network' in rule and network not in rule['network'].split(','):
            continue
        if 'port' in rule and str(port) != rule['port']:
            continue
        if 'domain' in rule and not any(
            domain is not None and (domain == value[7:] or domain.endswith('.'+value[7:]))
            for value in rule['domain'] if value.startswith('domain:')
        ):
            continue
        if 'ip' in rule and not any(
            not value.startswith('geoip:') and ipaddress.ip_address(host) in ipaddress.ip_network(value)
            for value in rule['ip']
        ):
            continue
        return rule['outboundTag']
    raise AssertionError('No matching literal/domain rule')


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('network', ['tcp','udp'])
def test_family_split_modes_keep_dns_and_block_known_encrypted_dns_before_bypasses(mode, network):
    config = WG.replace('9.9.9.9, 149.112.112.112','10.8.0.1')
    # Deliberately overlapping proxy rules must not override DNS restrictions.
    output = build(config, mode=mode, rules=['1.1.1.1','10.8.0.0/16','dns.google'], safe=True)
    assert first_route(output,host='1.1.1.1',port=53,network=network) == 'dns-out'
    assert first_route(output,host='10.8.0.1',port=53,network=network) == 'dns-out'
    assert first_route(output,host='10.8.0.1',port=443,network=network) == 'vpn'
    assert first_route(output,host='192.168.1.1',port=853,network=network) == 'block'
    assert first_route(output,host='1.1.1.1',port=443,network=network) == 'block'
    assert first_route(output,host='2606:4700:4700::1111',port=443,network=network) == 'block'
    assert first_route(output,host='203.0.113.5',domain='dns.google',port=443,network=network) == 'block'
    assert first_route(output,host='203.0.113.5',domain='child.cloudflare-dns.com',port=443,network=network) == 'block'
    assert first_route(output,host='192.168.1.1',port=443,network=network) == 'direct'
    assert output['routing']['rules'][-1]['outboundTag'] == ('direct' if mode=='custom' else 'vpn')


def test_ordinary_smart_mode_does_not_apply_family_encrypted_dns_blocks():
    output = build(mode='custom')
    assert first_route(output,host='1.1.1.1',port=443) == 'direct'
    assert first_route(output,host='192.168.1.1',port=853) == 'direct'
    assert first_route(output,host='203.0.113.5',domain='dns.google',port=443) == 'direct'


@pytest.mark.parametrize('mode',MODES)
def test_family_rejects_underlying_split_wireguard(mode):
    with pytest.raises(ValueError, match="full-tunnel WireGuard"):
        build(WG.replace("0.0.0.0/0, ::/0", "0.0.0.0/1, 128.0.0.0/2, ::/0"), mode=mode, safe=True)


@pytest.mark.parametrize(
    "original,replacement",
    [
        (f"PrivateKey = {PRIVATE}", "PrivateKey = invalid-secret"),
        (f"PublicKey = {PUBLIC}", "PublicKey = invalid-secret"),
        (f"PresharedKey = {PSK}", "PresharedKey = invalid-secret"),
        (f"PrivateKey = {PRIVATE}", "PrivateKey = " + base64.b64encode(b"short").decode()),
        (f"PrivateKey = {PRIVATE}", "PrivateKey = " + base64.b64encode(b"a" * 33).decode()),
        (f"PrivateKey = {PRIVATE}", ""),
        ("[Peer]", "[Peer]\nPublicKey = duplicate"),
        ("[Peer]", "[Other]"),
        ("[Peer]", "[Peer]\n[Peer]"),
        ("[Interface]", "[Interface]\n[Interface]"),
        ("MTU = 1380", "MTU = 1380\nListenPort = 12345"),
        ("MTU = 1380", "MTU = 1380\nPostUp = arbitrary-command"),
        ("MTU = 1380", "MTU = 1380\nTable = off"),
        ("MTU = 1380", "MTU = 1380\nSaveConfig = true"),
        ("MTU = 1380", "MTU = 0"),
        ("MTU = 1380", "MTU = auto"),
        ("Address = 10.8.0.2/32", "Address = 10.8.0.2"),
        ("Address = 10.8.0.2/32", "Address = invalid"),
        ("DNS = 9.9.9.9, 149.112.112.112", ""),
        ("DNS = 9.9.9.9, 149.112.112.112", "DNS = localhost"),
        ("DNS = 9.9.9.9, 149.112.112.112", "DNS = 9.9.9.9,"),
        ("DNS = 9.9.9.9, 149.112.112.112", "DNS = 2001:4860::8888"),
        ("DNS = 9.9.9.9, 149.112.112.112", "DNS = 0.0.0.0"),
        ("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.8.0.0/24"),
        ("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = invalid"),
        ("vpn.example.test:51820", "vpn.example.test"),
        ("vpn.example.test:51820", "vpn.example.test:0"),
        ("vpn.example.test:51820", "vpn.example.test:65536"),
        ("vpn.example.test:51820", "2001:db8::1:51820"),
        ("vpn.example.test:51820", "[fe80::1%eth0]:51820"),
        ("vpn.example.test:51820", "user:password@vpn.example.test:51820"),
        ("vpn.example.test:51820", "999.999.1.1:51820"),
        ("PersistentKeepalive = 25 # seconds", "PersistentKeepalive = 65536"),
        ("PersistentKeepalive = 25 # seconds", "PersistentKeepalive = -1"),
        ("PersistentKeepalive = 25 # seconds", "PersistentKeepalive = 1.5"),
    ],
)
def test_bad_wireguard_never_echoes_keys_or_parser_details(original, replacement):
    config = WG.replace(original, replacement)
    with pytest.raises(ValueError) as error:
        build(config)
    assert str(error.value) == "Invalid or unsupported WireGuard configuration"
    assert all(
        secret not in str(error.value) for secret in (PRIVATE, PUBLIC, PSK, replacement) if secret
    )
    assert error.value.__suppress_context__ is True


def test_generator_is_pure_and_output_can_be_json_encoded():
    rules = ["example.test", "192.0.2.1/24"]
    original = copy.deepcopy(rules)
    first = build(rules=rules)
    assert rules == original
    first["dns"]["servers"].append("192.0.2.1")
    first["routing"]["rules"].clear()
    assert build(rules=rules) != first
    json.dumps(build(rules=rules), allow_nan=False)
    assert GEOIP_URL.endswith("/geoip.dat")


def test_wireguard_tabs_crlf_and_disabled_keepalive():
    config = WG.replace(" = ", "\t=\t").replace("25 # seconds", "off").replace("\n", "\r\n")
    assert build(config)["outbounds"][0]["settings"]["peers"][0]["keepAlive"] == 0


@pytest.mark.parametrize("bad", [None, "all", [None], ["example.com\nelsewhere.test"], ["a,b"]])
def test_invalid_rule_list_rejected(bad):
    with pytest.raises(ValueError):
        build_happ_config(WG, "all", bad, safe_internet=False, remarks="Pilot")


def test_settings_validation():
    with pytest.raises(ValueError, match="Unsupported routing mode"):
        build(mode="arbitrary")
    with pytest.raises(ValueError, match="Invalid profile name"):
        build_happ_config(WG, "all", [], safe_internet=False, remarks="bad\nname")
    with pytest.raises(ValueError, match="Invalid Safe internet"):
        build_happ_config(WG, "all", [], safe_internet="false", remarks="Pilot")


def test_lan_bypass_is_not_broad_public_special_use_bypass():
    rules = build()["routing"]["rules"]
    lan = next(rule["ip"] for rule in rules if rule["outboundTag"] == "direct")
    networks = [ipaddress.ip_network(value) for value in lan]
    for address in ["100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1"]:
        ip = ipaddress.ip_address(address)
        assert not any(net.version == ip.version and ip in net for net in networks)
