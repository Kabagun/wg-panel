"""Synthetic transport and server-policy checks; no real VPN peers or keys."""

import base64
import copy
import ipaddress
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from wg_panel.happ_config import MODES, build_happ_config
from wg_panel.happ_transports import create_server_config, overlay_transport

ROOT = Path(__file__).resolve().parents[1]
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
UUID = "864b7267-9dfc-45a5-b235-e4c94738ebf6"
VLESS = {"host": "vpn.example.com", "port": 8443, "uuid": UUID, "public_key": KEY,
         "short_id": "12abcdef12345678", "server_name": "www.example.com"}
HYS = {"host": "vpn.example.com", "port": 8443, "password": "synthetic-hysteria-password",
       "server_name": "vpn.example.com"}
USERS = [{"id": UUID, "email": "device-0123456789abcdef01234567@pilot.invalid",
          "password": HYS["password"]}]
OPTIONS = {"reality_private_key": KEY, "reality_short_ids": [VLESS["short_id"]],
           "reality_target": "www.example.com:443", "reality_server_names": ["www.example.com"],
           "certificate_file": "/run/credentials/pilot/cert.pem", "key_file": "/run/credentials/pilot/key.pem"}
WG_KEYS = [base64.b64encode(bytes([i])*32).decode() for i in (1, 2, 3)]
WG = (f"[Interface]\nPrivateKey={WG_KEYS[0]}\nAddress=10.8.0.2/32\nDNS=10.8.0.1\n"
      f"[Peer]\nPublicKey={WG_KEYS[1]}\nPresharedKey={WG_KEYS[2]}\nEndpoint=vpn.example.com:51820\n"
      "AllowedIPs=0.0.0.0/0, ::/0\nPersistentKeepalive=25\n")


def base(mode="custom"):
    return build_happ_config(WG, mode, ["domain:example.net"], safe_internet=False, remarks="Synthetic")


def test_wireguard_is_unchanged_independent_copy():
    original = base()
    result = overlay_transport(original, "wireguard", {})
    assert result == original and result is not original
    result["dns"]["servers"].append("127.0.0.1")
    assert original["dns"]["servers"] == ["10.8.0.1"]


def test_vpn_tag_can_be_reordered_and_metadata_is_preserved():
    config = base()
    config["meta"] = {"revision":1.5,"serverDescription":"Synthetic"}
    config["outbounds"] = config["outbounds"][1:]+config["outbounds"][:1]
    result = overlay_transport(config,"hysteria2",HYS)
    assert result["outbounds"][:-1] == config["outbounds"][:-1]
    assert result["outbounds"][-1]["protocol"] == "hysteria"
    assert result["meta"] == config["meta"]


def test_wg_key_duplicated_outside_vpn_fails_instead_of_leaking():
    config = base()
    config["meta"] = {"unexpected":"copied-key:"+WG_KEYS[0]}
    with pytest.raises(ValueError,match="^Invalid Happ transport configuration$"):
        overlay_transport(config,"hysteria2",HYS)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("transport,settings", [("vless-reality", VLESS), ("hysteria2", HYS)])
def test_overlay_preserves_everything_except_vpn_and_removes_wg_material(mode, transport, settings):
    original, settings_before = base(mode), copy.deepcopy(settings)
    before = copy.deepcopy(original)
    result = overlay_transport(original, transport, settings)
    assert original == before and settings == settings_before
    assert {k:v for k,v in result.items() if k != "outbounds"} == {k:v for k,v in original.items() if k != "outbounds"}
    assert result["outbounds"][1:] == original["outbounds"][1:]
    assert result["outbounds"][0]["tag"] == "vpn"
    assert result["outbounds"][-1]["streamSettings"]["sockopt"]["dialerProxy"] == "vpn"
    serialized = json.dumps(result)
    assert all(key not in serialized for key in WG_KEYS)
    assert "wireguard" not in serialized and "secretKey" not in serialized and "preSharedKey" not in serialized
    result["routing"]["rules"].clear()
    assert original == before


def test_exact_protocol_fields_and_tls_verification():
    vless = overlay_transport(base(), "vless-reality", VLESS)["outbounds"][0]
    assert vless["settings"]["vnext"][0]["users"] == [{"id": UUID, "encryption":"none", "flow":"xtls-rprx-vision-udp443"}]
    assert vless["streamSettings"]["security"] == "reality"
    assert vless["streamSettings"]["realitySettings"]["fingerprint"] == "chrome"
    hys = overlay_transport(base(), "hysteria2", HYS)["outbounds"][0]
    assert hys["settings"]["version"] == 2 and hys["protocol"] == "hysteria"
    assert hys["streamSettings"]["network"] == "hysteria"
    assert hys["streamSettings"]["hysteriaSettings"] == {"version":2,"auth":HYS["password"]}
    assert hys["streamSettings"]["tlsSettings"] == {"serverName":HYS["server_name"],"allowInsecure":False,"alpn":["h3"]}


@pytest.mark.parametrize("field,value", [
    ("host", "https://user:secret@example.com"), ("host", "127.0.0.1"), ("host", "10.0.0.1"),
    ("host", "::1"), ("host", "localhost"), ("host", "service.local"), ("host", "a\n.example.com"),
    ("port", True), ("port", 0), ("port", 65536), ("port", "8443"), ("uuid", "not-a-uuid-secret"),
    ("public_key", "secret-bad-key"), ("public_key", "A"*43), ("short_id", "123"),
    ("short_id", "00"*9), ("short_id", "gg"), ("server_name", "*.example.com"),
    ("server_name", "www.example.com/path"), ("allowInsecure", True),
])
def test_client_rejects_invalid_or_extra_settings_without_echo(field, value):
    settings = {**VLESS, field:value}
    with pytest.raises(ValueError, match="^Invalid Happ transport configuration$"):
        overlay_transport(base(), "vless-reality", settings)


def test_endpoint_idna_and_global_ipv6_are_supported():
    result = overlay_transport(base(), "hysteria2", {**HYS,"host":"пример.com"})
    assert result["outbounds"][0]["settings"]["address"] == "xn--e1afmkfd.com"
    result = overlay_transport(base(), "hysteria2", {**HYS,"host":"2606:4700:4700::1111"})
    assert result["outbounds"][0]["settings"]["address"] == "2606:4700:4700::1111"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "other-wg", "wrong-protocol", "non-json"])
def test_bad_base_fails_closed(mutation):
    config = base()
    if mutation == "missing":
        config["outbounds"].pop(0)
    elif mutation == "duplicate":
        config["outbounds"].append(copy.deepcopy(config["outbounds"][0]))
    elif mutation == "other-wg":
        config["outbounds"].append({"tag":"unrelated", "protocol":"wireguard", "settings":{}})
    elif mutation == "wrong-protocol":
        config["outbounds"][0]["protocol"] = "freedom"
    else:
        config["not-json"] = float("nan")
    with pytest.raises(ValueError):
        overlay_transport(config, "vless-reality", VLESS)


@pytest.mark.parametrize("transport,settings", [("unknown",{}),("wireguard",VLESS),("hysteria2",{})])
def test_unknown_transport_or_incomplete_credentials_fail(transport, settings):
    with pytest.raises(ValueError):
        overlay_transport(base(), transport, settings)


def test_server_authentication_policy_dns_order_and_private_api():
    before = copy.deepcopy((USERS, OPTIONS))
    result = create_server_config(USERS, OPTIONS)
    assert (USERS,OPTIONS) == before
    vless,hys,api = result["inbounds"]
    assert vless["port"] == hys["port"] == 8443
    assert vless["settings"]["clients"][0]["id"] == UUID
    assert vless["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"
    assert hys["settings"]["users"][0]["auth"] == HYS["password"]
    assert hys["streamSettings"]["network"] == "hysteria"
    assert "auth" not in hys["streamSettings"]["hysteriaSettings"]
    assert api["listen"] == "127.0.0.1" and api["port"] == 18012
    assert result["api"]["services"] == ["StatsService"]
    assert result["policy"]["levels"]["0"] == {"statsUserUplink":True,"statsUserDownlink":True}
    rules = result["routing"]["rules"]
    assert rules[0]["outboundTag"] == "api"
    assert rules[1] == {"type":"field","user":[USERS[0]["email"]],"network":"tcp,udp","port":"53","outboundTag":"central-dns"}
    assert rules[2]["port"] == "853" and rules[2]["outboundTag"] == "block"
    assert rules[3]["port"] == "443" and "1.1.1.1" in rules[3]["ip"]
    assert "127.0.0.0/8" in rules[4]["ip"] and "fc00::/7" in rules[4]["ip"]
    central = result["outbounds"][1]["settings"]
    assert central["redirect"] == "127.0.0.1:18004"
    assert central["finalRules"] == [{"action":"allow","network":"tcp,udp","ip":["127.0.0.1"],"port":"18004"}]
    assert all("access" not in key and "error" not in key for key in result["log"])


def test_mixed_family_roster_enforces_only_protected_users_and_private_block_for_everyone():
    ordinary = {"id":"d4a79772-9db8-4bdc-a146-63fdd4709975", "password":"different-synthetic-password",
                "email":"device-abcdef0123456789abcdef01@pilot.invalid", "family":False}
    config = create_server_config([*USERS,ordinary],OPTIONS)
    def route(email,address,port):
        for rule in config["routing"]["rules"]:
            if "inboundTag" in rule:
                continue
            if "user" in rule and email not in rule["user"]:
                continue
            if "port" in rule and str(port) != rule["port"]:
                continue
            if "ip" in rule and not any(ipaddress.ip_address(address) in ipaddress.ip_network(value) for value in rule["ip"]):
                continue
            return rule["outboundTag"]
        raise AssertionError("No route")
    for email,protected in ((USERS[0]["email"],True),(ordinary["email"],False)):
        assert route(email,"1.1.1.1",53) == ("central-dns" if protected else "direct")
        assert route(email,"8.8.8.8",53) == ("central-dns" if protected else "direct")
        assert route(email,"1.1.1.1",853) == ("block" if protected else "direct")
        assert route(email,"1.1.1.1",443) == ("block" if protected else "direct")
        assert route(email,"10.0.0.1",443) == "block"
        assert route(email,"127.0.0.1",18004) == "block"
        assert route(email,"10.0.0.1",53) == ("central-dns" if protected else "block")
    assert [r["user"] for r in config["routing"]["rules"] if "user" in r] == [[USERS[0]["email"]]]*3
    only_ordinary = create_server_config([ordinary],OPTIONS)
    assert not any(r.get("outboundTag")=="central-dns" for r in only_ordinary["routing"]["rules"])


@pytest.mark.parametrize("family",[None,"false",0,1,[],{}])
def test_family_flag_must_be_boolean(family):
    with pytest.raises(ValueError):
        create_server_config([{**USERS[0],"family":family}],OPTIONS)


def test_empty_roster_has_no_public_proxy_and_api_can_be_disabled():
    result = create_server_config([], OPTIONS)
    assert [inbound["tag"] for inbound in result["inbounds"]] == ["api-in"]
    result = create_server_config([], {**OPTIONS,"api_port":None})
    assert result["inbounds"] == [] and "api" not in result


@pytest.mark.parametrize("field,value", [
    ("api_listen","0.0.0.0"),("api_listen","example.com"),("api_port",True),("api_port",8443),
    ("dns_host","10.0.0.1"),("dns_port",0),("port",65536),("port",18004),("listen",123),
    ("reality_private_key","sensitive-invalid-key"),("reality_short_ids",[]),
    ("reality_short_ids",[""]),("reality_short_ids",["aa","aa"]),
    ("reality_target","127.0.0.1:443"),("reality_target","https://example.com:443"),
    ("reality_server_names",["*.example.com"]),("certificate_file","relative.pem"),
    ("key_file","/secret\n.pem"),("arbitrary",True),
])
def test_bad_server_options_fail_sanitized(field,value):
    with pytest.raises(ValueError,match="^Invalid Happ transport configuration$"):
        create_server_config(USERS,{**OPTIONS,field:value})


@pytest.mark.parametrize("mutation", ["duplicate-id","duplicate-auth","duplicate-label","no-auth","real-email","extra"])
def test_server_roster_rejects_ambiguous_or_unauthenticated_users(mutation):
    users = copy.deepcopy(USERS)
    if mutation.startswith("duplicate"):
        extra = {"id":"d4a79772-9db8-4bdc-a146-63fdd4709975", "password":"different-synthetic-password",
                 "email":"device-abcdef0123456789abcdef01@pilot.invalid"}
        extra[{"duplicate-id":"id","duplicate-auth":"password","duplicate-label":"email"}[mutation]] = users[0][{"duplicate-id":"id","duplicate-auth":"password","duplicate-label":"email"}[mutation]]
        users.append(extra)
    elif mutation == "no-auth":
        users[0]["password"] = ""
    elif mutation == "real-email":
        users[0]["email"] = "synthetic@example.com"
    else:
        users[0]["extra"] = True
    with pytest.raises(ValueError):
        create_server_config(users,OPTIONS)


def test_official_xray_26_10_31_parses_all_modes_both_transports_and_server():
    """Optional existing-core check. No downloads, listeners, or service changes."""
    executable = ROOT / "temp/happ-validation/xray-26.10.31/xray.exe"
    if os.name != "nt" or not executable.is_file():
        pytest.skip("Existing official Windows Xray26.10.31 binary unavailable")
    scratch = ROOT / "temp"
    scratch.mkdir(exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="happ-transports-check-",dir=scratch) as directory:
        folder = Path(directory)
        # The core generates disposable synthetic cert material; never stdout.
        generated = subprocess.run([str(executable),"tls","cert","--domain=localhost","--expire=24h"],
            capture_output=True,text=True,timeout=10,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
        certificate = json.loads(generated.stdout)
        options = {**OPTIONS,"certificate_file":str(folder/"cert.pem"),"key_file":str(folder/"key.pem")}
        for name,value in (("cert",certificate["certificate"]),("key",certificate["key"])):
            path = folder / (name+".pem")
            path.write_text("\n".join(value)+"\n" if isinstance(value,list) else value,encoding="utf-8")
            path.chmod(0o600)
        cases = [(mode+"-"+transport,overlay_transport(base(mode),transport,settings))
                 for mode in MODES for transport,settings in (("vless-reality",VLESS),("hysteria2",HYS))]
        ordinary = {"id":"d4a79772-9db8-4bdc-a146-63fdd4709975", "password":"different-synthetic-password",
                    "email":"device-abcdef0123456789abcdef01@pilot.invalid", "family":False}
        cases += [("server",create_server_config(USERS,options)),
                  ("mixed-server",create_server_config([*USERS,ordinary],options)),
                  ("ordinary-server",create_server_config([ordinary],options)),
                  ("empty-server",create_server_config([],options))]
        for label,config in cases:
            path = folder / (label+".json")
            path.write_text(json.dumps(config),encoding="utf-8")
            path.chmod(0o600)
            checked = subprocess.run([str(executable),"run","-test","-config",str(path)],check=False,cwd=folder,
                env={**os.environ,"XRAY_LOCATION_ASSET":str(executable.parent)},
                capture_output=True,text=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
            # Do not expose config/logs that can contain runtime credential values.
            assert checked.returncode == 0, "Official core rejected synthetic case: " + label
            results.append({"case":label,"exit_code":checked.returncode})
    report = ROOT / "temp/happ-transports-cli-proof.json"
    report.write_text(json.dumps({"core":"26.10.31","checks":results},indent=2),encoding="utf-8")
