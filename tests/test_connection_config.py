import base64
import re
import subprocess
from types import SimpleNamespace

import pytest
import test_routes
from test_routes import csrf_session, user_record

from wg_panel import app, connection_config, core, traffic

runtime = test_routes.runtime


def test_summary_is_allowlisted_and_preserves_split_default_routes():
    config = (
        "[Interface]\nPrivateKey = private-secret\nAddress = 10.8.0.7/32\n"
        "Address = fd00::7/128\nDNS = 10.8.0.1\nMTU = 1380\nListenPort = 12345\n"
        "[Peer]\nPublicKey = server-public\nPresharedKey = shared-secret\n"
        "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\nAllowedIPs = ::/1, 8000::/1\n"
        "Endpoint = [2001:db8::1]:51820\nPersistentKeepalive = 25 # seconds\n"
        "PostUp = arbitrary-private-value\n"
    )
    details = connection_config.connection_details(config)
    assert details["address"] == "10.8.0.7/32, fd00::7/128"
    assert details["allowed_ips"] == "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1"
    assert details["endpoint"] == "[2001:db8::1]:51820"
    assert details["keepalive"] == "25"
    assert details["preshared_key_enabled"] is True
    assert not any(value in str(details) for value in (
        "private-secret", "shared-secret", "arbitrary-private-value",
    ))


@pytest.mark.parametrize("failure", [OSError(), subprocess.TimeoutExpired("wg", 2)])
def test_unavailable_public_key_derivation_keeps_parameters_available(monkeypatch, failure):
    def unavailable(*args, **kwargs):
        raise failure

    monkeypatch.setattr(connection_config.subprocess, "run", unavailable)
    key = base64.b64encode(b"x" * 32).decode()
    details = connection_config.connection_details(
        f"[Interface]\nPrivateKey = {key}\nAddress = 10.8.0.7/32\n",
        include_public_key=True,
    )
    assert details["address"] == "10.8.0.7/32"
    assert details["client_public_key"] == ""
    assert key not in str(details)


def test_public_key_derivation_uses_stdin_and_returns_only_public_key(monkeypatch):
    private_key = base64.b64encode(b"x" * 32).decode()
    public_key = base64.b64encode(b"y" * 32).decode()

    def derive(args, **kwargs):
        assert args == ["wg", "pubkey"]
        assert private_key not in str(args)
        assert kwargs["input"] == private_key + "\n"
        return SimpleNamespace(stdout=public_key + "\n")

    monkeypatch.setattr(connection_config.subprocess, "run", derive)
    assert connection_config.connection_details(
        f"[Interface]\nPrivateKey = {private_key}\n", include_public_key=True,
    )["client_public_key"] == public_key


@pytest.mark.parametrize("safe", [False, True])
def test_device_summary_and_cards_follow_downloaded_dns_and_addresses(runtime, safe):
    _data, clients = runtime
    core.save_users({"alice": user_record()})
    (clients / "alice-phone.conf").write_text(
        "[Interface]\nPrivateKey = private-secret\nAddress = 10.8.0.7/32\n"
        "DNS = 9.9.9.9\n[Peer]\nPublicKey = server-public\n"
        "PresharedKey = shared-secret\nEndpoint = vpn.example.test:51820\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
        encoding="utf-8",
    )
    traffic.save_device_meta({"alice-phone": {
        "owner": "alice", "device": "phone", "vpn_type": "wireguard", "safe_internet": safe,
    }})
    client = app.test_client()
    csrf_session(client, "alice")
    download = client.get("/device/alice-phone/download").get_data(as_text=True)
    page = client.get("/device/alice-phone").get_data(as_text=True)
    summary = re.search(r'<section class="panel config-summary".*?</section>', page, re.DOTALL)[0]
    card = client.get("/dashboard").get_data(as_text=True)
    dns = "1.1.1.3, 1.0.0.3" if safe else "1.1.1.1, 8.8.8.8"
    assert f"DNS = {dns}" in download
    assert dns in summary and dns in card
    assert "10.8.0.7/32" in summary and "10.8.0.7/32" in card
    assert "0.0.0.0/0, ::/0" in summary
    public_summary = summary.split('<details class="config-file">')[0]
    assert "private-secret" not in public_summary and "shared-secret" not in public_summary
    assert "vpn.example.test:51820" in summary
