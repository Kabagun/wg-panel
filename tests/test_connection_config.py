import base64
import re
import subprocess
from html import unescape
from types import SimpleNamespace

import pytest
import test_routes
from test_routes import csrf_session, user_record

from wg_panel import app, connection_config, core, traffic, wireguard
from wg_panel.i18n import t

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


@pytest.mark.parametrize("lang", ["en", "ru"])
@pytest.mark.parametrize("qr_available", [True, False])
def test_connection_columns_preserve_device_qr_download_and_copy(
    runtime, monkeypatch, lang, qr_available,
):
    _data, clients = runtime
    core.save_users({"alice": user_record()})
    name = "alice-laptop"
    display_name = "office <laptop>"
    (clients / f"{name}.conf").write_text(
        "[Interface]\nPrivateKey = synthetic-key\nAddress = 10.8.0.9/32\n"
        "DNS = 9.9.9.9\n[Peer]\nPublicKey = synthetic-server\n"
        "Endpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n",
        encoding="utf-8",
    )
    traffic.save_device_meta({name: {
        "owner": "alice", "device": display_name, "vpn_type": "wireguard",
        "safe_internet": False,
    }})
    client = app.test_client()
    csrf_session(client, "alice")
    attachment = client.get(f"/device/{name}/download")
    config = attachment.get_data(as_text=True)
    qr_inputs = []
    qr_svg = b'<svg xmlns="http://www.w3.org/2000/svg"><title>synthetic device QR</title></svg>'

    def encode(args, **kwargs):
        assert args == ["qrencode", "-t", "SVG", "-o", "-"]
        qr_inputs.append(kwargs["input"])
        return SimpleNamespace(returncode=0 if qr_available else 1, stdout=qr_svg)

    monkeypatch.setattr(wireguard.subprocess, "run", encode)
    response = client.get(f"/device/{name}", headers={"Accept-Language": lang})
    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert qr_inputs == [config.encode()]
    assert re.findall(r"<h1>(.*?)</h1>", page) == ["office &lt;laptop&gt;"]
    assert "My laptop" not in page
    assert page.index('class="connection-qr"') < page.index('class="connection-instructions"')
    assert page.index('class="connection-instructions"') < page.index('class="kill-switch-notice"')
    assert t("ui_qr_title", lang) in page
    assert t("ui_configuration_title", lang) in page
    assert t("kill_switch_notice_title", lang) in page
    assert 'aria-labelledby="connection-title"' in page
    if qr_available:
        qr_data = "data:image/svg+xml;base64," + base64.b64encode(qr_svg).decode()
        assert f'src="{qr_data}"' in page
        assert f'alt="{t("ui_qr_alt", lang)}"' in page
        assert 'class="qr-unavailable"' not in page
    else:
        assert 'class="qr-unavailable"' in page
        assert t("ui_qr_missing", lang) in page

    actions = re.search(r'<div class="connection-actions">(.*?)</div>', page, re.DOTALL)[1]
    assert f'href="/device/{name}/download" class="button primary"' in actions
    assert actions.index('class="button primary"') < actions.index('class="button secondary"')
    target, = re.findall(r'data-copy-target="([^"]+)"', actions)
    copied_config, = re.findall(
        rf'<pre id="{re.escape(target)}"[^>]*><code>(.*?)</code></pre>', page, re.DOTALL,
    )
    assert unescape(copied_config) == config
    assert f'data-copy-success="{t("ui_copied", lang)}"' in actions
    assert f'data-copy-error="{t("ui_copy_error", lang)}"' in actions
    assert 'data-copy-status role="status" aria-live="polite"' in page
    assert attachment.status_code == 200
    assert attachment.mimetype == "application/octet-stream"
    assert "attachment;" in attachment.headers["Content-Disposition"]
