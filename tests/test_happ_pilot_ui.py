"""Private pilot UI keeps logical device types and backend-supplied previews distinct."""

import copy
import re
from html import unescape
from types import SimpleNamespace

import pytest
from flask import session
from test_dashboard import DashboardHTML

from wg_panel import account_policy, app, core, happ_pilot, traffic, wireguard
from wg_panel.i18n import t
from wg_panel.routes import admin as admin_routes
from wg_panel.ui import render_page


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    for module, key, value in (
        (core, "DATA_DIR", data), (core, "USERS_FILE", data / "users.json"),
        (core, "DEVICE_META_FILE", data / "devices.json"),
        (traffic, "DEVICE_META_FILE", data / "devices.json"),
        (traffic, "CLIENTS_DIR", clients), (wireguard, "CLIENTS_DIR", clients),
        (wireguard, "WG_DIR", clients.parent),
    ):
        monkeypatch.setattr(module, key, str(value))
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", True)
    core.save_users({
        "operator": {"role": "admin", "approved": True, "max_devices": -1, "session_version": 1},
        "pilot-member": {"role": "user", "approved": True, "max_devices": 3, "session_version": 1},
        "regular-member": {"role": "user", "approved": True, "max_devices": 3, "session_version": 1},
    })
    identities = core.load_users()
    state = SimpleNamespace(eligible={identities[name]["account_id"] for name in ("operator", "pilot-member")})
    monkeypatch.setattr(happ_pilot, "available_for_user", lambda user: user.get("account_id") in state.eligible)
    monkeypatch.setattr(happ_pilot, "public_enabled", lambda: False)
    metadata = {}
    for name, label, extra in (
        ("pilot-classic", "classic", {}),
        ("pilot-happ", "phone", {"happ_pilot": True}),
        ("pilot-child", "internal-child", {"happ_transport_internal": True}),
    ):
        (clients / f"{name}.conf").write_text(
            "[Interface]\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1, 8.8.8.8\n", encoding="utf-8",
        )
        metadata[name] = {"owner": "pilot-member", "device": label, "vpn_type": "wireguard", **extra}
    traffic.save_device_meta(metadata)
    account_policy.save_account_policies({})
    state.metadata = metadata
    return state


def browser(username="pilot-member"):
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(user=username, account_id=core.load_users()[username]["account_id"],
                     session_version=1, _csrf_token="synthetic-csrf")
    return client


@pytest.mark.parametrize("lang", ["en", "ru"])
def test_noneligible_member_sees_only_classic_creation_without_pilot_advertising(runtime, lang):
    response = browser("regular-member").get("/add", headers={"Accept-Language": lang})
    body = response.get_data(as_text=True)
    page = DashboardHTML(body)
    assert response.status_code == 200
    assert len(page.with_class("vpn-choice-card")) == 1
    assert page.with_class("vpn-choice-wireguard")[0]["attrs"]["href"] == "/add?client_app=wireguard"
    assert not page.with_class("vpn-choice-happ")
    assert "Happ" not in body and "happ.info" not in body
    assert "client_app=happ" not in body and 'aria-disabled="true"' not in body


@pytest.mark.parametrize("username", ["operator", "pilot-member"])
def test_eligible_accounts_choose_happ_through_normal_device_creation(runtime, username):
    body = browser(username).get("/add").get_data(as_text=True)
    page = DashboardHTML(body)
    assert len(page.with_class("vpn-choice-card")) == 2
    assert page.with_class("vpn-choice-happ")[0]["attrs"]["href"] == "/add?client_app=happ"
    assert not re.search(r'class="nav-link[^\"]*" href="/admin/happ-pilot"', body)


def test_admin_table_shapes_one_logical_row_and_downloads_by_connection_type(runtime, monkeypatch):
    all_rows = [(item["owner"], item["device"], name) for name, item in runtime.metadata.items()]
    monkeypatch.setattr(admin_routes, "get_all_devices", lambda: all_rows)
    monkeypatch.setattr(admin_routes, "get_device", lambda name: copy.deepcopy(runtime.metadata[name]))
    response = browser("operator").get("/admin/devices", headers={"Accept-Language": "ru"})
    assert response.status_code == 200
    page = DashboardHTML(response.get_data(as_text=True))
    rows = [node for node in page.nodes if node["tag"] == "tr" and "data-search-item" in node["attrs"]]
    assert len(rows) == 2
    assert any(node["tag"] == "th" and node["text"] == "Тип подключения" for node in page.nodes)
    typed = {}
    for row in rows:
        children = page.within(row)
        cell, = [node for node in children if node["tag"] == "td"
                 and node["attrs"].get("data-label") == "Тип подключения"]
        typed[cell["text"]] = [node["attrs"]["href"] for node in children if node["tag"] == "a"]
    assert 'WireGuard' in typed and 'Happ' in typed
    assert "/device/pilot-classic/download" in typed["WireGuard"]
    assert "/device/pilot-classic" in typed["WireGuard"]
    assert "/device/pilot-happ/happ" in typed["Happ"]
    assert "/device/pilot-happ/happ/bundle/download" in typed["Happ"]
    assert "/device/pilot-happ/download" not in typed["Happ"]
    assert "internal-child" not in response.get_data(as_text=True)


def test_dashboard_happ_type_and_bundle_do_not_become_wireguard_when_creation_is_closed(runtime):
    runtime.eligible.discard(core.load_users()["pilot-member"]["account_id"])
    page = DashboardHTML(browser().get("/dashboard").get_data(as_text=True))
    cards = page.with_class("device-card")
    assert len(cards) == 2
    happ, = [card for card in cards if card["attrs"]["data-search-item"] == "phone"]
    children = page.within(happ)
    protocol, = [node for node in children if "device-protocol" in node["attrs"].get("class", "").split()]
    assert protocol["text"] == "Happ"
    hrefs = [node["attrs"]["href"] for node in children if node["tag"] == "a"]
    assert "/device/pilot-happ/happ" in hrefs
    assert "/device/pilot-happ/happ/bundle/download" in hrefs
    assert "/device/pilot-happ/download" not in hrefs


def render_detail(username="pilot-member", *, options=None, locked=False, lang="en"):
    context = {
        "device": {"device": "synthetic-phone", "safe_internet": locked}, "wg_name": "pilot-happ",
        "mode": "all" if locked else "custom",
        "modes": [{"id": mode, "title_key": "happ_mode_" + mode.replace("-", "_"),
                "enabled": not locked or mode == "all"} for mode in ("all", "custom", "by-ru-direct")],
        "rules_text": "example.org", "proxy_rules": ["domain:example.org"], "rules_revision": "a" * 64,
        "config_json": '{"remarks":"synthetic"}', "qr": None,
        "subscription_url": "https://vpn.example.org/sub/synthetic/bundle",
        "import_url": "happ://add/https://vpn.example.org/sub/synthetic/bundle",
        "shared_rules": True, "shared_rules_managed": True, "shared_rules_status": "current",
        "shared_rules_checked": "2026-11-13 12:00 UTC", "shared_rules_updated": "2026-11-13 11:55 UTC",
        "shared_rules_revision": "a" * 12, "shared_rules_publication": {"status": "updated"},
        "shared_rules_source_link": "https://github.com/example-owner/example-repo/blob/main/routing-domains.txt",
    }
    if options is not None:
        context.update(transport_options=options, transport="vless-reality")
    with app.test_request_context("/device/pilot-happ/happ"):
        session.update(user=username, account_id=core.load_users()[username]["account_id"],
                       session_version=1, _csrf_token="synthetic-csrf")
        return render_page("happ_device.html", "happ_title", lang=lang, **context)


@pytest.mark.parametrize("lang", ["en", "ru"])
@pytest.mark.parametrize("locked", [False, True])
def test_transport_mode_preview_uses_backend_inventory_and_keeps_bundle_unfiltered(runtime, lang, locked):
    inventory = [
        {"id": "wireguard", "title": "WireGuard baseline", "available": True},
        {"id": "vless-reality", "title": "VLESS Reality", "available": True},
        {"id": "hysteria2", "title": "Hysteria2", "available": False},
    ]
    body = render_detail(options=inventory, locked=locked, lang=lang)
    page = DashboardHTML(body)
    transport, = [node for node in page.nodes if node["tag"] == "select"
                   and node["attrs"].get("name") == "transport"]
    options = page.within(transport)
    by_id = {node["attrs"]["value"]: node for node in options if node["tag"] == "option"}
    assert "selected" in by_id["vless-reality"]["attrs"]
    assert "disabled" in by_id["hysteria2"]["attrs"]
    assert set(by_id) == {item["id"] for item in inventory}
    links = [node["attrs"]["href"] for node in page.nodes if node["tag"] == "a"]
    mode = "all" if locked else "custom"
    assert f"/device/pilot-happ/happ/{mode}/download?transport=vless-reality" in links
    assert "/device/pilot-happ/happ/bundle/download" in links
    assert not any("bundle/download?transport=" in link for link in links)
    assert 'class="back-link" href="/dashboard"' in body
    assert "HAPP · " + t("happ_pilot_badge", lang) in body
    assert 'href="/admin/' not in body
    assert "WireGuard VPN</span>" not in body
    assert not [node for node in page.nodes if node["attrs"].get("name") in {"ping", "interval", "update_interval"}]
    if locked:
        assert t("happ_protected_modes_note", lang) in unescape(body)
        mode_select, = [node for node in page.nodes if node["tag"] == "select"
                        and node["attrs"].get("name") == "mode"]
        assert len([node for node in page.within(mode_select) if node["tag"] == "option"
                    and "disabled" in node["attrs"]]) == 2


def test_legacy_detail_does_not_advertise_unconfigured_transports(runtime):
    body = render_detail()
    assert 'name="transport"' not in body
    assert "VLESS" not in body and "Hysteria2" not in body
    assert 'href="/device/pilot-happ/happ/custom/download"' in body
    assert 'href="/device/pilot-happ/happ/bundle/download"' in body


def test_backend_transport_titles_are_autoescaped(runtime):
    body = render_detail(options=[{"id": "vless-reality", "title": '<script>synthetic()</script>',
                                   "available": True}])
    assert "<script>synthetic()</script>" not in body
    assert "&lt;script&gt;synthetic()&lt;/script&gt;" in body
