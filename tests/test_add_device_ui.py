"""Two-step connection selection keeps Classic intact and respects Happ availability."""

from types import SimpleNamespace

import pytest
from flask import session
from test_dashboard import DashboardHTML
from werkzeug.datastructures import MultiDict

from wg_panel import account_policy, app, core, happ_pilot, traffic, wireguard
from wg_panel.i18n import t
from wg_panel.routes import devices as routes
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
        "alice": {"role": "user", "approved": True, "max_devices": 3, "session_version": 1},
        "pending": {"role": "user", "approved": False, "session_version": 1},
    })
    state = SimpleNamespace(eligible={core.load_users()["operator"]["account_id"]},
                            public=False, calls=[], clients=clients,
                            actual_available=happ_pilot.available_for_user,
                            actual_public=happ_pilot.public_enabled)
    monkeypatch.setattr(happ_pilot, "available_for_user",
                        lambda user: user.get("account_id") in state.eligible, raising=False)
    monkeypatch.setattr(happ_pilot, "public_enabled", lambda: state.public, raising=False)
    monkeypatch.setattr(routes, "qr_svg_b64", lambda _name: None)
    monkeypatch.setattr(routes, "send_telegram", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(routes, "create_device", lambda owner, name:
                        state.calls.append(("wireguard", owner, name)) or (True, "created-classic", ""))
    monkeypatch.setattr(happ_pilot, "create_pilot_device", lambda owner, name:
                        state.calls.append(("happ", owner, name)) or (True, "created-happ", ""))
    metadata = {}
    for name, label, owner, extra in (
        ("alice-classic", "classic", "alice", {}),
        ("alice-happ", "happ", "alice", {"happ_pilot": True}),
        ("alice-transport", "transport", "alice", {"happ_transport_internal": True}),
    ):
        (clients / f"{name}.conf").write_text(
            "[Interface]\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1, 8.8.8.8\n", encoding="utf-8",
        )
        metadata[name] = {"owner": owner, "device": label, "vpn_type": "wireguard", **extra}
    traffic.save_device_meta(metadata)
    account_policy.save_account_policies({})
    return state


def browser(username="alice"):
    client = app.test_client()
    if username:
        with client.session_transaction() as session:
            session.update(user=username, account_id=core.load_users()[username]["account_id"],
                           session_version=1, _csrf_token="synthetic-csrf")
    return client


def enable_member(runtime):
    runtime.public = True
    runtime.eligible.add(core.load_users()["alice"]["account_id"])


@pytest.mark.parametrize("available", [False, True])
@pytest.mark.parametrize("lang", ["en", "ru"])
def test_first_step_shows_only_available_accessible_choices_and_creates_nothing(runtime, available, lang):
    if available:
        enable_member(runtime)
    response = browser().get("/add", headers={"Accept-Language": lang})
    assert response.status_code == 200
    page = DashboardHTML(response.get_data(as_text=True))
    cards = page.with_class("vpn-choice-card")
    assert len(cards) == (2 if available else 1)
    classic, = page.with_class("vpn-choice-wireguard")
    assert classic["tag"] == "a" and classic["attrs"]["href"] == "/add?client_app=wireguard"
    assert t("vpn_classic_title", lang) in classic["text"]
    if available:
        modern, = page.with_class("vpn-choice-happ")
        assert t("vpn_happ_title", lang) in modern["text"]
        assert modern["tag"] == "a"
        assert modern["attrs"]["href"] == "/add?client_app=happ"
    else:
        assert not page.with_class("vpn-choice-happ")
        assert t("vpn_happ_title", lang) not in response.get_data(as_text=True)
    for card in cards:
        assert "onclick" not in card["attrs"]
        assert not [node for node in page.within(card) if node["tag"] in {"a", "button", "input"}]
        assert any(node["attrs"].get("id") == card["attrs"]["aria-labelledby"]
                   for node in page.within(card))
    assert not [node for node in page.nodes if node["attrs"].get("name") == "device"]
    assert not runtime.calls


@pytest.mark.parametrize("client_app", ["wireguard", "happ"])
def test_second_step_preserves_selected_method_with_versioned_post_form(runtime, client_app):
    enable_member(runtime)
    response = browser().get("/add?client_app=" + client_app)
    assert response.status_code == 200
    page = DashboardHTML(response.get_data(as_text=True))
    form, = [node for node in page.nodes if node["tag"] == "form"
             and node["attrs"].get("action") == "/add"]
    assert form["attrs"]["method"] == "post"
    fields = {node["attrs"].get("name"): node["attrs"] for node in page.within(form)
              if node["tag"] == "input"}
    assert fields["client_app"]["type"] == "hidden" and fields["client_app"]["value"] == client_app
    assert fields["csrf_token"]["value"] == "synthetic-csrf"
    assert "required" in fields["device"]
    assert page.with_class("back-link")[0]["attrs"]["href"] == "/add"
    assert not runtime.calls


def test_forged_happ_get_or_post_cannot_bypass_availability(runtime):
    client = browser()
    assert client.get("/add?client_app=happ").status_code == 403
    assert client.post("/add", data={"csrf_token": "synthetic-csrf", "device": "phone",
                                         "client_app": "happ"}).status_code == 403
    assert not runtime.calls


def test_existing_direct_post_still_uses_classic_creator_and_endpoint(runtime):
    response = browser().post("/add", data={"csrf_token": "synthetic-csrf", "device": "phone"})
    assert response.status_code == 302 and response.location.endswith("/device/created-classic")
    assert runtime.calls == [("wireguard", "alice", "phone")]


def test_eligible_member_can_post_happ_without_administrator_role(runtime):
    enable_member(runtime)
    response = browser().post("/add", data={"csrf_token": "synthetic-csrf", "device": "phone",
                                              "client_app": "happ"})
    assert response.status_code == 302 and response.location.endswith("/device/created-happ/happ")
    assert runtime.calls == [("happ", "alice", "phone")]


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_ambiguous_or_unknown_method_selection_is_rejected(runtime, method):
    client = browser()
    if method == "GET":
        assert client.get("/add?client_app=wireguard&client_app=happ").status_code == 400
        assert client.get("/add?client_app=unknown").status_code == 400
    else:
        fields = MultiDict({"csrf_token": "synthetic-csrf", "device": "phone", "client_app": "wireguard"})
        fields.add("client_app", "happ")
        assert client.post("/add", data=fields).status_code == 400
        assert client.post("/add", data={"csrf_token": "synthetic-csrf", "device": "phone",
                                             "client_app": "unknown"}).status_code == 400
    assert not runtime.calls


def test_invalid_name_stays_on_selected_form_and_is_escaped(runtime):
    enable_member(runtime)
    response = browser().post("/add", data={"csrf_token": "synthetic-csrf", "client_app": "happ",
                                              "device": '<script>synthetic()</script>'})
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'name="client_app" value="happ"' in body
    assert '<script>synthetic()</script>' not in body and '&lt;script&gt;' in body
    assert not runtime.calls


def test_locked_account_is_not_promised_selective_happ_modes(runtime):
    enable_member(runtime)
    account_policy.save_account_policies({"alice": {"safe_internet_locked": True}})
    page = DashboardHTML(browser().get("/add", headers={"Accept-Language": "ru"}).get_data(as_text=True))
    modern, = page.with_class("vpn-choice-happ")
    assert t("vpn_happ_locked", "ru") in modern["text"]
    assert t("vpn_happ_modes", "ru") not in modern["text"]
    assert 'name="safe_internet"' not in browser().get("/add?client_app=happ").get_data(as_text=True)


@pytest.mark.parametrize("available", [False,True])
def test_official_platform_links_follow_availability_and_separate_legacy_windows(runtime, available):
    if available:
        enable_member(runtime)
    page = DashboardHTML(browser().get("/add").get_data(as_text=True))
    links = {node["attrs"]["href"]: node for node in page.nodes if node["tag"] == "a"}
    assert "https://www.wireguard.com/install/" in links
    for architecture in ("amd64", "x86"):
        link = links[f"https://download.wireguard.com/windows-client/wireguard-{architecture}-0.5.3.msi"]
        assert "Windows 7" in link["text"] and "0.5.3" in link["text"]
    for url in (
        "https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe",
        "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215",
        "https://play.google.com/store/apps/details?id=com.happproxy", "https://happ.info/",
    ):
        assert (url in links) is available
    for url, link in links.items():
        if url.startswith("https://"):
            assert link["attrs"]["target"] == "_blank"
            assert {"noopener", "noreferrer"} <= set(link["attrs"]["rel"].split())


def test_owner_happ_dashboard_link_redirect_and_internal_children_are_private(runtime):
    enable_member(runtime)
    client = browser()
    body = client.get("/dashboard").get_data(as_text=True)
    assert 'href="/device/alice-happ/happ"' in body
    assert 'href="/device/alice-happ/happ/bundle/download"' in body
    assert 'href="/device/alice-transport' not in body
    response = client.get("/device/alice-happ")
    assert response.status_code == 302 and response.location.endswith("/device/alice-happ/happ")
    for owner in ("alice", "operator"):
        internal = browser(owner)
        assert internal.get("/device/alice-transport/download").status_code == 403
        assert internal.get("/device/alice-transport").status_code == 302
    foreign_admin = browser("operator").get("/device/alice-happ")
    assert foreign_admin.status_code == 302
    assert foreign_admin.location.endswith('/device/alice-happ/happ')


def test_closed_account_keeps_existing_happ_device_type_and_hides_only_creation_choice(runtime):
    client = browser()
    dashboard = DashboardHTML(client.get('/dashboard').get_data(as_text=True))
    protocols = [node['text'] for node in dashboard.with_class('device-protocol')]
    assert protocols.count('Happ') == 1 and protocols.count('WireGuard') == 1
    links = {node['attrs'].get('href') for node in dashboard.nodes if node['tag']=='a'}
    assert '/device/alice-happ/happ' in links
    assert '/device/alice-happ/happ/bundle/download' in links
    assert '/device/alice-happ/download' not in links
    assert '/device/alice-transport' not in links
    assert not DashboardHTML(client.get('/add').get_data(as_text=True)).with_class('vpn-choice-happ')


@pytest.mark.parametrize("username", [None, "pending"])
def test_creation_steps_require_an_approved_session(runtime, username):
    client = browser(username)
    response = client.get("/add")
    assert response.status_code == (302 if username is None else 200)
    assert "vpn-choice-card" not in response.get_data(as_text=True)
    assert not runtime.calls


def test_real_rollout_api_controls_member_choice(runtime, monkeypatch):
    monkeypatch.setattr(happ_pilot, "available_for_user", runtime.actual_available)
    monkeypatch.setattr(happ_pilot, "public_enabled", runtime.actual_public)
    monkeypatch.setitem(app.config, "HAPP_ROLLOUT_ENABLED", False)
    client = browser()
    before = DashboardHTML(client.get("/add").get_data(as_text=True))
    assert not before.with_class("vpn-choice-happ")
    assert client.get("/add?client_app=happ").status_code == 403
    monkeypatch.setitem(app.config, "HAPP_ROLLOUT_ENABLED", True)
    after = DashboardHTML(client.get("/add").get_data(as_text=True))
    assert after.with_class("vpn-choice-happ")[0]["tag"] == "a"
    assert client.get("/add?client_app=happ").status_code == 200


def test_member_happ_detail_has_owner_actions_without_admin_or_private_source_links(runtime):
    enable_member(runtime)
    with app.test_request_context("/device/alice-happ/happ"):
        session.update(user="alice", account_id=core.load_users()["alice"]["account_id"],
                       session_version=1, _csrf_token="synthetic-csrf")
        page = render_page(
            "happ_device.html", "happ_title", lang="ru",
            device={"device": "phone", "safe_internet": False}, wg_name="alice-happ", mode="custom",
            modes=[{"id": "custom", "title_key": "happ_mode_custom", "enabled": True}],
            proxy_rules=["domain:example.org"], rules_text="example.org", rules_revision="a" * 64,
            config_json='{"remarks":"synthetic"}', subscription_url="https://vpn.example.org/sub",
            import_url="happ://add/https://vpn.example.org/sub", qr=None, shared_rules=True,
            shared_rules_managed=True, shared_rules_status="current",
            shared_rules_checked="2026-11-13 12:00 UTC", shared_rules_updated="2026-11-13 11:55 UTC",
            shared_rules_revision="a" * 12,
            shared_rules_source_link="https://github.com/example-owner/private-repo/blob/main/routing-domains.txt",
            shared_rules_publication={"status": "error"},
        )
    assert 'class="back-link" href="/dashboard"' in page
    assert 'HAPP · ' + t('happ_pilot_badge','ru') in page
    assert 'href="/admin/' not in page and 'action="/account/happ-rules"' not in page
    assert "private-repo" not in page
    assert 'action="/device/alice-happ/happ/rotate"' in page
    assert 'href="/device/alice-happ/delete/confirm"' in page
