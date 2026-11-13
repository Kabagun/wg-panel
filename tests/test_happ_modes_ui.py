"""Routing diagrams explain one subscription without adding a creation-time mode choice."""

from html import unescape

import pytest
from flask import session
from test_dashboard import DashboardHTML

from wg_panel import account_policy, app, core, happ_pilot
from wg_panel.i18n import t
from wg_panel.ui import render_page


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "USERS_FILE", str(data / "users.json"))
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", True)
    core.save_users({"pilot-member": {"role": "user", "approved": True, "session_version": 1}})
    identity = core.load_users()["pilot-member"]["account_id"]
    monkeypatch.setattr(happ_pilot, "available_for_user", lambda user: user.get("account_id") == identity)
    monkeypatch.setattr(happ_pilot, "public_enabled", lambda: False)
    account_policy.save_account_policies({})


def browser():
    client = app.test_client()
    with client.session_transaction() as state:
        state.update(user="pilot-member", session_version=1, _csrf_token="synthetic-csrf",
                     account_id=core.load_users()["pilot-member"]["account_id"])
    return client


def assert_three_readonly_routes(document, lang):
    guide, = document.with_class("happ-modes-guide")
    cards = document.with_class("happ-mode-card")
    assert len(cards) == 3
    expected_titles = ("happ_mode_all", "happ_mode_by_ru_direct", "happ_mode_custom")
    expected_destinations = (("VPN",), (t("happ_flow_direct", lang), "VPN"),
                             ("VPN", t("happ_flow_direct", lang)))
    for card, title, destinations in zip(cards, expected_titles, expected_destinations, strict=True):
        children = document.within(card)
        heading, = [node for node in children if node["tag"] == "h3"]
        assert heading["text"] == t(title, lang)
        assert heading["attrs"]["id"] == card["attrs"]["aria-labelledby"]
        assert tuple(node["text"] for node in children if node["tag"] == "strong") == destinations
        assert not [node for node in children if node["tag"] in {"input", "select", "button", "a"}]
        assert card["tag"] == "article" and "tabindex" not in card["attrs"]
    assert t("happ_flow_internet", lang) in cards[0]["text"]
    assert t("happ_flow_regional", lang) in cards[1]["text"]
    assert "GeoIP" in cards[1]["text"] and ".by/.ru" in cards[1]["text"]
    assert t("happ_modes_regional_note", lang) in cards[1]["text"]
    assert t("happ_flow_admin_list", lang) in cards[2]["text"]
    return guide


@pytest.mark.parametrize("lang", ["en", "ru"])
@pytest.mark.parametrize("family", [False, True])
def test_selected_happ_explains_all_profiles_before_name_form_without_mode_submission(runtime, lang, family):
    if family:
        account_policy.save_account_policies({"pilot-member": {"safe_internet_locked": True}})
    response = browser().get("/add?client_app=happ", headers={"Accept-Language": lang})
    assert response.status_code == 200
    page = DashboardHTML(response.get_data(as_text=True))
    guide = assert_three_readonly_routes(page, lang)
    form, = [node for node in page.nodes if node["tag"] == "form"
             and node["attrs"].get("action") == "/add"]
    assert page.nodes.index(guide) < page.nodes.index(form)
    fields = {node["attrs"].get("name"): node["attrs"] for node in page.within(form)
              if node["tag"] == "input"}
    assert fields["client_app"]["value"] == "happ"
    assert fields["csrf_token"]["value"] == "synthetic-csrf"
    assert "device" in fields and "mode" not in fields and "transport" not in fields
    # Autofocus would scroll past the explanation to the name field on load.
    assert "autofocus" not in fields["device"]
    assert t("happ_modes_creation_intro", lang) in guide["text"]
    assert t("happ_modes_family_dns" if family else "happ_modes_account_dns", lang) in guide["text"]
    assert t("happ_modes_server_selection", lang) in guide["text"]
    assert "×" not in guide["text"] and "= 9" not in guide["text"]


def test_initial_happ_card_is_summary_only_and_classic_form_has_no_happ_diagram(runtime):
    choice = DashboardHTML(browser().get("/add").get_data(as_text=True))
    assert len(choice.with_class("vpn-choice-happ")) == 1
    assert not choice.with_class("happ-modes-guide")
    classic = DashboardHTML(browser().get("/add?client_app=wireguard").get_data(as_text=True))
    assert not classic.with_class("happ-modes-guide")
    assert any(node["attrs"].get("name") == "device" and "autofocus" in node["attrs"]
               for node in classic.nodes if node["tag"] == "input")


def test_diagram_does_not_change_private_pilot_eligibility(runtime, monkeypatch):
    monkeypatch.setattr(happ_pilot, "available_for_user", lambda _user: False)
    client = browser()
    body = client.get("/add").get_data(as_text=True)
    assert "happ-modes-guide" not in body and "client_app=happ" not in body
    assert client.get("/add?client_app=happ").status_code == 403


@pytest.mark.parametrize("lang", ["en", "ru"])
@pytest.mark.parametrize("family", [False, True])
def test_device_reuses_same_three_profiles_with_dns_independent_of_enabled_routing(runtime, lang, family):
    with app.test_request_context("/device/synthetic-pilot/happ"):
        session.update(user="pilot-member", session_version=1, _csrf_token="synthetic-csrf",
                       account_id=core.load_users()["pilot-member"]["account_id"])
        body = render_page(
            "happ_device.html", "happ_title", lang=lang, wg_name="synthetic-pilot",
            device={"device": "synthetic-phone", "safe_internet": family}, mode="custom",
            modes=[{"id": mode, "title_key": "happ_mode_" + mode.replace("-", "_"), "enabled": True}
                   for mode in ("all", "custom", "by-ru-direct")],
            transport="wireguard", transport_options=[
                {"id": "wireguard", "title": "WireGuard", "available": True}],
            proxy_rules=["domain:example.org"], rules_text="domain:example.org", rules_revision=0,
            config_json='{"remarks":"synthetic-private-config"}', qr=None,
            subscription_url="https://vpn.example.org/sub/synthetic/bundle",
            import_url="happ://add/https://vpn.example.org/sub/synthetic/bundle", shared_rules=False,
        )
    page = DashboardHTML(body)
    guide = assert_three_readonly_routes(page, lang)
    assert t("happ_modes_device_intro", lang) in guide["text"]
    assert t("happ_import_hint", lang) in unescape(body)
    assert t("happ_bundle_server_note", lang) in unescape(body)
    assert t("happ_modes_server_selection", lang) in guide["text"]
    assert t("happ_modes_family_dns" if family else "happ_modes_account_dns", lang) in guide["text"]
    assert not any(node["attrs"].get("name") == "transport" for node in page.nodes)
    assert not page.with_class("happ-transport-list")
    select, = [node for node in page.nodes if node["tag"] == "select"
               and node["attrs"].get("name") == "mode"]
    options = [node for node in page.within(select) if node["tag"] == "option"]
    assert {node["attrs"]["value"] for node in options} == {"all", "custom", "by-ru-direct"}
    assert not any("disabled" in node["attrs"] for node in options)
    assert 'href="/device/synthetic-pilot/happ/bundle/download"' in body
    assert page.with_class("back-link")[0]["attrs"]["href"] == "/dashboard"
    ids = [node["attrs"]["id"] for node in page.nodes if "id" in node["attrs"]]
    assert len(ids) == len(set(ids))
    assert "synthetic-private-config" not in guide["text"]
    assert "happ_modes_" not in unescape(body)
