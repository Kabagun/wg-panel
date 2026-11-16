"""Public Smart proposals and protection-only DNS proposals have distinct access."""
# Imported shared pytest fixtures intentionally shadow test arguments.
# ruff: noqa: F811
import copy
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_happ_rules_routes import CSRF, browser, runtime  # noqa: F401

from wg_panel import account_policy, core, family_dns, family_dns_requests, security, wireguard
from wg_panel import family_dns_notifications as notices
from wg_panel.routes import family_dns as dns_pages
from wg_panel.routes import happ_rules as smart_pages


class Page(HTMLParser):
    def __init__(self, response):
        super().__init__()
        self.nav_links = set()
        self.domain_form = False
        self.in_form = False
        self.feed(response.get_data(as_text=True))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "nav-link" in attrs.get("class", "").split():
            self.nav_links.add(attrs.get("href"))
        if tag == "form":
            self.in_form = True
        if tag == "input" and self.in_form and attrs.get("name") == "domain":
            self.domain_form = True

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False


@pytest.fixture
def visible_requests(runtime, monkeypatch):
    from wg_panel import app

    # This module covers archived family access distinctions on explicit restore.
    monkeypatch.setitem(app.config, "FAMILY_PROTECTION_ENABLED", True)
    monkeypatch.setitem(app.config, "HAPP_ROLLOUT_ENABLED", True)
    core.mutate_users(lambda users: users.update({
        "newcomer": {"role": "user", "approved": True, "session_version": 1},
    }))
    account_policy.save_account_policies({})
    devices, records, notifications = {}, {}, []
    monkeypatch.setattr(wireguard, "get_user_devices", lambda username: list(devices.get(username, [])))
    monkeypatch.setattr(wireguard, "client_name", lambda username, name: f"synthetic-{username}-{name}")
    monkeypatch.setattr(wireguard, "get_device", lambda name: copy.deepcopy(records.get(name)))
    monkeypatch.setattr(dns_pages, "public_rate_limiter", security.WindowRateLimiter())
    monkeypatch.setattr(smart_pages, "public_rate_limiter", security.WindowRateLimiter())

    def notify(record, *, kind="dns"):
        notifications.append((kind, copy.deepcopy(record)))
        return True

    def forbid_dns(*_args):
        pytest.fail("Proposal visibility and submission must not read or mutate DNS")

    monkeypatch.setattr(notices, "notify_request", notify)
    monkeypatch.setattr(family_dns, "status", forbid_dns)
    monkeypatch.setattr(family_dns, "change", forbid_dns)
    return SimpleNamespace(devices=devices, records=records, notifications=notifications,
                           managed_runtime=runtime)


def form(*, reason="Synthetic proposal", domain="shared.example.org"):
    return {"csrf_token": CSRF, "domain": domain, "reason": reason}


def protect(state, source, username="member"):
    if source == "account_lock":
        account_policy.save_account_policies({username: {"safe_internet_locked": True}})
    else:
        state.devices[username] = ["legacy-phone"]
        state.records[f"synthetic-{username}-legacy-phone"] = {
            "owner": username, "safe_internet": True,
        }


@pytest.mark.parametrize("username", ["member", "newcomer"])
def test_public_rollout_nonfamily_user_can_propose_smart_without_dns_nav_or_form(
        visible_requests, username):
    client = browser(username)
    smart = client.get("/happ/requests")
    assert smart.status_code == 200
    smart_page = Page(smart)
    assert "/happ/requests" in smart_page.nav_links and smart_page.domain_form
    assert "/family-dns/requests" not in smart_page.nav_links

    dns = client.get("/family-dns/requests")
    assert dns.status_code == 200
    dns_page = Page(dns)
    assert not dns_page.domain_form and "/family-dns/requests" not in dns_page.nav_links
    assert client.post("/family-dns/requests", data=form()).status_code == 403

    submitted = client.post("/happ/requests", data=form())
    assert submitted.status_code == 303 and submitted.location.endswith("/happ/requests")
    account = core.load_users()[username]["account_id"]
    smart_records = family_dns_requests.list_requests(account, kind="smart")
    assert len(smart_records) == 1 and smart_records[0]["status"] == "pending"
    assert family_dns_requests.list_requests() == []
    assert [kind for kind, _ in visible_requests.notifications] == ["smart"]
    assert visible_requests.managed_runtime.queued == []


@pytest.mark.parametrize("source", ["account_lock", "legacy_device"])
def test_family_user_has_both_links_and_forms_and_independent_request_namespaces(
        visible_requests, source):
    protect(visible_requests, source)
    client = browser("member")
    for path in ("/happ/requests", "/family-dns/requests"):
        response = client.get(path)
        assert response.status_code == 200
        page = Page(response)
        assert {"/happ/requests", "/family-dns/requests"} <= page.nav_links
        assert page.domain_form

    assert client.post("/happ/requests", data=form(reason="Smart-only proposal")).status_code == 303
    assert client.post("/family-dns/requests", data=form(reason="DNS-only proposal")).status_code == 303
    account = core.load_users()["member"]["account_id"]
    smart = family_dns_requests.list_requests(account, kind="smart")
    dns = family_dns_requests.list_requests(account)
    assert len(smart) == len(dns) == 1
    assert smart[0]["domain"] == dns[0]["domain"] == "shared.example.org"
    assert smart[0]["id"] != dns[0]["id"]
    assert smart[0]["reason"] == "Smart-only proposal" and dns[0]["reason"] == "DNS-only proposal"
    assert [kind for kind, _ in visible_requests.notifications] == ["smart", "dns"]
    smart_body = client.get("/happ/requests").get_data(as_text=True)
    dns_body = client.get("/family-dns/requests").get_data(as_text=True)
    assert "Smart-only proposal" in smart_body and "DNS-only proposal" not in smart_body
    assert "DNS-only proposal" in dns_body and "Smart-only proposal" not in dns_body
    assert visible_requests.managed_runtime.queued == []


@pytest.mark.parametrize("state", ["anonymous", "unapproved", "paused"])
@pytest.mark.parametrize("path", ["/happ/requests", "/family-dns/requests"])
def test_anonymous_unapproved_and_paused_users_cannot_submit_either_kind(
        visible_requests, state, path):
    protect(visible_requests, "account_lock")
    if state != "anonymous":
        update = {"approved": False} if state == "unapproved" else {"paused": True}
        core.mutate_users(lambda users: users["member"].update(update))
    client = browser(None if state == "anonymous" else "member")
    response = client.post(path, data=form())
    if state == "anonymous":
        assert response.status_code == 302 and response.location.endswith("/login")
    elif state == "paused":
        assert response.status_code == 302 and response.location.endswith("/dashboard")
    else:
        assert response.status_code == 200
        page = Page(response)
        assert not page.domain_form and not page.nav_links
    assert family_dns_requests.list_requests() == []
    assert family_dns_requests.list_requests(kind="smart") == []
    assert visible_requests.notifications == []


@pytest.mark.parametrize("flag", ["paused", "pause_pending", "revoking"])
def test_inactive_family_account_does_not_advertise_request_navigation(visible_requests, flag):
    protect(visible_requests, "account_lock")
    core.mutate_users(lambda users: users["member"].update({flag: True}))
    response = browser("member").get("/family-dns/requests")
    page = Page(response)
    assert "/family-dns/requests" not in page.nav_links
    assert "/happ/requests" not in page.nav_links


def test_internal_family_transport_does_not_grant_dns_proposal_visibility(visible_requests):
    protect(visible_requests, "legacy_device")
    visible_requests.records["synthetic-member-legacy-phone"]["happ_transport_internal"] = True
    client = browser("member")
    page = Page(client.get("/happ/requests"))
    assert "/happ/requests" in page.nav_links and page.domain_form
    assert "/family-dns/requests" not in page.nav_links
    assert client.post("/family-dns/requests", data=form()).status_code == 403


def test_corrupt_family_policy_hides_dns_link_without_disabling_smart_proposals(visible_requests):
    Path(account_policy.account_policy_path()).write_text("{invalid", encoding="utf-8")
    client = browser("member")
    response = client.get("/happ/requests")
    assert response.status_code == 200
    page = Page(response)
    assert "/family-dns/requests" not in page.nav_links
    assert "/happ/requests" in page.nav_links and page.domain_form
    assert client.post("/happ/requests", data=form()).status_code == 303
    assert len(family_dns_requests.list_requests(kind="smart")) == 1
    assert family_dns_requests.list_requests() == []


def test_unreadable_legacy_device_state_hides_dns_link_without_disabling_smart(
        visible_requests, monkeypatch):
    def unavailable(_username):
        raise OSError("Synthetic unavailable device state")

    monkeypatch.setattr(wireguard, "get_user_devices", unavailable)
    response = browser("member").get("/happ/requests")
    assert response.status_code == 200
    page = Page(response)
    assert "/family-dns/requests" not in page.nav_links
    assert "/happ/requests" in page.nav_links and page.domain_form


def test_administrator_uses_admin_navigation_instead_of_personal_request_links(visible_requests):
    protect(visible_requests, "account_lock", username="operator")
    response = browser("operator").get("/admin/happ-rules")
    assert response.status_code == 200
    page = Page(response)
    assert {"/admin/happ-rules", "/admin/family-dns"} <= page.nav_links
    assert "/family-dns/requests" not in page.nav_links
    assert "/happ/requests" not in page.nav_links


def test_nonmanaged_smart_list_hides_smart_link_without_hiding_family_dns(
        visible_requests, monkeypatch):
    from wg_panel import happ_shared_rules

    protect(visible_requests, "account_lock")
    monkeypatch.setattr(happ_shared_rules, "managed_mode", lambda: False)
    client = browser("member")
    page = Page(client.get("/family-dns/requests"))
    assert "/family-dns/requests" in page.nav_links and page.domain_form
    assert "/happ/requests" not in page.nav_links
    assert client.post("/happ/requests", data=form()).status_code == 404
