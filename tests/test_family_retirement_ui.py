"""Retired family routes remain dormant while public Smart proposals still work."""
# Imported shared pytest fixtures intentionally shadow test arguments.
# ruff: noqa: F811
import copy

import pytest
from test_request_visibility import (  # noqa: F401
    Page,
    browser,
    form,
    protect,
    runtime,
    visible_requests,
)

from wg_panel import account_policy, app, family_dns_requests, wireguard
from wg_panel.routes import devices, family_dns


@pytest.fixture
def retired(visible_requests, monkeypatch):
    monkeypatch.setitem(app.config, "FAMILY_PROTECTION_ENABLED", False)
    monkeypatch.setattr(devices, "set_account_safe_internet",
                        lambda *_args, **_kwargs: pytest.fail("retired account mutation"))
    monkeypatch.setattr(family_dns.family_dns_requests, "review",
                        lambda *_args, **_kwargs: pytest.fail("retired DNS review"))
    return visible_requests


@pytest.mark.parametrize("username", [None, "operator", "member"])
def test_retired_family_get_routes_are_unavailable_for_every_role(retired, username):
    client = browser(username)
    for path in ("/family-dns/requests", "/admin/family-dns"):
        assert client.get(path).status_code == 404


@pytest.mark.parametrize("username", [None, "operator", "member"])
def test_retired_family_post_routes_never_mutate_policy_or_requests(retired, username):
    protect(retired, "account_lock")
    before = copy.deepcopy(account_policy.load_account_policies())
    client = browser(username)
    for path in (
        "/family-dns/requests", "/admin/family-dns/allow",
        "/admin/family-dns/allow/remove", "/admin/family-dns/requests/synthetic/approve",
        "/admin/family-dns/requests/synthetic/reject", "/account/safe-internet",
        "/device/synthetic-member-legacy-phone/safe-internet",
    ):
        assert client.post(path, data={**form(), "safe_internet": "on",
                                       "safe_internet_confirmed": "on"}).status_code == 404
    assert account_policy.load_account_policies() == before
    assert family_dns_requests.list_requests() == []
    assert retired.notifications == []


@pytest.mark.parametrize("source", ["account_lock", "legacy_device"])
def test_formerly_protected_account_keeps_smart_proposals_without_dns_exposure(retired, source):
    protect(retired, source)
    client = browser("member")
    response = client.get("/happ/requests")
    page = Page(response)
    assert response.status_code == 200 and page.domain_form
    assert "/happ/requests" in page.nav_links
    assert "/family-dns/requests" not in page.nav_links
    assert "/admin/family-dns" not in page.nav_links
    assert client.post("/happ/requests", data=form()).status_code == 303
    assert len(family_dns_requests.list_requests(kind="smart")) == 1
    assert family_dns_requests.list_requests() == []


def test_retired_navigation_never_reads_legacy_family_policy(retired, monkeypatch):
    monkeypatch.setattr(family_dns, "_family_protection",
                        lambda *_args: pytest.fail("retired navigation read family policy"))
    monkeypatch.setattr(wireguard, "get_user_devices", lambda _username: [])
    for username in ("operator", "member"):
        response = browser(username).get("/dashboard")
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        for retired_control in ("/family-dns", "/account/safe-internet",
                                "protection-settings", "device-protection"):
            assert retired_control not in body
