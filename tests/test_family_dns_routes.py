import re

import pytest
from werkzeug.datastructures import MultiDict

from wg_panel import app, core, family_dns
from wg_panel.i18n import t


@pytest.fixture
def state():
    return family_dns.FamilyDnsState(
        ("example.com",), 4, True, 1700000000,
        family_dns.BackupStatus("updated", 1700000000, 1700000000, "a" * 40, 3),
    )


@pytest.fixture
def runtime(monkeypatch, tmp_path, state):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "USERS_FILE", str(data / "users.json"))
    core.save_users({
        "admin": {"role": "admin", "approved": True},
        "member": {"role": "user", "approved": True},
    })
    app.config.update(TESTING=True)
    calls = []

    def status():
        calls.append(("status",))
        return state

    def change(operation, domain, generation):
        calls.append((operation, domain, generation))
        return state

    monkeypatch.setattr(family_dns, "status", status)
    monkeypatch.setattr(family_dns, "change", change)
    return calls


def authenticated_client(username="admin"):
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session["_csrf_token"] = "synthetic-csrf"
        if username:
            user = core.load_users()[username]
            browser_session.update(
                user=username, account_id=user["account_id"], session_version=1,
            )
    return client


def form(**updates):
    return {"csrf_token": "synthetic-csrf", "domain": "example.com",
            "expected_generation": "4", **updates}


@pytest.mark.parametrize("username,destination", [(None, "/login"), ("member", "/dashboard")])
def test_all_routes_require_an_administrator(runtime, username, destination):
    client = authenticated_client(username)
    responses = [
        client.get("/admin/family-dns"),
        client.post("/admin/family-dns/allow", data=form()),
        client.post("/admin/family-dns/allow/remove", data=form()),
    ]
    assert all(response.status_code == 302 for response in responses)
    assert all(response.location.endswith(destination) for response in responses)
    assert runtime == []


def test_admin_get_is_read_only_and_forms_are_versioned(runtime):
    body = authenticated_client().get("/admin/family-dns").get_data(as_text=True)
    assert runtime == [("status",)]
    assert "example.com" in body
    assert "home internet" in body and "all its subdomains" in body
    assert "Current list applied" in body and "Daily GitHub backup" in body
    assert "14.11.2023 22:13 UTC" in body
    assert "awaiting the next daily backup" in body
    for action in ("/admin/family-dns/allow", "/admin/family-dns/allow/remove"):
        match = re.search(r'<form[^>]*action="' + action + r'"[^>]*>(.*?)</form>', body, re.DOTALL)
        assert match and 'method="post"' in match.group(0)
        assert 'name="csrf_token"' in match.group(1)
        assert 'name="expected_generation" value="4"' in match.group(1)
    assert not re.search(r'name="(?:deny|mode|safe_internet|allow_locked_disable)"', body)
    assert "WG_PANEL_" not in body and "/var/lib" not in body


@pytest.mark.parametrize("endpoint,operation", [("allow", "add"), ("allow/remove", "remove")])
def test_changes_are_post_only_and_use_form_generation(runtime, endpoint, operation):
    client = authenticated_client()
    assert client.get("/admin/family-dns/" + endpoint).status_code == 405
    response = client.post("/admin/family-dns/" + endpoint, data=form())
    assert response.status_code == 303 and response.location.endswith("/admin/family-dns")
    assert runtime == [(operation, "example.com", 4)]
    body = client.get(response.location).get_data(as_text=True)
    assert "shared protection has applied the change" in body


@pytest.mark.parametrize("endpoint", ["allow", "allow/remove"])
def test_global_csrf_and_same_origin_checks_protect_changes(runtime, endpoint):
    client = authenticated_client()
    path = "/admin/family-dns/" + endpoint
    assert client.post(path, data={"domain": "example.com"}).status_code == 400
    assert client.post(path, data=form(csrf_token="wrong")).status_code == 400
    assert client.post(path, data=form(), headers={"Origin": "https://other.example"}).status_code == 400
    assert runtime == []


@pytest.mark.parametrize("generation", ["", "-1", "1.2", "true", " 4", "4\n", "9" * 21])
def test_invalid_generation_never_reaches_helper(runtime, generation):
    client = authenticated_client()
    response = client.post("/admin/family-dns/allow", data=form(expected_generation=generation))
    assert response.status_code == 303 and runtime == []
    assert "list changed after this page" in client.get(response.location).get_data(as_text=True)


@pytest.mark.parametrize("field", ["domain", "expected_generation"])
def test_ambiguous_form_fields_are_rejected(runtime, field):
    client = authenticated_client()
    submitted = MultiDict(form())
    submitted.add(field, "other.example" if field == "domain" else "5")
    assert client.post("/admin/family-dns/allow", data=submitted).status_code == 303
    assert runtime == []


@pytest.mark.parametrize("code", ["stale_generation", "busy", "unavailable", "apply_failed"])
def test_helper_errors_are_localized_without_success_or_retry(runtime, monkeypatch, code):
    calls = []

    def fail(*args):
        calls.append(args)
        raise family_dns.FamilyDnsError(code)

    monkeypatch.setattr(family_dns, "change", fail)
    client = authenticated_client()
    response = client.post("/admin/family-dns/allow", data=form())
    assert len(calls) == 1
    body = client.get(response.location).get_data(as_text=True)
    assert t("family_dns_error_" + code, "en") in body
    assert "shared protection has applied the change" not in body


@pytest.mark.parametrize("code", ["unconfigured", "uninitialized", "unavailable", "degraded"])
def test_unavailable_status_keeps_page_usable_and_disables_editing(runtime, monkeypatch, code):
    def fail():
        raise family_dns.FamilyDnsError(code)

    monkeypatch.setattr(family_dns, "status", fail)
    response = authenticated_client().get("/admin/family-dns")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert t("family_dns_error_" + code, "en") in body
    assert 'name="domain"' not in body


def test_backup_failure_shows_status_and_preserves_editing(runtime, monkeypatch, state):
    failed = family_dns.FamilyDnsState(
        state.domains, state.generation, True, state.applied_at,
        family_dns.BackupStatus("error", 1700001000, 1700000000, "a" * 40),
    )
    monkeypatch.setattr(family_dns, "status", lambda: failed)
    body = authenticated_client().get("/admin/family-dns").get_data(as_text=True)
    assert "Backup delayed" in body and "Current list applied" in body
    assert 'action="/admin/family-dns/allow"' in body


def test_unapplied_status_is_visible(runtime, monkeypatch, state):
    monkeypatch.setattr(family_dns, "status", lambda: family_dns.FamilyDnsState(
        state.domains, state.generation, False, None, state.backup,
    ))
    body = authenticated_client().get("/admin/family-dns").get_data(as_text=True)
    assert "Application needs attention" in body and "has not been confirmed as applied" in body


def test_template_autoescapes_domains(runtime, monkeypatch, state):
    malicious = '<script>alert("x")</script>'
    monkeypatch.setattr(family_dns, "status", lambda: family_dns.FamilyDnsState(
        (malicious,), state.generation, True, state.applied_at, state.backup,
    ))
    body = authenticated_client().get("/admin/family-dns").get_data(as_text=True)
    assert malicious not in body
    assert "&lt;script&gt;" in body and "&#34;x&#34;" in body


def test_russian_copy_and_shared_safe_help(runtime):
    body = authenticated_client().get(
        "/admin/family-dns", headers={"Accept-Language": "ru"},
    ).get_data(as_text=True)
    assert "Исключения семейного DNS" in body
    assert "домашнего интернета" in body and "все его поддомены" in body
    assert "Текущий список применён" in body and "Ежедневная копия в GitHub" in body
    for lang in ("en", "ru"):
        assert "Cloudflare" not in t("safe_help", lang)
        assert "SSH" in t("safe_help", lang)
        assert "family_dns_" not in body


def test_missing_helper_does_not_affect_login_or_dashboard(runtime, monkeypatch):
    monkeypatch.setattr(family_dns, "status", lambda: pytest.fail("helper called"))
    monkeypatch.setattr(family_dns, "change", lambda *_args: pytest.fail("helper called"))
    assert app.test_client().get("/login").status_code == 200
    assert authenticated_client().get("/dashboard").status_code == 200
    member_body = authenticated_client("member").get("/dashboard").get_data(as_text=True)
    assert "/admin/family-dns" not in member_body
