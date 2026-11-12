"""Managed Happ list routes isolate active changes from Git publication."""

import copy
import hashlib
import re
import subprocess
from html import unescape
from types import SimpleNamespace

import pytest
from flask import session
from werkzeug.datastructures import MultiDict

from wg_panel import app, core, happ_pilot, happ_shared_rules
from wg_panel.i18n import t
from wg_panel.routes import happ_rules as routes
from wg_panel.ui import render_page

SOURCE = "https://raw.githubusercontent.com/example-owner/example-repo/main/routing-domains.txt"
CSRF = "synthetic-csrf"


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "USERS_FILE", str(data / "users.json"))
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", True)
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_MANAGED", "1")
    core.save_users({
        "operator": {"role": "admin", "approved": True, "session_version": 1},
        "member": {"role": "user", "approved": True, "session_version": 1},
        "pending": {"role": "admin", "approved": False, "session_version": 1},
    })
    snapshot = {
        "rules": ["domain:example.org", "domain:example.net"], "revision": "a" * 64,
        "last_checked": "2026-11-12T12:00:00Z", "last_success": "2026-11-12T11:55:00Z",
        "error": "",
    }
    publication = {
        "status": "updated", "last_attempt_at": "2026-11-12T11:56:00Z",
        "last_success_at": "2026-11-12T11:56:00Z", "commit": "c" * 40,
        "published_revision": snapshot["revision"],
    }
    calls = []
    queued = []
    state = SimpleNamespace(snapshot=snapshot, publication=publication, calls=calls, queued=queued)
    monkeypatch.setattr(happ_pilot, "shared_rules_url", lambda: SOURCE)
    monkeypatch.setattr(happ_shared_rules, "managed_mode", lambda: True, raising=False)

    def load(data_dir, source):
        assert data_dir == str(data) and source == SOURCE
        calls.append(("load",))
        return copy.deepcopy(snapshot)

    def status(data_dir, revision):
        assert data_dir == str(data)
        calls.append(("publication", revision))
        result = copy.deepcopy(publication)
        if result["status"] in {"updated", "unchanged"} and result["published_revision"] != revision:
            result["status"] = "pending"
        return result

    def change(data_dir, source, operation, domain, revision):
        assert data_dir == str(data) and source == SOURCE
        calls.append(("change", operation, domain, revision))
        if revision != snapshot["revision"]:
            raise ValueError("stale_revision")
        canonical = domain.strip().lower()
        if not re.fullmatch(r"[a-z0-9.-]+\.(?:org|net|com)", canonical):
            raise ValueError("invalid_domain")
        key = "domain:" + canonical
        values = list(snapshot["rules"])
        if operation == "add" and key not in values:
            values.append(key)
        elif operation == "remove" and key in values:
            values.remove(key)
        if values != snapshot["rules"]:
            snapshot["rules"] = values
            snapshot["revision"] = hashlib.sha256("\n".join(values).encode()).hexdigest()
            snapshot["last_success"] = "2026-11-12T12:05:00Z"
        return copy.deepcopy(snapshot)

    def enqueue(command, **kwargs):
        assert command == ["systemctl", "--no-block", "start", "wg-panel-happ-publish.service"]
        assert kwargs == {"capture_output": True, "timeout": 5, "check": False}
        queued.append(tuple(command))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(happ_shared_rules, "load_snapshot", load)
    monkeypatch.setattr(happ_shared_rules, "publication_status", status, raising=False)
    monkeypatch.setattr(happ_shared_rules, "change", change, raising=False)
    monkeypatch.setattr(routes.subprocess, "run", enqueue)
    return state


def browser(username="operator"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["_csrf_token"] = CSRF
        if username:
            session.update(user=username, account_id=core.load_users()[username]["account_id"],
                           session_version=1)
    return client


def form(**updates):
    return {"csrf_token": CSRF, "domain": "new.example.org", "revision": "a" * 64, **updates}


@pytest.mark.parametrize("username,destination", [(None, "/login"), ("member", "/dashboard")])
def test_managed_list_requires_an_administrator_before_read_or_change(runtime, username, destination):
    client = browser(username)
    responses = [client.get("/admin/happ-rules")]
    responses += [client.post("/admin/happ-rules/" + operation, data=form())
                  for operation in ("add", "remove")]
    assert all(response.status_code == 302 and response.location.endswith(destination)
               for response in responses)
    assert not runtime.calls and not runtime.queued


def test_unapproved_administrator_cannot_read_or_change_the_list(runtime):
    client = browser("pending")
    for response in (client.get("/admin/happ-rules"),
                     client.post("/admin/happ-rules/add", data=form())):
        assert response.status_code == 200
        assert 'name="domain"' not in response.get_data(as_text=True)
    assert not runtime.calls and not runtime.queued


@pytest.mark.parametrize("gate", ["pilot", "managed"])
def test_managed_editor_requires_both_feature_gates(runtime, monkeypatch, gate):
    if gate == "pilot":
        monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", False)
    else:
        monkeypatch.setattr(happ_shared_rules, "managed_mode", lambda: False)
    client = browser()
    for response in (client.get("/admin/happ-rules"),
                     client.post("/admin/happ-rules/add", data=form()),
                     client.post("/admin/happ-rules/remove", data=form())):
        assert response.status_code == 404
    assert not runtime.calls and not runtime.queued


def test_get_reads_status_and_renders_versioned_forms_without_mutation(runtime):
    before = copy.deepcopy(runtime.snapshot)
    response = browser().get("/admin/happ-rules")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert runtime.calls == [("load",), ("publication", "a" * 64)]
    assert not runtime.queued and runtime.snapshot == before
    assert "example.org" in body and "example.net" in body
    assert "12.11.2026 11:55 UTC" in body and "12.11.2026 11:56 UTC" in body
    assert t("happ_admin_applied", "en") in body
    assert t("happ_admin_publication_updated", "en") in body
    for action in ("add", "remove"):
        match = re.search(r'<form[^>]*action="/admin/happ-rules/' + action +
                          r'"[^>]*>(.*?)</form>', body, re.DOTALL)
        assert match and 'method="post"' in match[0]
        assert 'name="csrf_token"' in match[1]
        assert 'name="revision" value="' + "a" * 64 + '"' in match[1]
    assert re.search(r'data-confirm="[^"]*example.org', body)
    assert "WG_PANEL_" not in body and "/var/lib" not in body and "systemctl" not in body


def test_managed_admin_navigation_is_visible_on_its_page(runtime):
    body = browser().get("/admin/happ-rules").get_data(as_text=True)
    assert re.search(r'<a class="nav-link active" href="/admin/happ-rules" aria-current="page">', body)


@pytest.mark.parametrize("operation,domain", [("add", "new.example.org"), ("remove", "example.org")])
def test_changed_list_is_active_before_async_publication(runtime, operation, domain):
    client = browser()
    assert client.get("/admin/happ-rules/" + operation).status_code == 405
    response = client.post("/admin/happ-rules/" + operation, data=form(domain=domain))
    assert response.status_code == 303 and response.location.endswith("/admin/happ-rules")
    assert runtime.calls == [("load",), ("change", operation, domain, "a" * 64)]
    assert len(runtime.queued) == 1
    assert runtime.snapshot["revision"] != "a" * 64
    assert ("domain:" + domain in runtime.snapshot["rules"]) == (operation == "add")
    body = client.get(response.location).get_data(as_text=True)
    assert t("happ_admin_applied", "en") in body
    assert t("happ_admin_publication_pending", "en") in body


@pytest.mark.parametrize("operation,domain", [("add", "example.org"), ("remove", "absent.example.org")])
def test_noop_change_does_not_queue_publication(runtime, operation, domain):
    assert browser().post("/admin/happ-rules/" + operation, data=form(domain=domain)).status_code == 303
    assert runtime.snapshot["revision"] == "a" * 64
    assert not runtime.queued


@pytest.mark.parametrize("operation", ["add", "remove"])
def test_csrf_and_origin_validation_precede_backend_changes(runtime, operation):
    client = browser()
    path = "/admin/happ-rules/" + operation
    assert client.post(path, data={"domain": "example.org"}).status_code == 400
    assert client.post(path, data=form(csrf_token="wrong")).status_code == 400
    assert client.post(path, data=form(), headers={"Origin": "https://other.example.org"}).status_code == 400
    assert not runtime.calls and not runtime.queued


@pytest.mark.parametrize("revision", ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 64 + "\n"])
def test_invalid_revision_is_rejected_before_state_access(runtime, revision):
    assert browser().post("/admin/happ-rules/add", data=form(revision=revision)).status_code == 303
    assert not runtime.calls and not runtime.queued


@pytest.mark.parametrize("field", ["domain", "revision", "csrf_token"])
def test_duplicate_form_values_cannot_reach_change(runtime, field):
    submitted = MultiDict(form())
    submitted.add(field, submitted[field])
    assert browser().post("/admin/happ-rules/add", data=submitted).status_code == 303
    assert not runtime.calls and not runtime.queued


@pytest.mark.parametrize("domain", ["", "a" * 254])
def test_domain_input_is_bounded_before_backend_access(runtime, domain):
    assert browser().post("/admin/happ-rules/add", data=form(domain=domain)).status_code == 303
    assert not runtime.calls and not runtime.queued


@pytest.mark.parametrize("code", ["stale_revision", "invalid_domain", "unavailable",
                                "raw synthetic Git stderr must stay private"])
def test_change_failures_never_publish_or_expose_raw_errors(runtime, monkeypatch, code):
    before = copy.deepcopy(runtime.snapshot)

    def fail(*_args):
        raise ValueError(code)

    monkeypatch.setattr(happ_shared_rules, "change", fail)
    client = browser()
    response = client.post("/admin/happ-rules/add", data=form())
    assert response.status_code == 303
    assert runtime.snapshot == before and not runtime.queued
    body = client.get(response.location).get_data(as_text=True)
    expected = code if code in {"stale_revision", "invalid_domain", "unavailable"} else "unavailable"
    assert t("happ_admin_error_" + expected, "en") in body
    assert "raw synthetic Git stderr" not in body


@pytest.mark.parametrize("failure", ["nonzero", "missing", "timeout"])
def test_failed_queue_keeps_saved_list_and_shows_retry_without_raw_output(runtime, monkeypatch, failure):
    def queue(*_args, **_kwargs):
        if failure == "missing":
            raise OSError("synthetic private system path")
        if failure == "timeout":
            raise subprocess.TimeoutExpired("systemctl", 5, stderr=b"synthetic private stderr")
        return SimpleNamespace(returncode=1, stderr=b"synthetic private stderr")

    monkeypatch.setattr(routes.subprocess, "run", queue)
    client = browser()
    response = client.post("/admin/happ-rules/add", data=form())
    assert response.status_code == 303
    assert "domain:new.example.org" in runtime.snapshot["rules"]
    body = client.get(response.location).get_data(as_text=True)
    assert t("happ_admin_added", "en") in body and t("happ_admin_queue_delayed", "en") in body
    assert "synthetic private" not in body


def test_git_failure_does_not_disable_active_list_or_editing(runtime):
    runtime.publication["status"] = "error"
    body = browser().get("/admin/happ-rules").get_data(as_text=True)
    assert t("happ_admin_publication_error", "en") in body
    assert t("happ_admin_applied", "en") in body
    assert 'action="/admin/happ-rules/add"' in body
    assert t("happ_admin_publication_independent", "en") in body


def test_unavailable_active_list_returns_localized_503_without_edit_form(runtime, monkeypatch):
    def unavailable(*_args):
        raise ValueError("synthetic private path")

    monkeypatch.setattr(happ_shared_rules, "load_snapshot", unavailable)
    response = browser().get("/admin/happ-rules")
    body = response.get_data(as_text=True)
    assert response.status_code == 503
    assert t("happ_admin_error_unavailable", "en") in body
    assert 'name="domain"' not in body and "synthetic private path" not in body
    assert not runtime.queued


def test_russian_copy_and_autoescaped_domain_confirmation(runtime):
    runtime.snapshot["rules"] = ['domain:<script>synthetic("x")</script>']
    body = browser().get("/admin/happ-rules", headers={"Accept-Language": "ru"}).get_data(as_text=True)
    assert "Умный VPN" in body and "Публикация в GitHub" in body
    assert '<script>synthetic("x")</script>' not in body
    assert "&lt;script&gt;" in body and "&#34;x&#34;" in body
    assert "happ_admin_" not in body


@pytest.mark.parametrize("managed", [False, True])
@pytest.mark.parametrize("lang", ["en", "ru"])
def test_shared_device_panel_distinguishes_site_managed_list_from_legacy_github_source(
    runtime, monkeypatch, managed, lang,
):
    monkeypatch.setattr(happ_shared_rules, "managed_mode", lambda: managed)
    with app.test_request_context("/device/synthetic-pilot/happ"):
        session.update(user="operator", account_id=core.load_users()["operator"]["account_id"],
                       session_version=1, _csrf_token=CSRF)
        page = render_page(
            "happ_device.html", "happ_title", lang=lang,
            device={"device": "synthetic-pilot", "safe_internet": False},
            wg_name="synthetic-pilot", mode="custom",
            modes=[{"id": "custom", "title_key": "happ_mode_custom", "enabled": True}],
            proxy_rules=["domain:example.org"], rules_text="example.org", rules_revision="a" * 64,
            config_json='{"remarks":"synthetic"}', subscription_url="https://vpn.example.org/sub",
            import_url="happ://add/https://vpn.example.org/sub", qr=None,
            shared_rules=True, shared_rules_managed=managed, shared_rules_status="current",
            shared_rules_checked="2026-11-12 12:00 UTC", shared_rules_updated="2026-11-12 11:55 UTC",
            shared_rules_revision="a" * 12,
            shared_rules_source_link="https://github.com/example-owner/example-repo/blob/main/routing-domains.txt",
            shared_rules_publication={"status": "error"},
        )
    panel = re.search(r'<section class="panel happ-rules-panel".*?</section>', page, re.DOTALL)[0]
    assert "<form" not in panel and "<textarea" not in panel
    assert t("happ_shared_current", lang) in unescape(panel)
    if managed:
        assert 'href="/admin/happ-rules"' in panel
        assert t("happ_admin_site_edit", lang) in unescape(panel)
        assert t("happ_admin_publication_error", lang) in unescape(panel)
        assert t("happ_shared_edit", lang) not in unescape(panel)
        assert t("happ_shared_checked", lang) not in unescape(panel)
    else:
        assert 'href="/admin/happ-rules"' not in panel
        assert t("happ_shared_edit", lang) in unescape(panel)
