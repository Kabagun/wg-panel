"""Independent Smart VPN proposals reuse approval guards without touching DNS."""

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from wg_panel import core, family_dns, happ_pilot, happ_shared_rules
from wg_panel import family_dns_requests as requests

ACCOUNT = "a" * 64
OTHER_ACCOUNT = "b" * 64
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    users = {
        "member": {"account_id": ACCOUNT, "approved": True, "safe_internet": False},
        "other": {"account_id": OTHER_ACCOUNT, "approved": True},
    }
    data = tmp_path / "data"
    clock, normalizations, calls, dns_calls, mutations = [NOW], [], [], [], []
    applied = set()
    actual_normalize = happ_shared_rules.normalize_domain
    actual_apply = happ_shared_rules.apply_proposed_domain

    def normalize(value):
        normalizations.append(value)
        return actual_normalize(value)

    def apply(domain):
        calls.append(domain)
        if domain not in applied:
            mutations.append(domain)
            applied.add(domain)

    def forbidden_dns(*args):
        dns_calls.append(args)
        raise AssertionError("Smart proposals must not invoke DNS")

    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "load_users", lambda: copy.deepcopy(users))
    monkeypatch.setattr(requests, "_now", lambda: clock[0])
    monkeypatch.setattr(happ_shared_rules, "normalize_domain", normalize)
    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", apply)
    monkeypatch.setattr(family_dns, "status", forbidden_dns)
    monkeypatch.setattr(family_dns, "change", forbidden_dns)
    return SimpleNamespace(users=users, data=data, clock=clock, calls=calls, dns_calls=dns_calls,
                           normalizations=normalizations, applied=applied, mutations=mutations,
                           apply=apply, actual_apply=actual_apply, path=data / "smart_vpn_requests.json",
                           dns_path=data / "family_dns_requests.json")


def submit(domain="example.com", **kwargs):
    return requests.submit("member", ACCOUNT, domain, kind="smart", **kwargs)


def approve(record, reviewer="admin"):
    return requests.review(record["id"], "approve", reviewer, kind="smart")


def assert_error(code, function, *args, **kwargs):
    with pytest.raises(requests.RequestError) as failure:
        function(*args, **kwargs)
    assert failure.value.code == code
    assert str(failure.value) == code


def test_ordinary_nonfamily_account_can_submit_normalized_smart_proposal_without_any_mutation(runtime):
    record, created = submit("  ПРИМЕР.РФ.  ", reason="First line\nSecond\tline")
    assert created and runtime.users["member"]["safe_internet"] is False
    assert record["domain"] == "xn--e1afmkfd.xn--p1ai"
    assert record["reason"] == "First line Second line"
    assert record["status"] == "pending"
    assert "  ПРИМЕР.РФ.  " in runtime.normalizations
    assert requests.list_requests(kind="smart") == [record]
    assert runtime.calls == runtime.dns_calls == runtime.mutations == []
    assert not runtime.dns_path.exists()
    assert runtime.path.exists()


def test_duplicate_smart_proposal_returns_original_without_changing_file(runtime):
    record, _ = submit(reason="Original")
    before = runtime.path.read_bytes()
    duplicate, created = submit("EXAMPLE.COM.", reason="New reason")
    assert duplicate == record and created is False
    assert runtime.path.read_bytes() == before
    assert runtime.calls == runtime.dns_calls == []


@pytest.mark.family_archive
def test_smart_store_has_exact_existing_record_schema_and_does_not_modify_dns_file(runtime):
    dns, _ = requests.submit("member", ACCOUNT, "dns.example.com")
    before = runtime.dns_path.read_bytes()
    smart, _ = submit("smart.example.com")
    assert set(smart) == set(dns)
    assert "kind" not in smart
    assert json.loads(runtime.path.read_text(encoding="utf-8")) == {
        "version": 1, "requests": [smart]}
    assert requests.list_requests() == [dns]
    assert requests.list_requests(kind="smart") == [smart]
    assert approve(smart)["status"] == "approved"
    assert runtime.dns_path.read_bytes() == before
    assert (runtime.data / "family_dns_requests.json.lock").exists()
    assert (runtime.data / "smart_vpn_requests.json.lock").exists()


@pytest.mark.family_archive
def test_smart_and_dns_ids_are_resolved_only_in_selected_namespace(runtime):
    smart, _ = submit()
    assert_error("not_found", requests.review, smart["id"], "approve", "admin")
    dns, _ = requests.submit("member", ACCOUNT, "dns.example.com")
    assert_error("not_found", requests.review, dns["id"], "approve", "admin", kind="smart")
    assert runtime.calls == runtime.dns_calls == []
    assert requests.list_requests()[0]["status"] == "pending"
    assert requests.list_requests(kind="smart")[0]["status"] == "pending"


@pytest.mark.family_archive
def test_even_equal_ids_in_both_namespaces_cannot_change_the_other_record(runtime, monkeypatch):
    monkeypatch.setattr(requests.secrets, "token_hex", lambda length: "c" * (length * 2))
    dns, _ = requests.submit("member", ACCOUNT, "dns.example.com")
    smart, _ = submit("smart.example.com")
    assert smart["id"] == dns["id"]
    assert approve(smart)["status"] == "approved"
    assert requests.list_requests() == [dns]
    assert runtime.calls == ["smart.example.com"]
    requests.review(dns["id"], "reject", "admin")
    assert requests.list_requests()[0]["status"] == "rejected"
    assert requests.list_requests(kind="smart")[0]["status"] == "approved"
    assert runtime.dns_calls == []


def test_smart_approval_only_calls_managed_list_adapter_and_terminal_callback_is_idempotent(runtime):
    record, _ = submit()
    result = approve(record)
    assert result["status"] == "approved" and result["reviewer"] == "admin"
    assert result["reviewed_at"] == "2026-11-15T12:00:00.000000Z"
    assert result["claim"] is result["lease_until"] is None
    runtime.clock[0] += timedelta(seconds=10)
    assert approve(record, reviewer="another-admin") == result
    assert runtime.calls == runtime.mutations == ["example.com"]
    assert runtime.dns_calls == []
    assert_error("conflict", requests.review, record["id"], "reject", "admin", kind="smart")


def test_request_approval_integrates_with_real_managed_list_adapter_and_enqueues_publication(
        runtime, monkeypatch):
    snapshot = {"rules": [], "revision": "c" * 64}
    changes, publications = [], []

    def change(data_dir, source, operation, domain, revision):
        changes.append((data_dir, source, operation, domain, revision))
        snapshot["rules"] = ["domain:" + domain]
        snapshot["revision"] = "d" * 64
        return copy.deepcopy(snapshot)

    monkeypatch.setenv("WG_PANEL_HAPP_RULES_MANAGED", "1")
    monkeypatch.setattr(happ_pilot, "pilot_enabled", lambda: True)
    monkeypatch.setattr(happ_pilot, "shared_rules_url", lambda: "https://rules.example.com/list.txt")
    monkeypatch.setattr(happ_shared_rules, "load_snapshot", lambda *_: copy.deepcopy(snapshot))
    monkeypatch.setattr(happ_shared_rules, "change", change)
    monkeypatch.setattr(happ_shared_rules, "enqueue_publication", lambda: publications.append(True))
    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", runtime.actual_apply)
    record, _ = submit()
    assert approve(record)["status"] == "approved"
    assert changes == [(str(runtime.data), "https://rules.example.com/list.txt", "add", "example.com",
                        "c" * 64)]
    assert publications == [True] and runtime.dns_calls == []


def test_smart_rejection_never_calls_any_apply_adapter(runtime):
    record, _ = submit()
    result = requests.review(record["id"], "reject", "admin", kind="smart")
    assert result["status"] == "rejected"
    assert requests.review(record["id"], "reject", "other-admin", kind="smart") == result
    assert_error("conflict", approve, record)
    assert runtime.calls == runtime.dns_calls == []


@pytest.mark.parametrize("error,code", [
    (ValueError("invalid_domain"), "invalid_domain"),
    (ValueError("stale_revision"), "busy"),
    (ValueError("unavailable"), "unavailable"),
    (ValueError("private-secret"), "unavailable"),
    (OSError("private-path"), "unavailable"),
    (RuntimeError("private-failure"), "unavailable"),
])
def test_smart_apply_failures_are_stable_generic_and_leave_pending_requests(runtime, monkeypatch,
                                                                          error, code):
    record, _ = submit()

    def fail(domain):
        runtime.calls.append(domain)
        raise error

    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", fail)
    assert_error(code, approve, record)
    saved = requests.list_requests(kind="smart")[0]
    assert saved["status"] == "pending"
    assert saved["reviewer"] is saved["reviewed_at"] is saved["claim"] is saved["lease_until"] is None
    assert runtime.calls == ["example.com"] and runtime.dns_calls == []


def test_uncertain_smart_success_retries_idempotent_adapter_and_only_applies_once(runtime, monkeypatch):
    record, _ = submit()

    def uncertain(domain):
        runtime.apply(domain)
        raise OSError("response interrupted")

    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", uncertain)
    assert_error("unavailable", approve, record)
    assert requests.list_requests(kind="smart")[0]["status"] == "pending"
    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", runtime.apply)
    assert approve(record)["status"] == "approved"
    assert runtime.calls == ["example.com", "example.com"]
    assert runtime.mutations == ["example.com"] and runtime.dns_calls == []


@pytest.mark.parametrize("domain", [None, [], "https://example.com", "*.example.com",
                                    "127.0.0.1", "site.internal"])
def test_smart_submission_uses_smart_domain_validation(runtime, domain):
    assert_error("invalid_domain", submit, domain)
    assert not runtime.path.exists() and runtime.calls == runtime.dns_calls == []


@pytest.mark.parametrize("error,code", [(ValueError("invalid_domain"), "invalid_domain"),
                                       (ValueError("stale_revision"), "busy"),
                                       (ValueError("private"), "unavailable"),
                                       (OSError("private"), "unavailable")])
def test_smart_normalizer_errors_never_expose_raw_messages(runtime, monkeypatch, error, code):
    def fail(value):
        raise error

    monkeypatch.setattr(happ_shared_rules, "normalize_domain", fail)
    assert_error(code, submit)
    assert not runtime.path.exists() and runtime.calls == runtime.dns_calls == []


@pytest.mark.parametrize("replacement", [None, {"account_id": "c" * 64, "approved": True}])
def test_deleted_or_recreated_account_cannot_approve_old_smart_request(runtime, replacement):
    record, _ = submit()
    runtime.users.pop("member")
    if replacement is not None:
        runtime.users["member"] = replacement
    assert_error("ineligible", approve, record)
    assert runtime.calls == runtime.dns_calls == []


@pytest.mark.parametrize("flag", ["paused", "pause_pending", "revoking"])
def test_smart_review_rejects_ineligible_account_flags(runtime, flag):
    record, _ = submit()
    runtime.users["member"][flag] = True
    assert_error("ineligible", approve, record)
    assert_error("ineligible", submit, "another.example.com")
    assert runtime.calls == runtime.dns_calls == []


def test_smart_identity_is_rechecked_immediately_before_adapter(runtime, monkeypatch):
    record, _ = submit()
    reads = [0]

    def load_users():
        reads[0] += 1
        if reads[0] == 2:
            runtime.users["member"]["account_id"] = "c" * 64
        return copy.deepcopy(runtime.users)

    monkeypatch.setattr(core, "load_users", load_users)
    assert_error("ineligible", approve, record)
    assert requests.list_requests(kind="smart")[0]["status"] == "pending"
    assert runtime.calls == runtime.dns_calls == []


def test_smart_identity_is_rechecked_before_finalizing(runtime, monkeypatch):
    record, _ = submit()

    def apply_then_pause(domain):
        runtime.apply(domain)
        runtime.users["member"]["paused"] = True

    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", apply_then_pause)
    assert_error("ineligible", approve, record)
    assert requests.list_requests(kind="smart")[0]["status"] == "pending"
    assert runtime.calls == ["example.com"] and runtime.dns_calls == []


def test_terminal_smart_callback_still_checks_account_identity(runtime):
    record, _ = submit()
    approve(record)
    runtime.users["member"]["account_id"] = "c" * 64
    assert_error("ineligible", approve, record)
    assert runtime.calls == ["example.com"]


@pytest.mark.family_archive
def test_smart_helper_runs_without_store_lock_and_concurrent_callbacks_are_busy(runtime, monkeypatch):
    record, _ = submit()
    entered, release = threading.Event(), threading.Event()

    def slow_apply(domain):
        entered.set()
        assert release.wait(timeout=5)
        runtime.apply(domain)

    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", slow_apply)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(approve, record)
        try:
            assert entered.wait(timeout=5)
            assert requests.list_requests(kind="smart")[0]["status"] == "applying"
            assert submit()[1] is False
            assert requests.submit("member", ACCOUNT, "dns.example.com")[1] is True
            assert_error("busy", approve, record)
            assert_error("busy", requests.review, record["id"], "reject", "admin", kind="smart")
        finally:
            release.set()
        assert pending.result(timeout=5)["status"] == "approved"
    assert runtime.calls == ["example.com"] and runtime.dns_calls == []


def test_expired_smart_claim_reuses_idempotent_adapter_and_confirms_existing_application(runtime):
    record, _ = submit()
    store = json.loads(runtime.path.read_text(encoding="utf-8"))
    store["requests"][0].update(status="applying", claim="f" * 32,
                                lease_until="2026-11-15T12:05:00.000000Z")
    core.write_json_private(str(runtime.path), store)
    runtime.clock[0] += timedelta(seconds=301)
    runtime.applied.add("example.com")
    assert approve(record)["status"] == "approved"
    assert runtime.calls == ["example.com"] and runtime.mutations == runtime.dns_calls == []


def test_old_smart_claim_cannot_finalize_over_a_new_claim(runtime, monkeypatch):
    record, _ = submit()
    entered, release = threading.Event(), threading.Event()
    calls = [0]

    def apply(domain):
        calls[0] += 1
        runtime.apply(domain)
        if calls[0] == 1:
            entered.set()
            assert release.wait(timeout=5)

    monkeypatch.setattr(happ_shared_rules, "apply_proposed_domain", apply)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(approve, record)
        try:
            assert entered.wait(timeout=5)
            runtime.clock[0] += timedelta(seconds=301)
            result = approve(record, reviewer="second-admin")
            assert result["status"] == "approved"
        finally:
            release.set()
        with pytest.raises(requests.RequestError, match="^conflict$"):
            first.result(timeout=5)
    assert requests.list_requests(kind="smart")[0]["reviewer"] == "second-admin"
    assert runtime.mutations == ["example.com"] and runtime.dns_calls == []


@pytest.mark.family_archive
def test_smart_limits_are_independent_of_dns_pending_records(runtime):
    for number in range(10):
        submit(f"site{number}.example.com")
    assert_error("capacity", submit, "overflow.example.com")
    dns, created = requests.submit("member", ACCOUNT, "dns.example.com")
    assert created and requests.list_requests() == [dns]
    assert len(requests.list_requests(kind="smart")) == 10


def test_smart_list_filters_accounts_sorts_and_returns_independent_copies(runtime):
    first, _ = submit()
    runtime.clock[0] += timedelta(seconds=1)
    other, _ = requests.submit("other", OTHER_ACCOUNT, "another.example.com", kind="smart")
    assert requests.list_requests(kind="smart") == [other, first]
    assert requests.list_requests(ACCOUNT, kind="smart") == [first]
    assert requests.list_requests(OTHER_ACCOUNT, kind="smart") == [other]
    listed = requests.list_requests(kind="smart")
    listed[0]["status"] = "approved"
    first["domain"] = "changed.example.com"
    assert requests.list_requests(kind="smart")[0]["status"] == "pending"
    assert requests.list_requests(ACCOUNT, kind="smart")[0]["domain"] == "example.com"


@pytest.mark.family_archive
def test_smart_corruption_fails_closed_without_affecting_dns(runtime):
    dns, _ = requests.submit("member", ACCOUNT, "dns.example.com")
    smart, _ = submit()
    runtime.path.write_bytes(b"{broken-private-data")
    assert_error("unavailable", requests.list_requests, kind="smart")
    assert_error("unavailable", submit, "another.example.com")
    assert_error("unavailable", approve, smart)
    assert requests.list_requests() == [dns]
    assert runtime.path.read_bytes() == b"{broken-private-data"
    assert runtime.calls == runtime.dns_calls == []


def test_smart_stored_domain_is_validated_using_smart_rules(runtime):
    submit()
    store = json.loads(runtime.path.read_text(encoding="utf-8"))
    store["requests"][0]["domain"] = "site.internal"
    core.write_json_private(str(runtime.path), store)
    assert_error("unavailable", requests.list_requests, kind="smart")


@pytest.mark.parametrize("kind", [None, True, 1, "", "DNS", "family", "smart\nprivate", [], {}])
def test_invalid_kind_fails_closed_without_falling_back_to_dns_or_touching_store(runtime, kind):
    assert_error("invalid_request", requests.submit, "member", ACCOUNT, "example.com", kind=kind)
    assert_error("invalid_request", requests.list_requests, kind=kind)
    assert_error("invalid_request", requests.review, "c" * 32, "approve", "admin", kind=kind)
    assert not runtime.path.exists() and not runtime.dns_path.exists()
    assert runtime.normalizations == runtime.calls == runtime.dns_calls == []
