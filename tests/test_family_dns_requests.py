"""Private proposals, stable identities and leased, confirmed DNS approval."""

import copy
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from wg_panel import core, family_dns
from wg_panel import family_dns_requests as requests

ACCOUNT = "a" * 64
OTHER_ACCOUNT = "b" * 64
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


class Dns:
    def __init__(self):
        self.domains = set()
        self.generation = 4
        self.applied = True
        self.calls = []

    def state(self):
        return family_dns.FamilyDnsState(
            tuple(sorted(self.domains)), self.generation, self.applied, 100,
            family_dns.BackupStatus("never", None, None, None))

    def status(self):
        self.calls.append(("status",))
        return self.state()

    def change(self, operation, domain, generation):
        self.calls.append((operation, domain, generation))
        assert operation == "add" and generation == self.generation
        self.domains.add(domain)
        self.generation += 1
        return self.state()


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    users = {
        "member": {"account_id": ACCOUNT, "approved": True},
        "other": {"account_id": OTHER_ACCOUNT, "approved": True},
    }
    clock = [NOW]
    dns = Dns()
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA_DIR", str(data))
    monkeypatch.setattr(core, "load_users", lambda: copy.deepcopy(users))
    monkeypatch.setattr(requests, "_now", lambda: clock[0])
    monkeypatch.setattr(family_dns, "status", dns.status)
    monkeypatch.setattr(family_dns, "change", dns.change)
    return SimpleNamespace(users=users, clock=clock, dns=dns, data=data,
                           path=data / "family_dns_requests.json")


def submit(domain="example.com", **kwargs):
    return requests.submit("member", ACCOUNT, domain, **kwargs)


def approve(record, reviewer="admin"):
    return requests.review(record["id"], "approve", reviewer)


def assert_error(code, function, *args, **kwargs):
    with pytest.raises(requests.RequestError) as failure:
        function(*args, **kwargs)
    assert failure.value.code == code
    assert str(failure.value) == code


def test_submission_normalizes_domains_and_never_calls_dns(runtime):
    record, created = submit("  ПРИМЕР.РФ.  ", reason="  Please check this site.  ")
    assert created is True
    assert record["domain"] == "xn--e1afmkfd.xn--p1ai"
    assert record["reason"] == "Please check this site."
    assert record["status"] == "pending"
    assert record["reviewed_at"] is record["reviewer"] is None
    assert record["claim"] is record["lease_until"] is None
    assert len(record["id"]) == 32 and int(record["id"], 16) >= 0
    assert record["created_at"] == "2026-11-15T12:00:00.000000Z"
    assert requests.list_requests() == [record]
    assert runtime.dns.calls == []


def test_duplicate_pending_proposal_returns_original_reason_and_id_without_write(runtime):
    first, _ = submit(reason="Original")
    before = runtime.path.read_bytes()
    duplicate, created = submit("EXAMPLE.COM.", reason="Replacement")
    assert duplicate == first and created is False
    assert runtime.path.read_bytes() == before
    assert runtime.dns.calls == []


def test_account_filter_isolates_requests_and_lists_newest_first(runtime):
    first, _ = submit()
    runtime.clock[0] += timedelta(seconds=1)
    other, _ = requests.submit("other", OTHER_ACCOUNT, "example.com")
    assert requests.list_requests() == [other, first]
    assert requests.list_requests(ACCOUNT) == [first]
    assert requests.list_requests(OTHER_ACCOUNT) == [other]
    assert requests.list_requests("c" * 64) == []
    assert runtime.dns.calls == []


def test_returned_records_are_independent_copies(runtime):
    record, _ = submit()
    record["domain"] = "changed.example"
    listed = requests.list_requests()
    listed[0]["status"] = "approved"
    duplicate, created = submit()
    assert not created and duplicate["domain"] == "example.com"
    assert duplicate["status"] == "pending"


@pytest.mark.parametrize("domain", [None, [], "https://example.com", "*.example.com",
                                    "127.0.0.1", "single", "example.com\nprivate"])
def test_invalid_domains_fail_generically_without_dns_or_store(runtime, domain):
    assert_error("invalid_domain", submit, domain)
    assert not runtime.path.exists() and runtime.dns.calls == []


@pytest.mark.parametrize("reason", [None, [], "x" * 501, "nul\0text", "vertical\vtab",
                                    "invisible\u202etext", "surrogate\ud800", " " * 501])
def test_reasons_are_bounded_safe_text(runtime, reason):
    assert_error("invalid_reason", submit, reason=reason)
    assert not runtime.path.exists() and runtime.dns.calls == []


def test_reason_boundary_accepts_500_unicode_characters(runtime):
    record, _ = submit(reason="я" * 500)
    assert len(record["reason"]) == 500


def test_multiline_textarea_reason_is_stored_as_canonical_single_line(runtime):
    record, _ = submit(reason="  First line\r\nSecond\tline\nThird\rline  ")
    assert record["reason"] == "First line Second line Third line"
    assert requests.list_requests()[0]["reason"] == record["reason"]


@pytest.mark.parametrize("username,account", [(None, ACCOUNT), ("private\ntext", ACCOUNT),
                                            ("member", None), ("member", "private"),
                                            ("member", OTHER_ACCOUNT)])
def test_invalid_or_mismatched_submit_identity_is_ineligible(runtime, username, account):
    assert_error("ineligible", requests.submit, username, account, "example.com")
    assert not runtime.path.exists() and runtime.dns.calls == []


@pytest.mark.parametrize("flag,value", [("approved", False), ("approved", 1),
                                       ("paused", True), ("pause_pending", True),
                                       ("revoking", True)])
def test_submission_and_review_require_an_eligible_live_account(runtime, flag, value):
    record, _ = submit()
    runtime.users["member"][flag] = value
    assert_error("ineligible", submit, "other.example")
    assert_error("ineligible", approve, record)
    assert_error("ineligible", requests.review, record["id"], "reject", "admin")
    assert requests.list_requests(ACCOUNT)[0]["status"] == "pending"
    assert runtime.dns.calls == []


@pytest.mark.parametrize("replacement", [None, {"account_id": "c" * 64, "approved": True}])
def test_deleted_or_recreated_username_cannot_approve_old_identity(runtime, replacement):
    record, _ = submit()
    runtime.users.pop("member")
    if replacement is not None:
        runtime.users["member"] = replacement
    assert_error("ineligible", approve, record)
    assert runtime.dns.calls == []


def test_approval_uses_fresh_generation_and_confirms_applied_domain(runtime):
    record, _ = submit()
    result = approve(record)
    assert result["status"] == "approved" and result["reviewer"] == "admin"
    assert result["reviewed_at"] == "2026-11-15T12:00:00.000000Z"
    assert result["claim"] is result["lease_until"] is None
    assert runtime.dns.calls == [("status",), ("add", "example.com", 4)]
    result["status"] = "pending"
    assert requests.list_requests()[0]["status"] == "approved"


def test_already_listed_and_applied_domain_does_not_reapply(runtime):
    runtime.dns.domains.add("example.com")
    record, _ = submit()
    assert approve(record)["status"] == "approved"
    assert runtime.dns.calls == [("status",)]


def test_rejection_and_repeated_rejection_never_call_dns(runtime):
    record, _ = submit()
    result = requests.review(record["id"], "reject", "admin")
    runtime.clock[0] += timedelta(seconds=20)
    assert requests.review(record["id"], "reject", "another-admin") == result
    assert result["status"] == "rejected" and result["reviewer"] == "admin"
    assert_error("conflict", approve, record)
    assert runtime.dns.calls == []


def test_repeated_approval_returns_original_terminal_result_without_dns(runtime):
    record, _ = submit()
    result = approve(record)
    calls = list(runtime.dns.calls)
    runtime.clock[0] += timedelta(seconds=20)
    assert approve(record, reviewer="another-admin") == result
    assert_error("conflict", requests.review, record["id"], "reject", "admin")
    assert runtime.dns.calls == calls


def test_terminal_callback_still_rejects_a_recreated_account(runtime):
    record, _ = submit()
    approve(record)
    runtime.users["member"]["account_id"] = "c" * 64
    assert_error("ineligible", approve, record)
    assert len(runtime.dns.calls) == 2


@pytest.mark.parametrize("code", ["unavailable", "apply_failed", "stale_generation", "busy",
                                 "degraded", "unconfigured"])
def test_failed_apply_propagates_stable_helper_error_and_leaves_retryable_request(
        runtime, monkeypatch, code):
    record, _ = submit()

    def fail(*args):
        raise family_dns.FamilyDnsError(code)

    monkeypatch.setattr(family_dns, "change", fail)
    with pytest.raises(family_dns.FamilyDnsError) as failure:
        approve(record)
    assert failure.value.code == code
    saved = requests.list_requests()[0]
    assert saved["status"] == "pending"
    assert saved["claim"] is saved["lease_until"] is saved["reviewed_at"] is saved["reviewer"] is None


@pytest.mark.parametrize("domain_present", [False, True])
def test_unapplied_status_is_not_approved_or_mutated(runtime, domain_present):
    if domain_present:
        runtime.dns.domains.add("example.com")
    runtime.dns.applied = False
    record, _ = submit()
    with pytest.raises(family_dns.FamilyDnsError, match="^apply_failed$"):
        approve(record)
    assert runtime.dns.calls == [("status",)]
    assert requests.list_requests()[0]["status"] == "pending"


@pytest.mark.parametrize("applied,present", [(False, True), (True, False)])
def test_change_result_must_confirm_both_domain_and_application(runtime, monkeypatch, applied, present):
    record, _ = submit()

    def unconfirmed(*args):
        runtime.dns.applied = applied
        if present:
            runtime.dns.domains.add("example.com")
        return runtime.dns.state()

    monkeypatch.setattr(family_dns, "change", unconfirmed)
    with pytest.raises(family_dns.FamilyDnsError, match="^apply_failed$"):
        approve(record)
    assert requests.list_requests()[0]["status"] == "pending"


def test_uncertain_success_is_confirmed_on_retry_without_duplicate_add(runtime, monkeypatch):
    record, _ = submit()

    def timeout_after_add(*args):
        runtime.dns.change(*args)
        raise family_dns.FamilyDnsError("unavailable")

    monkeypatch.setattr(family_dns, "change", timeout_after_add)
    with pytest.raises(family_dns.FamilyDnsError, match="^unavailable$"):
        approve(record)
    assert requests.list_requests()[0]["status"] == "pending"
    assert approve(record)["status"] == "approved"
    assert runtime.dns.calls == [("status",), ("add", "example.com", 4), ("status",)]


def test_retry_after_failed_add_reads_status_and_uses_current_generation(runtime, monkeypatch):
    record, _ = submit()

    def fail(*args):
        raise family_dns.FamilyDnsError("unavailable")

    monkeypatch.setattr(family_dns, "change", fail)
    with pytest.raises(family_dns.FamilyDnsError):
        approve(record)
    runtime.dns.generation = 12
    monkeypatch.setattr(family_dns, "change", runtime.dns.change)
    assert approve(record)["status"] == "approved"
    assert runtime.dns.calls == [("status",), ("status",), ("add", "example.com", 12)]


def test_status_error_releases_claim_and_preserves_generic_error(runtime, monkeypatch):
    record, _ = submit()

    def fail():
        raise family_dns.FamilyDnsError("unavailable")

    monkeypatch.setattr(family_dns, "status", fail)
    with pytest.raises(family_dns.FamilyDnsError, match="^unavailable$"):
        approve(record)
    assert requests.list_requests()[0]["status"] == "pending"


def test_unexpected_helper_exception_is_generic_and_releases_claim(runtime, monkeypatch):
    record, _ = submit()

    def fail():
        raise RuntimeError("private-account-secret")

    monkeypatch.setattr(family_dns, "status", fail)
    assert_error("unavailable", approve, record)
    assert requests.list_requests()[0]["status"] == "pending"


@pytest.mark.parametrize("already_present", [False, True])
def test_identity_is_rechecked_after_status_before_add_or_approval(runtime, monkeypatch, already_present):
    record, _ = submit()
    if already_present:
        runtime.dns.domains.add("example.com")

    def status():
        runtime.users["member"]["account_id"] = "c" * 64
        return runtime.dns.status()

    monkeypatch.setattr(family_dns, "status", status)
    assert_error("ineligible", approve, record)
    assert runtime.dns.calls == [("status",)]
    assert requests.list_requests()[0]["status"] == "pending"


def test_identity_is_rechecked_before_finalizing_success(runtime, monkeypatch):
    record, _ = submit()

    def change(*args):
        state = runtime.dns.change(*args)
        runtime.users["member"]["paused"] = True
        return state

    monkeypatch.setattr(family_dns, "change", change)
    assert_error("ineligible", approve, record)
    assert requests.list_requests()[0]["status"] == "pending"


def test_concurrent_submissions_create_one_pending_request(runtime):
    barrier = threading.Barrier(6)

    def concurrent_submit():
        barrier.wait(timeout=5)
        return submit()

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: concurrent_submit(), range(6)))
    assert sum(created for _, created in results) == 1
    assert len({record["id"] for record, _ in results}) == 1
    assert len(requests.list_requests()) == 1 and runtime.dns.calls == []


def test_concurrent_review_is_busy_and_helper_does_not_hold_store_lock(runtime, monkeypatch):
    record, _ = submit()
    entered, release = threading.Event(), threading.Event()

    def slow_status():
        entered.set()
        assert release.wait(timeout=5)
        return runtime.dns.status()

    monkeypatch.setattr(family_dns, "status", slow_status)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(approve, record)
        try:
            assert entered.wait(timeout=5)
            assert requests.list_requests()[0]["status"] == "applying"
            duplicate, created = submit()
            assert not created and duplicate["id"] == record["id"]
            assert_error("busy", approve, record)
            assert_error("busy", requests.review, record["id"], "reject", "admin")
            assert submit("another.example")[1] is True
        finally:
            release.set()
        assert pending.result(timeout=5)["status"] == "approved"
    assert runtime.dns.calls == [("status",), ("add", "example.com", 4)]


def expire_claim(runtime, record):
    store = json.loads(runtime.path.read_text(encoding="utf-8"))
    stored = next(item for item in store["requests"] if item["id"] == record["id"])
    stored.update(status="applying", claim="f" * 32,
                  lease_until="2026-11-15T12:05:00.000000Z")
    core.write_json_private(str(runtime.path), store)
    runtime.clock[0] = NOW + timedelta(seconds=301)


@pytest.mark.parametrize("present", [False, True])
def test_expired_claim_rechecks_applied_state_before_confirming_or_versioned_add(runtime, present):
    record, _ = submit()
    expire_claim(runtime, record)
    if present:
        runtime.dns.domains.add("example.com")
    assert approve(record)["status"] == "approved"
    assert runtime.dns.calls == ([("status",)] if present
                                 else [("status",), ("add", "example.com", 4)])


def test_expired_uncertain_claim_does_not_repeat_add_when_current_state_is_unapplied(runtime):
    record, _ = submit()
    expire_claim(runtime, record)
    runtime.dns.applied = False
    with pytest.raises(family_dns.FamilyDnsError, match="^apply_failed$"):
        approve(record)
    assert runtime.dns.calls == [("status",)]
    assert requests.list_requests()[0]["status"] == "pending"


def test_old_claim_cannot_overwrite_new_review_after_expiration(runtime, monkeypatch):
    record, _ = submit()
    entered, release = threading.Event(), threading.Event()
    count = [0]

    def status():
        count[0] += 1
        state = runtime.dns.status()
        if count[0] == 1:
            entered.set()
            assert release.wait(timeout=5)
        return state

    monkeypatch.setattr(family_dns, "status", status)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(approve, record)
        try:
            assert entered.wait(timeout=5)
            runtime.clock[0] += timedelta(seconds=301)
            runtime.dns.domains.add("example.com")
            result = approve(record, reviewer="second-admin")
            assert result["status"] == "approved"
        finally:
            release.set()
        with pytest.raises(requests.RequestError, match="^conflict$"):
            first.result(timeout=5)
    assert requests.list_requests()[0]["reviewer"] == "second-admin"
    assert not any(call[0] == "add" for call in runtime.dns.calls)


def test_per_account_pending_limit_counts_applying_and_duplicate_remains_idempotent(runtime):
    records = [submit(f"site{number}.example")[0] for number in range(10)]
    expire_claim(runtime, records[0])
    before = runtime.path.read_bytes()
    assert_error("capacity", submit, "overflow.example")
    assert runtime.path.read_bytes() == before
    duplicate, created = submit("site0.example")
    assert not created and duplicate["id"] == records[0]["id"]
    requests.review(records[1]["id"], "reject", "admin")
    assert submit("overflow.example")[1] is True


def test_global_capacity_fails_without_pruning_active_requests(runtime, monkeypatch):
    monkeypatch.setattr(requests, "MAX_RECORDS", 3)
    for number in range(3):
        submit(f"site{number}.example")
    before = runtime.path.read_bytes()
    assert_error("capacity", submit, "overflow.example")
    assert runtime.path.read_bytes() == before


def test_global_bound_prunes_oldest_terminal_record_only(runtime, monkeypatch):
    monkeypatch.setattr(requests, "MAX_RECORDS", 3)
    oldest, _ = submit("oldest.example")
    runtime.clock[0] += timedelta(seconds=1)
    terminal, _ = submit("terminal.example")
    requests.review(terminal["id"], "reject", "admin")
    runtime.clock[0] += timedelta(seconds=1)
    submit("latest.example")
    runtime.clock[0] += timedelta(seconds=1)
    submit("newest.example")
    records = requests.list_requests()
    assert len(records) == 3
    assert oldest["id"] in {record["id"] for record in records}
    assert terminal["id"] not in {record["id"] for record in records}


@pytest.mark.parametrize("payload", [b"", b"{broken", b"[]", b'{"version":1,"requests":null}',
                                     b'{"version":true,"requests":[]}',
                                     b'{"version":1,"version":1,"requests":[]}',
                                     b'{"version":1,"requests":[],"private":"text"}'])
def test_corruption_fails_closed_without_replacing_store_or_calling_dns(runtime, payload):
    core.ensure_private_dir(runtime.data)
    runtime.path.write_bytes(payload)
    assert_error("unavailable", requests.list_requests)
    assert_error("unavailable", submit)
    assert_error("unavailable", requests.review, "a" * 32, "approve", "admin")
    assert runtime.path.read_bytes() == payload and runtime.dns.calls == []


@pytest.mark.parametrize("field,value", [
    ("id", "private"), ("username", "secret\ntext"), ("account_id", "secret"),
    ("domain", "EXAMPLE.COM"), ("reason", "x" * 501), ("reason", "hidden\u202e"),
    ("reason", "noncanonical\ntext"), ("reason", " spaced "),
    ("status", []), ("status", "unknown"), ("created_at", "2026-02-30T12:00:00Z"),
    ("reviewed_at", "2026-11-15T12:00:00Z"), ("reviewer", "admin"),
    ("claim", "a" * 32), ("lease_until", "2026-11-15T12:05:00Z"), ("extra", "value"),
])
def test_malformed_record_is_unavailable_without_mutation(runtime, field, value):
    submit()
    store = json.loads(runtime.path.read_text(encoding="utf-8"))
    store["requests"][0][field] = value
    core.write_json_private(str(runtime.path), store)
    before = runtime.path.read_bytes()
    assert_error("unavailable", requests.list_requests)
    assert_error("unavailable", submit, "other.example")
    assert runtime.path.read_bytes() == before and runtime.dns.calls == []


def test_duplicate_active_records_are_corruption_even_with_different_ids(runtime):
    submit()
    store = json.loads(runtime.path.read_text(encoding="utf-8"))
    duplicate = copy.deepcopy(store["requests"][0])
    duplicate["id"] = "f" * 32
    store["requests"].append(duplicate)
    core.write_json_private(str(runtime.path), store)
    assert_error("unavailable", requests.list_requests)


def test_oversized_store_is_unavailable_and_new_writes_are_bounded(runtime, monkeypatch):
    monkeypatch.setattr(requests, "MAX_STORE_BYTES", 100)
    assert_error("unavailable", submit)
    assert not runtime.path.exists()
    runtime.path.write_bytes(b" " * 101)
    assert_error("unavailable", requests.list_requests)


def test_private_writer_and_private_store_permissions_are_used(runtime, monkeypatch):
    original = core.write_json_private
    paths = []

    def write(path, data):
        paths.append(path)
        original(path, data)

    monkeypatch.setattr(core, "write_json_private", write)
    submit()
    assert paths == [str(runtime.path)]
    if os.name != "nt":
        assert runtime.path.stat().st_mode & 0o777 == 0o600
        assert runtime.data.stat().st_mode & 0o777 == 0o700


def test_process_lock_is_taken_and_released_when_available(runtime, monkeypatch):
    calls = []

    def flock(descriptor, operation):
        os.fstat(descriptor)
        calls.append(operation)

    monkeypatch.setattr(core, "fcntl", SimpleNamespace(LOCK_EX=1, LOCK_UN=2, flock=flock))
    submit()
    requests.list_requests()
    assert calls == [1, 2, 1, 2]


def test_write_failure_is_generic_and_preserves_previous_store(runtime, monkeypatch):
    submit()
    before = runtime.path.read_bytes()

    def fail(*args):
        raise OSError("private-account-secret")

    monkeypatch.setattr(core, "write_json_private", fail)
    assert_error("unavailable", submit, "another.example")
    assert runtime.path.read_bytes() == before


@pytest.mark.parametrize("request_id", [None, [], "", "private-secret", "f" * 32])
def test_unknown_or_malformed_request_id_is_not_found(runtime, request_id):
    assert_error("not_found", requests.review, request_id, "approve", "admin")
    assert runtime.dns.calls == []


@pytest.mark.parametrize("decision,reviewer", [(None, "admin"), ([], "admin"),
                                               ("approved", "admin"), ("approve", None),
                                               ("approve", []), ("approve", " "),
                                               ("approve", "x" * 129),
                                               ("approve", "admin\nsecret")])
def test_invalid_review_inputs_fail_without_dns(runtime, decision, reviewer):
    record, _ = submit()
    assert_error("invalid_request", requests.review, record["id"], decision, reviewer)
    assert requests.list_requests()[0]["status"] == "pending" and runtime.dns.calls == []


def test_invalid_account_list_filter_cannot_return_other_accounts(runtime):
    submit()
    assert_error("ineligible", requests.list_requests, "private")


def test_request_error_never_echoes_unknown_codes():
    assert str(requests.RequestError("private-secret")) == "unavailable"
    assert str(requests.RequestError([])) == "unavailable"
