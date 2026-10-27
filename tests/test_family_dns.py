import copy
import json
import subprocess
import sys

import pytest

from wg_panel import family_dns


@pytest.fixture
def response():
    return {
        "ok": True, "domains": ["example.com"], "generation": 3,
        "applied": True, "applied_at": 1700000000,
        "backup": {
            "status": "updated", "last_attempt_at": 1700000000,
            "last_success_at": 1700000000, "commit": "a" * 40, "generation": 2,
        },
    }


@pytest.fixture
def helper(monkeypatch, tmp_path):
    path = tmp_path / "family helper.py"
    monkeypatch.setenv("WG_PANEL_FAMILY_DNS_HELPER", str(path))

    def configure(source):
        path.write_text(source, encoding="utf-8")
        return path

    return configure


def test_status_uses_python_absolute_argv_and_read_only_request(helper, response, monkeypatch):
    path = helper(
        "import json, sys\n"
        "assert json.load(sys.stdin) == {'operation': 'status'}\n"
        f"print({json.dumps(json.dumps(response))})\n"
    )
    real_popen = subprocess.Popen
    calls = []
    waits = []

    def popen(args, **kwargs):
        calls.append((args, kwargs))
        process = real_popen(args, **kwargs)
        real_wait = process.wait

        def wait(*args, **kwargs):
            waits.append(kwargs.get("timeout"))
            return real_wait(*args, **kwargs)

        process.wait = wait
        return process

    monkeypatch.setattr(family_dns.subprocess, "Popen", popen)
    state = family_dns.status()
    assert state.domains == ("example.com",)
    assert state.generation == 3 and state.applied
    assert state.backup.generation == 2
    assert len(calls) == 1
    assert calls[0][0] == [sys.executable, str(path)]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["stderr"] == subprocess.DEVNULL
    assert 195 < waits[0] <= 200


@pytest.mark.parametrize("operation", ["add", "remove"])
def test_change_normalizes_and_sends_version_once(helper, response, operation):
    helper(
        "import json, sys\n"
        f"assert json.load(sys.stdin) == {{'operation': '{operation}', "
        "'domain': 'example.com', 'expected_generation': 2}\n"
        f"print({json.dumps(json.dumps(response))})\n"
    )
    assert family_dns.change(operation, "  ExAmPlE.CoM.  ", 2).applied


@pytest.mark.parametrize("value", [
    "https://example.com", "example.com/path", "*.example.com", "localhost", "127.0.0.1",
    "[::1]", "example..com", "example.com..", "-a.example", "a-.example", "a\n.example",
    "example.com other.com", "x" * 64 + ".example", "<script>alert(1)</script>", "", None,
])
def test_rejects_invalid_domains_without_invoking_helper(value, monkeypatch):
    monkeypatch.setattr(family_dns, "_invoke", lambda _payload: pytest.fail("helper invoked"))
    with pytest.raises(family_dns.FamilyDnsError, match="invalid_domain"):
        family_dns.change("add", value, 1)


def test_normalizes_internationalized_domain():
    assert family_dns.normalize_domain("пример.рф") == "xn--e1afmkfd.xn--p1ai"


@pytest.mark.parametrize("operation,generation", [("status", 1), ("add", True), ("remove", -1)])
def test_rejects_invalid_change_schema(operation, generation, monkeypatch):
    monkeypatch.setattr(family_dns, "_invoke", lambda _payload: pytest.fail("helper invoked"))
    with pytest.raises(family_dns.FamilyDnsError, match="invalid_request"):
        family_dns.change(operation, "example.com", generation)


@pytest.mark.parametrize("code", [
    "invalid_domain", "stale_generation", "busy", "uninitialized", "unavailable",
    "apply_failed", "degraded",
])
def test_preserves_stable_helper_errors(helper, code):
    helper(f"import sys\nprint('{{\"ok\":false,\"error\":\"{code}\"}}')\nsys.exit(1)\n")
    with pytest.raises(family_dns.FamilyDnsError) as failure:
        family_dns.change("add", "example.com", 1)
    assert failure.value.code == code


def test_sanitizes_unknown_errors_and_stderr(helper):
    helper(
        "import json, sys\n"
        "print('/private/server/path secret', file=sys.stderr)\n"
        "print(json.dumps({'ok': False, 'error': '/private/server/path secret'}))\n"
    )
    with pytest.raises(family_dns.FamilyDnsError) as failure:
        family_dns.status()
    assert str(failure.value) == "unavailable"


@pytest.mark.parametrize("path,value", [
    (("ok",), 1), (("domains",), "example.com"), (("domains",), ["EXAMPLE.COM"]),
    (("domains",), ["example.com", "example.com"]), (("domains",), ["<script>"]),
    (("domains",), [False]), (("generation",), True), (("generation",), -1),
    (("applied",), 1), (("applied_at",), "today"), (("backup",), []),
    (("backup", "status"), "unknown"), (("backup", "last_attempt_at"), False),
    (("backup", "last_success_at"), -1), (("backup", "commit"), []),
    (("backup", "generation"), True),
])
def test_rejects_invalid_response_schema(response, path, value):
    malformed = copy.deepcopy(response)
    target = malformed
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(family_dns.FamilyDnsError, match="unavailable"):
        family_dns._state_from_response(json.dumps(malformed), 0)


@pytest.mark.parametrize("raw", ["not JSON", "[]", "null", '{"ok":true,"ok":false}'])
def test_rejects_non_protocol_output(raw):
    with pytest.raises(family_dns.FamilyDnsError, match="unavailable"):
        family_dns._state_from_response(raw, 0)


def test_backup_failure_does_not_block_applied_changes(helper, response):
    response["backup"].update(status="error", last_success_at=None, commit=None)
    helper(f"print({json.dumps(json.dumps(response))})\n")
    assert family_dns.change("add", "example.com", 2).backup.status == "error"


def test_unapplied_mutation_is_not_reported_as_success(helper, response):
    response["applied"] = False
    helper(f"print({json.dumps(json.dumps(response))})\n")
    with pytest.raises(family_dns.FamilyDnsError, match="apply_failed"):
        family_dns.change("add", "example.com", 2)


def test_nonzero_success_is_rejected(helper, response):
    helper(f"import sys\nprint({json.dumps(json.dumps(response))})\nsys.exit(1)\n")
    with pytest.raises(family_dns.FamilyDnsError, match="unavailable"):
        family_dns.status()


def test_unconfigured_or_relative_helper_never_starts_process(monkeypatch):
    monkeypatch.setattr(family_dns.subprocess, "Popen", lambda *_a, **_k: pytest.fail("started"))
    monkeypatch.delenv("WG_PANEL_FAMILY_DNS_HELPER", raising=False)
    with pytest.raises(family_dns.FamilyDnsError, match="unconfigured"):
        family_dns.status()
    monkeypatch.setenv("WG_PANEL_FAMILY_DNS_HELPER", "relative/helper.py")
    with pytest.raises(family_dns.FamilyDnsError, match="unavailable"):
        family_dns.status()


def test_missing_helper_is_a_friendly_error(helper):
    with pytest.raises(family_dns.FamilyDnsError, match="unavailable"):
        family_dns.status()


def test_request_limit_is_checked_before_launch(helper, monkeypatch):
    monkeypatch.setattr(family_dns.subprocess, "Popen", lambda *_a, **_k: pytest.fail("started"))
    with pytest.raises(family_dns.FamilyDnsError, match="invalid_request"):
        family_dns._invoke({"operation": "x" * family_dns.MAX_REQUEST_BYTES})


def test_output_is_bounded(helper):
    helper(f"import sys\nsys.stdout.write('x' * {family_dns.MAX_RESPONSE_BYTES + 10000})\n")
    with pytest.raises(family_dns.FamilyDnsError, match="unavailable"):
        family_dns.status()


def test_timeout_is_not_retried(helper, monkeypatch):
    helper("import time\ntime.sleep(10)\n")
    monkeypatch.setattr(family_dns, "HELPER_TIMEOUT_SECONDS", 0.05)
    real_popen = subprocess.Popen
    calls = []

    def popen(*args, **kwargs):
        calls.append(True)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(family_dns.subprocess, "Popen", popen)
    with pytest.raises(family_dns.FamilyDnsError, match="unavailable"):
        family_dns.change("add", "example.com", 1)
    assert len(calls) == 1
