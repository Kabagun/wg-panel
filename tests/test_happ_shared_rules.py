"""Synthetic sources; no requests to a real domain or application imports."""

import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.request import Request

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "src/wg_panel/happ_shared_rules.py"
SPEC = importlib.util.spec_from_file_location("standalone_happ_shared_rules", MODULE_PATH)
rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rules)

URL = "https://raw.githubusercontent.com/synthetic/safe-internet/main/routing-domains.txt"
NOW = datetime(2026, 11, 12, 12, 30, tzinfo=UTC)
LATER = NOW + timedelta(minutes=5)


def fetch(data=b"example.com\ngithub.com\n"):
    def get(url, *, timeout, max_bytes):
        assert url == URL
        assert timeout == 15 and max_bytes == 65536
        return data

    return get


def successful(tmp_path, data=b"example.com\ngithub.com\n", now=NOW):
    return rules.sync(tmp_path, URL, fetch=fetch(data), now=now)


def broken_fetch(*args, **kwargs):
    raise OSError("synthetic-private-token must never appear in errors")


def test_success_canonical_idna_comments_and_stable_revision(tmp_path):
    first = successful(
        tmp_path,
        b"# public routing list\r\nGitHub.COM. # code\r\n\r\nexample.com\ndomain:github.com\n",
    )
    assert first["rules"] == ["domain:example.com", "domain:github.com"]
    assert len(first["revision"]) == 64
    assert first["last_checked"] == first["last_success"] == "2026-11-12T12:30:00Z"
    assert first["error"] is None
    assert set(first) == {"rules", "revision", "last_checked", "last_success", "error"}
    second = successful(tmp_path, b"github.com\nexample.com\n", LATER)
    assert second["revision"] == first["revision"]
    assert second["last_success"] == "2026-11-12T12:35:00Z"
    assert rules.load_snapshot(tmp_path, URL) == second
    third = successful(tmp_path, "домен.рф\nEXAMPLE.com\n".encode(), LATER)
    assert third["rules"] == ["domain:example.com", "domain:xn--d1acufc.xn--p1ai"]


def test_failed_refresh_retains_last_good_and_then_recovers(tmp_path):
    first = successful(tmp_path)
    second = rules.sync(tmp_path, URL, fetch=broken_fetch, now=LATER)
    assert second["rules"] == first["rules"]
    assert second["revision"] == first["revision"]
    assert second["last_success"] == first["last_success"]
    assert second["last_checked"] == "2026-11-12T12:35:00Z"
    assert second["error"] == "Shared routing list refresh failed"
    assert "synthetic-private-token" not in json.dumps(second)
    assert rules.load_snapshot(tmp_path, URL) == second
    assert successful(tmp_path, now=LATER)["error"] is None


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"# only comments\n",
        b"\xff",
        b"x" * 65537,
        b"example.com\nhttps://github.com\n",
        b"example.com\n*.github.com\n",
        b"example.com\nlocalhost\n",
        b"example.com\n192.168.1.1\n",
        b"example.com\nregexp:.*\n",
        b"example.com\ngeoip:ru\n",
        b"example.com\nexample.com\x00",
        b"example.com\t\n",
        b"example.com\n" * 257,
        "exam\u200bple.com".encode(),
    ],
    ids=lambda payload: f"payload-bytes-{len(payload)}",
)
def test_bad_source_cannot_replace_good_rules(tmp_path, data):
    first = successful(tmp_path)
    second = rules.sync(tmp_path, URL, fetch=fetch(data), now=LATER)
    assert second["rules"] == first["rules"] and second["revision"] == first["revision"]
    assert second["last_success"] == first["last_success"] and second["error"]


@pytest.mark.parametrize(
    "domain",
    [
        "127.0.0.1",
        "192.168.1.1",
        "8.8.8.8",
        "2001:4860::8888",
        "10.0.0.0/8",
        "localhost",
        "localhost.localdomain",
        "router.local",
        "router.lan",
        "router.home",
        "router.home.arpa",
        "name.internal",
        "name.corp",
        "name.private",
        "name.onion",
        "name.i2p",
        "name.test",
        "name.example",
        "name.invalid",
        "name.alt",
        "example.com/path",
        "example.com:443",
        "user@example.com",
        "*.example.com",
        "-bad.example.com",
        "bad-.example.com",
        "name..com",
        "name.123",
        "name.xn--a",
        "full:example.com",
        "geosite:github",
        "https://example.com",
        ".example.com",
        "example.com..",
        "example com",
        "example.com\t",
        "a" * 64 + ".com",
    ],
)
def test_rejects_nonpublic_or_non_domain_entries(tmp_path, domain):
    with pytest.raises(ValueError, match="Shared routing list refresh failed"):
        successful(tmp_path, domain.encode())
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path, URL)


def test_rule_and_byte_limits(tmp_path):
    data = "\n".join(f"host{i}.example.com" for i in range(256)).encode()
    assert len(successful(tmp_path, data)["rules"]) == 256
    padded = b"example.com\n#" + b"x" * (65536 - len(b"example.com\n#"))
    assert len(padded) == 65536
    assert successful(tmp_path, padded)["rules"] == ["domain:example.com"]


def test_large_canonical_cache_is_rejected_before_replacing_good_rules(tmp_path):
    first = successful(tmp_path)
    domains = [
        f"{str(index).ljust(63, 'a')}.{'b' * 63}.{'c' * 63}.{'d' * 61}" for index in range(256)
    ]
    payload = "\n".join(domains).encode()
    assert len(payload) <= 65536
    snapshot = successful(tmp_path, payload, LATER)
    assert snapshot["rules"] == first["rules"] and snapshot["error"]
    assert (tmp_path / rules.CACHE_NAME).stat().st_size <= 65536


def test_no_cache_failure_never_exports_empty_success(tmp_path):
    data = tmp_path / "data"
    with pytest.raises(ValueError, match="refresh failed"):
        rules.sync(data, URL, fetch=broken_fetch, now=NOW)
    assert not (data / rules.CACHE_NAME).exists()
    with pytest.raises(ValueError):
        rules.load_snapshot(data, URL)


def test_load_missing_is_strictly_read_only(tmp_path):
    data = tmp_path / "missing"
    with pytest.raises(ValueError):
        rules.load_snapshot(data, URL)
    assert not data.exists()
    tmp_path.mkdir(exist_ok=True)
    before = list(tmp_path.iterdir())
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path, URL)
    assert list(tmp_path.iterdir()) == before


def test_load_good_is_read_only_and_returns_independent_rules(tmp_path):
    first = successful(tmp_path)
    path = tmp_path / rules.CACHE_NAME
    lock = tmp_path / (rules.CACHE_NAME + ".lock")
    lock.unlink()
    before = path.stat(), path.read_bytes(), set(tmp_path.iterdir())
    loaded = rules.load_snapshot(tmp_path, URL)
    loaded["rules"].clear()
    assert rules.load_snapshot(tmp_path, URL) == first
    after = path.stat(), path.read_bytes(), set(tmp_path.iterdir())
    assert before[0].st_mtime_ns == after[0].st_mtime_ns
    assert before[1:] == after[1:]
    assert not lock.exists()


def test_source_mismatch_fails_closed_and_refresh_can_switch_source(tmp_path):
    first = successful(tmp_path)
    other = URL.replace("routing-domains.txt", "different-routing-domains.txt")
    before = (tmp_path / rules.CACHE_NAME).read_bytes()
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path, other)
    with pytest.raises(ValueError):
        rules.sync(tmp_path, other, fetch=broken_fetch, now=LATER)
    assert (tmp_path / rules.CACHE_NAME).read_bytes() == before
    assert rules.load_snapshot(tmp_path, URL) == first
    changed = rules.sync(tmp_path, other, fetch=lambda *a, **kw: b"github.com", now=LATER)
    assert changed["rules"] == ["domain:github.com"]
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path, URL)


@pytest.mark.parametrize(
    "change",
    [
        {"version": True},
        {"version": 2},
        {"sha256": "bad"},
        {"revision": "bad"},
        {"rules": []},
        {"rules": ["example.com"]},
        {"rules": ["domain:127.0.0.1"]},
        {"rules": [None]},
        {"rules": "example.com"},
        {"extra": "unknown"},
        {"last_checked": "2026-11-12"},
        {"last_success": None},
        {"error": "secret-diagnostic"},
    ],
)
def test_corrupt_cache_is_not_exported(tmp_path, change):
    successful(tmp_path)
    path = tmp_path / rules.CACHE_NAME
    record = json.loads(path.read_bytes())
    record.update(change)
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="cache is unavailable or invalid"):
        rules.load_snapshot(tmp_path, URL)


def test_invalid_json_and_oversize_cache_rejected_and_repaired(tmp_path):
    path = tmp_path / rules.CACHE_NAME
    path.write_bytes(b"invalid json")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path, URL)
    assert successful(tmp_path)["error"] is None
    path.write_bytes(b" " * 65537)
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path, URL)


def test_atomic_replace_failure_keeps_previous_bytes_and_removes_temp(tmp_path, monkeypatch):
    successful(tmp_path)
    previous = (tmp_path / rules.CACHE_NAME).read_bytes()

    def fail(*args):
        raise OSError("synthetic-private-token")

    monkeypatch.setattr(rules.os, "replace", fail)
    with pytest.raises(ValueError, match="cache could not be written") as error:
        successful(tmp_path, b"github.com", LATER)
    assert "synthetic-private-token" not in str(error.value)
    assert (tmp_path / rules.CACHE_NAME).read_bytes() == previous
    assert not list(tmp_path.glob(".happ-shared-*"))


def test_readers_see_valid_previous_or_next_snapshot_at_atomic_boundary(tmp_path, monkeypatch):
    first = successful(tmp_path)
    original = rules.os.replace
    observed = []

    def replace(source, destination):
        observed.append(rules.load_snapshot(tmp_path, URL)["rules"])
        original(source, destination)
        observed.append(rules.load_snapshot(tmp_path, URL)["rules"])

    monkeypatch.setattr(rules.os, "replace", replace)
    next_snapshot = successful(tmp_path, b"github.com", LATER)
    assert observed == [first["rules"], next_snapshot["rules"]]


def test_refreshes_are_serialized(tmp_path):
    first_entered, release, second_entered = (threading.Event() for _ in range(3))
    errors = []

    def first(*args, **kwargs):
        first_entered.set()
        assert release.wait(3)
        return b"example.com"

    def second(*args, **kwargs):
        second_entered.set()
        return b"github.com"

    def work(downloader):
        try:
            rules.sync(tmp_path, URL, fetch=downloader, now=NOW)
        except (ValueError, AssertionError, OSError) as error:
            errors.append(error)

    one = threading.Thread(target=work, args=(first,))
    two = threading.Thread(target=work, args=(second,))
    one.start()
    assert first_entered.wait(3)
    two.start()
    assert not second_entered.wait(0.05)
    release.set()
    one.join(3)
    two.join(3)
    assert not one.is_alive() and not two.is_alive() and not errors
    assert rules.load_snapshot(tmp_path, URL)["rules"] == ["domain:github.com"]


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://raw.githubusercontent.com/list",
        "file:///etc/passwd",
        "https://user:secret@example.com/list",
        "https://@example.com/list",
        "https://example.com:0/list",
        "https://example.com:65536/list",
        "https://example.com:bad/list",
        "https://localhost/list",
        "https://127.0.0.1/list",
        "https://router.internal/list",
        "https://example.com/list#fragment",
        "https://example.com/list\nsecret",
        "https://example.com\\evil/list",
    ],
)
def test_invalid_source_url_rejected_without_fetch_or_files(tmp_path, url):
    called = []
    with pytest.raises(ValueError):
        rules.sync(tmp_path / "new", url, fetch=lambda *a, **kw: called.append(1), now=NOW)
    assert not called and not (tmp_path / "new").exists()


@pytest.mark.parametrize(
    "target",
    [
        "http://raw.githubusercontent.com/list",
        "https://example.com/list",
        "https://raw.githubusercontent.com:444/list",
        "https://user:secret@raw.githubusercontent.com/list",
    ],
)
def test_redirects_cannot_downgrade_change_origin_or_add_auth(target):
    with pytest.raises(ValueError):
        rules._SameOriginRedirect().redirect_request(Request(URL), None, 302, "Found", {}, target)


def test_same_origin_https_redirect_permitted():
    target = "https://raw.githubusercontent.com/new-path"
    request = rules._SameOriginRedirect().redirect_request(
        Request(URL), None, 302, "Found", {}, target
    )
    assert request.full_url == target


def test_default_fetch_uses_verified_tls_bounded_read_and_timeout(monkeypatch):
    class Response:
        def __init__(self):
            self.headers = {"Content-Length": "11"}

        def geturl(self):
            return URL

        def read(self, size):
            assert size == 65537
            return b"example.com"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == URL and timeout == 15
            return Response()

    def build(*handlers):
        https = next(
            handler
            for handler in handlers
            if isinstance(handler, rules.urllib.request.HTTPSHandler)
        )
        assert https._context.verify_mode == ssl.CERT_REQUIRED and https._context.check_hostname
        assert any(isinstance(handler, rules._SameOriginRedirect) for handler in handlers)
        return Opener()

    monkeypatch.setattr(rules.urllib.request, "build_opener", build)
    assert rules._fetch(URL, timeout=15, max_bytes=65536) == b"example.com"


def test_environment_source_and_utc_conversion(tmp_path, monkeypatch):
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_URL", URL)
    now = NOW.astimezone(__import__("datetime").timezone(timedelta(hours=3)))
    snapshot = rules.sync(tmp_path, fetch=fetch(), now=now)
    assert snapshot["last_success"] == "2026-11-12T12:30:00Z"
    assert rules.load_snapshot(tmp_path) == snapshot
    with pytest.raises(ValueError, match="clock"):
        rules.sync(tmp_path, URL, fetch=fetch(), now=datetime(2026, 11, 12))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions and symlink semantics")
def test_permissions_and_symlinks(tmp_path):
    data = tmp_path / "cache"
    successful(data)
    assert data.stat().st_mode & 0o777 == 0o700
    assert (data / rules.CACHE_NAME).stat().st_mode & 0o777 == 0o600
    assert (data / (rules.CACHE_NAME + ".lock")).stat().st_mode & 0o777 == 0o600
    (data / rules.CACHE_NAME).chmod(0o644)
    with pytest.raises(ValueError):
        rules.load_snapshot(data, URL)
    (data / rules.CACHE_NAME).unlink()
    target = tmp_path / "outside"
    target.write_text("keep unchanged")
    (data / rules.CACHE_NAME).symlink_to(target)
    with pytest.raises(ValueError):
        rules.load_snapshot(data, URL)
    successful(data)
    assert target.read_text() == "keep unchanged"
    linked = tmp_path / "linked"
    linked.symlink_to(data, target_is_directory=True)
    with pytest.raises(ValueError):
        rules.load_snapshot(linked, URL)
    with pytest.raises(ValueError):
        successful(linked)


def test_cli_reports_no_source_or_private_diagnostics(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        rules, "sync", lambda *args: (_ for _ in ()).throw(ValueError("synthetic-private-token"))
    )
    assert rules.main(["--sync", "--data-dir", str(tmp_path), "--source-url", URL]) == 1
    assert capsys.readouterr().out == "Shared routing list refresh failed\n"


def test_standalone_script_does_not_import_application(tmp_path):
    code = f"""import builtins, runpy
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name == 'flask' or name == 'wg_panel' or name.startswith('wg_panel.'):
        raise AssertionError('Application import forbidden')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
runpy.run_path({str(MODULE_PATH)!r}, run_name='standalone_check')
print('standalone stdlib import passed')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0 and result.stdout.strip() == "standalone stdlib import passed"


def test_timer_does_not_restart_or_depend_on_network_services():
    directory = MODULE_PATH.parents[2] / "systemd"
    service = (directory / "wg-panel-happ-rules.service").read_text()
    timer = (directory / "wg-panel-happ-rules.timer").read_text()
    assert "EnvironmentFile=-/etc/wg-panel/wg-panel.env" in service
    assert "happ_shared_rules.py --sync" in service
    assert "TimeoutStartSec=40" in service and "UMask=0077" in service
    assert not any(
        word in service
        for word in ("wg0", "dnsdist", "safe-internet", "restart", "Requires=wg-panel")
    )
    assert "OnBootSec=2min" in timer and "OnUnitActiveSec=5min" in timer


@pytest.fixture
def bare_git(tmp_path):
    if not shutil.which("git"):
        pytest.skip("Git is required for the read-only mirror integration checks")
    directory = tmp_path / "synthetic.git"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Synthetic Fixture",
            "GIT_AUTHOR_EMAIL": "synthetic@example.com",
            "GIT_COMMITTER_NAME": "Synthetic Fixture",
            "GIT_COMMITTER_EMAIL": "synthetic@example.com",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )

    def git(*args, data=None):
        return subprocess.run(
            ["git", "-c", "commit.gpgsign=false", f"--git-dir={directory}", *args],
            input=data,
            capture_output=True,
            check=True,
            env=environment,
            timeout=5,
        ).stdout.strip()

    subprocess.run(
        ["git", "init", "--bare", str(directory)],
        env=environment,
        capture_output=True,
        check=True,
        timeout=5,
    )

    def commit(payload=b"github.com\nexample.com\n", mode="100644", filename="routing-domains.txt"):
        blob = git("hash-object", "-w", "--stdin", data=payload)
        tree = git(
            "mktree", data=mode.encode() + b" blob " + blob + b"\t" + filename.encode() + b"\n"
        )
        revision = git("commit-tree", tree.decode(), "-m", "test: add synthetic routing domains")
        git("update-ref", "refs/heads/main", revision.decode())
        fetch_head = directory / "FETCH_HEAD"
        fetch_head.write_bytes(revision + b"\t\tbranch 'main' of synthetic-local\n")
        os.utime(fetch_head, (NOW.timestamp(), NOW.timestamp()))
        return blob.decode()

    commit()
    return directory, commit


def test_git_mirror_sync_is_read_only_and_uses_no_https(tmp_path, bare_git, monkeypatch):
    mirror, commit = bare_git
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_GIT_DIR", str(mirror))
    https_calls = []
    monkeypatch.setattr(rules, "_fetch", lambda *args, **kwargs: https_calls.append(True))
    before = {
        str(path.relative_to(mirror)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in mirror.rglob("*")
        if path.is_file()
    }
    snapshot = rules.sync(tmp_path / "cache", URL, now=NOW)
    after = {
        str(path.relative_to(mirror)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in mirror.rglob("*")
        if path.is_file()
    }
    assert before == after and not https_calls
    assert snapshot["rules"] == ["domain:example.com", "domain:github.com"]
    commit(b"cloudflare.com\n")
    next_snapshot = rules.sync(tmp_path / "cache", URL, now=LATER)
    assert next_snapshot["rules"] == ["domain:cloudflare.com"]
    assert next_snapshot["revision"] != snapshot["revision"]


@pytest.mark.parametrize("age", [901, -61])
def test_stale_or_future_mirror_keeps_last_good_without_https(tmp_path, bare_git, monkeypatch, age):
    mirror, _ = bare_git
    cache = tmp_path / "cache"
    previous = successful(cache)
    timestamp = LATER.timestamp() - age
    os.utime(mirror / "FETCH_HEAD", (timestamp, timestamp))
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_GIT_DIR", str(mirror))
    calls = []
    monkeypatch.setattr(rules, "_fetch", lambda *args, **kwargs: calls.append(True))
    snapshot = rules.sync(cache, URL, now=LATER)
    assert snapshot["rules"] == previous["rules"] and snapshot["error"]
    assert snapshot["last_success"] == previous["last_success"]
    assert snapshot["last_checked"] == "2026-11-12T12:35:00Z" and not calls


@pytest.mark.parametrize("mode", ["100755", "120000"])
def test_git_reader_rejects_executable_and_symlink_blob_modes(
    tmp_path, bare_git, monkeypatch, mode
):
    mirror, commit = bare_git
    commit(mode=mode)
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_GIT_DIR", str(mirror))
    with pytest.raises(ValueError, match="refresh failed"):
        rules.sync(tmp_path / "cache", URL, now=NOW)


@pytest.mark.parametrize("case", ["oversize", "empty", "missing-file", "malformed-head"])
def test_git_invalid_object_or_head_never_exports_empty(tmp_path, bare_git, monkeypatch, case):
    mirror, commit = bare_git
    if case == "oversize":
        commit(b"x" * 65537)
    elif case == "empty":
        commit(b"")
    elif case == "missing-file":
        commit(filename="different.txt")
    else:
        (mirror / "FETCH_HEAD").write_bytes(b"not-a-commit\n")
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_GIT_DIR", str(mirror))
    with pytest.raises(ValueError, match="refresh failed"):
        rules.sync(tmp_path / "cache", URL, now=NOW)
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path / "cache", URL)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/synthetic/safe-internet/main/routing-domains.txt",
        "https://raw.githubusercontent.com/synthetic/safe-internet/dev/routing-domains.txt",
        "https://raw.githubusercontent.com/synthetic/safe-internet/main/proxy-domains.txt",
        "https://raw.githubusercontent.com/synthetic/safe-internet/main/subdir/routing-domains.txt",
        "https://raw.githubusercontent.com/synthetic/safe-internet/main/../routing-domains.txt",
        "https://raw.githubusercontent.com/synthetic/safe-internet/main/%72outing-domains.txt",
        URL + "?token=synthetic-private-token",
    ],
)
def test_git_source_path_is_strict_and_does_not_reuse_dns_blocklist(url):
    with pytest.raises(ValueError):
        rules._git_source_path(url)
    assert rules._git_source_path(URL) == "routing-domains.txt"


def test_git_stdout_and_timeout_are_bounded(bare_git, monkeypatch):
    mirror, commit = bare_git
    blob = commit(b"example.com\n" * 100)
    with pytest.raises(ValueError, match="refresh failed"):
        rules._git_run(mirror, ["cat-file", "blob", blob], limit=10, timeout=2)
    original = rules.subprocess.Popen
    processes = []

    def sleeping(*args, **kwargs):
        process = original([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(rules.subprocess, "Popen", sleeping)
    started = time.monotonic()
    with pytest.raises(ValueError, match="refresh failed"):
        rules._git_run(mirror, ["rev-parse", "HEAD"], limit=128, timeout=0.05)
    assert time.monotonic() - started < 3 and processes[0].poll() is not None


def test_git_environment_disables_credentials_hooks_and_fetch(bare_git, monkeypatch):
    mirror, _ = bare_git
    original = rules.subprocess.Popen
    calls = []

    def capture(command, **kwargs):
        calls.append((command, kwargs["env"]))
        return original(command, **kwargs)

    monkeypatch.setenv("GIT_SSH_COMMAND", "synthetic-do-not-execute")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "credential.helper")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "synthetic-do-not-execute")
    monkeypatch.setattr(rules.subprocess, "Popen", capture)
    payload = rules._fetch_git(URL, git_dir=mirror, now=NOW, timeout=15, max_bytes=65536)
    assert payload == b"github.com\nexample.com\n" and len(calls) == 4
    for command, environment in calls:
        assert "core.hooksPath=/dev/null" in command and "core.fsmonitor=false" in command
        assert "credential.helper=" in command and "protocol.allow=never" in command
        assert environment["GIT_OPTIONAL_LOCKS"] == "0"
        assert environment["GIT_TERMINAL_PROMPT"] == "0" and environment["GIT_ALLOW_PROTOCOL"] == ""
        assert environment["GIT_NO_LAZY_FETCH"] == "1" and environment["GIT_CONFIG_COUNT"] == "0"
        assert "GIT_CONFIG_KEY_0" not in environment and "GIT_SSH_COMMAND" not in environment
        assert not any(argument in command for argument in ("fetch", "reset", "checkout"))


def test_git_head_race_and_blob_size_mismatch_rejected(bare_git, monkeypatch):
    mirror, _ = bare_git
    original = rules._git_run

    def change_head(directory, arguments, **kwargs):
        result = original(directory, arguments, **kwargs)
        if arguments[:2] == ["cat-file", "blob"]:
            path = mirror / "FETCH_HEAD"
            os.utime(path, (NOW.timestamp() + 1, NOW.timestamp() + 1))
        return result

    monkeypatch.setattr(rules, "_git_run", change_head)
    with pytest.raises(ValueError):
        rules._fetch_git(URL, git_dir=mirror, now=NOW, timeout=15, max_bytes=65536)
    monkeypatch.setattr(
        rules,
        "_git_run",
        lambda directory, arguments, **kwargs: (
            b"too-many-bytes"
            if arguments[:2] == ["cat-file", "blob"]
            else original(directory, arguments, **kwargs)
        ),
    )
    with pytest.raises(ValueError):
        rules._fetch_git(URL, git_dir=mirror, now=NOW, timeout=15, max_bytes=65536)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink semantics")
def test_git_directory_and_fetch_head_symlinks_rejected(tmp_path, bare_git):
    mirror, _ = bare_git
    linked = tmp_path / "linked.git"
    linked.symlink_to(mirror, target_is_directory=True)
    with pytest.raises(ValueError):
        rules._fetch_git(URL, git_dir=linked, now=NOW, timeout=15, max_bytes=65536)
    original = mirror / "FETCH_HEAD"
    contents = original.read_bytes()
    original.unlink()
    target = tmp_path / "original-head"
    target.write_bytes(contents)
    original.symlink_to(target)
    with pytest.raises(ValueError):
        rules._fetch_git(URL, git_dir=mirror, now=NOW, timeout=15, max_bytes=65536)


@pytest.fixture
def managed_cache(tmp_path, monkeypatch):
    monkeypatch.delenv("WG_PANEL_HAPP_RULES_MANAGED", raising=False)
    snapshot = successful(tmp_path)
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_MANAGED", "1")
    return snapshot


@pytest.mark.parametrize(
    "value,enabled", [(None, False), ("", False), ("0", False), ("true", False), ("1", True)]
)
def test_managed_mode_requires_explicit_opt_in(monkeypatch, value, enabled):
    if value is None:
        monkeypatch.delenv("WG_PANEL_HAPP_RULES_MANAGED", raising=False)
    else:
        monkeypatch.setenv("WG_PANEL_HAPP_RULES_MANAGED", value)
    assert rules.managed_mode() is enabled


def test_managed_sync_is_read_only_and_never_imports_external_changes(
    tmp_path, managed_cache, monkeypatch
):
    changed = rules.change(tmp_path, URL, "add", "cloudflare.com", managed_cache["revision"])
    path = tmp_path / rules.CACHE_NAME
    lock = tmp_path / (rules.CACHE_NAME + ".lock")
    lock.unlink()
    before = path.read_bytes(), path.stat().st_mtime_ns, set(tmp_path.iterdir())
    calls = []
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_GIT_DIR", "/synthetic/unused.git")
    monkeypatch.setattr(rules, "_fetch_git", lambda *a, **kw: calls.append("git"))
    monkeypatch.setattr(rules, "_fetch", lambda *a, **kw: calls.append("https"))
    result = rules.sync(
        tmp_path, URL, fetch=lambda *a, **kw: calls.append("injected"), now="ignored"
    )
    assert result == changed and not calls
    assert (path.read_bytes(), path.stat().st_mtime_ns, set(tmp_path.iterdir())) == before


def test_managed_missing_or_bad_cache_has_no_bootstrap_or_git_resurrection(tmp_path, monkeypatch):
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_MANAGED", "1")
    missing = tmp_path / "missing"
    calls = []
    with pytest.raises(ValueError):
        rules.sync(missing, URL, fetch=lambda *a, **kw: calls.append(True))
    assert not missing.exists() and not calls
    path = tmp_path / rules.CACHE_NAME
    path.write_bytes(b"broken-cache")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        rules.sync(tmp_path, URL, fetch=lambda *a, **kw: b"github.com")
    assert path.read_bytes() == b"broken-cache"


def test_managed_add_remove_is_canonical_versioned_and_does_not_publish(tmp_path, managed_cache):
    added = rules.change(tmp_path, URL, "add", "домен.рф", managed_cache["revision"])
    assert added["rules"] == [
        "domain:example.com",
        "domain:github.com",
        "domain:xn--d1acufc.xn--p1ai",
    ]
    assert added["revision"] != managed_cache["revision"] and added["error"] is None
    assert added["last_checked"] == added["last_success"]
    assert not (tmp_path / rules.PUBLICATION_NAME).exists()
    removed = rules.change(tmp_path, URL, "remove", "domain:example.com", added["revision"])
    assert removed["rules"] == ["domain:github.com", "domain:xn--d1acufc.xn--p1ai"]
    assert rules.load_snapshot(tmp_path, URL) == removed


@pytest.mark.parametrize("operation,domain", [("add", "example.com"), ("remove", "cloudflare.com")])
def test_managed_noop_preserves_cache_bytes_revision_and_timestamps(
    tmp_path, managed_cache, operation, domain
):
    path = tmp_path / rules.CACHE_NAME
    before = path.read_bytes(), path.stat().st_mtime_ns
    assert (
        rules.change(tmp_path, URL, operation, domain, managed_cache["revision"]) == managed_cache
    )
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize("revision", [None, 1, "1", "a" * 64])
def test_managed_revision_guard_is_exact_sha(tmp_path, managed_cache, revision):
    with pytest.raises(ValueError, match="^stale_revision$"):
        rules.change(tmp_path, URL, "add", "cloudflare.com", revision)
    assert rules.load_snapshot(tmp_path, URL) == managed_cache


@pytest.mark.parametrize(
    "operation,domain",
    [
        ("clear", "example.com"),
        ("add", "localhost"),
        ("add", "127.0.0.1"),
        ("add", "https://example.com"),
        ("add", "*.example.com"),
        ("add", "example.com\nother.com"),
        ("remove", None),
    ],
)
def test_managed_bad_input_has_stable_error_and_no_changes(
    tmp_path, managed_cache, operation, domain
):
    with pytest.raises(ValueError, match="^invalid_domain$"):
        rules.change(tmp_path, URL, operation, domain, managed_cache["revision"])
    assert rules.load_snapshot(tmp_path, URL) == managed_cache


def test_unmanaged_changes_are_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("WG_PANEL_HAPP_RULES_MANAGED", raising=False)
    with pytest.raises(ValueError, match="^unavailable$"):
        rules.change(tmp_path / "missing", URL, "add", "example.com", "a" * 64)
    assert not (tmp_path / "missing").exists()


def test_intentional_empty_list_is_available_only_in_managed_mode(
    tmp_path, managed_cache, monkeypatch
):
    one = rules.change(tmp_path, URL, "remove", "example.com", managed_cache["revision"])
    empty = rules.change(tmp_path, URL, "remove", "github.com", one["revision"])
    assert empty["rules"] == [] and len(empty["revision"]) == 64
    assert rules.load_snapshot(tmp_path, URL) == rules.sync(tmp_path, URL) == empty
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_MANAGED", "0")
    with pytest.raises(ValueError):
        rules.load_snapshot(tmp_path, URL)
    with pytest.raises(ValueError):
        rules._parse_rules(b"")


def test_concurrent_managed_changes_allow_one_winner(tmp_path, managed_cache):
    barrier = threading.Barrier(2)
    results, errors = [], []

    def edit(domain):
        barrier.wait(timeout=3)
        try:
            results.append(rules.change(tmp_path, URL, "add", domain, managed_cache["revision"]))
        except ValueError as error:
            errors.append(str(error))

    threads = [
        threading.Thread(target=edit, args=(domain,)) for domain in ("cloudflare.com", "python.org")
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3)
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 1 and errors == ["stale_revision"]
    assert rules.load_snapshot(tmp_path, URL) == results[0]


def test_managed_failed_atomic_write_preserves_authority(tmp_path, managed_cache, monkeypatch):
    path = tmp_path / rules.CACHE_NAME
    before = path.read_bytes()

    def fail(*args):
        raise OSError("synthetic-private-diagnostic")

    monkeypatch.setattr(rules.os, "replace", fail)
    with pytest.raises(ValueError, match="^unavailable$"):
        rules.change(tmp_path, URL, "add", "cloudflare.com", managed_cache["revision"])
    assert path.read_bytes() == before and not list(tmp_path.glob(".happ-shared-*"))


def publication(status="updated", revision="a" * 64):
    return {
        "status": status,
        "last_attempt_at": "2026-11-12T12:35:00Z",
        "last_success_at": "2026-11-12T12:35:00Z",
        "commit": "b" * 40,
        "published_revision": revision,
    }


def test_missing_publication_metadata_is_never_and_read_only(tmp_path):
    missing = tmp_path / "missing"
    assert rules.publication_status(missing, "a" * 64) == {
        "status": "never",
        "last_attempt_at": None,
        "last_success_at": None,
        "commit": None,
        "published_revision": None,
    }
    assert not missing.exists()


def test_publication_pending_error_and_recovery_do_not_invalidate_active_list(
    tmp_path, managed_cache
):
    initial = publication(revision=managed_cache["revision"])
    assert rules.write_publication_status(tmp_path, initial) == initial
    assert rules.publication_status(tmp_path, managed_cache["revision"])["status"] == "updated"
    changed = rules.change(tmp_path, URL, "add", "cloudflare.com", managed_cache["revision"])
    pending = rules.publication_status(tmp_path, changed["revision"])
    assert (
        pending["status"] == "pending"
        and pending["published_revision"] == managed_cache["revision"]
    )
    failure = {**initial, "status": "error"}
    rules.write_publication_status(tmp_path, failure)
    assert rules.publication_status(tmp_path, changed["revision"])["status"] == "error"
    assert rules.load_snapshot(tmp_path, URL) == changed
    success = publication("unchanged", changed["revision"])
    rules.write_publication_status(tmp_path, success)
    assert rules.publication_status(tmp_path, changed["revision"]) == success


def test_first_publication_attempt_pending_metadata_allowed(tmp_path):
    first = {
        "status": "pending",
        "last_attempt_at": "2026-11-12T12:35:00Z",
        "last_success_at": None,
        "commit": None,
        "published_revision": None,
    }
    rules.write_publication_status(tmp_path, first)
    assert rules.publication_status(tmp_path, "a" * 64) == first


@pytest.mark.parametrize(
    "change",
    [
        {"status": "secret-error-content"},
        {"commit": "not-a-commit"},
        {"published_revision": "not-a-hash"},
        {"last_attempt_at": "invalid-date"},
        {"last_success_at": 1},
        {"extra_secret": "synthetic-private-diagnostic"},
    ],
)
def test_bad_publication_metadata_is_sanitized_and_cache_remains_usable(
    tmp_path, managed_cache, change
):
    record = {**publication(), **change}
    path = tmp_path / rules.PUBLICATION_NAME
    path.write_text(json.dumps(record))
    path.chmod(0o600)
    status = rules.publication_status(tmp_path, managed_cache["revision"])
    assert status == {
        "status": "error",
        "last_attempt_at": None,
        "last_success_at": None,
        "commit": None,
        "published_revision": None,
    }
    assert rules.load_snapshot(tmp_path, URL) == managed_cache
    with pytest.raises(ValueError, match="^Invalid publication status$"):
        rules.write_publication_status(tmp_path, record)


def test_publication_reads_do_not_create_locks_or_rewrite_file(tmp_path):
    record = publication()
    rules.write_publication_status(tmp_path, record)
    lock = tmp_path / (rules.PUBLICATION_NAME + ".lock")
    lock.unlink()
    path = tmp_path / rules.PUBLICATION_NAME
    before = path.read_bytes(), path.stat().st_mtime_ns, set(tmp_path.iterdir())
    assert rules.publication_status(tmp_path, "a" * 64) == record
    assert (path.read_bytes(), path.stat().st_mtime_ns, set(tmp_path.iterdir())) == before


def test_failed_publication_write_preserves_previous_status_and_active_rules(
    tmp_path, managed_cache, monkeypatch
):
    record = publication(revision=managed_cache["revision"])
    rules.write_publication_status(tmp_path, record)
    path = tmp_path / rules.PUBLICATION_NAME
    before = path.read_bytes()

    def fail(*args):
        raise OSError("synthetic-private-diagnostic")

    monkeypatch.setattr(rules.os, "replace", fail)
    with pytest.raises(ValueError, match="^Invalid publication status$"):
        rules.write_publication_status(tmp_path, {**record, "status": "error"})
    assert path.read_bytes() == before
    assert rules.load_snapshot(tmp_path, URL) == managed_cache


def test_managed_add_cannot_exceed_256_rules(tmp_path, monkeypatch):
    monkeypatch.delenv("WG_PANEL_HAPP_RULES_MANAGED", raising=False)
    initial = successful(tmp_path, "\n".join(f"host{i}.example.com" for i in range(256)).encode())
    monkeypatch.setenv("WG_PANEL_HAPP_RULES_MANAGED", "1")
    with pytest.raises(ValueError, match="^invalid_domain$"):
        rules.change(tmp_path, URL, "add", "cloudflare.com", initial["revision"])
    assert rules.load_snapshot(tmp_path, URL) == initial


def test_invalid_publication_json_does_not_affect_current_cache(tmp_path, managed_cache):
    path = tmp_path / rules.PUBLICATION_NAME
    path.write_bytes(b"invalid private diagnostic data")
    path.chmod(0o600)
    result = rules.publication_status(tmp_path, managed_cache["revision"])
    assert result["status"] == "error" and result["commit"] is None
    assert "private diagnostic" not in json.dumps(result)
    assert rules.load_snapshot(tmp_path, URL) == managed_cache
