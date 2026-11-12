"""Standalone updater for the shared Happ routing domain list.

Reads never create directories, lock files or an empty default list. Refreshes
retain the last validated snapshot on network/source failure. This module can
run as a script without importing the Flask application or its credentials.
An operator-configured Git mirror is read without fetching or authentication.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import unicodedata
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    import fcntl
except ImportError:  # Windows development; production uses flock.
    fcntl = None
    import msvcrt

CACHE_NAME = "happ_shared_rules.json"
PUBLICATION_NAME = "happ_routing_publish.json"
MAX_BYTES = 64 * 1024
MAX_RULES = 256
HTTP_TIMEOUT = 15
GIT_MAX_AGE = 900
GIT_MAX_FUTURE = 60
_LOCK = threading.RLock()
_CACHE_ERROR = "Shared routing list cache is unavailable or invalid"
_SOURCE_ERROR = "Shared routing list source is unavailable or invalid"
_REFRESH_ERROR = "Shared routing list refresh failed"
_WRITE_ERROR = "Shared routing list cache could not be written"
_PUBLICATION_FIELDS = {
    "status",
    "last_attempt_at",
    "last_success_at",
    "commit",
    "published_revision",
}
_PUBLICATION_STATES = {"never", "pending", "updated", "unchanged", "error"}
_PRIVATE_SUFFIXES = {
    "alt",
    "arpa",
    "corp",
    "example",
    "home",
    "i2p",
    "internal",
    "intranet",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "onion",
    "private",
    "test",
}
_FIELDS = {
    "version",
    "source_url",
    "rules",
    "sha256",
    "revision",
    "last_checked",
    "last_success",
    "error",
}


def _domain(value):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(char.isspace() or unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValueError(_SOURCE_ERROR)
    if value.lower().startswith("domain:"):
        value = value[7:]
    value = value.removesuffix(".")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError(_SOURCE_ERROR)
    value = value.encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if (
        len(labels) < 2
        or len(value) > 253
        or labels[-1] in _PRIVATE_SUFFIXES
        or not re.fullmatch(r"(?:[a-z]{2,63}|xn--[a-z0-9-]+)", labels[-1])
        or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    ):
        raise ValueError(_SOURCE_ERROR)
    for label in labels:
        # ASCII IDNA input is otherwise passed through without validation.
        if (
            label.startswith("xn--")
            and label.encode("ascii").decode("idna").encode("idna").decode("ascii") != label
        ):
            raise ValueError(_SOURCE_ERROR)
    return value


def _source_url(value):
    if value is None:
        value = os.environ.get("WG_PANEL_HAPP_RULES_URL", "")
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(char.isspace() or unicodedata.category(char).startswith("C") for char in value)
        or "\\" in value
    ):
        raise ValueError(_SOURCE_ERROR)
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(_SOURCE_ERROR)
        host = _domain(parsed.hostname)
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError(_SOURCE_ERROR)
        authority = host + (f":{port}" if port not in (None, 443) else "")
        return urlunsplit(("https", authority, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError):
        raise ValueError(_SOURCE_ERROR) from None


def managed_mode():
    """Explicitly opt into the panel-owned list; external sources become read-only backups."""
    return os.environ.get("WG_PANEL_HAPP_RULES_MANAGED", "").strip() == "1"


def _parse_rules(data, *, allow_empty=False):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError(_SOURCE_ERROR)
    text = data.decode("utf-8-sig")
    if any(unicodedata.category(char).startswith("C") and char not in "\r\n" for char in text):
        raise ValueError(_SOURCE_ERROR)
    values = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    values = [value for value in values if value]
    if len(values) > MAX_RULES or (not values and not allow_empty):
        raise ValueError(_SOURCE_ERROR)
    return sorted({"domain:" + _domain(value) for value in values})


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = _source_url(newurl)
        if urlsplit(target).netloc != urlsplit(_source_url(req.full_url)).netloc:
            raise ValueError(_REFRESH_ERROR)
        return super().redirect_request(req, fp, code, msg, headers, target)


def _fetch(url, *, timeout, max_bytes):
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _SameOriginRedirect(),
    )
    request = urllib.request.Request(url, headers={"User-Agent": "wg-panel-happ-rules/1"})
    with opener.open(request, timeout=timeout) as response:
        # Same-origin path redirects are permitted, never another host/port.
        if urlsplit(_source_url(response.geturl())).netloc != urlsplit(url).netloc:
            raise ValueError(_REFRESH_ERROR)
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > max_bytes):
            raise ValueError(_REFRESH_ERROR)
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(_REFRESH_ERROR)
    return data


def _git_source_path(url):
    parsed = urlsplit(_source_url(url))
    if (
        parsed.netloc != "raw.githubusercontent.com"
        or parsed.query
        or not re.fullmatch(
            r"/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*/main/routing-domains\.txt",
            parsed.path,
        )
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise ValueError(_SOURCE_ERROR)
    return "routing-domains.txt"


def _git_run(directory, arguments, *, limit, timeout):
    """Bound stdout and execution without executing hooks or Git transports."""
    if timeout <= 0:
        raise ValueError(_REFRESH_ERROR)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_ASKPASS": "",
        }
    )
    command = [
        "git",
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.allow=never",
        f"--git-dir={directory}",
        *arguments,
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output, errors = [], []

    def read_output():
        try:
            output.append(process.stdout.read(limit + 1))
        except OSError as error:
            errors.append(error)

    reader = threading.Thread(target=read_output, daemon=True)
    deadline = time.monotonic() + timeout
    try:
        reader.start()
        reader.join(timeout)
        if reader.is_alive() or errors or not output or len(output[0]) > limit:
            raise ValueError(_REFRESH_ERROR)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise ValueError(_REFRESH_ERROR)
        return output[0]
    except subprocess.TimeoutExpired:
        raise ValueError(_REFRESH_ERROR) from None
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        reader.join(2)
        process.stdout.close()


def _fetch_git(url, *, git_dir, now, timeout, max_bytes):
    filename = _git_source_path(url)
    directory = Path(git_dir)
    info = directory.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & reparse:
        raise ValueError(_REFRESH_ERROR)
    fetch_head = directory / "FETCH_HEAD"
    initial = fetch_head.lstat()
    age = now.timestamp() - initial.st_mtime
    if not _regular(initial) or age > GIT_MAX_AGE or age < -GIT_MAX_FUTURE:
        raise ValueError(_REFRESH_ERROR)
    deadline = time.monotonic() + timeout

    def run(arguments, limit):
        return _git_run(directory, arguments, limit=limit, timeout=deadline - time.monotonic())

    commit = run(["rev-parse", "--verify", "FETCH_HEAD^{commit}"], 128).strip()
    if not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
        raise ValueError(_REFRESH_ERROR)
    entry = run(["ls-tree", "-z", commit.decode("ascii"), "--", filename], 512)
    match = re.fullmatch(rb"100644 blob ([0-9a-f]{40}|[0-9a-f]{64})\trouting-domains\.txt\0", entry)
    if not match:
        raise ValueError(_REFRESH_ERROR)
    blob = match[1].decode("ascii")
    size = run(["cat-file", "-s", blob], 32).strip()
    if not size.isdigit() or not 1 <= int(size) <= max_bytes:
        raise ValueError(_REFRESH_ERROR)
    data = run(["cat-file", "blob", blob], max_bytes)
    current = fetch_head.lstat()
    if (
        len(data) != int(size)
        or not _regular(current)
        or not os.path.samestat(initial, current)
        or (initial.st_mtime_ns, initial.st_size) != (current.st_mtime_ns, current.st_size)
    ):
        raise ValueError(_REFRESH_ERROR)
    return data


def _regular(info):
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISREG(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & reparse)


def _timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise ValueError(_CACHE_ERROR)
    datetime.fromisoformat(value)
    return value


def _revision(rules):
    return hashlib.sha256(
        json.dumps(rules, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read_cache(data_dir, source, *, allow_empty=False):
    try:
        directory = Path(data_dir)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(_CACHE_ERROR)
        path = directory / CACHE_NAME
        initial = path.lstat()
        if not _regular(initial) or initial.st_size > MAX_BYTES:
            raise ValueError(_CACHE_ERROR)
        if os.name == "posix" and initial.st_mode & 0o077:
            raise ValueError(_CACHE_ERROR)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _regular(opened) or not os.path.samestat(initial, opened):
                raise ValueError(_CACHE_ERROR)
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError(_CACHE_ERROR)
        record = json.loads(raw)
        if (
            not isinstance(record, dict)
            or set(record) != _FIELDS
            or type(record["version"]) is not int
            or record["version"] != 1
            or record["source_url"] != source
            or not isinstance(record["rules"], list)
            or (not record["rules"] and not allow_empty)
            or len(record["rules"]) > MAX_RULES
            or not all(isinstance(rule, str) for rule in record["rules"])
            or _parse_rules("\n".join(record["rules"]).encode(), allow_empty=allow_empty)
            != record["rules"]
            or record["sha256"] != _revision(record["rules"])
            or record["revision"] != record["sha256"]
            or record["error"] not in (None, _REFRESH_ERROR)
        ):
            raise ValueError(_CACHE_ERROR)
        _timestamp(record["last_checked"])
        _timestamp(record["last_success"])
        return record
    except (OSError, ValueError, TypeError, UnicodeError):
        raise ValueError(_CACHE_ERROR) from None


def _snapshot(record):
    return {
        key: (list(record[key]) if key == "rules" else record[key])
        for key in ("rules", "revision", "last_checked", "last_success", "error")
    }


def load_snapshot(data_dir, source_url=None):
    """Read a validated matching cache without creating or changing any files."""
    return _snapshot(_read_cache(data_dir, _source_url(source_url), allow_empty=managed_mode()))


@contextmanager
def _sync_lock(data_dir, *, lock_name=CACHE_NAME + ".lock"):
    directory = Path(data_dir)
    if directory.is_symlink():
        raise ValueError(_WRITE_ERROR)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / lock_name
    try:
        if not _regular(path.lstat()):
            raise ValueError(_WRITE_ERROR)
    except FileNotFoundError:
        pass
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    with _LOCK, os.fdopen(os.open(path, flags, 0o600), "r+b") as stream:
        if not _regular(os.fstat(stream.fileno())):
            raise ValueError(_WRITE_ERROR)
        path.chmod(0o600)
        if fcntl:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        else:  # pragma: no cover - executed by Windows rather than Linux CI.
            if os.fstat(stream.fileno()).st_size == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield directory
        finally:
            if fcntl:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            else:  # pragma: no cover
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def _cache_bytes(record):
    data = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
    if len(data) > MAX_BYTES:
        raise ValueError(_WRITE_ERROR)
    return data


def _write_cache(directory, record, *, filename=CACHE_NAME):
    data = _cache_bytes(record)
    fd, name = tempfile.mkstemp(prefix=".happ-shared-", dir=directory)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            temporary.chmod(0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / filename)
        if os.name == "posix":
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def sync(data_dir, source_url=None, *, fetch=None, now=None):
    """Refresh, or retain last-good rules with a generic error status.

    ``fetch(url, *, timeout, max_bytes)`` can inject a bytes-returning downloader.
    ``now`` can inject an aware datetime. A failure without a usable matching
    snapshot raises ValueError; it never creates an empty export.
    """
    if managed_mode():
        return load_snapshot(data_dir, source_url)
    source = _source_url(source_url)
    current = datetime.now(UTC) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("Invalid shared routing list clock")
    checked = current.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        with _sync_lock(data_dir) as directory:
            try:
                previous = _read_cache(directory, source)
            except ValueError:
                previous = None
            try:
                git_dir = os.environ.get("WG_PANEL_HAPP_RULES_GIT_DIR")
                if fetch is None and git_dir:
                    data = _fetch_git(
                        source,
                        git_dir=git_dir,
                        now=current,
                        timeout=HTTP_TIMEOUT,
                        max_bytes=MAX_BYTES,
                    )
                else:
                    data = (fetch or _fetch)(source, timeout=HTTP_TIMEOUT, max_bytes=MAX_BYTES)
                rules = _parse_rules(data)
                revision = _revision(rules)
                record = {
                    "version": 1,
                    "source_url": source,
                    "rules": rules,
                    "sha256": revision,
                    "revision": revision,
                    "last_checked": checked,
                    "last_success": checked,
                    "error": None,
                }
                # Reserve room for a future failure status before accepting a
                # large source, so last-good state remains writable on failure.
                _cache_bytes({**record, "error": _REFRESH_ERROR})
            except Exception:  # noqa: BLE001 - untrusted fetch must preserve last-good state.
                if previous is None:
                    raise ValueError(_REFRESH_ERROR) from None
                record = {**previous, "last_checked": checked, "error": _REFRESH_ERROR}
            _write_cache(directory, record)
            return _snapshot(record)
    except (OSError, TypeError):
        raise ValueError(_WRITE_ERROR) from None


def change(data_dir, source_url, operation, domain, expected_revision):
    """Apply one managed edit under an exact content-revision guard; never publish here."""
    if not managed_mode():
        raise ValueError("unavailable")
    try:
        if operation not in ("add", "remove"):
            raise ValueError("invalid_domain")
        canonical = "domain:" + _domain(domain)
    except (ValueError, UnicodeError):
        raise ValueError("invalid_domain") from None
    try:
        source = _source_url(source_url)
        with _sync_lock(data_dir) as directory:
            try:
                previous = _read_cache(directory, source, allow_empty=True)
            except ValueError:
                raise ValueError("unavailable") from None
            if not isinstance(expected_revision, str) or expected_revision != previous["revision"]:
                raise ValueError("stale_revision")
            current = set(previous["rules"])
            if (operation == "add" and canonical in current) or (
                operation == "remove" and canonical not in current
            ):
                return _snapshot(previous)
            if operation == "add":
                current.add(canonical)
            else:
                current.remove(canonical)
            if len(current) > MAX_RULES:
                raise ValueError("invalid_domain")
            checked = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
            revision = _revision(sorted(current))
            record = {
                **previous,
                "rules": sorted(current),
                "sha256": revision,
                "revision": revision,
                "last_checked": checked,
                "last_success": checked,
                "error": None,
            }
            try:
                _cache_bytes({**record, "error": _REFRESH_ERROR})
            except ValueError:
                raise ValueError("invalid_domain") from None
            _write_cache(directory, record)
            return _snapshot(record)
    except (OSError, TypeError):
        raise ValueError("unavailable") from None


def _empty_publication(status="never"):
    return {
        "status": status,
        "last_attempt_at": None,
        "last_success_at": None,
        "commit": None,
        "published_revision": None,
    }


def _publication_record(record):
    if (
        not isinstance(record, dict)
        or set(record) != _PUBLICATION_FIELDS
        or not isinstance(record["status"], str)
        or record["status"] not in _PUBLICATION_STATES
    ):
        raise ValueError("Invalid publication status")
    for key in ("last_attempt_at", "last_success_at"):
        if record[key] is not None:
            _timestamp(record[key])
    for key, size in (("commit", 40), ("published_revision", 64)):
        if record[key] is not None and (
            not isinstance(record[key], str) or not re.fullmatch(f"[0-9a-f]{{{size}}}", record[key])
        ):
            raise ValueError("Invalid publication status")
    return dict(record)


def publication_status(data_dir, active_revision):
    """Read publication health independently from the authoritative active list.

    Missing metadata means never published. A known earlier successful revision
    means pending after an edit. The last publication failure remains visible
    until a publisher records a later outcome. No file is created or modified.
    """
    try:
        if not isinstance(active_revision, str) or not re.fullmatch(
            "[0-9a-f]{64}", active_revision
        ):
            return _empty_publication("error")
        directory = Path(data_dir)
        if directory.is_symlink():
            return _empty_publication("error")
        path = directory / PUBLICATION_NAME
        initial = path.lstat()
        if not _regular(initial) or initial.st_size > MAX_BYTES:
            return _empty_publication("error")
        if os.name == "posix" and initial.st_mode & 0o077:
            return _empty_publication("error")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not os.path.samestat(initial, os.fstat(stream.fileno())):
                return _empty_publication("error")
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return _empty_publication("error")
        record = _publication_record(json.loads(raw))
        if record["status"] != "error" and record["published_revision"] != active_revision:
            record["status"] = "pending"
        return record
    except FileNotFoundError:
        return _empty_publication()
    except (OSError, ValueError, TypeError, UnicodeError):
        return _empty_publication("error")


def write_publication_status(data_dir, record):
    """Atomically persist a validated, credential-free publisher outcome."""
    try:
        validated = _publication_record(record)
        with _sync_lock(data_dir, lock_name=PUBLICATION_NAME + ".lock") as directory:
            _write_cache(directory, validated, filename=PUBLICATION_NAME)
        return dict(validated)
    except (OSError, ValueError, TypeError):
        raise ValueError("Invalid publication status") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Refresh the shared Happ routing list")
    parser.add_argument("--sync", action="store_true", required=True)
    parser.add_argument(
        "--data-dir", default=os.environ.get("WG_PANEL_DATA_DIR", "/opt/wg-panel/data")
    )
    parser.add_argument("--source-url", default=None)
    args = parser.parse_args(argv)
    try:
        snapshot = sync(args.data_dir, args.source_url)
    except ValueError:
        print(_REFRESH_ERROR)
        return 1
    if snapshot["error"]:
        print("Shared routing list refresh failed; last good snapshot retained")
        return 1
    print(
        f"Shared routing list refreshed: rules={len(snapshot['rules'])} revision={snapshot['revision']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
