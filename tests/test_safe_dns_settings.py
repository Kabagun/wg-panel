import os
import stat
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from wg_panel.dns_enforcement import SafeDnsEnforcementError
from wg_panel.safe_dns_settings import SafeDnsTarget, load_safe_dns_target

ERROR_MESSAGE = "Safe DNS target configuration is unavailable or invalid"


def assert_invalid(wg_dir):
    with pytest.raises(SafeDnsEnforcementError) as raised:
        load_safe_dns_target(wg_dir)
    assert str(raised.value) == ERROR_MESSAGE
    assert raised.value.__cause__ is None


def test_absent_target_preserves_legacy_filtered_dns(tmp_path):
    assert load_safe_dns_target(tmp_path) == SafeDnsTarget(
        address="1.1.1.3", port=53, client_dns_servers="1.1.1.3, 1.0.0.3", custom=False
    )


def test_target_value_is_frozen(tmp_path):
    target = load_safe_dns_target(tmp_path)
    with pytest.raises(FrozenInstanceError):
        target.address = "192.0.2.1"


def test_target_is_read_again_after_operator_changes(tmp_path):
    path = tmp_path / "safe-dns-target"
    path.write_text("10.0.0.1:18004", encoding="ascii")
    assert load_safe_dns_target(tmp_path).address == "10.0.0.1"
    path.write_text("192.0.2.1:53", encoding="ascii")
    assert load_safe_dns_target(tmp_path).address == "192.0.2.1"
    path.unlink()
    assert not load_safe_dns_target(tmp_path).custom


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_custom_private_target_exposes_bare_client_dns(tmp_path, ending):
    (tmp_path / "safe-dns-target").write_bytes(b"10.0.0.1:18004" + ending)
    assert load_safe_dns_target(tmp_path) == SafeDnsTarget(
        address="10.0.0.1", port=18004, client_dns_servers="10.0.0.1", custom=True
    )


@pytest.mark.parametrize("address,port", [("192.0.2.1", 1), ("198.51.100.1", 65535)])
def test_canonical_unicast_target_and_port_boundaries(tmp_path, address, port):
    (tmp_path / "safe-dns-target").write_text(f"{address}:{port}", encoding="ascii")
    target = load_safe_dns_target(tmp_path)
    assert (target.address, target.port, target.client_dns_servers, target.custom) == (
        address, port, address, True
    )


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"10.0.0.1",
        b"10.0.0.999:53",
        b"010.0.0.1:53",
        b"10.0.0.1:0",
        b"10.0.0.1:65536",
        b"10.0.0.1:053",
        b"10.0.0.1:+53",
        b"10.0.0.1:-53",
        b"resolver.example.test:53",
        b"[fd00::1]:53",
        b" 10.0.0.1:53",
        b"10.0.0.1:53 ",
        b"10.0.0.1:53\r",
        b"10.0.0.1:53\n\n",
        b"10.0.0.1:53\n192.0.2.1:53",
        b"10.0.0.1:53 # comment",
        b"10.0.0.1:53; command",
        b"10.0.0.1:53\x00",
        b"\xff10.0.0.1:53",
    ],
)
def test_malformed_existing_target_never_selects_legacy_dns(tmp_path, content):
    (tmp_path / "safe-dns-target").write_bytes(content)
    assert_invalid(tmp_path)


@pytest.mark.parametrize(
    "address",
    ["0.0.0.0", "0.1.2.3", "127.0.0.1", "127.1.2.3", "224.0.0.1", "239.1.2.3",
     "240.0.0.1", "255.255.255.255"],
)
def test_non_unicast_targets_are_not_advertised_to_clients(tmp_path, address):
    (tmp_path / "safe-dns-target").write_text(f"{address}:53", encoding="ascii")
    assert_invalid(tmp_path)


def test_excessive_existing_target_is_rejected_before_open(tmp_path, monkeypatch):
    (tmp_path / "safe-dns-target").write_bytes(b"10.0.0.1:53\n" + b" " * 128)

    def unexpected_open(*_args, **_kwargs):
        pytest.fail("oversized target must not be opened")

    monkeypatch.setattr(os, "open", unexpected_open)
    assert_invalid(tmp_path)


def test_directory_target_is_rejected(tmp_path):
    (tmp_path / "safe-dns-target").mkdir()
    assert_invalid(tmp_path)


@pytest.mark.parametrize("dangling", [False, True])
def test_symlink_target_is_rejected(tmp_path, dangling):
    destination = tmp_path / "destination"
    if not dangling:
        destination.write_text("10.0.0.1:53", encoding="ascii")
    try:
        (tmp_path / "safe-dns-target").symlink_to(destination)
    except OSError:
        pytest.skip("platform does not permit creating symlinks")
    assert_invalid(tmp_path)


def test_nonregular_target_is_rejected_without_open(tmp_path, monkeypatch):
    regular = (tmp_path / "safe-dns-target")
    regular.write_text("10.0.0.1:53", encoding="ascii")
    observed = os.lstat(regular)
    nonregular = os.stat_result((stat.S_IFIFO, *observed[1:]))
    monkeypatch.setattr(os, "lstat", lambda _path: nonregular)

    def unexpected_open(*_args, **_kwargs):
        pytest.fail("nonregular target must not be opened")

    monkeypatch.setattr(os, "open", unexpected_open)
    assert_invalid(tmp_path)


def test_reparse_target_is_rejected_without_following_it(tmp_path, monkeypatch):
    reparse_flag = 0x400
    observed = SimpleNamespace(
        st_mode=stat.S_IFREG, st_file_attributes=reparse_flag, st_size=12
    )
    monkeypatch.setattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", reparse_flag, raising=False)
    monkeypatch.setattr(os, "lstat", lambda _path: observed)
    assert_invalid(tmp_path)


@pytest.mark.parametrize("operation", ["lstat", "open"])
def test_permission_errors_do_not_disclose_paths_or_select_defaults(tmp_path, monkeypatch, operation):
    (tmp_path / "safe-dns-target").write_text("10.0.0.1:53", encoding="ascii")

    def denied(*_args, **_kwargs):
        raise PermissionError("synthetic private deployment path")

    monkeypatch.setattr(os, operation, denied)
    assert_invalid(tmp_path)


def test_disappearing_existing_target_does_not_select_defaults(tmp_path, monkeypatch):
    (tmp_path / "safe-dns-target").write_text("10.0.0.1:53", encoding="ascii")

    def disappeared(*_args, **_kwargs):
        raise FileNotFoundError("synthetic private deployment path")

    monkeypatch.setattr(os, "open", disappeared)
    assert_invalid(tmp_path)


def test_read_failure_does_not_disclose_details_or_select_defaults(tmp_path, monkeypatch):
    (tmp_path / "safe-dns-target").write_text("10.0.0.1:53", encoding="ascii")

    def failed_read(*_args, **_kwargs):
        raise OSError("synthetic private deployment path")

    monkeypatch.setattr(os, "read", failed_read)
    assert_invalid(tmp_path)


def test_target_growing_after_stat_is_still_size_limited(tmp_path, monkeypatch):
    (tmp_path / "safe-dns-target").write_text("10.0.0.1:53", encoding="ascii")
    requested_sizes = []

    def grown_target(_descriptor, size):
        requested_sizes.append(size)
        return b" " * size

    monkeypatch.setattr(os, "read", grown_target)
    assert_invalid(tmp_path)
    assert requested_sizes == [65]


def test_open_uses_available_no_follow_flags(tmp_path, monkeypatch):
    (tmp_path / "safe-dns-target").write_text("10.0.0.1:53", encoding="ascii")
    actual_open = os.open
    observed = []

    def record_open(path, flags):
        observed.append(flags)
        return actual_open(path, flags)

    monkeypatch.setattr(os, "open", record_open)
    assert load_safe_dns_target(tmp_path).custom
    for flag in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
        available = getattr(os, flag, 0)
        assert observed[0] & available == available


def test_replaced_path_is_rejected_after_open(tmp_path, monkeypatch):
    path = tmp_path / "safe-dns-target"
    path.write_text("10.0.0.1:53", encoding="ascii")
    replacement = tmp_path / "replacement"
    replacement.write_text("192.0.2.1:53", encoding="ascii")
    initial = os.lstat(path)
    changed = os.lstat(replacement)
    snapshots = iter((initial, changed))
    monkeypatch.setattr(os, "lstat", lambda _path: next(snapshots))
    assert_invalid(tmp_path)
