"""Read the operator-owned resolver target shared by Safe internet clients.

The WireGuard directory is a trusted, administrator-managed directory.  This
reader rejects links and nonregular files and uses no-follow opens where the
platform supports them; it does not impose POSIX ownership rules on Windows.
Only an absent target selects the legacy filtered resolver.
"""

import ipaddress
import os
import re
import stat
from dataclasses import dataclass

from .dns_enforcement import SafeDnsEnforcementError


@dataclass(frozen=True)
class SafeDnsTarget:
    address: str
    port: int
    client_dns_servers: str
    custom: bool


_LEGACY_TARGET = SafeDnsTarget("1.1.1.3", 53, "1.1.1.3, 1.0.0.3", False)
_MAX_TARGET_BYTES = 64
_TARGET_PATTERN = re.compile(
    rb"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([1-9][0-9]{0,4})(?:\r?\n)?"
)
_TARGET_ERROR = "Safe DNS target configuration is unavailable or invalid"


def _regular_file(info):
    # On Windows a reparse point may carry file mode bits in addition to its
    # link attributes.  Such a file is not an operator-owned regular target.
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISREG(info.st_mode) and not (
        getattr(info, "st_file_attributes", 0) & reparse_flag
    )


def _read_target(path):
    try:
        initial = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise SafeDnsEnforcementError(_TARGET_ERROR) from None

    if not _regular_file(initial) or initial.st_size > _MAX_TARGET_BYTES:
        raise SafeDnsEnforcementError(_TARGET_ERROR)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            current = os.lstat(path)
            if (
                not _regular_file(opened)
                or not _regular_file(current)
                or not os.path.samestat(initial, opened)
                or not os.path.samestat(opened, current)
            ):
                raise SafeDnsEnforcementError(_TARGET_ERROR)
            content = os.read(descriptor, _MAX_TARGET_BYTES + 1)
        finally:
            os.close(descriptor)
    except OSError:
        # A file disappearing after lstat is an error, not a default-mode
        # request.  Suppress OS details, which can include deployment paths.
        raise SafeDnsEnforcementError(_TARGET_ERROR) from None

    if len(content) > _MAX_TARGET_BYTES:
        raise SafeDnsEnforcementError(_TARGET_ERROR)
    return content


def load_safe_dns_target(wg_dir: str | os.PathLike[str]) -> SafeDnsTarget:
    """Return validated DNAT and client DNS settings for ``wg_dir``.

    Custom configuration is one canonical IPv4:port line, optionally ending
    with LF or CRLF.  WireGuard's DNS field accepts the bare address; selected
    peers reach the configured port through the existing port-53 DNAT rules.
    No fallback is made for an existing invalid or unreadable configuration.
    """
    content = _read_target(os.path.join(os.fspath(wg_dir), "safe-dns-target"))
    if content is None:
        return _LEGACY_TARGET

    match = _TARGET_PATTERN.fullmatch(content)
    if not match:
        raise SafeDnsEnforcementError(_TARGET_ERROR)
    try:
        address = ipaddress.IPv4Address(match[1].decode("ascii"))
        port = int(match[2])
    except ValueError:
        raise SafeDnsEnforcementError(_TARGET_ERROR) from None
    if (
        address.is_loopback
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or int(address) < 0x01000000
        or port > 65535
    ):
        raise SafeDnsEnforcementError(_TARGET_ERROR)
    return SafeDnsTarget(str(address), port, str(address), True)
