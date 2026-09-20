import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_wireguard_scripts_enforce_locking_permissions_and_failures():
    add_script = (ROOT / "scripts" / "add-client.sh").read_text(encoding="utf-8")
    remove_script = (ROOT / "scripts" / "remove-client.sh").read_text(encoding="utf-8")
    for script in (add_script, remove_script):
        assert "set -Eeuo pipefail" in script
        assert "umask 077" in script
        assert "flock -x" in script
        assert "install -d -m 700" in script
        assert "chmod 600" in script
    assert "address pool is exhausted" in add_script
    assert "LIVE_ADDED" in add_script
    assert "LIVE_REMOVED" in remove_script
    assert "Expected one persistent peer block" in remove_script
    assert "Live peer still exists after removal" in remove_script


def remove_persistent_peer(tmp_path, content, public_key):
    """Execute the exact Python parser shipped inside the installed helper."""
    script = (ROOT / "scripts" / "remove-client.sh").read_text(encoding="utf-8")
    parser = re.search(r"<<'PY'\n(.*?)\nPY\n", script, re.DOTALL).group(1)
    source = tmp_path / "wg0.conf"
    target = tmp_path / "updated.conf"
    source.write_text(content, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-c", parser, str(source), str(target), public_key],
        capture_output=True, text=True, check=False,
    )
    return result, target.read_text(encoding="utf-8") if result.returncode == 0 else None


@pytest.mark.parametrize("order", [("phone", "phone2", "tablet"), ("tablet", "phone2", "phone")])
@pytest.mark.parametrize("selected", ["phone", "phone2", "tablet"])
def test_peer_parser_preserves_neighbors_and_all_remain_revocable(tmp_path, order, selected):
    interface = "[Interface]\nPrivateKey = SERVER=\nAddress = 10.0.0.1/24\n"
    blocks = {name: f"\n# alice-{name}\n[Peer]\nPublicKey = {name}=\n"
              f"PresharedKey = psk=\nAllowedIPs = 10.0.0.{index + 2}/32\n"
              for index, name in enumerate(order)}
    content = interface + "".join(blocks[name] for name in order)
    result, updated = remove_persistent_peer(tmp_path, content, f"{selected}=")
    assert result.returncode == 0, result.stderr
    assert updated == interface + "".join(blocks[name] for name in order if name != selected)
    for name in order:
        if name != selected:
            result, updated = remove_persistent_peer(tmp_path, updated, f"{name}=")
            assert result.returncode == 0, result.stderr
    assert updated == interface


def test_peer_parser_recovers_missing_marker_and_handles_bracket_comments(tmp_path):
    content = ("[Interface]\nPrivateKey = server=\n\n[Peer]\nPublicKey = target=\n"
               "# comment containing [brackets]\nAllowedIPs = 10.0.0.2/32\n"
               "\n# bob-phone\n[Peer]\nPublicKey = survivor=\nAllowedIPs = 10.0.0.3/32\n")
    result, updated = remove_persistent_peer(tmp_path, content, "target=")
    assert result.returncode == 0, result.stderr
    assert updated == ("[Interface]\nPrivateKey = server=\n\n# bob-phone\n[Peer]\n"
                       "PublicKey = survivor=\nAllowedIPs = 10.0.0.3/32\n")


@pytest.mark.parametrize("content", [
    "[Peer]\nPublicKey = other=\n",
    "[Peer]\nPublicKey = target=\n[Peer]\nPublicKey = target=\n",
    "[Peer]\nPublicKey = target=\nPublicKey = other=\n",
])
def test_peer_parser_refuses_missing_duplicate_and_ambiguous_keys(tmp_path, content):
    result, updated = remove_persistent_peer(tmp_path, content, "target=")
    assert result.returncode != 0
    assert updated is None
