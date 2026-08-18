from pathlib import Path

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
