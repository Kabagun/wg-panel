"""Run protected preparation against isolated Linux WireGuard doubles."""

import base64
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_peer_pause_runtime import MOCK_IP, MOCK_WG

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "Actual Bash helpers are tested on Linux")
class ProtectedProvisionRuntimeTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "temp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="protected-provision-", dir=ROOT / "temp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clients = self.root / "clients"
        self.clients.mkdir()
        binaries = self.root / "bin"
        binaries.mkdir()
        for name, content in (("wg", MOCK_WG), ("ip", MOCK_IP)):
            executable = binaries / name
            executable.write_text(content, encoding="utf-8")
            executable.chmod(0o700)
        self.state = self.root / "live.json"
        self.state.write_text("{}", encoding="utf-8")
        self.server = self.root / "wg0.conf"
        self.server.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
        (self.root / "server_public.key").write_text("fake-server=", encoding="utf-8")
        self.env = {
            **os.environ, "PATH": f"{binaries}:{os.environ['PATH']}",
            "WG_DIR": str(self.root), "CLIENTS_DIR": str(self.clients),
            "WG_INTERFACE_NAME": "wg0", "WG_ENDPOINT_HOST": "vpn.example.test",
            "MOCK_WG_STATE": str(self.state),
        }

    def run_helper(self, script, *arguments, **extra_env):
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / script), *arguments],
            env={**self.env, **extra_env}, capture_output=True, text=True,
            check=False, timeout=10,
        )

    def test_prepared_peer_never_becomes_live_until_explicit_resume(self):
        result = self.run_helper("add-client.sh", "alice-new", "--prepare", MOCK_FAIL_ADD="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.state.read_text()), {})
        config = (self.clients / "alice-new.conf").read_text()
        self.assertIn("DNS = 1.1.1.3, 1.0.0.3", config)
        persistent = self.server.read_text()
        self.assertNotIn("[Peer]", persistent)
        match = re.search(r"# WG-PANEL-PAUSED-DATA ([A-Za-z0-9+/=]+)", persistent)
        self.assertIsNotNone(match)
        peer = base64.b64decode(match.group(1)).decode()
        self.assertIn("# alice-new\n[Peer]", peer)
        self.assertIn("AllowedIPs = 10.0.0.2/32", peer)
        resumed = self.run_helper("set-client-state.sh", "alice-new", "resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(json.loads(self.state.read_text()), {"public_new=": "10.0.0.2/32"})
        self.assertNotIn("WG-PANEL-PAUSED-BEGIN", self.server.read_text())

    def test_failed_resume_remains_inactive_and_prepared_profile_can_be_revoked(self):
        result = self.run_helper("add-client.sh", "alice-new", "--prepare")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_helper("set-client-state.sh", "alice-new", "resume", MOCK_FAIL_ADD="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.state.read_text()), {})
        self.assertIn("WG-PANEL-PAUSED-BEGIN", self.server.read_text())
        result = self.run_helper("remove-client.sh", "alice-new")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.clients / "alice-new.conf").exists())
        self.assertNotIn("WG-PANEL-PAUSED-BEGIN", self.server.read_text())

    def test_invalid_prepare_option_is_rejected_before_any_file_or_peer_change(self):
        before = self.server.read_text()
        result = self.run_helper("add-client.sh", "alice-new", "--unknown")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.state.read_text()), {})
        self.assertEqual(self.server.read_text(), before)
        self.assertFalse(list(self.clients.iterdir()))


if __name__ == "__main__":
    unittest.main()
