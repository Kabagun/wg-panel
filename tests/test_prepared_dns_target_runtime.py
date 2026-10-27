"""Protected profile preparation reads the operator DNS target before keys.

Run directly with the Python standard library on Linux/WSL. The test uses only
synthetic endpoints and WireGuard command doubles, never a live interface.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_infrastructure_allocator_runtime import MOCK_IP, MOCK_WG, SERVER

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "Actual Bash preparation is tested on Linux")
class PreparedDnsTargetRuntimeTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "temp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="prepared-dns-target-", dir=ROOT / "temp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clients = self.root / "clients"
        self.bin = self.root / "bin"
        self.data = self.root / "data"
        for directory in (self.clients, self.bin, self.data):
            directory.mkdir(mode=0o700)
        for name, content in (("wg", MOCK_WG), ("ip", MOCK_IP)):
            path = self.bin / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o700)
        self.server = self.root / "wg0.conf"
        self.server.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
        (self.root / "server_public.key").write_text(SERVER, encoding="utf-8")
        self.target = self.root / "safe-dns-target"
        self.log = self.root / "wg.log"
        self.env = {
            **os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
            "WG_DIR": str(self.root), "CLIENTS_DIR": str(self.clients),
            "WG_ENDPOINT_HOST": "vpn.example.test", "MOCK_WG_LOG": str(self.log),
            "INFRASTRUCTURE_CLIENTS_DIR": str(self.root / "infrastructure"),
            "INFRASTRUCTURE_REGISTRY": str(self.data / "infrastructure_peers.json"),
        }

    def run_helper(self, name="alice-protected"):
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / "add-client.sh"), name, "--prepare"],
            env=self.env, capture_output=True, text=True, check=False, timeout=10,
        )

    def write_target(self, content):
        self.target.write_bytes(content)
        self.target.chmod(0o600)

    def assert_blocked_before_keys(self):
        before = self.server.read_bytes()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Safe DNS target configuration is unavailable or invalid", result.stderr)
        self.assertEqual(self.server.read_bytes(), before)
        self.assertFalse(list(self.clients.iterdir()))
        commands = self.log.read_text().splitlines() if self.log.exists() else []
        self.assertNotIn("genkey", commands)
        self.assertNotIn("genpsk", commands)
        self.assertNotIn("set", commands)

    def test_private_custom_target_exports_bare_ipv4_and_keeps_prepared_peer_inactive(self):
        for index, ending in enumerate((b"", b"\n", b"\r\n")):
            with self.subTest(ending=ending):
                self.write_target(b"10.0.0.1:18004" + ending)
                name = f"alice-protected-{index}"
                result = self.run_helper(name)
                self.assertEqual(result.returncode, 0, result.stderr)
                config = (self.clients / f"{name}.conf").read_text()
                self.assertIn("\nDNS = 10.0.0.1\n", config)
                self.assertNotIn("DNS = 10.0.0.1:18004", config)
                self.assertNotIn("DNS = 1.1.1.3", config)
        commands = self.log.read_text().splitlines()
        self.assertNotIn("set", commands)
        persistent = self.server.read_text()
        self.assertNotIn("[Peer]", persistent)
        self.assertEqual(persistent.count("# WG-PANEL-PAUSED-BEGIN v1"), 3)

    def test_missing_target_keeps_legacy_filtered_dns(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        config = (self.clients / "alice-protected.conf").read_text()
        self.assertIn("\nDNS = 1.1.1.3, 1.0.0.3\n", config)
        self.assertNotIn("set", self.log.read_text().splitlines())

    def test_existing_malformed_address_port_or_string_fails_before_keys(self):
        cases = (
            b"", b"\n", b"10.0.0.1", b"10.0.0.1:0", b"10.0.0.1:65536",
            b"10.0.0.1:018004", b"10.0.0.1:+53", b"10.0.0.1:53 ",
            b" 10.0.0.1:53", b"dns.example.test:53", b"[::1]:53",
            b"127.0.0.1:53", b"224.0.0.1:53", b"240.0.0.1:53", b"0.0.0.0:53",
            b"0.1.2.3:53", b"10.0.0.256:53", b"010.0.0.1:53",
            b"10.0.0.1:53\n10.0.0.2:53", b"10.0.0.1:53\x00", b"x" * 65,
        )
        for content in cases:
            with self.subTest(content=content):
                self.write_target(content)
                self.assert_blocked_before_keys()

    def test_symlink_and_dangling_symlink_target_fail_before_keys(self):
        real = self.root / "real-target"
        real.write_bytes(b"10.0.0.1:18004\n")
        self.target.symlink_to(real)
        self.assert_blocked_before_keys()
        self.target.unlink()
        self.target.symlink_to(self.root / "missing-target")
        self.assert_blocked_before_keys()

    def test_nonregular_directory_and_fifo_fail_before_keys_without_blocking(self):
        self.target.mkdir()
        self.assert_blocked_before_keys()
        self.target.rmdir()
        os.mkfifo(self.target, mode=0o600)
        self.assert_blocked_before_keys()


if __name__ == "__main__":
    unittest.main()
