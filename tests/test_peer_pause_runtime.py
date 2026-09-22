"""Exercise pause/resume helpers against isolated WireGuard test doubles.

This test module uses only the Python standard library and can also run directly
under Linux/WSL when the main pytest environment is Windows.
"""

import base64
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOCK_WG = '''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
state_path = Path(os.environ["MOCK_WG_STATE"])
if args == ["genkey"]:
    print("private_new=")
    raise SystemExit(0)
if args == ["genpsk"]:
    print("new-psk=")
    raise SystemExit(0)
if args == ["pubkey"]:
    print(sys.stdin.read().strip().replace("private_", "public_"))
    raise SystemExit(0)
state = json.loads(state_path.read_text())
if args == ["show", "wg0", "peers"]:
    if os.environ.get("MOCK_FAIL_SHOW"):
        raise SystemExit("mock show failure")
    print("\\n".join(state))
elif args[:3] == ["set", "wg0", "peer"]:
    key = args[3]
    if args[4:] == ["remove"]:
        if os.environ.get("MOCK_FAIL_REMOVE"):
            raise SystemExit("mock removal failure")
        if not os.environ.get("MOCK_RETAIN_PEER"):
            state.pop(key, None)
    elif args[4] == "preshared-key" and args[6] == "allowed-ips":
        if os.environ.get("MOCK_FAIL_ADD"):
            raise SystemExit("mock add failure")
        expected = "new-psk=" if key == "public_new=" else "test-psk="
        assert Path(args[5]).read_text() == expected
        state[key] = args[7]
    else:
        raise SystemExit("unexpected wg mutation")
    state_path.write_text(json.dumps(state))
else:
    raise SystemExit("unexpected wg command")
'''
MOCK_IP = '''#!/usr/bin/env python3
import sys

args = sys.argv[1:]
if args == ["-o", "-4", "route", "show", "to", "default"]:
    print("default via 192.0.2.1 dev eth0")
elif args == ["-4", "addr", "show", "eth0"]:
    print("2: eth0    inet 192.0.2.10/24 scope global eth0")
else:
    raise SystemExit("unexpected ip command")
'''


@unittest.skipUnless(os.name == "posix", "Actual Bash helpers are tested on Linux")
class PeerPauseRuntimeTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "temp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="pause-test-", dir=ROOT / "temp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clients = self.root / "clients"
        self.clients.mkdir()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name, content in (("wg", MOCK_WG), ("ip", MOCK_IP)):
            executable = bin_dir / name
            executable.write_text(content, encoding="utf-8")
            executable.chmod(0o700)
        self.state = self.root / "live.json"
        self.conf = self.root / "wg0.conf"
        (self.root / "server_public.key").write_text("server-public=", encoding="utf-8")
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "WG_DIR": str(self.root),
            "CLIENTS_DIR": str(self.clients),
            "WG_INTERFACE_NAME": "wg0",
            "WG_ENDPOINT_HOST": "vpn.example.test",
            "MOCK_WG_STATE": str(self.state),
        }
        self.prepare()

    def prepare(self):
        self.interface = "[Interface]\nPrivateKey = server=\nAddress = 10.0.0.1/24\n"
        self.alice_block = (
            "\n# alice\n[Peer]\nPublicKey = public_alice=\n"
            "PresharedKey = test-psk=\nAllowedIPs = 10.0.0.2/32\n"
        )
        self.bob_block = (
            "\n# bob\n[Peer]\nPublicKey = public_bob=\n"
            "PresharedKey = test-psk=\nAllowedIPs = 10.0.0.3/32\n"
        )
        self.original_conf = self.interface + self.alice_block + self.bob_block
        self.conf.write_text(self.original_conf, encoding="utf-8")
        self.alice_config = (
            "[Interface]\nPrivateKey = private_alice=\nAddress = 10.0.0.2/32\n"
            "DNS = 1.1.1.1\n\n[Peer]\nPublicKey = server-public=\n"
            "PresharedKey = test-psk=\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        )
        (self.clients / "alice.conf").write_text(self.alice_config, encoding="utf-8")
        (self.clients / "bob.conf").write_text(
            self.alice_config.replace("private_alice=", "private_bob=").replace(
                "10.0.0.2/32", "10.0.0.3/32", 1
            ),
            encoding="utf-8",
        )
        self.state.write_text(
            json.dumps({"public_alice=": "10.0.0.2/32", "public_bob=": "10.0.0.3/32"}),
            encoding="utf-8",
        )

    def add_charlie(self):
        self.charlie_block = (
            "\n# charlie\n[Peer]\nPublicKey = public_charlie=\n"
            "PresharedKey = test-psk=\nAllowedIPs = 10.0.0.4/32\n"
        )
        self.original_conf += self.charlie_block
        self.conf.write_text(self.original_conf, encoding="utf-8")
        (self.clients / "charlie.conf").write_text(
            self.alice_config.replace("private_alice=", "private_charlie=").replace(
                "10.0.0.2/32", "10.0.0.4/32", 1
            ),
            encoding="utf-8",
        )
        live = json.loads(self.state.read_text())
        live["public_charlie="] = "10.0.0.4/32"
        self.state.write_text(json.dumps(live), encoding="utf-8")

    def run_script(self, script, *args, extra_env=None):
        env = {**self.env, **(extra_env or {})}
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / script), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_pause_resume_are_lossless_restart_safe_and_idempotent(self):
        client_before = (self.clients / "alice.conf").read_bytes()
        result = self.run_script("set-client-state.sh", "alice", "pause")
        self.assertEqual(result.returncode, 0, result.stderr)
        paused = self.conf.read_text()
        self.assertIn("# WG-PANEL-PAUSED-BEGIN v1 public_alice=", paused)
        self.assertNotIn("\nPublicKey = public_alice=\n", paused)
        self.assertIn(self.bob_block, paused)
        self.assertNotIn("public_alice=", json.loads(self.state.read_text()))
        self.assertEqual((self.clients / "alice.conf").read_bytes(), client_before)
        # A config-only restart cannot load the encoded/commented peer.
        active_keys = re.findall(r"(?m)^PublicKey = (.+)$", paused)
        self.assertEqual(active_keys, ["public_bob="])

        paused_before = self.conf.read_bytes()
        result = self.run_script("set-client-state.sh", "alice", "pause")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_bytes(), paused_before)

        result = self.run_script("set-client-state.sh", "alice", "resume")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text(), self.original_conf)
        self.assertEqual((self.clients / "alice.conf").read_bytes(), client_before)
        self.assertEqual(json.loads(self.state.read_text())["public_alice="], "10.0.0.2/32")

        resumed_before = self.conf.read_bytes()
        result = self.run_script("set-client-state.sh", "alice", "resume")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_bytes(), resumed_before)

    def test_pause_failure_stays_persistently_disabled_and_retry_recovers(self):
        result = self.run_script(
            "set-client-state.sh", "alice", "pause", extra_env={"MOCK_RETAIN_PEER": "1"}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Live peer still exists after pause", result.stderr)
        self.assertIn("# WG-PANEL-PAUSED-BEGIN v1 public_alice=", self.conf.read_text())
        self.assertIn("public_alice=", json.loads(self.state.read_text()))

        result = self.run_script("set-client-state.sh", "alice", "pause")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("public_alice=", json.loads(self.state.read_text()))

    def test_pause_verification_failure_is_nonzero_and_safely_retryable(self):
        result = self.run_script(
            "set-client-state.sh", "alice", "pause", extra_env={"MOCK_FAIL_SHOW": "1"}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot verify live peers after pause", result.stderr)
        self.assertIn("# WG-PANEL-PAUSED-BEGIN v1 public_alice=", self.conf.read_text())
        self.assertNotIn("public_alice=", json.loads(self.state.read_text()))

        result = self.run_script("set-client-state.sh", "alice", "pause")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_resume_failure_keeps_peer_paused_and_retry_recovers(self):
        self.assertEqual(
            self.run_script("set-client-state.sh", "alice", "pause").returncode, 0
        )
        paused = self.conf.read_bytes()
        result = self.run_script(
            "set-client-state.sh", "alice", "resume", extra_env={"MOCK_FAIL_ADD": "1"}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.conf.read_bytes(), paused)
        self.assertNotIn("public_alice=", json.loads(self.state.read_text()))

        result = self.run_script("set-client-state.sh", "alice", "resume")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text(), self.original_conf)

    def test_paused_address_is_reserved_for_new_client(self):
        self.assertEqual(
            self.run_script("set-client-state.sh", "alice", "pause").returncode, 0
        )
        result = self.run_script("add-client.sh", "new")
        self.assertEqual(result.returncode, 0, result.stderr)
        new_config = (self.clients / "new.conf").read_text()
        self.assertIn("Address = 10.0.0.4/32", new_config)
        self.assertNotIn("Address = 10.0.0.2/32", new_config)

    def test_remove_paused_peer_preserves_unrelated_block(self):
        self.assertEqual(
            self.run_script("set-client-state.sh", "alice", "pause").returncode, 0
        )
        result = self.run_script("remove-client.sh", "alice")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text(), self.interface + self.bob_block)
        self.assertFalse((self.clients / "alice.conf").exists())
        self.assertEqual(
            json.loads(self.state.read_text()), {"public_bob=": "10.0.0.3/32"}
        )

    def test_adjacent_peers_pause_and_resume_in_any_order(self):
        cases = (
            (("alice", "bob", "charlie"), ("charlie", "alice", "bob")),
            (("charlie", "bob", "alice"), ("bob", "charlie", "alice")),
        )
        for pause_order, resume_order in cases:
            with self.subTest(pause_order=pause_order, resume_order=resume_order):
                self.prepare()
                self.add_charlie()
                original = self.original_conf
                for name in pause_order:
                    result = self.run_script("set-client-state.sh", name, "pause")
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.conf.read_text().count("WG-PANEL-PAUSED-BEGIN"), 3)
                for name in resume_order:
                    result = self.run_script("set-client-state.sh", name, "resume")
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.conf.read_text(), original)

    def test_remove_active_neighbor_on_either_side_of_paused_peer(self):
        cases = (("alice", "bob", self.alice_block), ("bob", "alice", self.bob_block))
        for paused, removed, survivor_block in cases:
            with self.subTest(paused=paused, removed=removed):
                self.prepare()
                result = self.run_script("set-client-state.sh", paused, "pause")
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script("remove-client.sh", removed)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script("set-client-state.sh", paused, "resume")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.conf.read_text(), self.interface + survivor_block)

    def test_saveconfig_true_is_rejected_without_changes(self):
        self.original_conf = self.original_conf.replace(
            "Address = 10.0.0.1/24\n", "Address = 10.0.0.1/24\nSaveConfig = TRUE  # managed\n"
        )
        self.conf.write_text(self.original_conf, encoding="utf-8")
        live_before = self.state.read_bytes()
        for action in ("pause", "resume"):
            with self.subTest(action=action):
                result = self.run_script("set-client-state.sh", "alice", action)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("SaveConfig = true is unsupported", result.stderr)
                self.assertEqual(self.conf.read_text(), self.original_conf)
                self.assertEqual(self.state.read_bytes(), live_before)

    def test_malformed_paused_payloads_are_rejected(self):
        invalid_blocks = (
            (
                "\n[Peer]\nPublicKey = public_alice=\nAllowedIPs = 10.0.0.2/32\n"
                "[Interface]\nAddress = 10.0.0.9/32\n"
            ),
            (
                "\n[Peer]\nPublicKey = public_alice=\nAllowedIPs = 10.0.0.2/32\n"
                "# WG-PANEL-PAUSED-BEGIN v1 nested=\n"
            ),
        )
        for invalid in invalid_blocks:
            with self.subTest(invalid=invalid):
                self.prepare()
                result = self.run_script("set-client-state.sh", "alice", "pause")
                self.assertEqual(result.returncode, 0, result.stderr)
                encoded = base64.b64encode(invalid.encode()).decode()
                damaged = re.sub(
                    r"(?m)^# WG-PANEL-PAUSED-DATA .+$",
                    f"# WG-PANEL-PAUSED-DATA {encoded}",
                    self.conf.read_text(),
                    count=1,
                )
                self.conf.write_text(damaged, encoding="utf-8")
                before = self.conf.read_bytes()
                result = self.run_script("set-client-state.sh", "alice", "pause")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.conf.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
