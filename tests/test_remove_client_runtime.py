"""Run the actual Bash revocation helper with an isolated WireGuard test double.

Uses only Python's standard library; also runnable with ``python3 <this file>``
on Linux when the main test environment is on Windows.
"""

import json
import os
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
        if not os.environ.get("MOCK_RETAIN_PEER"):
            state.pop(key, None)
    elif args[4] == "preshared-key" and args[6] == "allowed-ips":
        assert Path(args[5]).read_text() == "test-psk="
        state[key] = args[7]
    else:
        raise SystemExit("unexpected wg mutation")
    state_path.write_text(json.dumps(state))
else:
    raise SystemExit("unexpected wg command")
'''


@unittest.skipUnless(os.name == "posix", "Actual Bash helper is tested on Linux")
class RemoveClientRuntimeTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "temp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="revoke-test-", dir=ROOT / "temp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clients = self.root / "clients"
        self.clients.mkdir()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        wg = bin_dir / "wg"
        wg.write_text(MOCK_WG, encoding="utf-8")
        wg.chmod(0o700)
        self.state = self.root / "live.json"
        self.conf = self.root / "wg0.conf"
        self.env = {
            **os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "WG_DIR": str(self.root), "CLIENTS_DIR": str(self.clients),
            "WG_INTERFACE_NAME": "wg0", "MOCK_WG_STATE": str(self.state),
        }

    def prepare(self, names, *, missing_marker=None):
        self.interface = "[Interface]\nPrivateKey = server=\nAddress = 10.0.0.1/24\n"
        self.blocks = {}
        live = {}
        for index, name in enumerate(names):
            address = f"10.0.0.{index + 2}/32"
            key = f"public_{name}="
            live[key] = address
            marker = "" if name == missing_marker else f"# {name}\n"
            self.blocks[name] = (
                f"\n{marker}[Peer]\nPublicKey = {key}\n"
                f"PresharedKey = test-psk=\nAllowedIPs = {address}\n"
            )
            (self.clients / f"{name}.conf").write_text(
                f"[Interface]\nPrivateKey = private_{name}=\nAddress = {address}\n"
                "\n[Peer]\nPublicKey = server=\nPresharedKey = test-psk=\n",
                encoding="utf-8",
            )
        self.conf.write_text(self.interface + "".join(self.blocks.values()), encoding="utf-8")
        self.state.write_text(json.dumps(live), encoding="utf-8")

    def revoke(self, name):
        return subprocess.run(
            ["bash", str(ROOT / "scripts/remove-client.sh"), name],
            env=self.env, capture_output=True, text=True, timeout=10, check=False,
        )

    def test_every_position_and_prefix_order_then_revoke_survivors(self):
        for names in (("alice-phone", "alice-phone2", "bob-tablet"),
                      ("bob-tablet", "alice-phone2", "alice-phone")):
            for target in names:
                with self.subTest(names=names, target=target):
                    self.prepare(names)
                    result = self.revoke(target)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.conf.read_text(), self.interface + "".join(
                        self.blocks[name] for name in names if name != target
                    ))
                    self.assertNotIn(f"public_{target}=", json.loads(self.state.read_text()))
                    self.assertFalse((self.clients / f"{target}.conf").exists())
                    for name in names:
                        if name != target:
                            result = self.revoke(name)
                            self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(self.state.read_text()), {})
                    self.assertEqual(self.conf.read_text(), self.interface)

    def test_revoke_peer_whose_marker_was_previously_lost(self):
        self.prepare(("alice-phone", "bob-tablet"), missing_marker="alice-phone")
        result = self.revoke("alice-phone")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.conf.read_text(), self.interface + self.blocks["bob-tablet"])
        self.assertEqual(set(json.loads(self.state.read_text())), {"public_bob-tablet="})

    def test_real_live_revocation_failure_still_rolls_back(self):
        self.prepare(("alice-phone", "bob-tablet"))
        before = self.conf.read_text()
        live = self.state.read_text()
        self.env["MOCK_RETAIN_PEER"] = "1"
        result = self.revoke("alice-phone")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Live peer still exists after removal", result.stderr)
        self.assertEqual(self.conf.read_text(), before)
        self.assertEqual(self.state.read_text(), live)
        self.assertTrue((self.clients / "alice-phone.conf").exists())

    def test_live_inspection_failure_changes_nothing(self):
        self.prepare(("alice-phone", "bob-tablet"))
        before = self.conf.read_text()
        live = self.state.read_text()
        self.env["MOCK_FAIL_SHOW"] = "1"
        result = self.revoke("alice-phone")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot inspect live peers before removal", result.stderr)
        self.assertEqual(self.conf.read_text(), before)
        self.assertEqual(self.state.read_text(), live)
        self.assertTrue((self.clients / "alice-phone.conf").exists())


if __name__ == "__main__":
    unittest.main()
