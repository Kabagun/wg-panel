"""Execute the installed allocator with isolated infrastructure reservations.

This standard-library test also runs directly under Linux/WSL without the panel
or its Python dependencies installed there.
"""

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = base64.b64encode(bytes([1]) * 32).decode()
PUBLIC = base64.b64encode(bytes([2]) * 32).decode()
SERVER = base64.b64encode(bytes([3]) * 32).decode()
PSK = base64.b64encode(bytes([4]) * 32).decode()
NEW_PRIVATE = base64.b64encode(bytes([5]) * 32).decode()
NEW_PUBLIC = base64.b64encode(bytes([6]) * 32).decode()
NAME = "opaque-router"
CONFIG = (
    f"[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.0.0.2/32\n"
    f"\n[Peer]\nPublicKey = {SERVER}\nPresharedKey = {PSK}\n"
    "Endpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
).encode()
MOCK_WG = f'''#!/usr/bin/env python3
import os
import sys
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ["MOCK_WG_LOG"]).open("a") as log:
    log.write(args[0] + "\\n")
if args == ["genkey"]:
    print({NEW_PRIVATE!r})
elif args == ["genpsk"]:
    print({PSK!r})
elif args == ["pubkey"]:
    private = sys.stdin.read().strip()
    print({PUBLIC!r} if private == {PRIVATE!r} else {NEW_PUBLIC!r})
elif args[:1] == ["set"]:
    pass
else:
    raise SystemExit("unexpected wg command")
'''
MOCK_IP = '''#!/usr/bin/env python3
import sys
if sys.argv[1:] == ["-o", "-4", "route", "show", "to", "default"]:
    print("default via 192.0.2.1 dev eth0")
elif sys.argv[1:] == ["-4", "addr", "show", "eth0"]:
    print("2: eth0 inet 192.0.2.10/24 scope global eth0")
else:
    raise SystemExit("unexpected ip command")
'''


@unittest.skipUnless(os.name == "posix", "Actual Bash allocator is tested on Linux")
class InfrastructureAllocatorRuntimeTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "temp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="infrastructure-allocator-", dir=ROOT / "temp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clients = self.root / "clients"
        self.configs = self.root / "infrastructure"
        self.data = self.root / "data"
        self.bin = self.root / "bin"
        for directory in (self.clients, self.configs, self.data, self.bin):
            directory.mkdir(mode=0o700)
        for name, content in (("wg", MOCK_WG), ("ip", MOCK_IP)):
            path = self.bin / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o700)
        self.server = self.root / "wg0.conf"
        self.server.write_text("[Interface]\nAddress = 10.0.0.1/24\n", encoding="utf-8")
        (self.root / "server_public.key").write_text(SERVER, encoding="utf-8")
        self.config = self.configs / f"{NAME}.conf"
        self.config.write_bytes(CONFIG)
        self.config.chmod(0o600)
        self.registry = self.data / "infrastructure_peers.json"
        self.record = {
            "kind": "router", "label": "home-router", "public_key": PUBLIC,
            "ipv4": "10.0.0.2", "config_sha256": hashlib.sha256(CONFIG).hexdigest(),
        }
        self.write_registry()
        self.log = self.root / "wg.log"
        self.env = {
            **os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
            "WG_DIR": str(self.root), "CLIENTS_DIR": str(self.clients),
            "WG_ENDPOINT_HOST": "vpn.example.test", "MOCK_WG_LOG": str(self.log),
            "INFRASTRUCTURE_CLIENTS_DIR": str(self.configs),
            "INFRASTRUCTURE_REGISTRY": str(self.registry),
        }

    def write_registry(self):
        self.registry.write_text(json.dumps({"version": 1, "peers": {NAME: self.record}}),
                                 encoding="utf-8")
        self.registry.chmod(0o600)

    def run_helper(self, name="alice-new"):
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / "add-client.sh"), name, "--prepare"],
            env=self.env, capture_output=True, text=True, check=False, timeout=10,
        )

    def assert_blocked(self, name="alice-new"):
        before = self.server.read_bytes()
        result = self.run_helper(name)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.server.read_bytes(), before)
        self.assertFalse(list(self.clients.iterdir()))
        commands = self.log.read_text().splitlines() if self.log.exists() else []
        self.assertNotIn("genkey", commands)
        self.assertNotIn("genpsk", commands)
        self.assertNotIn("set", commands)
        return result

    def test_inactive_and_paused_infrastructure_address_is_never_reallocated(self):
        peer = f"[Peer]\nPublicKey = {PUBLIC}\nAllowedIPs = 10.0.0.2/32\n"
        encoded = base64.b64encode(peer.encode()).decode()
        with self.server.open("a") as handle:
            handle.write(f"# WG-PANEL-PAUSED-BEGIN v1 {PUBLIC}\n"
                         f"# WG-PANEL-PAUSED-DATA {encoded}\n"
                         f"# WG-PANEL-PAUSED-END v1 {PUBLIC}\n")
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Address = 10.0.0.3/32", (self.clients / "alice-new.conf").read_text())
        self.assertEqual(self.config.read_bytes(), CONFIG)

    def test_infrastructure_name_cannot_be_recreated_as_personal(self):
        result = self.assert_blocked(NAME)
        self.assertIn("reserved for infrastructure", result.stderr)

    def test_malformed_registry_fails_before_generating_keys(self):
        self.registry.write_text("{", encoding="utf-8")
        self.assert_blocked()

    def test_duplicate_json_fields_fail_before_generating_keys(self):
        self.registry.write_text('{"version":1,"peers":{},"peers":{}}', encoding="utf-8")
        self.assert_blocked()

    def test_orphan_config_and_missing_config_fail_before_generating_keys(self):
        self.registry.unlink()
        self.assert_blocked()
        self.write_registry()
        self.config.unlink()
        self.assert_blocked()

    def test_tampered_config_fails_before_generating_keys(self):
        self.config.write_bytes(CONFIG + b"# changed\n")
        self.assert_blocked()

    def test_identity_or_out_of_pool_address_mismatch_fails_before_generating_keys(self):
        self.record["public_key"] = NEW_PUBLIC
        self.write_registry()
        self.assert_blocked()
        self.record["public_key"] = PUBLIC
        self.record["ipv4"] = "10.0.0.255"
        self.write_registry()
        self.assert_blocked()

    def test_symlink_config_fails_before_generating_keys(self):
        elsewhere = self.root / "elsewhere.conf"
        self.config.rename(elsewhere)
        self.config.symlink_to(elsewhere)
        self.assert_blocked()

    def test_incomplete_adoption_blocks_direct_allocator_invocation(self):
        (self.data / "infrastructure_adoption.json").write_text("{}", encoding="utf-8")
        self.assert_blocked()


if __name__ == "__main__":
    unittest.main()
