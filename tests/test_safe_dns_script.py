"""Run the real helper against isolated nft transaction stubs on POSIX.

This verifies generated transactions and failure handling without changing the
host firewall. Kernel nft validation remains a deployment acceptance check.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
SCRIPT = ROOT / "scripts" / "safe-dns.sh"
NFT_STUB = r'''
import json
import os
from pathlib import Path
import sys

root = Path(os.environ["SAFE_DNS_TEST_ROOT"])
args = sys.argv[1:]
state = root / "active.nft"
if args[:2] == ["list", "table"]:
    sys.exit(0 if state.exists() else 1)
if args[:1] != ["-f"]:
    raise RuntimeError("unexpected nft call")
batch = Path(args[1]).read_text()
with (root / "batches.jsonl").open("a") as stream:
    stream.write(json.dumps(batch) + "\n")
if (root / "reject").exists():
    print("fixture rejected transaction", file=sys.stderr)
    sys.exit(1)
if batch.strip() == "delete table inet wg_panel_safe_dns":
    state.unlink(missing_ok=True)
else:
    state.write_text(batch)
'''


@unittest.skipUnless(os.name == "posix" and BASH and getattr(os, "geteuid", lambda: -1)() == 0,
                     "requires POSIX bash and root-owned helper fixtures")
class SafeDnsScriptTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "temp").mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="safe-dns-", dir=ROOT / "temp")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        nft = self.bin / "nft"
        nft.write_text(f"#!{sys.executable}\n" + NFT_STUB)
        nft.chmod(0o755)
        self.wg = self.root / "wireguard"
        self.wg.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        SAFE_DNS_TEST_ROOT=str(self.root), WG_DIR=str(self.wg),
                        WG_INTERFACE_NAME="wg0", TMPDIR=str(self.root))

    def invoke(self, *ips, expected=0):
        result = subprocess.run([BASH, str(SCRIPT), "--sync", *ips], env=self.env,
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def batches(self):
        path = self.root / "batches.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_selected_set_sorted_unique_and_all_packet_rules_scoped(self):
        self.invoke("10.0.0.8", "10.0.0.2", "10.0.0.8")
        batch = self.batches()[0]
        self.assertIn("  10.0.0.2,\n  10.0.0.8,\n", batch)
        self.assertEqual(batch.count("10.0.0.8"), 1)
        rules = [line for line in batch.splitlines() if line.startswith("add rule ")]
        self.assertEqual(len(rules), 6)
        for rule in rules:
            self.assertIn('iifname "wg0" ip saddr @safe_clients ', rule)
            self.assertTrue(rule.startswith("add rule inet wg_panel_safe_dns "))
        for protocol in ("tcp", "udp"):
            self.assertIn(f"{protocol} dport 53 dnat ip to 1.1.1.3:53", batch)
            self.assertIn(f"{protocol} dport 853 counter drop", batch)
            self.assertIn(
                f"ip daddr @public_dns_v4 {protocol} dport {{ 443, 5443, 8853, 9953 }} counter drop",
                batch,
            )
        self.assertNotIn("output", batch)
        self.assertNotIn("flush", batch)
        for address in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "9.9.9.12", "94.140.14.14"):
            self.assertIn(address, batch)

    def test_local_filter_target_is_used_without_affecting_server_output(self):
        (self.wg / "safe-dns-target").write_text("192.0.2.1:18004\n")
        self.invoke("10.0.0.2")
        batch = self.batches()[0]
        self.assertEqual(batch.count("dnat ip to 192.0.2.1:18004"), 2)
        self.assertNotIn("hook output", batch)

    def test_failed_replace_leaves_previous_transaction_active(self):
        self.invoke("10.0.0.2")
        previous = (self.root / "active.nft").read_text()
        (self.root / "reject").touch()
        self.invoke("10.0.0.8", expected=1)
        self.assertEqual((self.root / "active.nft").read_text(), previous)
        self.assertTrue(self.batches()[-1].startswith("delete table inet wg_panel_safe_dns\nadd table"))

    def test_empty_set_only_removes_owned_table_and_is_idempotent(self):
        self.invoke("10.0.0.2")
        self.invoke()
        self.assertEqual(self.batches()[-1], "delete table inet wg_panel_safe_dns\n")
        self.invoke()
        self.assertEqual(len(self.batches()), 2)

    def test_invalid_sources_never_reach_a_mutating_transaction(self):
        for address in ("10.0.0.1", "10.0.0.255", "10.0.1.2", "10.0.0.02", "::1", "10.0.0.2;drop"):
            with self.subTest(address=address):
                self.invoke(address, expected=1)
                self.assertEqual(self.batches(), [])

    def test_malformed_target_never_reaches_a_mutating_transaction(self):
        for target in ("192.0.2.999:53", "192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:53\ndrop"):
            with self.subTest(target=target):
                (self.wg / "safe-dns-target").write_text(target)
                self.invoke("10.0.0.2", expected=1)
                self.assertEqual(self.batches(), [])


if __name__ == "__main__":
    unittest.main()
