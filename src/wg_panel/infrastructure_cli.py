"""Operator-only adoption: stop wg-panel first; leave wg0 running.

Usage: python -m wg_panel.infrastructure_cli adopt PEER --maintenance \
    --expected-public-key-fingerprint SHA256:... --label home-router

The fingerprint hashes the decoded 32-byte client public key, not its base64
text. The controller must stage a private backup and stop the panel/collector
before invoking this command. Repeating the same command resumes its checkpoint.
"""

import argparse
import sys

from .infrastructure import InfrastructureStateError, adopt_infrastructure_peer


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    adopt = commands.add_parser("adopt", help="Adopt an unchanged existing router profile")
    adopt.add_argument("peer", help="Existing opaque client basename; no config is printed")
    adopt.add_argument("--label", default="home-router")
    adopt.add_argument("--expected-public-key-fingerprint", required=True)
    adopt.add_argument(
        "--maintenance", action="store_true", required=True,
        help="Assert that the controller stopped wg-panel and staged a private backup",
    )
    args = parser.parse_args(argv)
    from .wireguard import reconcile_safe_dns

    try:
        result = adopt_infrastructure_peer(
            args.peer, label=args.label, maintenance=args.maintenance,
            expected_public_key_fingerprint=args.expected_public_key_fingerprint,
            enforce=reconcile_safe_dns,
        )
    except (InfrastructureStateError, OSError) as exc:
        print(f"Infrastructure adoption failed: {exc}", file=sys.stderr)
        return 1
    print("Infrastructure peer already adopted" if result["already_adopted"]
          else "Infrastructure peer adopted; existing tunnel preserved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
