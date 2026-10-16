"""Fail-closed standalone owner CLI. No hostname selection arguments."""
import argparse
import json
import subprocess
from pathlib import Path
import sys

from .manager import CertificateManager, CertificateError
from .inspection_result import selected_inspect
from .model import Authorization, PolicyError
from .security import trusted_policy

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="certify-manage")
    parser.add_argument("action", choices=["prepare", "inspect", "issue", "renew", "recover", "stage"])
    parser.add_argument("--policy", type=Path, default=Path("/etc/zog/certify-manage/policy.json"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/zog-certify-manage"))
    parser.add_argument("--confirm-uncertain-recovery", action="store_true",
                        help="Explicit acknowledgement; host-owner authorization remains required")
    args = parser.parse_args(argv)
    if args.confirm_uncertain_recovery and args.action != "recover":
        parser.error("--confirm-uncertain-recovery is only valid for recover")
    try:
        raw = trusted_policy(args.policy)
        policy = Authorization.from_dict(json.loads(raw))
        manager = CertificateManager(args.state, policy)
        if args.action == "inspect":
            # One *finite* selected runtime, one schema-pinned line.
            # Root-control must read it by exact invocation, never infer
            # certificate validity from the process exit code alone.
            print(selected_inspect(args.state, policy))
            return 0
        if args.action == "prepare":
            manager.prepare()
            value = {"certificate_id": policy.certificate_id, "state": "prepared"}
        else:
            if args.action == "recover":
                result = manager.recover(acknowledge=args.confirm_uncertain_recovery)
            else:
                result = getattr(manager, args.action)()
            value = result if args.action == "stage" else result.as_dict()
        print(json.dumps(value, sort_keys=True))
        return 0
    except (PolicyError, CertificateError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError):
        print(json.dumps({"error": "certify-manage-operation-rejected"}), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
