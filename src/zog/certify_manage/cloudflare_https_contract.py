"""Issuer-side read-only receipt of root-owned HTTPS credential installation.

The issuer does NOT retrieve credentials. An explicitly selected protected
host/root-control operation requests the Cloudflare token from the Command
Center over authenticated HTTPS and installs through install_from_fd.

This module observes only trusted nonsecret metadata plus the existing 0600
issuer-owned file. Never use it to auto-fetch on issue/renew/recover/inspect.
"""
from __future__ import annotations
from pathlib import Path
import re

from .model import Authorization, PolicyError
from .security import cloudflare_credential_snapshot

SCHEMA = "zog-certify-cloudflare-https-consumer-v1"
RECEIPT_SCHEMA = "zog-issuer-cloudflare-installation-v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def verify_installed(state: Path, policy: Authorization, *,
                     approved, installed, issuer_uid: int):
    """Nonsecret independent readback, not authority to issue or renew.

    Both records MUST originate from root-only approved installation and
    authenticated current owner/assignment reads, never an issuer web request.
    Root-control's own selected 'issue'/'renew' gate still checks grant,
    persisted Certbot account, credential revision and private storage.
    """
    try:
        if (not isinstance(state, Path) or not state.is_absolute()
                or policy.challenge != "dns-01"
                or policy.dns_plugin != "dns-cloudflare"
                or type(issuer_uid) is not int or issuer_uid < 1000
                or type(approved) is not dict
                or type(installed) is not dict
                or set(approved) != {
                    "schema", "certificate_id", "hostnames", "dns_zone",
                    "credential_id", "credential_revision",
                    "assignment_revision", "grant_id", "storage_id",
                    "issuer_uid", "policy_sha256"}
                or approved["schema"] != SCHEMA
                or approved["certificate_id"] != policy.certificate_id
                or tuple(approved["hostnames"]) != policy.hostnames
                or len(policy.hostnames) != 1
                or approved["dns_zone"] not in policy.hostnames[0]
                or not policy.hostnames[0].endswith(
                    "." + approved["dns_zone"])
                or approved["issuer_uid"] != issuer_uid
                or type(approved["credential_revision"]) is not int
                or approved["credential_revision"] < 1
                or type(approved["assignment_revision"]) is not int
                or approved["assignment_revision"] < 1
                or type(approved["policy_sha256"]) is not str
                or not _SHA.fullmatch(approved["policy_sha256"])
                or installed.get("schema") != RECEIPT_SCHEMA
                or installed.get("status") != "installed"
                or installed.get("credential_revision") !=
                    approved["credential_revision"]
                or installed.get("assignment_revision") !=
                    approved["assignment_revision"]):
            raise PolicyError("cloudflare-https-installed-credential-not-current")
        # This validates the actual Certbot Cloudflare plugin's existing
        # 0600 file without returning any token or file hash to a caller.
        cloudflare_credential_snapshot(state)
        return {"schema": SCHEMA, "status": "issuer-private-file-current",
                "certificate_id": policy.certificate_id,
                "credential_revision": approved["credential_revision"],
                "assignment_revision": approved["assignment_revision"],
                "can_issue": False, "can_renew": False,
                "requires_selected_controller_admission": True}
    except (KeyError, ValueError, TypeError, AttributeError):
        raise PolicyError("cloudflare-https-installed-credential-not-current") from None
