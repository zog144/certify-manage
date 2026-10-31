"""Source-only readback of a root-installed Cloudflare HTTPS credential.

The issuer never fetches a secret or validates an independent station signer.
The protected root owner must first authenticate the signed assignment via
host-deploy's reviewed owner ledger, verify the canonical HTTPS v1 envelope
using host-identify, and read the root-only authorization/ledger from protected
descriptors. This function correlates the *already verified* nonsecret records
with the actual issuer-owned private file. It grants no issuance or renewal.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from .model import Authorization, PolicyError
from .security import cloudflare_credential_snapshot

SCHEMA = "zog-certify-cloudflare-https-consumer-v1"
AUTH_SCHEMA = "zog-issuer-cloudflare-credential-v1"
RECEIPT_SCHEMA = "zog-issuer-cloudflare-installation-v1"
CANONICAL_AUTH_SCHEMA = "zog-credential-authorization-v1"
CANONICAL_RECEIPT_SCHEMA = "zog-credential-installation-receipt-v1"
OWNER_SCHEMA = "zog-host-deploy-certificate-owner-authority-v1"
PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"

_APPROVED = frozenset((
    "schema state project certificate_id assignment_id assignment_revision "
    "credential_id credential_revision zone_id zone_name grant_id storage_id "
    "policy_sha256 receipt_sha256 expires_at"
).split())
_INSTALLED = (_APPROVED - {"schema", "state"}) | {"schema", "state", "status", "installed_at"}
_INSPECT = frozenset((
    "schema status assignment_revision credential_revision grant_id storage_id"
).split())
_OWNER = frozenset((
    "schema origin verified_by host_id installation_id operation_id revision "
    "status approved_at expires_at revoked_at certificate_id service_id "
    "hostnames policy_sha256 challenge dns_mode dns_zone credential_id "
    "credential_revision"
).split())
_BINDING = frozenset((
    "host_id host_fingerprint installation_id state_volume_id registry_id "
    "consumer purpose credential_id"
).split())
_CANONICAL_AUTH = _BINDING | frozenset((
    "schema issuer credential_revision authorization_id revision status "
    "approved_at revoked_at expires_at"
).split())
_CANONICAL_RECEIPT = _BINDING | frozenset((
    "schema credential_revision authorization_id authorization_revision "
    "request_id delivery_id receipt_id outcome installed_at"
).split())
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_ZONE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
_DENIAL = "cloudflare-https-installed-credential-not-current"


def _deny():
    raise PolicyError(_DENIAL) from None


def _exact(value, names):
    if type(value) is not dict or set(value) != names:
        _deny()
    return value


def _hash(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, UnicodeError):
        _deny()
    return hashlib.sha256(raw).hexdigest()


def _valid_id(value, *, short=False):
    pat = _HEX32 if short else _HEX64
    if type(value) is not str or pat.fullmatch(value) is None:
        _deny()


def _zone(name, zone):
    if (type(name) is not str or type(zone) is not str
            or len(name) > 253 or len(zone) > 253
            or _ZONE.fullmatch(name) is None or _ZONE.fullmatch(zone) is None
            or name == zone or not name.endswith("." + zone)):
        _deny()


def verify_installed(state: Path, policy: Authorization, *, approved: dict,
                     installed: dict, root_inspection: dict, owner: dict,
                     canonical_authorization: dict, canonical_receipt: dict,
                     installation: dict, issuer_uid: int, now: int) -> dict:
    """Correlate root/owner/canonical-v1 records and check private issuer bytes.

    Every parameter is untrusted until the root owner has authenticated its
    filesystem/signature/protocol origin. A caller-supplied 'verified' boolean
    is never accepted. This pure cross-check cannot prove HTTPS delivery or
    grant controller selected issue/renew/stage.
    """
    try:
        a = _exact(approved, _APPROVED)
        i = _exact(installed, _INSTALLED)
        observed = _exact(root_inspection, _INSPECT)
        o = _exact(owner, _OWNER)
        ca = _exact(canonical_authorization, _CANONICAL_AUTH)
        cr = _exact(canonical_receipt, _CANONICAL_RECEIPT)
        binding = _exact(installation, _BINDING | frozenset((
            "issuer_uid issuer_gid issuer_grant_id issuer_storage_id "
            "assignment_id assignment_revision assignment_receipt_sha256 "
            "owner_authority_sha256 policy_sha256"
        ).split()))
        if (type(now) is not int or now <= 0
                or type(issuer_uid) is not int or issuer_uid < 1000
                or issuer_uid != os.geteuid()
                or not isinstance(state, Path) or not state.is_absolute()
                or not isinstance(policy, Authorization)
                or policy.challenge != "dns-01" or policy.dns_plugin != "dns-cloudflare"
                or len(policy.hostnames) != 1):
            _deny()
        if (a["schema"] != AUTH_SCHEMA or a["state"] != "approved"
                or i["schema"] != RECEIPT_SCHEMA or i["state"] != "approved"
                or i["status"] != "installed" or observed["schema"] != RECEIPT_SCHEMA
                or observed["status"] != "installed"
                or type(a["expires_at"]) is not int or a["expires_at"] <= now
                or type(i["expires_at"]) is not int or i["expires_at"] <= now
                or type(i["installed_at"]) is not int or not 0 < i["installed_at"] <= now + 5):
            _deny()
        for k in _APPROVED - {"schema"}:
            if a[k] != i[k]:
                _deny()
        for k in ("assignment_revision", "credential_revision", "grant_id", "storage_id"):
            if i[k] != observed[k]:
                _deny()
        if (a["certificate_id"] != policy.certificate_id
                or a["policy_sha256"] != policy.fingerprint
                or type(a["assignment_revision"]) is not int or a["assignment_revision"] < 1
                or type(a["credential_revision"]) is not int or a["credential_revision"] < 1
                or type(a["credential_id"]) is not str or _UUID.fullmatch(a["credential_id"]) is None):
            _deny()
        _valid_id(a["grant_id"], short=True)
        _valid_id(a["storage_id"], short=True)
        _valid_id(a["receipt_sha256"])
        _zone(policy.hostnames[0], a["zone_name"])

        # The owner receipt is an output of separately verified Ed25519 signed
        # assignment and monotonic second-owner ledger, not a browser claim.
        if (o["schema"] != OWNER_SCHEMA or o["origin"] != "managed"
                or o["verified_by"] != "signed-host-discover"
                or o["status"] != "approved" or o["revoked_at"] is not None
                or type(o["revision"]) is not int or o["revision"] < 1
                or type(o["expires_at"]) is not int or o["expires_at"] <= now
                or o["certificate_id"] != a["certificate_id"]
                or o["hostnames"] != list(policy.hostnames)
                or o["policy_sha256"] != policy.fingerprint
                or o["challenge"] != "dns-01"
                or o["dns_mode"] != "local-cloudflare"
                or o["dns_zone"] != a["zone_name"]
                or o["credential_id"] != "cloudflare-" + a["credential_id"].replace("-", "")
                or o["credential_revision"] != a["credential_revision"]
                or o["revision"] != a["assignment_revision"]):
            _deny()
        # Independent installed Host/installation/STATE witness and policy
        # may not be supplied by the issuer, rootfs or HTTP response itself.
        if (binding["issuer_uid"] != issuer_uid
                or type(binding["issuer_gid"]) is not int or binding["issuer_gid"] < 1000
                or binding["issuer_grant_id"] != a["grant_id"]
                or binding["issuer_storage_id"] != a["storage_id"]
                or binding["assignment_id"] != a["assignment_id"]
                or binding["assignment_revision"] != a["assignment_revision"]
                or binding["assignment_receipt_sha256"] != a["receipt_sha256"]
                or binding["owner_authority_sha256"] != _hash(o)
                or binding["policy_sha256"] != policy.fingerprint
                or binding["host_id"] != o["host_id"]
                or binding["installation_id"] != o["installation_id"]
                or binding["consumer"] != CONSUMER
                or binding["purpose"] != PURPOSE
                or binding["credential_id"] != o["credential_id"]):
            _deny()
        for key in ("host_id", "installation_id", "state_volume_id", "assignment_id"):
            if type(binding[key]) is not str or _UUID.fullmatch(binding[key]) is None:
                _deny()
        for key in ("host_fingerprint", "assignment_receipt_sha256",
                    "owner_authority_sha256", "policy_sha256"):
            _valid_id(binding[key])
        if (type(binding["registry_id"]) is not str
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", binding["registry_id"])):
            _deny()

        # Canonical HTTPS v1 authorization and receipt MUST already have
        # passed host-identify's signature + durable anti-replay validation.
        # The issuer only checks their exact nonsecret identity and revision.
        if (ca["schema"] != CANONICAL_AUTH_SCHEMA
                or cr["schema"] != CANONICAL_RECEIPT_SCHEMA
                or ca["status"] != "approved" or ca["revoked_at"] is not None
                or type(ca["expires_at"]) is not int or ca["expires_at"] <= now
                or type(ca["credential_revision"]) is not int
                or ca["credential_revision"] != a["credential_revision"]
                or type(ca["revision"]) is not int or ca["revision"] < 1
                or cr["outcome"] != "installed"
                or type(cr["installed_at"]) is not int
                or cr["installed_at"] > now + 5
                or cr["installed_at"] <= 0
                or cr["authorization_id"] != ca["authorization_id"]
                or cr["authorization_revision"] != ca["revision"]
                or cr["credential_revision"] != ca["credential_revision"]
                or type(cr["request_id"]) is not str or _UUID.fullmatch(cr["request_id"]) is None
                or type(cr["delivery_id"]) is not str or _UUID.fullmatch(cr["delivery_id"]) is None
                or type(cr["receipt_id"]) is not str or _UUID.fullmatch(cr["receipt_id"]) is None):
            _deny()
        for k in _BINDING:
            if ca[k] != binding[k] or cr[k] != binding[k]:
                _deny()
        # Do not accept synthetically advanced root ledger in place of
        # the exact signed delivery/installer transaction.
        if cr["installed_at"] < i["installed_at"]:
            _deny()

        # Only the issuer UID can read its actual private STATE file; no
        # returned token, digest or issuer readiness claim.  Existing
        # operation locks and root-owned certificate policy remain separate.
        cloudflare_credential_snapshot(state)
        return {
            "schema": SCHEMA, "status": "issuer-private-file-source-correlated",
            "certificate_id": policy.certificate_id,
            "credential_revision": a["credential_revision"],
            "assignment_revision": a["assignment_revision"],
            "can_issue": False, "can_renew": False, "tls_ready": False,
            "requires_selected_controller_admission": True,
        }
    except (KeyError, TypeError, AttributeError, ValueError, OSError):
        _deny()
