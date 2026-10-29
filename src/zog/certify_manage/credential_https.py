"""Nonsecret Cloudflare consumer binding for Zog's protected HTTPS delivery.

This module is a *source-level owner-to-issuer interface*, not a transport,
controller authorization, certificate program, or root credential installer.
Only an independently authenticated host owner/root consumer may use it after
loading current protected files and independently validating their signatures,
revision ledgers, TLS authority, exact peer identities and installation state.
It never accepts, transports, stores or returns a Cloudflare API token.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass

from .model import Authorization

SCHEMA = "zog-certify-cloudflare-https-consumer-v1"
REQUEST_SCHEMA = "zog-certify-cloudflare-https-request-v1"
PURPOSE = "certify-manage-dns-cloudflare"
ROOT_APPROVAL_SCHEMA = "zog-issuer-cloudflare-credential-v1"
ROOT_INSTALLED_SCHEMA = "zog-issuer-cloudflare-installation-v1"
HOST_ADMISSION_SCHEMA = "zog-host-deploy-cross-host-issuer-admission-v1"
OWNER_SCHEMA = "zog-host-deploy-certificate-owner-authority-v1"
CLIENT_FIELDS = frozenset((
    "schema host_id host_fingerprint installation_id state_volume_id "
    "registry_id station_authority_sha256 owner_authority_sha256 "
    "signer_pin_sha256 credential_authorization_id issuer_grant_id "
    "issuer_storage_id issuer_uid issuer_gid software_view certificate_id "
    "fqdn dns_zone credential_id credential_revision assignment_id "
    "assignment_revision assignment_receipt_sha256 delivery_policy_sha256 "
    "https_authority_pin_sha256 consumer"
).split())
REQUEST_FIELDS = frozenset((
    "schema purpose request_id nonce host_id host_fingerprint installation_id "
    "state_volume_id registry_id certificate_id fqdn dns_zone credential_id "
    "credential_revision assignment_id assignment_revision "
    "assignment_receipt_sha256 authorization_id owner_authority_sha256 "
    "station_authority_sha256 signer_pin_sha256 issuer_grant_id "
    "issuer_storage_id https_authority_pin_sha256"
).split())
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_HEX32 = re.compile(r"[a-f0-9]{32}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_REGISTRY = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_UUID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")


class CloudflareDeliveryDenied(ValueError):
    """One fixed, secret-free error (no injected value in the message)."""


def _deny():
    raise CloudflareDeliveryDenied("issuer-https-credential-binding-unavailable") from None


def _exact(obj, fields):
    if type(obj) is not dict or set(obj) != fields:
        _deny()
    return obj


def _hex(v):
    if type(v) is not str or _HEX.fullmatch(v) is None:
        _deny()


def _uuid(v):
    if type(v) is not str or _UUID.fullmatch(v) is None:
        _deny()
    try:
        if str(uuid.UUID(v)) != v:
            _deny()
    except ValueError:
        _deny()


def _canonical_sha(value):
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _deny()
    return hashlib.sha256(raw).hexdigest()


def _zone(name, zone):
    if (type(name) is not str or type(zone) is not str
            or len(name) > 253 or len(zone) > 253
            or _HOST.fullmatch(name) is None or _HOST.fullmatch(zone) is None
            or not name.endswith("." + zone)):
        _deny()


@dataclass(frozen=True)
class HttpsCloudflareSelection:
    """Fixed prevalidated request metadata, **not** issuer authorization.

    The root owner must hold the same current locks and independently verify
    the protected sources before and after the common HTTPS transfer. The
    caller of the normal Certbot issue/renew operation never constructs this.
    """
    fields: dict

    def request(self, *, request_id: str, nonce: str) -> dict:
        _uuid(request_id)
        if type(nonce) is not str or _HEX32.fullmatch(nonce) is None:
            _deny()
        v = self.fields
        record = {
            "schema": REQUEST_SCHEMA, "purpose": PURPOSE,
            "request_id": request_id, "nonce": nonce,
            "host_id": v["host_id"], "host_fingerprint": v["host_fingerprint"],
            "installation_id": v["installation_id"],
            "state_volume_id": v["state_volume_id"],
            "registry_id": v["registry_id"],
            "certificate_id": v["certificate_id"],
            "fqdn": v["fqdn"], "dns_zone": v["dns_zone"],
            "credential_id": v["credential_id"],
            "credential_revision": v["credential_revision"],
            "assignment_id": v["assignment_id"],
            "assignment_revision": v["assignment_revision"],
            "assignment_receipt_sha256": v["assignment_receipt_sha256"],
            "authorization_id": v["credential_authorization_id"],
            "owner_authority_sha256": v["owner_authority_sha256"],
            "station_authority_sha256": v["station_authority_sha256"],
            "signer_pin_sha256": v["signer_pin_sha256"],
            "issuer_grant_id": v["issuer_grant_id"],
            "issuer_storage_id": v["issuer_storage_id"],
            "https_authority_pin_sha256": v["https_authority_pin_sha256"],
        }
        if set(record) != REQUEST_FIELDS:
            _deny()
        # This is a nonsecret purpose-scoped request BODY to be enveloped and
        # signed by the *common* HTTPS protocol; it is not an HTTPS client.
        if len(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()) > 2048:
            _deny()
        return record


def select_https_cloudflare(*, client: dict, admission: dict,
                            root_approval: dict, issuer_policy: Authorization,
                            now: int) -> HttpsCloudflareSelection:
    """Require a current *upstream-authenticated* owner and root approval.

    Never accept PR#6's old SSH client schema or broad generic credential
    purpose. All trust checks are additionally performed by the real protected
    root reader; dictionary values alone do not authenticate their source.
    """
    try:
        c = _exact(client, CLIENT_FIELDS)
        if (c["schema"] != SCHEMA or c["consumer"] != "host-nginx-https"
                or type(now) is not int or now <= 0
                or issuer_policy.challenge != "dns-01"
                or issuer_policy.dns_plugin != "dns-cloudflare"
                or len(issuer_policy.hostnames) != 1
                or c["certificate_id"] != issuer_policy.certificate_id
                or c["fqdn"] != issuer_policy.hostnames[0]):
            _deny()
        _zone(c["fqdn"], c["dns_zone"])
        for n in ("host_id", "installation_id", "state_volume_id", "assignment_id"):
            _uuid(c[n])
        for n in ("host_fingerprint", "station_authority_sha256",
                  "owner_authority_sha256", "signer_pin_sha256",
                  "credential_authorization_id", "assignment_receipt_sha256",
                  "delivery_policy_sha256", "https_authority_pin_sha256"):
            _hex(c[n])
        if (type(c["registry_id"]) is not str or _REGISTRY.fullmatch(c["registry_id"]) is None
                or type(c["credential_id"]) is not str or _ID.fullmatch(c["credential_id"]) is None
                or type(c["credential_revision"]) is not int or c["credential_revision"] <= 0
                or type(c["assignment_revision"]) is not int or c["assignment_revision"] <= 0
                or type(c["issuer_grant_id"]) is not str or _HEX32.fullmatch(c["issuer_grant_id"]) is None
                or type(c["issuer_storage_id"]) is not str or _HEX32.fullmatch(c["issuer_storage_id"]) is None
                or type(c["issuer_uid"]) is not int or c["issuer_uid"] < 1000
                or type(c["issuer_gid"]) is not int or c["issuer_gid"] < 1000
                or type(c["software_view"]) is not str or not re.fullmatch(r"sha256:[a-f0-9]{64}", c["software_view"])):
            _deny()
        # Upstream host-deploy PR #6 independently checks signed receipt,
        # ledger, root approval and selected nginx delivery policy. Do not
        # replace that verifier with a caller-provided boolean.
        a = _exact(admission, frozenset((
            "schema status host_id installation_id owner_revision "
            "credential_revision authorization_id delivery_policy_sha256 "
            "installed_bytes_verified credential_transferred"
        ).split()))
        if (a["schema"] != HOST_ADMISSION_SCHEMA
                or a["status"] != "source-bound-nonsecret-admission"
                or a["installed_bytes_verified"] is not False
                or a["credential_transferred"] is not False
                or a["host_id"] != c["host_id"]
                or a["installation_id"] != c["installation_id"]
                or a["owner_revision"] != c["assignment_revision"]
                or a["credential_revision"] != c["credential_revision"]
                or a["authorization_id"] != c["credential_authorization_id"]
                or a["delivery_policy_sha256"] != c["delivery_policy_sha256"]):
            _deny()
        r = _exact(root_approval, frozenset((
            "schema state project certificate_id assignment_id "
            "assignment_revision credential_id credential_revision zone_id "
            "zone_name grant_id storage_id policy_sha256 receipt_sha256 expires_at"
        ).split()))
        if (r["schema"] != ROOT_APPROVAL_SCHEMA or r["state"] != "approved"
                or type(r["expires_at"]) is not int or r["expires_at"] <= now
                or r["certificate_id"] != c["certificate_id"]
                or r["assignment_id"] != c["assignment_id"]
                or r["assignment_revision"] != c["assignment_revision"]
                or r["credential_revision"] != c["credential_revision"]
                or c["credential_id"] != "cloudflare-" + r["credential_id"].replace("-", "")
                or r["zone_name"] != c["dns_zone"]
                or r["grant_id"] != c["issuer_grant_id"]
                or r["storage_id"] != c["issuer_storage_id"]
                or r["policy_sha256"] != issuer_policy.fingerprint
                or r["receipt_sha256"] != c["assignment_receipt_sha256"]
                or _canonical_sha(r) != c["credential_authorization_id"]):
            _deny()
        _uuid(r["credential_id"])
        if c["credential_id"] != "cloudflare-" + r["credential_id"].replace("-", ""):
            _deny()
        return HttpsCloudflareSelection(fields=dict(c))
    except (KeyError, TypeError, AttributeError, ValueError):
        _deny()


def check_installed_credential(selection: HttpsCloudflareSelection, *,
                               root_ledger: dict, root_inspection: dict,
                               now: int) -> dict:
    """Return redacted source-level reconciliation after a *separate* install.

    Root owner independently reads a protected file + its current installed
    ledger and has authenticated the HTTP delivery/request IDs and installed
    bytes before invoking this check. It does not authorize issuer execution.
    """
    try:
        if not isinstance(selection, HttpsCloudflareSelection):
            _deny()
        c = selection.fields
        approval_fields = frozenset((
            "schema state status project certificate_id assignment_id assignment_revision "
            "credential_id credential_revision zone_id zone_name grant_id storage_id "
            "policy_sha256 receipt_sha256 expires_at installed_at"
        ).split())
        r = _exact(root_ledger, approval_fields)
        i = _exact(root_inspection, frozenset((
            "schema status assignment_revision credential_revision grant_id storage_id"
        ).split()))
        if (r["schema"] != ROOT_INSTALLED_SCHEMA or r["state"] != "approved" or r["status"] != "installed"
                or i["schema"] != ROOT_INSTALLED_SCHEMA or i["status"] != "installed"
                or type(now) is not int or now <= 0
                or type(r["expires_at"]) is not int or r["expires_at"] <= now
                or type(r["installed_at"]) is not int or r["installed_at"] > now + 300
                or r["certificate_id"] != c["certificate_id"]
                or r["assignment_id"] != c["assignment_id"]
                or r["assignment_revision"] != c["assignment_revision"]
                or r["credential_revision"] != c["credential_revision"]
                or c["credential_id"] != "cloudflare-" + r["credential_id"].replace("-", "")
                or r["zone_name"] != c["dns_zone"]
                or r["grant_id"] != c["issuer_grant_id"]
                or r["storage_id"] != c["issuer_storage_id"]
                or r["receipt_sha256"] != c["assignment_receipt_sha256"]
                or _canonical_sha({**{k: v for k, v in r.items()
                                      if k not in ("schema", "status", "installed_at")},
                                    "schema": ROOT_APPROVAL_SCHEMA, "state": "approved"})
                   != c["credential_authorization_id"]):
            _deny()
        for key in ("assignment_revision", "credential_revision", "grant_id", "storage_id"):
            if i[key] != r[key]:
                _deny()
        return {
            "schema": SCHEMA, "status": "root-install-ledger-correlated-only",
            "host_id": c["host_id"], "installation_id": c["installation_id"],
            "certificate_id": c["certificate_id"], "fqdn": c["fqdn"],
            "dns_zone": c["dns_zone"], "credential_revision": c["credential_revision"],
            "authorization_id": c["credential_authorization_id"],
            "issuer_grant_id": c["issuer_grant_id"],
            "issuer_storage_id": c["issuer_storage_id"],
            "credential_transferred": False, "issuer_ready": False,
            "tls_ready": False,
        }
    except (KeyError, TypeError, ValueError, AttributeError):
        _deny()
