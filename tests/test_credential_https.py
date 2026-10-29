"""Source-only Cloudflare HTTPS consumer contract: no network, SSH or secrets."""
import copy
import hashlib
import json
import uuid

import pytest

from zog.certify_manage import Authorization
from zog.certify_manage.credential_https import (
    CloudflareDeliveryDenied, CLIENT_FIELDS, SCHEMA, PURPOSE, REQUEST_FIELDS,
    select_https_cloudflare, check_installed_credential,
)
from test_model import policy

NOW = 1793000000

def u(n):
    return str(uuid.UUID("00000000-0000-4000-8000-" + f"{n:012x}"))

def sha(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True,
                                    separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

def fixture():
    auth = Authorization.from_dict(policy(challenge="dns-01", dns_plugin="dns-cloudflare"))
    cred_id = u(7)
    root = {
        "schema": "zog-issuer-cloudflare-credential-v1", "state": "approved",
        "project": "/approved/controller", "certificate_id": auth.certificate_id,
        "assignment_id": u(8), "assignment_revision": 4, "credential_id": cred_id,
        "credential_revision": 5, "zone_id": "zone7", "zone_name": "example.org",
        "grant_id": "a" * 32, "storage_id": "b" * 32,
        "policy_sha256": auth.fingerprint,
        "receipt_sha256": "f" * 64, "expires_at": NOW + 7200,
    }
    client = {
        "schema": SCHEMA, "host_id": u(1), "host_fingerprint": "a" * 64,
        "installation_id": u(2), "state_volume_id": u(3),
        "registry_id": "main-registry", "station_authority_sha256": "c" * 64,
        "owner_authority_sha256": "d" * 64, "signer_pin_sha256": "e" * 64,
        "credential_authorization_id": sha(root),
        "issuer_grant_id": "a" * 32, "issuer_storage_id": "b" * 32,
        "issuer_uid": 28001, "issuer_gid": 28002, "software_view": "sha256:" + "4" * 64,
        "certificate_id": auth.certificate_id, "fqdn": auth.hostnames[0],
        "dns_zone": "example.org",
        "credential_id": "cloudflare-" + cred_id.replace("-", ""),
        "credential_revision": 5, "assignment_id": u(8), "assignment_revision": 4,
        "assignment_receipt_sha256": "f" * 64, "delivery_policy_sha256": "1" * 64,
        "https_authority_pin_sha256": "2" * 64, "consumer": "host-nginx-https",
    }
    admission = {
        "schema": "zog-host-deploy-cross-host-issuer-admission-v1",
        "status": "source-bound-nonsecret-admission",
        "host_id": u(1), "installation_id": u(2), "owner_revision": 4,
        "credential_revision": 5, "authorization_id": sha(root),
        "delivery_policy_sha256": "1" * 64,
        "installed_bytes_verified": False, "credential_transferred": False,
    }
    return {"client": client, "admission": admission, "root_approval": root,
            "issuer_policy": auth, "now": NOW}

def select(value=None):
    return select_https_cloudflare(**(value or fixture()))

def test_https_selection_is_purpose_scoped_nonsecret():
    selected = select()
    req = selected.request(request_id=u(9), nonce="a" * 32)
    assert set(req) == REQUEST_FIELDS
    assert set(selected.fields) == CLIENT_FIELDS
    assert req["schema"] == "zog-certify-cloudflare-https-request-v1"
    assert req["purpose"] == PURPOSE
    assert req["request_id"] != req["assignment_id"]
    assert req["fqdn"] == "station.example.org"
    assert req["dns_zone"] == "example.org"
    assert req["credential_revision"] == 5
    assert "ssh" not in str(req).lower()
    assert "token" not in str(req).lower()
    assert "api_key" not in str(req).lower()
    assert "private" not in str(req).lower()
    assert "cloudflare.ini" not in str(req)
    assert "https_authority_pin_sha256" in req

@pytest.mark.parametrize(("field", "key", "value"), [
    ("client", "schema", "zog-issuer-cross-host-client-v1"),
    ("client", "fqdn", "other.example.org"),
    ("client", "dns_zone", "other.org"),
    ("client", "credential_revision", 6),
    ("client", "assignment_revision", 3),
    ("client", "host_id", u(20)),
    ("client", "state_volume_id", u(20)),
    ("client", "https_authority_pin_sha256", "bad"),
    ("client", "issuer_uid", 0),
    ("client", "issuer_storage_id", "0" * 32),
    ("client", "consumer", "other"),
    ("admission", "status", "revoked"),
    ("admission", "owner_revision", 3),
    ("admission", "credential_transferred", True),
    ("admission", "installed_bytes_verified", True),
    ("root_approval", "expires_at", NOW),
    ("root_approval", "state", "revoked"),
    ("root_approval", "credential_revision", 4),
    ("root_approval", "grant_id", "0" * 32),
    ("root_approval", "receipt_sha256", "0" * 64),
    ("root_approval", "zone_name", "other.example.org"),
])
def test_stale_mismatched_foreign_or_ssh_client_denied(field,key,value):
    d = fixture()
    d[field][key] = value
    with pytest.raises(CloudflareDeliveryDenied, match="issuer-https-credential-binding-unavailable"):
        select(d)

def test_extra_selectors_and_secrets_denied():
    for field in ("client", "root_approval", "admission"):
        d = fixture()
        d[field]["token"] = "must-not-be-accepted"
        with pytest.raises(CloudflareDeliveryDenied):
            select(d)

def test_no_implicit_secret_fetch_on_certificate_policy_or_renewal(monkeypatch, tmp_path):
    import zog.certify_manage.credential_https as bridge
    def deny(*args, **kwargs):
        raise AssertionError("HTTPS credential delivery was invoked from certificate code")
    monkeypatch.setattr(bridge, "select_https_cloudflare", deny)
    auth = Authorization.from_dict(policy())
    assert auth.challenge == "http-01"
    # The module never participates in normal issuer command construction.
    from zog.certify_manage.adapter import CertbotAdapter
    arguments = CertbotAdapter().arguments("renew", tmp_path, auth)
    assert "renew" in arguments
    from zog.certify_manage.inspection_result import SCHEMA as INSPECT
    assert INSPECT == "zog-certify-inspection-result-v1"

def test_installed_root_ledger_correlated_but_not_https_or_tls_ready():
    f = fixture()
    s = select(f)
    root = {**f["root_approval"], "schema": "zog-issuer-cloudflare-installation-v1",
            "status": "installed", "installed_at": NOW - 30}
    inspect = {
        "schema": root["schema"], "status": "installed",
        "assignment_revision": root["assignment_revision"],
        "credential_revision": root["credential_revision"],
        "grant_id": root["grant_id"], "storage_id": root["storage_id"],
    }
    result = check_installed_credential(s, root_ledger=root,
                                        root_inspection=inspect, now=NOW)
    assert result["status"] == "root-install-ledger-correlated-only"
    assert result["credential_transferred"] is False
    assert result["issuer_ready"] is False
    assert result["tls_ready"] is False
    for k in ("status", "grant_id", "storage_id", "credential_revision", "assignment_revision"):
        bad = copy.deepcopy(inspect)
        bad[k] = "mismatch"
        with pytest.raises(CloudflareDeliveryDenied):
            check_installed_credential(s, root_ledger=root, root_inspection=bad, now=NOW)
    bad = copy.deepcopy(root)
    bad["credential_revision"] += 1
    with pytest.raises(CloudflareDeliveryDenied):
        check_installed_credential(s, root_ledger=bad, root_inspection=inspect, now=NOW)

def test_request_does_not_allow_replay_id_or_nonce_from_issuer_or_http_ui():
    s = select()
    for id, nonce in [(u(8), "g" * 32), ("bad", "a" * 32)]:
        if id == u(8):
            with pytest.raises(CloudflareDeliveryDenied):
                s.request(request_id=id, nonce=nonce)
        else:
            with pytest.raises(CloudflareDeliveryDenied):
                s.request(request_id=id, nonce=nonce)
