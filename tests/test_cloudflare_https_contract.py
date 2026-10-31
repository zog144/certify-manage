"""Cloudflare HTTPS v1 readback against independent root/owner protocol facts.

All tests are source-only, with synthetic non-live credentials. The shared
host-identify signature/ledger checker and root-control protected open happen
*before* this readback in a real installation.
"""
import copy
import hashlib
import json
import os
import uuid

import pytest

from zog.certify_manage.model import Authorization, PolicyError
from zog.certify_manage.cloudflare_https_contract import (
    AUTH_SCHEMA, CANONICAL_AUTH_SCHEMA, CANONICAL_RECEIPT_SCHEMA,
    OWNER_SCHEMA, RECEIPT_SCHEMA, SCHEMA, _private_file_generation, verify_installed,
)
from zog.certify_manage.adapter import CertbotAdapter
from test_model import policy

NOW = 1793500000

def ident(n):
    return str(uuid.UUID("00000000-0000-4000-8000-" + format(n, "012x")))

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True).encode("ascii")).hexdigest()

def fixture(tmp_path):
    p = Authorization.from_dict(policy(challenge="dns-01", dns_plugin="dns-cloudflare"))
    dns = tmp_path / "dns"
    dns.mkdir(mode=0o700)
    target = dns / "cloudflare.ini"
    target.write_bytes(b"dns_cloudflare_api_token = " + b"x" * 24 + b"\n")
    target.chmod(0o600)

    credential = ident(7)
    owner = {
        "schema": OWNER_SCHEMA, "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": ident(1), "installation_id": ident(2),
        "operation_id": ident(3), "revision": 3, "status": "approved",
        "approved_at": NOW - 200, "expires_at": NOW + 1800,
        "revoked_at": None, "certificate_id": p.certificate_id,
        "service_id": "candidate-nginx", "hostnames": list(p.hostnames),
        "policy_sha256": p.fingerprint, "challenge": "dns-01",
        "dns_mode": "local-cloudflare", "dns_zone": "example.org",
        "credential_id": "cloudflare-" + credential.replace("-", ""),
        "credential_revision": 7,
    }
    root = {
        "schema": AUTH_SCHEMA, "state": "approved", "project": "/protected/project",
        "certificate_id": p.certificate_id, "assignment_id": ident(8),
        "assignment_revision": 3, "credential_id": credential,
        "credential_revision": 7, "zone_id": "zone7", "zone_name": "example.org",
        "grant_id": "a" * 32, "storage_id": "b" * 32,
        "policy_sha256": p.fingerprint, "receipt_sha256": "c" * 64,
        "expires_at": NOW + 1700,
    }
    installed = {**root, "schema": RECEIPT_SCHEMA,
                 "status": "installed", "installed_at": NOW - 90}
    inspection = {
        "schema": RECEIPT_SCHEMA, "status": "installed",
        "assignment_revision": 3, "credential_revision": 7,
        "grant_id": root["grant_id"], "storage_id": root["storage_id"],
    }
    binding = {
        "host_id": owner["host_id"], "host_fingerprint": "d" * 64,
        "installation_id": owner["installation_id"],
        "state_volume_id": ident(4), "registry_id": "station-registry",
        "consumer": "certify-manage", "purpose": "issuer-cloudflare-dns01",
        "credential_id": owner["credential_id"],
        "issuer_uid": os.geteuid(), "issuer_gid": os.getegid(),
        "issuer_grant_id": root["grant_id"], "issuer_storage_id": root["storage_id"],
        "assignment_id": root["assignment_id"],
        "assignment_revision": root["assignment_revision"],
        "assignment_receipt_sha256": root["receipt_sha256"],
        "owner_authority_sha256": digest(owner),
        "policy_sha256": p.fingerprint,
        "file_generation_sha256": _private_file_generation(tmp_path),
    }
    common = {
        k: binding[k] for k in (
            "host_id", "host_fingerprint", "installation_id", "state_volume_id",
            "registry_id", "consumer", "purpose", "credential_id")
    }
    canonical_auth = {
        **common, "schema": CANONICAL_AUTH_SCHEMA,
        "issuer": "https://credential-authority.example.org",
        "credential_revision": 7, "authorization_id": ident(11),
        "revision": 5, "status": "approved", "approved_at": NOW - 300,
        "revoked_at": None, "expires_at": NOW + 1600,
    }
    canonical_receipt = {
        **common, "schema": CANONICAL_RECEIPT_SCHEMA,
        "credential_revision": 7, "authorization_id": canonical_auth["authorization_id"],
        "authorization_revision": 5, "request_id": ident(12),
        "delivery_id": ident(13), "receipt_id": ident(14),
        "outcome": "installed", "installed_at": NOW - 80,
    }
    args = dict(
        state=tmp_path, policy=p, approved=root, installed=installed,
        root_inspection=inspection, owner=owner,
        canonical_authorization=canonical_auth,
        canonical_receipt=canonical_receipt,
        installation=binding, issuer_uid=os.geteuid(), now=NOW,
    )
    return args, target

def accepted(args):
    return verify_installed(**args)

def test_source_correlated_readback_not_issuer_or_transport_success(tmp_path):
    args, target = fixture(tmp_path)
    # The source-only fixture's active euid must be a nonroot issuer.
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged issuer uid")
    result = accepted(args)
    assert result == {
        "schema": SCHEMA, "status": "issuer-private-file-source-correlated",
        "certificate_id": "station-web", "credential_revision": 7,
        "assignment_revision": 3, "can_issue": False,
        "can_renew": False, "tls_ready": False,
        "requires_selected_controller_admission": True,
    }
    assert "token" not in str(result)
    assert "--dns-cloudflare-credentials" in CertbotAdapter().arguments(
        "issue", args["state"], args["policy"])
    assert "request_fd" not in " ".join(CertbotAdapter().arguments(
        "issue", args["state"], args["policy"]))

@pytest.mark.parametrize("component,key,value", [
    ("approved", "policy_sha256", "f" * 64),
    ("approved", "grant_id", "0" * 32),
    ("approved", "storage_id", "0" * 32),
    ("approved", "receipt_sha256", "0" * 64),
    ("approved", "assignment_revision", 4),
    ("approved", "credential_revision", 8),
    ("approved", "zone_name", "ample.org"),
    ("approved", "zone_name", "other.example.org"),
    ("approved", "state", "revoked"),
    ("approved", "expires_at", NOW),
    ("installed", "status", "pending"),
    ("installed", "credential_revision", 8),
    ("installed", "assignment_revision", 2),
    ("installed", "grant_id", "0" * 32),
    ("installed", "installed_at", NOW + 400),
    ("root_inspection", "credential_revision", 8),
    ("root_inspection", "status", "blocked"),
    ("owner", "verified_by", "browser-proposal"),
    ("owner", "status", "revoked"),
    ("owner", "expires_at", NOW),
    ("owner", "revoked_at", NOW - 1),
    ("owner", "revision", 4),
    ("owner", "hostnames", ["foreign.example.org"]),
    ("owner", "dns_zone", "other.example.org"),
    ("owner", "credential_revision", 9),
    ("owner", "policy_sha256", "0" * 64),
    ("owner", "host_id", ident(77)),
    ("installation", "state_volume_id", "not-a-uuid"),
    ("installation", "issuer_storage_id", "0" * 32),
    ("installation", "issuer_grant_id", "0" * 32),
    ("installation", "issuer_uid", 0),
    ("installation", "owner_authority_sha256", "0" * 64),
    ("installation", "assignment_receipt_sha256", "0" * 64),
    ("installation", "purpose", "station-access-password"),
    ("installation", "file_generation_sha256", "0" * 64),
    ("installation", "consumer", "host-nginx-https"),
    ("canonical_authorization", "schema", "unreviewed"),
    ("canonical_authorization", "status", "revoked"),
    ("canonical_authorization", "expires_at", NOW),
    ("canonical_authorization", "credential_revision", 8),
    ("canonical_authorization", "authorization_id", ident(71)),
    ("canonical_authorization", "host_fingerprint", "f" * 64),
    ("canonical_receipt", "outcome", "failed"),
    ("canonical_receipt", "credential_revision", 8),
    ("canonical_receipt", "authorization_revision", 6),
    ("canonical_receipt", "authorization_id", ident(71)),
    ("canonical_receipt", "installation_id", ident(71)),
    ("canonical_receipt", "installed_at", NOW + 300),
])
def test_changed_revision_signed_owner_issuer_grant_or_canonical_delivery_denied(
        tmp_path, component, key, value):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged issuer uid")
    args, _ = fixture(tmp_path)
    args[component][key] = value
    with pytest.raises(PolicyError, match="cloudflare-https-installed-credential-not-current"):
        accepted(args)

def test_extra_fields_and_untrusted_tokens_are_never_accepted(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged issuer uid")
    for field in ("approved", "installed", "root_inspection", "owner",
                  "installation", "canonical_authorization", "canonical_receipt"):
        target_root = tmp_path / field
        target_root.mkdir(mode=0o700)
        args, _ = fixture(target_root)
        args[field]["cloudflare_api_token"] = "synthetic-test-only"
        with pytest.raises(PolicyError, match="cloudflare-https-installed"):
            accepted(args)

def test_root_euid_mismatch_blocks_before_private_file_read(tmp_path):
    args, target = fixture(tmp_path)
    args["issuer_uid"] = 28001 if os.geteuid() != 28001 else 28002
    with pytest.raises(PolicyError, match="cloudflare-https-installed"):
        accepted(args)
    assert target.exists()

def test_file_symlink_missing_group_mode_or_wrong_directory_denied(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged issuer uid")
    args, target = fixture(tmp_path)
    for mode in (0o644, 0o640, 0o666):
        target.chmod(mode)
        with pytest.raises(PolicyError):
            accepted(args)
    target.chmod(0o600)
    # In-process replacement of issuer credential must not be read via symlink.
    backup = tmp_path / "other"
    backup.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(backup)
    with pytest.raises(PolicyError):
        accepted(args)
    target.unlink()
    with pytest.raises(PolicyError):
        accepted(args)
    target.write_bytes(b"dns_cloudflare_api_token = " + b"x"*24 + b"\n")
    target.chmod(0o600)
    (tmp_path / "dns").chmod(0o777)
    with pytest.raises(PolicyError):
        accepted(args)


def test_private_credential_fifo_is_rejected_without_blocking(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged issuer uid")
    args, target = fixture(tmp_path)
    target.unlink()
    os.mkfifo(target, 0o600)
    with pytest.raises(PolicyError, match="cloudflare-https-installed"):
        accepted(args)

def test_replaced_credential_bytes_require_new_root_installation_witness(tmp_path):
    # The old root ledger alone cannot distinguish same-revision swaps.
    # The newly root-installed, nonsecret inode-generation witness does so,
    # without storing a reusable token hash in the canonical HTTPS ledger.
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged issuer uid")
    args, target = fixture(tmp_path)
    before = accepted(args)
    temp = target.parent / ".replaced"
    temp.write_bytes(b"dns_cloudflare_api_token = " + b"y"*24 + b"\n")
    temp.chmod(0o600)
    os.replace(temp, target)
    with pytest.raises(PolicyError, match="cloudflare-https-installed"):
        accepted(args)
    assert before["can_issue"] is False
    # An actual authorized new rotation requires a new approved credential
    # revision, a new root install ledger and a new signed canonical delivery;
    # this test deliberately cannot manufacture an approval from new metadata.


def test_identical_token_atomic_replacement_rejects_old_file_generation(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged issuer uid")
    args, target = fixture(tmp_path)
    assert accepted(args)["can_renew"] is False
    old_identity = args["installation"]["file_generation_sha256"]
    new_path = target.parent / ".same-bytes-replacement"
    new_path.write_bytes(target.read_bytes())
    new_path.chmod(0o600)
    os.replace(new_path, target)
    assert _private_file_generation(args["state"]) != old_identity
    with pytest.raises(PolicyError, match="cloudflare-https-installed"):
        accepted(args)

def test_automatic_issue_renew_inspect_and_recover_do_not_invoke_https():
    import inspect
    from zog.certify_manage.manager import CertificateManager
    from zog.certify_manage import __main__ as cli
    for method in ("issue", "renew", "recover", "inspect", "stage"):
        source = inspect.getsource(getattr(CertificateManager, method))
        assert "credential_delivery" not in source
        assert "cloudflare_https_contract" not in source
        assert "https" not in source.lower()
    assert '"request-credential"' not in inspect.getsource(cli.main)
    assert '"fetch-cloudflare"' not in inspect.getsource(cli.main)
