"""Selected issuer readback of root-installed Cloudflare token, no fetch."""
from pathlib import Path
import copy

import pytest
from zog.certify_manage.model import Authorization, PolicyError
from zog.certify_manage.cloudflare_https_contract import verify_installed, SCHEMA, RECEIPT_SCHEMA
from zog.certify_manage.adapter import CertbotAdapter
from test_model import policy


def fixture(tmp_path):
    p = Authorization.from_dict(policy(
        challenge="dns-01", dns_plugin="dns-cloudflare"))
    dns = tmp_path / "dns"
    dns.mkdir(mode=0o700)
    target = dns / "cloudflare.ini"
    # Test-only dummy, never an actual Cloudflare credential.
    target.write_bytes(b"dns_cloudflare_api_token = " + b"x"*24 + b"\n")
    target.chmod(0o600)
    approved = {
        "schema": SCHEMA, "certificate_id": p.certificate_id,
        "hostnames": list(p.hostnames), "dns_zone": "example.org",
        "credential_id": "cloudflare-approved",
        "credential_revision": 7, "assignment_revision": 3,
        "grant_id": "a"*32, "storage_id": "b"*32,
        "issuer_uid": 28001, "policy_sha256": "c"*64,
    }
    installed = {"schema": RECEIPT_SCHEMA, "status": "installed",
                 "credential_revision": 7, "assignment_revision": 3}
    return p, approved, installed, target


def test_selected_readback_preserves_private_certbot_file_and_no_grant(tmp_path):
    p, approved, installed, target = fixture(tmp_path)
    result = verify_installed(tmp_path, p, approved=approved,
                              installed=installed, issuer_uid=28001)
    assert result["status"] == "issuer-private-file-current"
    assert result["requires_selected_controller_admission"] is True
    assert not result["can_issue"] and not result["can_renew"]
    assert "token" not in str(result)
    assert "--dns-cloudflare-credentials" in CertbotAdapter().arguments(
        "issue", tmp_path, p)
    assert "https" not in " ".join(CertbotAdapter().arguments(
        "issue", tmp_path, p))


@pytest.mark.parametrize("place,key,value", [
    ("approved","credential_revision",8),
    ("approved","assignment_revision",4),
    ("approved","issuer_uid",0),
    ("approved","dns_zone","another.example.org"),
    ("approved","certificate_id","foreign"),
    ("approved","policy_sha256","bad"),
    ("installed","credential_revision",8),
    ("installed","assignment_revision",4),
    ("installed","status","blocked"),
])
def test_stale_rotation_assignment_or_issuer_identity_denied(
        tmp_path, place, key, value):
    p, approved, installed, _ = fixture(tmp_path)
    (approved if place == "approved" else installed)[key] = value
    with pytest.raises(PolicyError, match="cloudflare-https-installed"):
        verify_installed(tmp_path, p, approved=approved,
                         installed=installed, issuer_uid=28001)


def test_issuer_mode_or_secret_file_missing_blocks(tmp_path):
    p, approved, installed, target = fixture(tmp_path)
    target.chmod(0o644)
    with pytest.raises(PolicyError):
        verify_installed(tmp_path, p, approved=approved,
                         installed=installed, issuer_uid=28001)
    target.unlink()
    with pytest.raises((PolicyError, FileNotFoundError)):
        verify_installed(tmp_path, p, approved=approved,
                         installed=installed, issuer_uid=28001)


def test_fetch_is_not_part_of_selected_issue_renew_inspect_recover():
    import inspect
    from zog.certify_manage.manager import CertificateManager
    from zog.certify_manage import __main__ as cli
    for method in ("issue", "renew", "recover", "inspect", "stage"):
        source = inspect.getsource(getattr(CertificateManager, method))
        assert "credential_delivery" not in source
        assert "request_fd" not in source
        assert "https" not in source.lower()
    assert "credential" not in inspect.getsource(cli.main).split(
        'choices=')[1].split(']')[0]  # no secret-fetch CLI action
