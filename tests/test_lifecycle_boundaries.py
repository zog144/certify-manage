"""Issuer-only DNS credential and immutable publication fault boundaries.

All examples use synthetic keys, offline Certbot adapters, and no provider
network access. Trusted zone authorization belongs to root-control.
"""
from pathlib import Path
import os
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from zog.certify_manage import Authorization, CertificateManager, UncertainOperation
from zog.certify_manage.model import PolicyError
from zog.certify_manage.security import cloudflare_credential_snapshot
import zog.certify_manage.publication as pub
from test_model import policy
from test_manager import Runner, make_cert


def _issuer(tmp_path):
    state = tmp_path / "issuer"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    return state, manager


def _credential(state, token=b"SyntheticCloudflareToken1234567890"):
    path = state / "dns" / "cloudflare.ini"
    path.write_bytes(b"dns_cloudflare_api_token = " + token + b"\n")
    path.chmod(0o600)
    return path


def test_cloudflare_issuer_requires_one_scoped_token_directive(tmp_path):
    state = tmp_path / "issuer"
    state.mkdir(mode=0o700)
    (state / "dns").mkdir(mode=0o700)
    token = _credential(state)
    digest = cloudflare_credential_snapshot(state)
    assert len(digest) == 64
    for value in (
        b"dns_cloudflare_email = somebody@example.org\n"
        b"dns_cloudflare_api_key = global\n",
        b"dns_cloudflare_api_token = SomeTokenValue1234567890\n"
        b"deploy_hook = /usr/bin/false\n",
        b"dns_cloudflare_api_token = short\n",
        b"dns_cloudflare_api_token = SomeTokenValue1234567890\n"
        b"dns_cloudflare_api_token = SomeOtherToken123456789\n",
        b"token = SomeTokenValue1234567890\n",
    ):
        token.write_bytes(value)
        with pytest.raises(PolicyError, match="unsupported-cloudflare-credential-format"):
            cloudflare_credential_snapshot(state)
    _credential(state)
    token.chmod(0o640)
    with pytest.raises(PolicyError):
        cloudflare_credential_snapshot(state)
    token.chmod(0o600)
    outside = tmp_path / "other"
    outside.write_bytes(token.read_bytes())
    token.unlink()
    token.symlink_to(outside)
    with pytest.raises((PolicyError, OSError)):
        cloudflare_credential_snapshot(state)


def test_secret_content_never_entered_inspection_or_receipt(tmp_path):
    state, manager = _issuer(tmp_path)
    receipt = manager.stage()
    assert "SyntheticCloudflareToken" not in str(receipt)
    assert "cloudflare" not in str(receipt)
    assert "tls_ready" not in receipt


def test_stage_refuses_changed_key_between_validation_and_staging(tmp_path, monkeypatch):
    state, manager = _issuer(tmp_path)
    original = pub._lineage_file
    replacement = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evil_key = replacement.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    def replaced(root, name, filename, *, private):
        if filename == "privkey.pem":
            return evil_key
        return original(root, name, filename, private=private)
    monkeypatch.setattr(pub, "_lineage_file", replaced)
    with pytest.raises(PolicyError, match="stage-private-key-mismatch"):
        manager.stage()
    assert not list((state / "publications").rglob("receipt.json"))


def test_stage_refuses_changed_certificate_chain(tmp_path, monkeypatch):
    state, manager = _issuer(tmp_path)
    donor = tmp_path / "donor"
    donor.mkdir(mode=0o700)
    make_cert(donor, "station-web")
    incorrect_chain = (donor / "certbot/config/archive/station-web/fullchain1.pem").read_bytes()
    original = pub._lineage_file
    def replaced(root, name, filename, *, private):
        if filename == "fullchain.pem":
            return incorrect_chain
        return original(root, name, filename, private=private)
    monkeypatch.setattr(pub, "_lineage_file", replaced)
    with pytest.raises(PolicyError, match="stage-fingerprint-mismatch"):
        manager.stage()
    assert not list((state / "publications").rglob("receipt.json"))


def test_interrupted_stage_keeps_private_pending_and_blocks_replay(tmp_path, monkeypatch):
    state, manager = _issuer(tmp_path)
    original = pub._write
    count = 0
    def interrupted(fd, name, data):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("synthetic-power-loss")
        return original(fd, name, data)
    monkeypatch.setattr(pub, "_write", interrupted)
    with pytest.raises(OSError, match="synthetic-power-loss"):
        manager.stage()
    root = state / "publications/station-web"
    pending = list(root.glob(".pending-*"))
    assert len(pending) == 1
    assert (pending[0] / "fullchain.pem").exists()
    assert not list(root.glob("[0-9a-f]" * 64))
    monkeypatch.setattr(pub, "_write", original)
    with pytest.raises(PolicyError, match="publication-pending-manual-recovery"):
        manager.stage()
    # Operator-controlled evidence disposition, not an automatic issuer cleanup.
    shutil.rmtree(pending[0])
    assert manager.stage()["state"] == "issuer-private-unbound"


def test_completed_stage_replay_checks_actual_private_bytes(tmp_path):
    state, manager = _issuer(tmp_path)
    original = manager.stage()
    dest = state / "publications/station-web" / original["certificate_fingerprint_sha256"]
    key = dest / "privkey.pem"
    key.write_bytes(b"fake-private-key")
    with pytest.raises(PolicyError, match="publication-generation-conflict"):
        manager.stage()


def test_renew_fails_closed_if_approved_credential_changes_during_certbot(tmp_path):
    state = tmp_path / "issuer"
    state.mkdir(mode=0o700)
    auth = Authorization.from_dict(policy(challenge="dns-01", dns_plugin="dns-cloudflare"))
    manager = CertificateManager(state, auth, Runner(state))
    manager.prepare()
    make_cert(state, "station-web")
    conf = state / "certbot/config/renewal/station-web.conf"
    lines = conf.read_text().splitlines()
    out = []
    for line in lines:
        if line.startswith("webroot_path =") or line.startswith("[[webroot_map]]") or line.startswith("station.example.org ="):
            continue
        if line == "authenticator = webroot":
            out.append("authenticator = dns-cloudflare")
            out.append("dns_cloudflare_credentials = " + str(state / "dns/cloudflare.ini"))
        else:
            out.append(line)
    conf.write_text("\n".join(out) + "\n")
    token = _credential(state)
    status = manager.inspect()
    assert status.health == "valid"
    manager._record("issue", "ready", status.fingerprint_sha256, "abcdef123456", "issued")

    class RotatingRunner:
        def arguments(self, action, state, owner):
            return ("renew",)
        def run(self, args):
            _credential(state, b"RotatedCloudflareToken123456789000")
            return 0

    manager = CertificateManager(state, auth, RotatingRunner())
    with pytest.raises(UncertainOperation, match="cloudflare-credential-changed-during-operation"):
        manager.renew()
    assert manager.inspect().health == "uncertain"
    with pytest.raises(UncertainOperation, match="operator-recovery-required"):
        manager.renew()


def test_identical_token_replacement_has_distinct_issuer_snapshot(tmp_path):
    state = tmp_path / "issuer"
    state.mkdir(mode=0o700)
    (state / "dns").mkdir(mode=0o700)
    token = _credential(state)
    before = cloudflare_credential_snapshot(state)
    # The host owner uses a private fsynced temp + atomic replacement. Even
    # keeping token bytes unchanged must produce a new file-generation check.
    replacement = state / "dns" / ".replacement"
    replacement.write_bytes(token.read_bytes())
    replacement.chmod(0o600)
    os.replace(replacement, token)
    after = cloudflare_credential_snapshot(state)
    assert before != after


def test_expired_certificate_blocks_private_stage_and_positive_inspection(tmp_path, monkeypatch):
    import zog.certify_manage.certificates as certs
    from datetime import datetime, timezone, timedelta
    from zog.certify_manage.inspection_result import selected_inspect, PREFIX
    import json
    state, manager = _issuer(tmp_path)
    real_datetime = datetime

    class LaterDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz or timezone.utc) + timedelta(days=366)

    monkeypatch.setattr(certs, "datetime", LaterDateTime)
    assert manager.inspect().health == "expired-or-not-yet-valid"
    with pytest.raises(Exception, match="publication-requires-matching-lineage"):
        manager.stage()
    line = selected_inspect(state, manager.policy)
    result = json.loads(line[len(PREFIX):])
    assert result["health"] == "expired-or-not-yet-valid"
    assert result["issuer_verified"] is False
    assert result["tls_ready"] is False


def test_pending_stage_survives_fresh_manager_recovery_without_reissue(tmp_path, monkeypatch):
    state, manager = _issuer(tmp_path)
    original = pub._write

    def fail_after_first(fd, name, data):
        if name == "privkey.pem":
            raise OSError("synthetic-crash-after-chain")
        return original(fd, name, data)

    monkeypatch.setattr(pub, "_write", fail_after_first)
    with pytest.raises(OSError):
        manager.stage()
    monkeypatch.setattr(pub, "_write", original)
    # New issuer process after reboot: issuer journal remains ready, yet the
    # stage operation still cannot silently discard uncertain partial files.
    new_process = CertificateManager(state, manager.policy, Runner(state))
    assert new_process.inspect().health == "valid"
    with pytest.raises(PolicyError, match="publication-pending-manual-recovery"):
        new_process.stage()
    assert len(list((state / "publications/station-web").glob(".pending-*"))) == 1
