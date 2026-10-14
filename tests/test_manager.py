from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from zog.certify_manage import Authorization, CertificateManager, CertificateError, UncertainOperation
from test_model import policy

def make_cert(root, name):
    path = root / "certbot" / "config"
    arc = path / "archive" / name
    live = path / "live" / name
    arc.mkdir(parents=True)
    live.mkdir(parents=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "station.example.org")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "station.example.org")]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=60))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("station.example.org")]), critical=False)
            .sign(key, hashes.SHA256()))
    files = {"cert.pem": cert.public_bytes(serialization.Encoding.PEM),
             "fullchain.pem": cert.public_bytes(serialization.Encoding.PEM),
             "privkey.pem": key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption())}
    for filename, raw in files.items():
        archived = arc / (filename.replace(".pem", "1.pem"))
        archived.write_bytes(raw)
        archived.chmod(0o600)
        (live / filename).symlink_to(archived.relative_to(live) if False else
                                     "../../archive/" + name + "/" + archived.name)

class Runner:
    def __init__(self, state, code=0):
        self.state = state
        self.code = code
        self.count = 0
    def arguments(self, action, state, policy):
        return (action,)
    def run(self, argv):
        self.count += 1
        if self.code == 0 and argv[0] == "issue":
            make_cert(self.state, "station-web")
        return self.code

def test_issue_and_renew_and_read_only_inspect(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    runner = Runner(state)
    manager = CertificateManager(state, Authorization.from_dict(policy()), runner)
    assert manager.inspect().health == "missing"
    assert not (state / "operations").exists()
    result = manager.issue()
    assert result.health == "valid" and len(result.fingerprint_sha256) == 64
    assert manager.renew().health == "valid"
    assert manager.inspect().health == "valid"
    assert runner.count == 2
    with pytest.raises(CertificateError, match="lineage-already-present"):
        manager.issue()

def test_interrupted_operation_blocks_mutations(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    manager._record("issue", "uncertain")
    with pytest.raises(UncertainOperation):
        manager.issue()
    assert manager.inspect().health == "uncertain"
    with pytest.raises(CertificateError, match="recover-requires-valid-lineage"):
        manager.recover()
    make_cert(state, "station-web")
    assert manager.recover().health == "valid"

def test_failed_renew_keeps_certificate_and_reports_failure(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    runner = Runner(state)
    manager = CertificateManager(state, Authorization.from_dict(policy()), runner)
    manager.issue()
    bad = CertificateManager(state, Authorization.from_dict(policy()), Runner(state, 1))
    with pytest.raises(CertificateError, match="certbot-operation-failed"):
        bad.renew()
    status = bad.inspect()
    assert status.health == "valid"
    assert status.detail == "last-operation-failed"

def test_wrong_policy_rejected(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    manager._record("issue", "ready")
    other = CertificateManager(state, Authorization.from_dict(policy(email="other@example.org")), Runner(state))
    with pytest.raises(CertificateError, match="policy-or-operation-mismatch"):
        other.renew()
