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
    live.mkdir(parents=True, mode=0o700)
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
        (live / filename).symlink_to("../../archive/" + name + "/" + archived.name)
    renewal = path / "renewal"
    renewal.mkdir(exist_ok=True)
    (renewal / (name + ".conf")).write_text(
        "version = 5.8.0\n"
        + "archive_dir = " + str(path / "archive" / name) + "\n"
        + "".join(k + " = " + str(path / "live" / name / (k + ".pem")) + "\n"
                  for k in ("cert", "privkey", "chain", "fullchain"))
        + "[renewalparams]\n"
        + "account = abcdef123456\n"
        + "server = https://acme-staging-v02.api.letsencrypt.org/directory\n"
        + "authenticator = webroot\n"
        + "webroot_path = " + str(root / "challenges" / name) + ",\n"
        + "[[webroot_map]]\n"
        + "station.example.org = " + str(root / "challenges" / name) + "\n"
    )

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
    renewed = manager.renew()
    assert renewed.health == "valid" and renewed.outcome == "unchanged"
    assert manager.inspect().health == "valid"
    assert manager.inspect().outcome == "unchanged"
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
        manager.recover(acknowledge=True)
    make_cert(state, "station-web")
    assert manager.recover(acknowledge=True).health == "valid"

def test_failed_renew_keeps_certificate_and_reports_failure(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    runner = Runner(state)
    manager = CertificateManager(state, Authorization.from_dict(policy()), runner)
    manager.issue()
    bad = CertificateManager(state, Authorization.from_dict(policy()), Runner(state, 1))
    with pytest.raises(UncertainOperation, match="certbot-outcome-unproven"):
        bad.renew()
    status = bad.inspect()
    assert status.health == "uncertain"
    assert status.detail == "operator-recovery-required"
    with pytest.raises(UncertainOperation):
        bad.renew()
    recovered = bad.recover(acknowledge=True)
    assert recovered.health == "valid"
    assert recovered.outcome == "recovered-unverified"
    with pytest.raises(CertificateError, match="publication-requires-ready-issuance"):
        bad.stage()

def test_wrong_policy_rejected(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    manager._record("issue", "ready")
    other = CertificateManager(state, Authorization.from_dict(policy(email="other@example.org")), Runner(state))
    with pytest.raises(CertificateError, match="policy-or-operation-mismatch"):
        other.renew()

def test_renew_rejects_persisted_server_tampering(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    path = state / "certbot/config/renewal/station-web.conf"
    path.write_text(path.read_text().replace("acme-staging-v02", "acme-v02"))
    with pytest.raises(Exception, match="renewal-account-or-server-mismatch"):
        manager.renew()

def test_renew_rejects_persisted_hooks(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    path = state / "certbot/config/renewal/station-web.conf"
    path.write_text(path.read_text().replace("authenticator = webroot\n", "authenticator = webroot\npost_hook = /bin/true\n"))
    with pytest.raises(Exception, match="renewal-unknown"):
        manager.renew()

def test_unapproved_global_certbot_configuration_blocks_issue(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    (state / "certbot/config/cli.ini").write_text("post_hook = /bin/true")
    with pytest.raises(Exception, match="certbot-global-config"):
        manager.issue()

def test_archive_escape_refused(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    live = state / "certbot/config/live/station-web/cert.pem"
    live.unlink()
    live.symlink_to("/etc/passwd")
    assert manager.inspect().health == "invalid"

def test_account_identity_pin_refuses_switched_renewal_account(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    path = state / "certbot/config/renewal/station-web.conf"
    path.write_text(path.read_text().replace("abcdef123456", "abcdef123457"))
    with pytest.raises(CertificateError, match="acme-account-binding-mismatch"):
        manager.renew()
    assert manager.inspect().health == "invalid"

def test_operation_journal_symlink_cannot_escape_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    outside = tmp_path / "outside"
    outside.write_text("protected")
    (state / "operations/station-web.json").symlink_to(outside)
    with pytest.raises((OSError, CertificateError, ValueError)):
        manager.issue()
    assert outside.read_text() == "protected"

def test_lock_symlink_rejected(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    outside = tmp_path / "outside"
    outside.write_text("protected")
    (state / "locks/issuer.lock").symlink_to(outside)
    with pytest.raises((OSError, CertificateError, ValueError)):
        manager.issue()
    assert outside.read_text() == "protected"

def test_private_publication_candidate_is_atomic_and_idempotent(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    issued = manager.issue()
    receipt = manager.stage()
    assert receipt["state"] == "issuer-private-unbound"
    assert receipt["certificate_fingerprint_sha256"] == issued.fingerprint_sha256
    base = state / "publications/station-web" / issued.fingerprint_sha256
    assert sorted(p.name for p in base.iterdir()) == ["fullchain.pem", "privkey.pem", "receipt.json"]
    assert base.stat().st_mode & 0o077 == 0
    assert all(p.stat().st_mode & 0o077 == 0 for p in base.iterdir())
    assert "PRIVATE KEY" not in str(receipt)
    assert manager.stage() == receipt

def test_publication_disallows_unverified_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    with pytest.raises(CertificateError, match="publication-requires-ready-issuance"):
        manager.stage()

def test_issuer_disables_directory_hooks(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.prepare()
    (state / "certbot/config/renewal-hooks").mkdir(mode=0o700)
    with pytest.raises(Exception, match="certbot-global-config-or-hooks-forbidden"):
        manager.issue()

def test_timeout_leaves_uncertain_journal(tmp_path):
    import subprocess
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    class LostReply(Runner):
        def run(self, argv):
            raise subprocess.TimeoutExpired(argv, 1)
    lost = CertificateManager(state, Authorization.from_dict(policy()), LostReply(state))
    with pytest.raises(subprocess.TimeoutExpired):
        lost.renew()
    assert lost.inspect().health == "uncertain"
    with pytest.raises(UncertainOperation):
        lost.renew()
    assert lost.recover(acknowledge=True).health == "valid"

def test_new_fingerprint_reports_renewed(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    previous = manager.issue()
    class RotatingRunner(Runner):
        def run(self, argv):
            if argv[0] == "renew":
                import shutil
                shutil.rmtree(self.state / "certbot/config/archive/station-web")
                shutil.rmtree(self.state / "certbot/config/live/station-web")
                (self.state / "certbot/config/renewal/station-web.conf").unlink()
                make_cert(self.state, "station-web")
            return 0
    manager = CertificateManager(state, Authorization.from_dict(policy()), RotatingRunner(state))
    now = manager.renew()
    assert now.health == "valid" and now.outcome == "renewed"
    assert now.fingerprint_sha256 != previous.fingerprint_sha256
    assert manager.inspect().outcome == "renewed"

def test_successful_exit_without_lineage_still_blocks(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    class EmptyRunner(Runner):
        def run(self, argv):
            return 0
    manager = CertificateManager(state, Authorization.from_dict(policy()), EmptyRunner(state))
    with pytest.raises(UncertainOperation, match="certbot-lineage-not-valid"):
        manager.issue()
    assert manager.inspect().health == "uncertain"

def test_redacted_inspect_binds_policy_and_operation_time(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    issued = manager.issue()
    value = manager.inspect().as_dict()
    assert value["policy_sha256"] == manager.policy.fingerprint
    assert value["operation_updated_at"] is not None
    assert value["outcome"] == "issued"
    assert "account_id" not in value
    assert "privkey" not in str(value)

def test_reject_duplicate_fullchain_certificates(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    fullchain = state / "certbot/config/archive/station-web/fullchain1.pem"
    fullchain.write_bytes(fullchain.read_bytes() * 2)
    assert manager.inspect().health == "invalid"
    with pytest.raises(CertificateError, match="publication-requires-matching-lineage"):
        manager.stage()

def test_uncertain_recovery_requires_explicit_confirmation(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    manager._record("renew", "uncertain", manager.inspect().fingerprint_sha256,
                    "abcdef123456")
    with pytest.raises(CertificateError, match="explicit-recovery-confirmation-required"):
        manager.recover()
    assert manager.inspect().health == "uncertain"
    recovered = manager.recover(acknowledge=True)
    assert recovered.outcome == "recovered-unverified"
    assert manager.inspect().outcome == "recovered-unverified"
    with pytest.raises(CertificateError, match="publication-requires-ready-issuance"):
        manager.stage()

def test_recovery_refuses_account_change_even_with_confirmation(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    manager._record("renew", "uncertain", manager.inspect().fingerprint_sha256,
                    "abcdef123456")
    renewal = state / "certbot/config/renewal/station-web.conf"
    renewal.write_text(renewal.read_text().replace("abcdef123456", "switched7890"))
    with pytest.raises(CertificateError, match="acme-account-changed"):
        manager.recover(acknowledge=True)
    assert manager.inspect().health == "uncertain"

def test_recovery_fails_closed_with_missing_renewal_baseline(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    manager.issue()
    manager._record("renew", "uncertain", None, "abcdef123456")
    with pytest.raises(CertificateError, match="renewal-baseline-missing"):
        manager.recover(acknowledge=True)
    assert manager.inspect().health == "uncertain"
