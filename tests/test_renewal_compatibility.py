"""Certbot v5 policy-compatibility and crash/recovery regression matrix.

These tests use synthetic protected lineages and no ACME network. The real
Certbot smoke job separately confirms CLI/plugin compatibility.
"""
from pathlib import Path
import shutil

import pytest

from zog.certify_manage.adapter import CertbotAdapter
from zog.certify_manage.manager import CertificateManager, CertificateError, UncertainOperation
from zog.certify_manage.model import Authorization, PolicyError
from zog.certify_manage.renewal import validate_renewal
from test_manager import Runner, make_cert
from test_model import policy


@pytest.fixture
def issued(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    runner = Runner(state)
    manager = CertificateManager(state, Authorization.from_dict(policy()), runner)
    manager.issue()
    return state, manager, runner


def renewal_file(state):
    return state / "certbot/config/renewal/station-web.conf"


def test_accept_pinned_certbot_5x_safe_webroot_and_ari_metadata(issued):
    state, manager, runner = issued
    conf = renewal_file(state)
    config = conf.read_text()
    config = config.replace(
        "[renewalparams]\n",
        "# Options restored at renewal\n[renewalparams]\n"
        "key_type = ecdsa\n"
        "reuse_key = False\n"
        "elliptic_curve = secp256r1\n"
        "pref_challs = http-01,\n",
    )
    config += ("[acme_renewal_info]\n"
               "ari_retry_after = 2026-10-15T13:00:00+00:00\n"
               "ari_cert_id = sample-cert-id\n")
    conf.write_text(config)
    assert validate_renewal(state, manager.policy, required=True) == "abcdef123456"
    result = manager.renew()
    assert result.outcome == "unchanged"
    assert runner.count == 2


@pytest.mark.parametrize(("change", "expected"), [
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = standalone"), "renewal-authenticator-mismatch"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\npre_hook = /bin/true"), "renewal-unknown-parameter"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\ndeploy_hook = /bin/true"), "renewal-unknown-parameter"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\ninstaller = nginx"), "renewal-installer-forbidden"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\nkey_type = unsupported"), "renewal-unsupported-key-type"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\nrsa_key_size = 512"), "renewal-invalid-rsa-size"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\nreuse_key = perhaps"), "renewal-invalid-reuse-key"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\nelliptic_curve = invalid"), "renewal-invalid-curve"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\npref_challs = dns-01"), "renewal-challenge-policy-mismatch"),
    (lambda s, root: s.replace("station.example.org = ", "another.example.org = "),
     "renewal-webroot-map-mismatch"),
    (lambda s, root: s.replace(str(root / "challenges" / "station-web"), "/tmp/attacker"),
     "renewal-webroot-map-mismatch"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\ndns_cloudflare_credentials = /tmp/secret"),
     "renewal-authenticator-mismatch"),
    (lambda s, root: s + "[[foreign_nested]]\nvalue = malicious\n",
     "renewal-unknown-section"),
    (lambda s, root: s + "[acme_renewal_info]\nari_retry_after = 2026-10-15\n"
                        "[acme_renewal_info]\nari_retry_after = 2026-10-16\n",
     "renewal-invalid-section"),
    (lambda s, root: s.replace("authenticator = webroot",
                               "authenticator = webroot\npost_hook = /bin/false\npost_hook = /bin/true"),
     "renewal-unknown-parameter"),
])
def test_unreviewed_renewal_settings_cannot_invoke_certbot(issued, change, expected):
    state, manager, runner = issued
    config = renewal_file(state)
    config.write_text(change(config.read_text(), state))
    with pytest.raises(PolicyError, match=expected):
        manager.renew()
    assert runner.count == 1, "rejected renewal must not invoke Certbot"
    assert manager._read()["status"] == "ready"
    assert manager.inspect().health == "invalid"


def test_ari_section_cannot_be_used_to_hide_another_renewal_section(issued):
    state, manager, runner = issued
    conf = renewal_file(state)
    conf.write_text(conf.read_text() +
                    "[acme_renewal_info]\nari_retry_after = 2026-10-15\n"
                    "[[webroot_map]]\nstation.example.org = /tmp/wrong\n")
    with pytest.raises(PolicyError, match="renewal-invalid-section"):
        manager.renew()
    assert runner.count == 1


def test_dns_renew_requires_current_private_credential_not_just_saved_path(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    auth = Authorization.from_dict(policy(challenge="dns-01", dns_plugin="dns-cloudflare"))
    manager = CertificateManager(state, auth)
    manager.prepare()
    secret = state / "dns/cloudflare.ini"
    secret.write_text("dns_cloudflare_api_token = SYNTHETIC-DO-NOT-USE")
    secret.chmod(0o600)
    adapter = CertbotAdapter()
    assert "--cert-name" in adapter.arguments("renew", state, auth)
    secret.chmod(0o644)
    with pytest.raises(PolicyError, match="unsafe-secret-file"):
        adapter.arguments("renew", state, auth)
    secret.unlink()
    with pytest.raises(FileNotFoundError):
        adapter.arguments("renew", state, auth)
    external = tmp_path / "other-secret"
    external.write_text("synthetic")
    secret.symlink_to(external)
    with pytest.raises(OSError):
        adapter.arguments("renew", state, auth)


def test_nonzero_after_successor_side_effect_requires_review_not_stage(issued):
    state, manager, _ = issued
    original = manager.inspect().fingerprint_sha256

    class MutateThenFail(Runner):
        def run(self, argv):
            shutil.rmtree(self.state / "certbot/config/archive/station-web")
            shutil.rmtree(self.state / "certbot/config/live/station-web")
            renewal_file(self.state).unlink()
            make_cert(self.state, "station-web")
            return 2

    manager = CertificateManager(state, manager.policy, MutateThenFail(state))
    with pytest.raises(UncertainOperation, match="certbot-outcome-unproven"):
        manager.renew()
    current = manager.inspect()
    assert current.health == "uncertain"
    with pytest.raises(UncertainOperation):
        manager.renew()
    with pytest.raises(CertificateError, match="publication-requires-ready-issuance"):
        manager.stage()
    recovery = manager.recover(acknowledge=True)
    assert recovery.fingerprint_sha256 != original
    assert recovery.outcome == "recovered-unverified"
    with pytest.raises(CertificateError, match="publication-requires-ready-issuance"):
        manager.stage()


def test_uncertain_renewal_with_invalid_successor_cannot_be_cleared(issued):
    state, manager, _ = issued
    before = manager.inspect().fingerprint_sha256

    class BreakThenFail(Runner):
        def run(self, argv):
            (self.state / "certbot/config/archive/station-web/cert1.pem").write_text("not PEM")
            return 2

    manager = CertificateManager(state, manager.policy, BreakThenFail(state))
    with pytest.raises(UncertainOperation):
        manager.renew()
    assert manager.inspect().health == "uncertain"
    with pytest.raises(CertificateError, match="recover-requires-valid-lineage"):
        manager.recover(acknowledge=True)
    assert manager._read()["certificate_fingerprint"] == before
    assert manager._read()["status"] == "uncertain"
