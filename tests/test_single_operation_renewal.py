"""Single-operation renewal source contract; fake runner, no live ACME."""
import json
import subprocess

import pytest

from zog.certify_manage.inspection import inspect_once
from zog.certify_manage.inspection_result import PREFIX, selected_inspect
from zog.certify_manage.manager import CertificateManager, CertificateError, UncertainOperation
from zog.certify_manage.model import Authorization

from test_manager import Runner
from test_model import policy


def _issued(tmp_path):
    state = tmp_path / "issuer-private-state"
    state.mkdir(mode=0o700)
    auth = Authorization.from_dict(policy())
    runner = Runner(state)
    manager = CertificateManager(state, auth, runner)
    initial = manager.issue()
    assert initial.health == "valid"
    return state, auth, initial, runner


def test_selected_renew_noop_produces_durable_unchanged_and_verified_inspection(tmp_path):
    state, auth, initial, runner = _issued(tmp_path)
    manager = CertificateManager(state, auth, runner)
    result = manager.renew()
    assert runner.count == 2  # issue once, renew once
    assert result.outcome == "unchanged"
    assert result.fingerprint_sha256 == initial.fingerprint_sha256
    raw = json.loads((state / "operations" / (auth.certificate_id + ".json")).read_text())
    assert raw["schema"] == "zog-certify-operation-v1"
    assert raw["operation"] == "renew" and raw["status"] == "ready"
    assert raw["outcome"] == "unchanged"
    assert raw["certificate_fingerprint"] == initial.fingerprint_sha256
    assert raw["policy_sha256"] == auth.fingerprint
    observed = inspect_once(state, auth)
    assert observed["operation"] == "renew" and observed["outcome"] == "unchanged"
    assert observed["issuer_verified"] is True and observed["tls_ready"] is False
    assert observed["operation_updated_at"] == raw["updated_at"]
    assert "account_id" not in observed
    assert "certificate-data" not in str(observed)
    assert selected_inspect(state, auth).startswith(PREFIX)
    assert not (state / "publications" / auth.certificate_id).exists()


@pytest.mark.parametrize("failure", ["nonzero", "timeout", "postflight-account"])
def test_renewal_failure_retains_uncertain_baseline_and_forbids_replay_or_stage(tmp_path, failure):
    state, auth, initial, _ = _issued(tmp_path)

    class FailingRunner(Runner):
        def run(self, argv):
            self.count += 1
            if failure == "timeout":
                raise subprocess.TimeoutExpired(["certbot", "--token", "/private/cloudflare.ini"], 1)
            if failure == "postflight-account":
                conf = state / "certbot" / "config" / "renewal" / (auth.certificate_id + ".conf")
                conf.write_text(conf.read_text().replace("abcdef123456", "switched-account"))
                return 0
            return 7

    runner = FailingRunner(state)
    manager = CertificateManager(state, auth, runner)
    with pytest.raises((UncertainOperation, subprocess.TimeoutExpired, ValueError)):
        manager.renew()
    assert runner.count == 1
    journal = json.loads((state / "operations" / (auth.certificate_id + ".json")).read_text())
    assert journal["status"] == "uncertain" and journal["operation"] == "renew"
    assert journal["certificate_fingerprint"] == initial.fingerprint_sha256
    assert journal["policy_sha256"] == auth.fingerprint
    observed = inspect_once(state, auth)
    assert observed["issuer_verified"] is False
    assert observed["tls_ready"] is False
    assert observed["health"] != "valid" or observed["operation"] == "renew"
    with pytest.raises(UncertainOperation, match="operator-recovery-required"):
        manager.renew()
    with pytest.raises(CertificateError, match="publication-requires-ready-issuance"):
        manager.stage()
    assert runner.count == 1
    assert not (state / "publications" / auth.certificate_id).exists()


def test_operator_recovery_is_not_verified_renewal_or_publication(tmp_path):
    state, auth, initial, _ = _issued(tmp_path)
    broken = CertificateManager(state, auth, Runner(state, code=5))
    with pytest.raises(UncertainOperation):
        broken.renew()
    with pytest.raises(CertificateError, match="explicit-recovery-confirmation-required"):
        broken.recover()
    recovered = broken.recover(acknowledge=True)
    assert recovered.outcome == "recovered-unverified"
    snapshot = inspect_once(state, auth)
    assert snapshot["health"] == "valid"
    assert snapshot["certificate_fingerprint_sha256"] == initial.fingerprint_sha256
    assert snapshot["operation"] == "recover"
    assert snapshot["outcome"] == "recovered-unverified"
    assert snapshot["issuer_verified"] is False
    assert snapshot["tls_ready"] is False
    with pytest.raises(CertificateError, match="publication-requires-ready-issuance"):
        broken.stage()
