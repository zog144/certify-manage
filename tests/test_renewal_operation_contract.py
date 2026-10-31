"""Single-operation renewal contract, across issuer CLI/record/selected inspect.

Only synthetic Certbot adapters and synthetic private issuer STATE are used.
Controller/systemd/journald request attribution is explicitly an external
root-control gate and is NEVER inferred from these producer records.
"""
import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from zog.certify_manage.__main__ import main
from zog.certify_manage import Authorization, CertificateManager, UncertainOperation
from zog.certify_manage.inspection_result import (
    MAX_RECORD_BYTES, PREFIX, SCHEMA, selected_inspect,
)
from test_manager import Runner, make_cert
from test_model import policy

RECORD_FIELDS = {
    "schema", "policy_sha256", "operation", "status",
    "certificate_fingerprint", "account_id", "outcome", "updated_at",
}


def issuer(tmp_path):
    state = tmp_path / "issuer"
    state.mkdir(mode=0o700)
    auth = Authorization.from_dict(policy())
    runner = Runner(state)
    manager = CertificateManager(state, auth, runner)
    first = manager.issue()
    assert first.health == "valid"
    return state, auth, runner


def record(state):
    raw = (state / "operations" / "station-web.json").read_text()
    obj = json.loads(raw)
    assert set(obj) == RECORD_FIELDS
    assert obj["schema"] == "zog-certify-operation-v1"
    return obj


def inspected(state, auth):
    line = selected_inspect(state, auth)
    assert len(line.encode("ascii")) <= MAX_RECORD_BYTES
    assert line.count(PREFIX) == 1 and line.startswith(PREFIX)
    value = json.loads(line[len(PREFIX):])
    assert value["schema"] == SCHEMA
    assert value["tls_ready"] is False
    assert "request_id" not in value
    assert "runtime_id" not in value
    assert "invocation_id" not in value
    return value


def test_one_selected_renewal_persists_unchanged_and_independent_inspection(tmp_path):
    state, auth, runner = issuer(tmp_path)
    before = record(state)["certificate_fingerprint"]
    manager = CertificateManager(state, auth, runner)
    result = manager.renew()
    assert runner.count == 2  # issue and one selected renew, never a second hidden call
    assert result.operation == "renew" and result.outcome == "unchanged"
    written = record(state)
    assert written["operation"] == "renew"
    assert written["status"] == "ready" and written["outcome"] == "unchanged"
    assert written["certificate_fingerprint"] == before
    assert written["account_id"] == "abcdef123456"
    independent = inspected(state, auth)
    assert independent["issuer_verified"] is True
    assert independent["operation"] == "renew"
    assert independent["outcome"] == "unchanged"
    assert independent["operation_updated_at"] == written["updated_at"]
    assert independent["certificate_fingerprint_sha256"] == before
    # A new selected call on the same issuer is a different operation;
    # only host-deploy/controller may authorize its own new request ID.
    assert CertificateManager(state, auth, Runner(state)).inspect().outcome == "unchanged"


def test_renewed_leaf_requires_distinct_verified_fingerprint(tmp_path):
    state, auth, runner = issuer(tmp_path)
    original = record(state)["certificate_fingerprint"]

    class NewLeaf(Runner):
        def run(self, argv):
            self.count += 1
            assert argv == ("renew",)
            config = self.state / "certbot/config"
            shutil.rmtree(config / "archive/station-web")
            shutil.rmtree(config / "live/station-web")
            (config / "renewal/station-web.conf").unlink()
            make_cert(self.state, "station-web")
            return 0

    changed = NewLeaf(state)
    result = CertificateManager(state, auth, changed).renew()
    assert changed.count == 1
    assert result.outcome == "renewed"
    written = record(state)
    assert written["status"] == "ready" and written["outcome"] == "renewed"
    assert written["certificate_fingerprint"] != original
    proof = inspected(state, auth)
    assert proof["issuer_verified"] is True
    assert proof["operation"] == "renew" and proof["outcome"] == "renewed"
    assert proof["certificate_fingerprint_sha256"] == written["certificate_fingerprint"]


def test_nonzero_certbot_keeps_uncertain_but_reports_failed_not_renewed(tmp_path):
    state, auth, _ = issuer(tmp_path)
    baseline = record(state)["certificate_fingerprint"]
    failed = Runner(state, code=19)
    with pytest.raises(UncertainOperation, match="certbot-outcome-unproven"):
        CertificateManager(state, auth, failed).renew()
    assert failed.count == 1
    saved = record(state)
    assert saved["status"] == "uncertain" and saved["outcome"] == "failed"
    assert saved["operation"] == "renew"
    assert saved["certificate_fingerprint"] == baseline
    proof = inspected(state, auth)
    assert proof["health"] == "uncertain"
    assert proof["operation"] == "renew" and proof["outcome"] == "failed"
    assert proof["issuer_verified"] is False
    assert proof["operation_updated_at"] == saved["updated_at"]
    assert proof["tls_ready"] is False
    with pytest.raises(UncertainOperation, match="operator-recovery-required"):
        CertificateManager(state, auth, failed).renew()
    assert failed.count == 1
    with pytest.raises(Exception, match="publication-requires-ready-issuance"):
        CertificateManager(state, auth, failed).stage()


def test_lost_reply_preserves_unknown_effect_without_declaring_failed(tmp_path):
    state, auth, _ = issuer(tmp_path)

    class LostReply(Runner):
        def run(self, argv):
            self.count += 1
            raise subprocess.TimeoutExpired(["/private/binary", "--credentials", "/secret"], 1)

    lost = LostReply(state)
    with pytest.raises(subprocess.TimeoutExpired):
        CertificateManager(state, auth, lost).renew()
    saved = record(state)
    assert saved["status"] == "uncertain"
    assert saved["outcome"] is None  # no witnessed exit code
    status = inspected(state, auth)
    assert status["health"] == "uncertain"
    assert status["issuer_verified"] is False and status["outcome"] is None
    with pytest.raises(UncertainOperation):
        CertificateManager(state, auth, lost).renew()
    assert lost.count == 1


def test_failed_result_commit_crash_remains_uncertain_without_success(tmp_path, monkeypatch):
    import zog.certify_manage.manager as module
    state, auth, _ = issuer(tmp_path)
    real = module._save

    def disk_full_on_failed(path, value):
        if value["operation"] == "renew" and value["outcome"] == "failed":
            raise OSError("simulated-fsync-failure")
        return real(path, value)

    monkeypatch.setattr(module, "_save", disk_full_on_failed)
    with pytest.raises(OSError, match="simulated-fsync-failure"):
        CertificateManager(state, auth, Runner(state, code=1)).renew()
    saved = record(state)
    assert saved["status"] == "uncertain" and saved["outcome"] is None
    assert inspected(state, auth)["issuer_verified"] is False


def test_manual_recovery_cannot_promote_failed_or_unknown_to_verified(tmp_path):
    state, auth, _ = issuer(tmp_path)
    bad = CertificateManager(state, auth, Runner(state, code=1))
    with pytest.raises(UncertainOperation):
        bad.renew()
    recovered = bad.recover(acknowledge=True)
    assert recovered.outcome == "recovered-unverified"
    proof = inspected(state, auth)
    assert proof["issuer_verified"] is False
    assert proof["operation"] == "recover"
    assert proof["outcome"] == "recovered-unverified"
    with pytest.raises(Exception, match="publication-requires-ready-issuance"):
        bad.stage()


def test_exact_selected_renew_program_and_cli_emit_one_secret_free_result(tmp_path, monkeypatch, capsys):
    import ast
    import zog.certify_manage.__main__ as cli

    app = Path(__file__).resolve().parents[1] / "integration/box-control/application.py"
    tree = ast.parse(app.read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "program"]
    selected = {}
    for node in calls:
        kws = {k.arg: k.value for k in node.keywords}
        name = ast.literal_eval(kws["name"])
        selected[name] = ast.literal_eval(kws["command"])
    assert "renew" in selected and "inspect" in selected
    assert selected["renew"] == (
        "/applications/certify-manage/bin/python3", "-m", "zog.certify_manage",
        "renew", "--state", "/var/lib/zog-certify-manage",
        "--policy", "/run/zog-host/certify-policy/policy.json",
    )
    assert selected["renew"] != selected["inspect"]
    state, auth, _ = issuer(tmp_path)
    monkeypatch.setattr(cli, "trusted_policy", lambda path: json.dumps(policy()).encode())
    calls = []

    def selected_manager(_state, _policy):
        assert Path(_state) == state and _policy.fingerprint == auth.fingerprint
        run = Runner(state)
        calls.append(run)
        return CertificateManager(_state, _policy, run)

    monkeypatch.setattr(cli, "CertificateManager", selected_manager)
    assert main(["renew", "--state", str(state),
                 "--policy", "/run/zog-host/certify-policy/policy.json"]) == 0
    output = capsys.readouterr()
    assert output.err == "" and output.out.count("\n") == 1
    obj = json.loads(output.out.strip())
    assert obj["outcome"] == "unchanged" and obj["operation"] == "renew"
    assert obj["policy_sha256"] == auth.fingerprint
    assert obj["health"] == "valid"
    assert calls[0].count == 1
    assert not any(x in output.out for x in (
        "account_id", "request_id", "runtime_id", "invocation_id",
        "PRIVATE KEY", "dns_cloudflare_api_token", "/private/"))
    # Process stdout is NOT a controller-attested result; selected inspect
    # after this invocation still needs a distinct saved controller request.


def test_nonzero_cli_has_no_success_stdout_and_generic_error(tmp_path, monkeypatch, capsys):
    import zog.certify_manage.__main__ as cli
    state, _, _ = issuer(tmp_path)
    monkeypatch.setattr(cli, "trusted_policy", lambda path: json.dumps(policy()).encode())
    monkeypatch.setattr(cli, "CertificateManager",
                        lambda state, policy: CertificateManager(
                            state, policy, Runner(state, code=17)))
    assert main(["renew", "--state", str(state)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err) == {"error": "certify-manage-operation-rejected"}
    assert record(state)["outcome"] == "failed"
