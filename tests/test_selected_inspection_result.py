"""Short-lived selected inspect emits one strict record, not a deployment grant."""
from copy import deepcopy
import fcntl
import json

import pytest

from zog.certify_manage import Authorization, CertificateManager
from zog.certify_manage.__main__ import main
from zog.certify_manage.inspection_result import (
    InspectionRecordError, MAX_RECORD_BYTES, PREFIX, SCHEMA,
    selected_inspect, serialize_inspection_result,
)
from test_manager import Runner
from test_model import policy


def fixture(tmp_path):
    state = tmp_path / "issuer"
    state.mkdir(mode=0o700)
    owner = Authorization.from_dict(policy())
    manager = CertificateManager(state, owner, Runner(state))
    manager.issue()
    return state, owner, manager


def parse_record(line):
    assert line.startswith(PREFIX)
    assert len(line.encode("ascii")) <= MAX_RECORD_BYTES
    result = json.loads(line[len(PREFIX):])
    assert result["schema"] == SCHEMA
    return result


def test_finite_inspect_one_record_reuses_existing_validation(tmp_path):
    state, authorization, manager = fixture(tmp_path)
    line = selected_inspect(state, authorization)
    result = parse_record(line)
    assert result["issuer_verified"] is True
    assert result["health"] == "valid"
    assert result["certificate_fingerprint_sha256"] == manager.inspect().fingerprint_sha256
    assert result["certificate_id"] == authorization.certificate_id
    assert result["hostnames"] == list(authorization.hostnames)
    assert result["policy_sha256"] == authorization.fingerprint
    assert result["operation"] == "issue"
    assert result["outcome"] == "issued"
    assert result["operation_updated_at"] == manager.inspect().operation_updated_at
    assert result["tls_ready"] is False
    assert "request_id" not in result
    assert "runtime_id" not in result
    assert "invocation_id" not in result
    assert "account_id" not in result
    assert not any(s in line for s in ("PRIVATE KEY", "cloudflare.ini",
                                        "abcdef123456", "/var/lib/", "\\n"))


def test_selected_cli_single_line_and_no_extra_stdout(tmp_path, monkeypatch, capsys):
    import zog.certify_manage.__main__ as cli
    state, authorization, _ = fixture(tmp_path)
    monkeypatch.setattr(cli, "trusted_policy", lambda path: json.dumps(policy()).encode())
    assert main(["inspect", "--state", str(state),
                 "--policy", "/run/zog-host/certify-policy/policy.json"]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    assert out.out.count("\n") == 1
    parsed = parse_record(out.out.removesuffix("\n"))
    assert parsed["issuer_verified"] is True
    assert parsed["tls_ready"] is False


def test_expired_or_invalid_leaf_is_successful_observation_not_x509_proof(tmp_path, monkeypatch, capsys):
    import zog.certify_manage.__main__ as cli
    state, _, manager = fixture(tmp_path)
    (state / "certbot/config/archive/station-web/cert1.pem").write_text("corrupted")
    monkeypatch.setattr(cli, "trusted_policy", lambda path: json.dumps(policy()).encode())
    assert main(["inspect", "--state", str(state)]) == 0
    stdout = capsys.readouterr().out
    result = parse_record(stdout.strip())
    assert result["health"] == "invalid"
    assert result["issuer_verified"] is False
    assert result["tls_ready"] is False


def test_uncertain_or_manual_recovery_never_positive(tmp_path):
    state, authorization, manager = fixture(tmp_path)
    cert = manager.inspect()
    manager._record("renew", "uncertain", cert.fingerprint_sha256, "abcdef123456")
    status = parse_record(selected_inspect(state, authorization))
    assert status["health"] == "uncertain"
    assert status["issuer_verified"] is False
    manager._record("recover", "ready", cert.fingerprint_sha256,
                    "abcdef123456", "recovered-unverified")
    status = parse_record(selected_inspect(state, authorization))
    assert status["health"] == "valid"
    assert status["outcome"] == "recovered-unverified"
    assert status["issuer_verified"] is False


def test_journal_and_lineage_fingerprint_mismatch_blocks_verification(tmp_path):
    state, owner, manager = fixture(tmp_path)
    manager._record("renew", "ready", "0"*64, "abcdef123456", "renewed")
    result = parse_record(selected_inspect(state, owner))
    assert result["health"] == "valid"
    assert result["issuer_verified"] is False


def test_busy_writer_lock_rejects_inspection_without_stdout(tmp_path, monkeypatch, capsys):
    import zog.certify_manage.__main__ as cli
    state, _, _ = fixture(tmp_path)
    monkeypatch.setattr(cli, "trusted_policy", lambda path: json.dumps(policy()).encode())
    with open(state / "locks/issuer.lock", "rb") as fd:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            assert main(["inspect", "--state", str(state)]) == 2
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    out = capsys.readouterr()
    assert out.out == ""
    assert json.loads(out.err)["error"] == "certify-manage-operation-rejected"


def test_no_unprepared_private_state_is_created(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with pytest.raises((FileNotFoundError, ValueError)):
        selected_inspect(state, Authorization.from_dict(policy()))
    assert list(state.iterdir()) == []


@pytest.mark.parametrize(("field", "value"), [
    ("schema", "wrong"),
    ("certificate_id", "foreign"),
    ("policy_sha256", "0"*64),
    ("hostnames", ["foreign.example.org"]),
    ("issuer_verified", "true"),
    ("tls_ready", True),
    ("operation", "recover"),
    ("outcome", "recovered-unverified"),
    ("certificate_fingerprint_sha256", "not-a-digest"),
    ("observed_at", "yesterday"),
    ("operation_updated_at", "2030-01-01T00:00:00"),
    ("days_remaining", True),
])
def test_structured_record_refuses_unapproved_fields(tmp_path, field, value):
    state, auth, _ = fixture(tmp_path)
    evidence = parse_record(selected_inspect(state, auth))
    changed = deepcopy(evidence)
    changed[field] = value
    if field in ("operation", "outcome"):
        changed["issuer_verified"] = True
    with pytest.raises(InspectionRecordError):
        serialize_inspection_result(changed, auth)


def test_no_surplus_keys_no_unbounded_message_and_no_newline_injection(tmp_path):
    state, auth, _ = fixture(tmp_path)
    result = parse_record(selected_inspect(state, auth))
    with pytest.raises(InspectionRecordError):
        serialize_inspection_result({**result, "private_key": "secret"}, auth)
    result["hostnames"] = list(auth.hostnames) + ["foreign.example.org"] * 1000
    with pytest.raises(InspectionRecordError):
        serialize_inspection_result(result, auth)


def test_original_socket_envelope_remains_separate_from_invocation_record(tmp_path):
    from zog.certify_manage.inspection import IssuerInspector, SCHEMA as SOCKET_SCHEMA
    import os
    state, auth, _ = fixture(tmp_path)
    inspector = IssuerInspector(state, auth, authorized_uid=max(1000, os.geteuid()))
    payload = inspector.inspect("f"*32)
    assert payload["schema"] == SOCKET_SCHEMA
    assert payload["nonce"] == "f"*32
    assert payload["issuer_verified"] is True
    line = parse_record(selected_inspect(state, auth))
    assert "nonce" not in line
    assert line["schema"] != SOCKET_SCHEMA

@pytest.mark.parametrize(("operation", "outcome"), [
    ("issue", "renewed"),
    ("issue", "unchanged"),
    ("renew", "issued"),
])
def test_invalid_operation_outcome_pairs_never_verified_or_serialized(
        tmp_path, operation, outcome):
    state, authorization, manager = fixture(tmp_path)
    current = manager.inspect()
    manager._record(operation, "ready", current.fingerprint_sha256,
                    "abcdef123456", outcome)
    result = parse_record(selected_inspect(state, authorization))
    assert result["issuer_verified"] is False
    assert result["operation"] == operation
    assert result["outcome"] == outcome
    assert result["tls_ready"] is False
    tampered = deepcopy(result)
    tampered["issuer_verified"] = True
    with pytest.raises(InspectionRecordError, match="unproven-inspection-verification"):
        serialize_inspection_result(tampered, authorization)


@pytest.mark.parametrize(("operation", "outcome"), [
    ("issue", "issued"),
    ("renew", "renewed"),
    ("renew", "unchanged"),
])
def test_recognized_ready_operation_pairs_keep_controller_wire_schema(
        tmp_path, operation, outcome):
    state, authorization, manager = fixture(tmp_path)
    current = manager.inspect()
    manager._record(operation, "ready", current.fingerprint_sha256,
                    "abcdef123456", outcome)
    line = selected_inspect(state, authorization)
    assert line.count(PREFIX) == 1
    assert line.startswith(PREFIX)
    assert len(line.encode("ascii")) <= 4096
    result = parse_record(line)
    assert result["issuer_verified"] is True
    assert result["operation"] == operation
    assert result["outcome"] == outcome
    assert result["tls_ready"] is False
    assert set(result) == {
        "schema", "certificate_id", "hostnames", "policy_sha256", "health",
        "certificate_fingerprint_sha256", "valid_from", "expires_at",
        "days_remaining", "operation", "outcome", "operation_updated_at",
        "issuer_verified", "observed_at", "tls_ready",
    }
    assert line == serialize_inspection_result(result, authorization)
