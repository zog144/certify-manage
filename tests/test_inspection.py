"""Issuer-owned socket inspection tests; no real ACME or systemd required."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import fcntl
import json
import os
import socket
import threading

import pytest

from zog.certify_manage import Authorization, CertificateManager
from zog.certify_manage.inspection import (
    InspectionError, IssuerInspector, SCHEMA, _peer_uid, _read_request,
    _snapshot_lock, respond_one,
)
from zog.certify_manage.inspection_client import IssuerInspectionClient
from test_manager import Runner
from test_model import policy


def prepared(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    auth = Authorization.from_dict(policy())
    manager = CertificateManager(state, auth, Runner(state))
    manager.issue()
    inspector = IssuerInspector(state, auth, authorized_uid=max(1000, os.geteuid()))
    return state, manager, inspector


def test_shared_read_uses_existing_x509_key_chain_and_policy_validation(tmp_path):
    state, manager, inspector = prepared(tmp_path)
    result = inspector.inspect("a" * 32)
    assert result["schema"] == SCHEMA
    assert result["issuer_verified"] is True
    assert result["health"] == "valid"
    assert result["certificate_fingerprint_sha256"] == manager.inspect().fingerprint_sha256
    assert result["operation"] == "issue"
    assert result["outcome"] == "issued"
    assert result["tls_ready"] is False
    assert result["hostnames"] == ["station.example.org"]
    assert set(result).isdisjoint({"account_id", "private_key", "provider_token", "state_path"})
    assert "PRIVATE KEY" not in json.dumps(result)
    assert not any(x in json.dumps(result) for x in ("/var/lib/", "cloudflare.ini"))


def test_invalid_certificate_and_uncertain_state_never_verify(tmp_path):
    state, manager, inspector = prepared(tmp_path)
    cert = state / "certbot/config/archive/station-web/cert1.pem"
    cert.write_text("corrupt")
    result = inspector.inspect("b" * 32)
    assert result["health"] == "invalid"
    assert result["issuer_verified"] is False
    assert result["tls_ready"] is False
    # Existing valid file but an unresolved ACME attempt also blocks.
    state2, manager2, inspector2 = prepared(tmp_path / "second")
    manager2._record("renew", "uncertain", manager2.inspect().fingerprint_sha256, "abcdef123456")
    result = inspector2.inspect("c" * 32)
    assert result["health"] == "uncertain"
    assert result["issuer_verified"] is False


def test_recovered_unverified_remains_false(tmp_path):
    _, manager, inspector = prepared(tmp_path)
    current = manager.inspect()
    manager._record("recover", "ready", current.fingerprint_sha256,
                    "abcdef123456", "recovered-unverified")
    result = inspector.inspect("b" * 32)
    assert result["health"] == "valid"
    assert result["outcome"] == "recovered-unverified"
    assert result["issuer_verified"] is False


def test_mismatched_journal_fingerprint_and_future_timestamp_fail_closed(tmp_path):
    _, manager, inspector = prepared(tmp_path)
    current = manager.inspect()
    manager._record("renew", "ready", "0" * 64, "abcdef123456", "renewed")
    assert inspector.inspect("c" * 32)["issuer_verified"] is False
    manager._record("renew", "ready", current.fingerprint_sha256,
                    "abcdef123456", "renewed")
    journal = manager._read()
    journal["updated_at"] = "9999-12-31T23:00:00+00:00"
    manager._record_path().write_text(json.dumps(journal))
    assert inspector.inspect("d" * 32)["issuer_verified"] is False


def test_never_creates_state_or_lock_during_inspection(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    inspector = IssuerInspector(state, Authorization.from_dict(policy()),
                                authorized_uid=max(1000, os.geteuid()))
    with pytest.raises((InspectionError, FileNotFoundError)):
        inspector.inspect("e" * 32)
    assert list(state.iterdir()) == []


def test_busy_writer_blocks_reader_without_waiting(tmp_path):
    state, _, inspector = prepared(tmp_path)
    with open(state / "locks/issuer.lock", "rb") as writer:
        fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(InspectionError, match="issuer-busy"):
            inspector.inspect("f" * 32)


def test_authenticated_socket_returns_exact_redacted_response(tmp_path):
    _, _, inspector = prepared(tmp_path)
    inspector.authorized_uid = os.geteuid()
    left, right = socket.socketpair()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(respond_one, inspector, left)
        right.sendall(json.dumps({"schema": SCHEMA, "operation": "inspect",
                                  "nonce": "a" * 32}).encode() + b"\n")
        response = b""
        while not response.endswith(b"\n"):
            response += right.recv(4096)
        right.close()
        future.result(timeout=3)
    data = json.loads(response)
    assert data["ok"] is True
    assert data["result"]["nonce"] == "a" * 32
    assert data["result"]["issuer_verified"] is True
    assert _peer_uid(socket.socketpair()[0]) == os.geteuid()


def test_unauthorized_socket_peer_is_dropped_before_request_parse(tmp_path, monkeypatch):
    import zog.certify_manage.inspection as module
    _, _, inspector = prepared(tmp_path)
    monkeypatch.setattr(module, "_peer_uid", lambda sock: inspector.authorized_uid + 1)
    monkeypatch.setattr(module, "_read_request", lambda sock: pytest.fail("request parsed before authentication"))
    left, right = socket.socketpair()
    right.settimeout(2)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(respond_one, inspector, left)
        assert right.recv(512) == b""
        future.result(timeout=3)
    right.close()


@pytest.mark.parametrize("payload", [
    b'{"schema":"zog-certify-inspection-v1","operation":"stage","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n',
    b'{"schema":"zog-certify-inspection-v1","operation":"inspect","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","path":"/private"}\n',
    b'{"schema":"zog-certify-inspection-v1","operation":"inspect","operation":"inspect","nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n',
    b'{"schema":"zog-certify-inspection-v1","operation":"inspect","nonce":"zz"}\n',
    b'[]\n', b'{}\n', b'A'*1100+b'\n',
])
def test_malformed_requests_never_expose_state(tmp_path, payload):
    _, _, inspector = prepared(tmp_path)
    inspector.authorized_uid = os.geteuid()
    left, right = socket.socketpair()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(respond_one, inspector, left)
        right.settimeout(3)
        right.sendall(payload)
        received = right.recv(4096)
        future.result(timeout=3)
    right.close()
    assert json.loads(received) == {"ok": False, "error": "inspection-unavailable"}


def test_policy_change_revalidated_per_request(tmp_path, monkeypatch):
    import zog.certify_manage.inspection as module
    _, _, inspector = prepared(tmp_path)
    inspector.policy_path = tmp_path / "protected-policy.json"
    monkeypatch.setattr(module, "trusted_policy", lambda path: json.dumps(policy()).encode())
    assert inspector.inspect("1"*32)["issuer_verified"] is True
    monkeypatch.setattr(module, "trusted_policy",
                        lambda path: json.dumps(policy(email="changed@example.org")).encode())
    with pytest.raises(InspectionError, match="issuer-policy-changed"):
        inspector.inspect("2"*32)


def test_client_checks_socket_issuer_uid_nonce_and_reply(tmp_path):
    _, _, inspector = prepared(tmp_path)
    inspector.authorized_uid = os.geteuid()
    location = tmp_path / "inspect.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(location))
    listener.listen(1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        def serving():
            conn, _ = listener.accept()
            respond_one(inspector, conn)
        future = pool.submit(serving)
        client = IssuerInspectionClient(location, expected_issuer_uid=max(1000,os.geteuid()))
        value = client.inspect()
        assert value["issuer_verified"] is True
        assert value["tls_ready"] is False
        future.result(timeout=3)
    listener.close()
    with pytest.raises(InspectionError, match="invalid-issuer-uid"):
        IssuerInspectionClient(location, expected_issuer_uid=0)


def test_client_rejects_wrong_socket_peer(tmp_path, monkeypatch):
    import zog.certify_manage.inspection_client as module
    location = tmp_path / "inspect.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(location))
    listener.listen(1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(lambda: listener.accept()[0].close())
        client = IssuerInspectionClient(location, expected_issuer_uid=max(1000, os.geteuid()))
        monkeypatch.setattr(module, "_peer_uid", lambda conn: 123456)
        with pytest.raises(InspectionError, match="inspector-peer-mismatch"):
            client.inspect()
        future.result(timeout=3)
    listener.close()


def test_inspector_never_claims_request_or_tls_provenance(tmp_path):
    _, _, inspector = prepared(tmp_path)
    result = inspector.inspect("e" * 32)
    assert "request_id" not in result
    assert "runtime_id" not in result
    assert "grant_id" not in result
    assert "storage_id" not in result
    assert result["tls_ready"] is False
