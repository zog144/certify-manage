"""Issuer-owned, authenticated, read-only X.509 and lineage inspection.

This service authenticates the AF_UNIX peer UID. It cannot attest a
controller request ID: host-deploy MUST separately obtain root-control's
request-bound issuer observation and compare the independent evidence.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct

from .manager import CertificateManager, CertificateError
from .model import Authorization, PolicyError
from .security import protected_directory, trusted_policy

SCHEMA = "zog-certify-inspection-v1"
NONCE = re.compile(r"[0-9a-f]{32}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES = {"issued", "renewed", "unchanged"}
_FIELDS = frozenset((
    "schema", "nonce", "certificate_id", "hostnames", "policy_sha256",
    "health", "certificate_fingerprint_sha256", "valid_from", "expires_at",
    "days_remaining", "operation", "outcome", "operation_updated_at",
    "issuer_verified", "observed_at", "tls_ready",
))


class InspectionError(ValueError):
    """Generic peer-visible rejection; never expose issuer file details."""


def _timestamp(value):
    if type(value) is not str or len(value) > 80:
        raise InspectionError("invalid-timestamp")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("naive")
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise InspectionError("invalid-timestamp") from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InspectionError("duplicate-fields")
        result[key] = value
    return result


def _json(data):
    return json.dumps(data, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("utf-8")


def _peer_uid(conn: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise InspectionError("unix-peer-authentication-unavailable")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    if len(raw) != 12:
        raise InspectionError("peer-credentials-invalid")
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def _read_request(conn):
    chunks = bytearray()
    while len(chunks) <= 1024:
        part = conn.recv(min(1025 - len(chunks), 256))
        if not part:
            break
        chunks.extend(part)
        if b"\n" in part:
            break
    if len(chunks) > 1024 or not chunks.endswith(b"\n") or chunks.count(b"\n") != 1:
        raise InspectionError("invalid-request-framing")
    try:
        request = json.loads(chunks[:-1].decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError):
        raise InspectionError("invalid-request") from None
    if (type(request) is not dict
            or set(request) != {"schema", "operation", "nonce"}
            or request["schema"] != SCHEMA
            or request["operation"] != "inspect"
            or type(request["nonce"]) is not str
            or NONCE.fullmatch(request["nonce"]) is None):
        raise InspectionError("unsupported-request")
    return request["nonce"]


@contextmanager
def _snapshot_lock(state: Path):
    """Read under the existing issuer writer's flock, without creating files."""
    protected_directory(state, owner=os.geteuid())
    lock_dir = state / "locks"
    protected_directory(lock_dir, owner=os.geteuid())
    fd = os.open(lock_dir / "issuer.lock",
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise InspectionError("invalid-issuer-lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InspectionError("issuer-busy") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class IssuerInspector:
    """Pinned protected policy/state; one fixed certificate, one operation."""

    def __init__(self, state: Path, policy: Authorization, *,
                 authorized_uid: int, policy_path: Path | None = None):
        if type(authorized_uid) is not int or not 1000 <= authorized_uid < 2**31:
            raise InspectionError("invalid-authorized-peer")
        self.state = Path(state)
        self.policy = policy
        self.authorized_uid = authorized_uid
        self.policy_path = Path(policy_path) if policy_path is not None else None

    def _check_policy(self):
        if self.policy_path is not None:
            # Recheck protected authorization on EVERY request; policy
            # replacement/revocation must not preserve a stale successful view.
            try:
                current = Authorization.from_dict(
                    json.loads(trusted_policy(self.policy_path), object_pairs_hook=_unique_object)
                )
            except (ValueError, OSError, TypeError):
                raise InspectionError("issuer-policy-unavailable") from None
            if current.fingerprint != self.policy.fingerprint:
                raise InspectionError("issuer-policy-changed")

    def inspect(self, nonce: str) -> dict:
        if type(nonce) is not str or NONCE.fullmatch(nonce) is None:
            raise InspectionError("invalid-nonce")
        self._check_policy()
        # The old peer-authenticated socket and the selected one-shot
        # invocation reuse exactly the same issuer-owned validation.
        result = inspect_once(self.state, self.policy)
        result["schema"] = SCHEMA
        result["nonce"] = nonce
        if set(result) != _FIELDS:
            raise InspectionError("invalid-inspection-result")
        return result


def inspect_once(state: Path, policy: Authorization) -> dict:
    """One finite, read-only issuer snapshot; never attest a controller run.

    A selected inspect runs only after the controller singleton admits it,
    but using the existing nonblocking writer lock here also guards
    against unreviewed concurrent mutation of the private lineage.
    """
    state = Path(state)
    with _snapshot_lock(state):
        manager = CertificateManager(state, policy)
        status = manager.inspect()  # key, SAN, fullchain, renewal, account
        record = manager._read()     # under the same issuer snapshot lock
    now = datetime.now(timezone.utc)
    verified = False
    if (record is not None and record.get("status") == "ready"
            and record.get("operation") in ("issue", "renew")
            and record.get("outcome") in _OUTCOMES
            and status.health == "valid" and status.detail is None
            and record.get("certificate_fingerprint") == status.fingerprint_sha256
            and record.get("policy_sha256") == policy.fingerprint
            and status.operation == record["operation"]
            and status.outcome == record["outcome"]):
        try:
            updated = _timestamp(record.get("updated_at"))
            verified = updated <= now + timedelta(minutes=2)
        except InspectionError:
            verified = False

    return {
        "schema": "zog-certify-inspection-result-v1",
        "certificate_id": status.certificate_id,
        "hostnames": list(status.hostnames),
        "policy_sha256": policy.fingerprint,
        "health": status.health,
        "certificate_fingerprint_sha256": status.fingerprint_sha256,
        "valid_from": status.valid_from,
        "expires_at": status.expires_at,
        "days_remaining": status.days_remaining,
        "operation": status.operation,
        "outcome": status.outcome,
        "operation_updated_at": status.operation_updated_at,
        "issuer_verified": verified,
        "observed_at": now.isoformat(),
        "tls_ready": False,
    }


def respond_one(inspector: IssuerInspector, conn: socket.socket):
    """Authenticate BEFORE parsing, and respond with bounded sanitized JSON."""
    with conn:
        conn.settimeout(5)
        if _peer_uid(conn) != inspector.authorized_uid:
            return
        try:
            nonce = _read_request(conn)
            data = _json({"ok": True, "result": inspector.inspect(nonce)}) + b"\n"
            if len(data) > 4096:
                raise InspectionError("oversized-inspection")
        except Exception:
            data = _json({"ok": False, "error": "inspection-unavailable"}) + b"\n"
        try:
            conn.sendall(data)
        except OSError:
            pass


def _activated_socket(expected_path: str):
    """Use exactly the single systemd-managed FD 3; never bind a public socket."""
    if (os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"):
        raise InspectionError("systemd-socket-activation-required")
    if not expected_path.startswith("/") or ".." in Path(expected_path).parts:
        raise InspectionError("invalid-pinned-socket")
    listener = socket.socket(fileno=os.dup(3))
    try:
        if (listener.family != socket.AF_UNIX
                or listener.type & 0xF != socket.SOCK_STREAM
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or listener.getsockname() != expected_path):
            raise InspectionError("unexpected-activated-socket")
        return listener
    except BaseException:
        listener.close()
        raise


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Issuer-UID-only X.509 inspector")
    parser.add_argument("--authorized-uid", type=int, required=True)
    parser.add_argument("--socket-path", required=True)
    parser.add_argument("--state", default="/var/lib/zog-certify-manage")
    parser.add_argument("--policy", default="/run/zog-host/certify-policy/policy.json")
    args = parser.parse_args(argv)
    if os.geteuid() == 0 or os.geteuid() == args.authorized_uid:
        raise InspectionError("distinct-unprivileged-issuer-identity-required")
    # Only the controller-approved guest locations are accepted.
    if (args.state != "/var/lib/zog-certify-manage"
            or args.policy != "/run/zog-host/certify-policy/policy.json"):
        raise InspectionError("unapproved-issuer-source")
    policy_path = Path(args.policy)
    policy = Authorization.from_dict(
        json.loads(trusted_policy(policy_path), object_pairs_hook=_unique_object)
    )
    inspector = IssuerInspector(Path(args.state), policy,
                                authorized_uid=args.authorized_uid,
                                policy_path=policy_path)
    inspector._check_policy()
    with _activated_socket(args.socket_path) as listener:
        while True:
            conn, _ = listener.accept()
            respond_one(inspector, conn)


if __name__ == "__main__":
    main()
