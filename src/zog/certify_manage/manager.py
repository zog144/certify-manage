"""One-writer ACME lifecycle and crash-evidenced operations."""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import fcntl
import json
import os
import stat

from .adapter import CertbotAdapter
from .certificates import inspect_cert
from .model import Authorization, CertificateStatus, PolicyError
from .security import protected_directory, protected_file_read
from .renewal import validate_renewal
from .publication import stage_candidate

class CertificateError(RuntimeError):
    pass

class UncertainOperation(CertificateError):
    pass

def _save(path: Path, data: dict) -> None:
    """Durably replace one operation record via its already-open directory."""
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise CertificateError("unsafe-operation-directory")
        temp = path.name + ".tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temp, dir_fd=parent)
            except FileNotFoundError:
                pass
    finally:
        os.close(parent)

class CertificateManager:
    def __init__(self, state: Path, policy: Authorization, adapter: CertbotAdapter | None = None):
        self.state = Path(state)
        self.policy = policy
        self.adapter = adapter or CertbotAdapter()

    def _record_path(self) -> Path:
        return self.state / "operations" / (self.policy.certificate_id + ".json")

    def _read(self) -> dict | None:
        path = self._record_path()
        if not path.exists():
            return None
        obj = json.loads(protected_file_read(
            self.state, Path("operations") / path.name, 65536))
        if not isinstance(obj, dict) or obj.get("schema") != "zog-certify-operation-v1" or obj.get("policy_sha256") != self.policy.fingerprint:
            raise CertificateError("policy-or-operation-mismatch")
        return obj

    def prepare(self) -> None:
        protected_directory(self.state, owner=os.geteuid())
        for relative in ("certbot", "certbot/config", "certbot/work", "certbot/logs",
                         "challenges", "challenges/" + self.policy.certificate_id,
                         "dns", "operations", "locks", "publications"):
            path = self.state / relative
            if not path.exists():
                path.mkdir(mode=0o700)
            protected_directory(path, owner=os.geteuid())

    @contextmanager
    def _locked(self):
        self.prepare()
        fd = os.open(self.state / "locks" / "issuer.lock",
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise CertificateError("unsafe-lock-file")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def inspect(self) -> CertificateStatus:
        # A read must not create mounts, directories, locks or state.
        protected_directory(self.state, owner=os.geteuid())
        status = inspect_cert(self.state / "certbot" / "config", self.policy)
        try:
            account = validate_renewal(self.state, self.policy, required=status.health != "missing")
            record = self._read()
            if record and record.get("account_id") and record["account_id"] != account:
                raise PolicyError("acme-account-changed")
        except (PolicyError, OSError):
            status = replace(status, health="invalid", detail="renewal-policy-mismatch")
        obj = self._read()
        if obj:
            detail = obj.get("status")
            if detail == "uncertain":
                return replace(status, health="uncertain", operation=obj.get("operation"), detail="operator-recovery-required")
            if detail == "failed":
                return replace(status, operation=obj.get("operation"), detail="last-operation-failed")
            return replace(status, operation=obj.get("operation"))
        return status

    def _record(self, operation: str, status: str, fingerprint: str | None = None, account_id: str | None = None) -> None:
        _save(self._record_path(), {"schema": "zog-certify-operation-v1",
             "policy_sha256": self.policy.fingerprint, "operation": operation,
             "status": status, "certificate_fingerprint": fingerprint,
             "account_id": account_id,
             "updated_at": datetime.now(timezone.utc).isoformat()})

    def _execute(self, operation: str) -> CertificateStatus:
        with self._locked():
            old = self._read()
            if old and old["status"] == "uncertain":
                raise UncertainOperation("operator-recovery-required")
            before = inspect_cert(self.state / "certbot" / "config", self.policy)
            if operation == "issue" and before.health != "missing":
                raise CertificateError("lineage-already-present")
            if operation == "renew" and before.health != "valid":
                raise CertificateError("renew-requires-valid-lineage")
            # Certbot restores settings from its lineage, not solely argv.
            # Verify the on-disk authority before each mutating invocation.
            account_before = validate_renewal(self.state, self.policy, required=operation == "renew")
            if operation == "renew" and (not old or not old.get("account_id") or old["account_id"] != account_before):
                raise CertificateError("acme-account-binding-mismatch")
            args = self.adapter.arguments(operation, self.state, self.policy)
            self._record(operation, "uncertain", before.fingerprint_sha256, account_before)
            code = self.adapter.run(args)
            after = inspect_cert(self.state / "certbot" / "config", self.policy)
            try:
                if code != 0 or after.health != "valid":
                    raise CertificateError("certbot-operation-failed-or-invalid")
                account_after = validate_renewal(self.state, self.policy, required=True)
                if operation == "renew" and account_after != account_before:
                    raise CertificateError("acme-account-changed")
            except (PolicyError, CertificateError, OSError, ValueError):
                self._record(operation, "failed", before.fingerprint_sha256, account_before)
                raise CertificateError("certbot-operation-failed-or-invalid") from None
            if operation == "issue" and after.fingerprint_sha256 == before.fingerprint_sha256:
                self._record(operation, "failed")
                raise CertificateError("certificate-was-not-issued")
            self._record(operation, "ready", after.fingerprint_sha256, account_after)
            return after

    def stage(self) -> dict:
        """Stage verified issuer-private material; does not export or reload."""
        with self._locked():
            old = self._read()
            if not old or old.get("status") != "ready":
                raise CertificateError("publication-requires-ready-issuance")
            account = validate_renewal(self.state, self.policy, required=True)
            if not account or account != old.get("account_id"):
                raise CertificateError("publication-account-mismatch")
            current = inspect_cert(self.state / "certbot" / "config", self.policy)
            if current.health != "valid" or current.fingerprint_sha256 != old.get("certificate_fingerprint"):
                raise CertificateError("publication-requires-matching-lineage")
            return stage_candidate(self.state, self.policy, current)

    def issue(self) -> CertificateStatus:
        return self._execute("issue")

    def renew(self) -> CertificateStatus:
        return self._execute("renew")

    def recover(self) -> CertificateStatus:
        with self._locked():
            old = self._read()
            if old is None or old["status"] != "uncertain":
                raise CertificateError("no-uncertain-operation")
            current = inspect_cert(self.state / "certbot" / "config", self.policy)
            if current.health != "valid":
                raise CertificateError("recover-requires-valid-lineage")
            account = validate_renewal(self.state, self.policy, required=True)
            if old.get("account_id") and old["account_id"] != account:
                raise CertificateError("acme-account-changed")
            self._record("recover", "ready", current.fingerprint_sha256, account)
            return current
