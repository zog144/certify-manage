"""Private, atomically staged certificate candidates. No consumer export or reload."""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import os
import stat
from uuid import uuid4

from .certificates import _lineage_file, validate_staged_pem
from .model import Authorization, CertificateStatus, PolicyError
from .security import protected_directory, protected_file_read

def _write(dir_fd: int, name: str, content: bytes) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
    finally:
        pass

def stage_candidate(state: Path, policy: Authorization, status: CertificateStatus) -> dict:
    """Atomic private staging of a verified issuer certificate generation.

    The resulting folder remains under the issuer-only persistent mount. A
    separately approved host-owner broker must authenticate the consumer,
    revalidate the files and publish to the service before HTTPS is ready.
    """
    if status.health != "valid" or not status.fingerprint_sha256:
        raise PolicyError("certificate-not-locally-valid")
    key = _lineage_file(state, policy.certificate_id, "privkey.pem", private=True)
    fullchain = _lineage_file(state, policy.certificate_id, "fullchain.pem", private=False)
    cert = _lineage_file(state, policy.certificate_id, "cert.pem", private=False)
    validate_staged_pem(cert, fullchain, key, policy, status.fingerprint_sha256)
    # inspect_cert uses X.509 certificate fingerprint in DER form; key material
    # gets a separate digest, neither should ever be printed as bytes.
    record = {
        "schema": "zog-certify-publication-candidate-v1",
        "certificate_id": policy.certificate_id,
        "policy_sha256": policy.fingerprint,
        "certificate_fingerprint_sha256": status.fingerprint_sha256,
        "hostnames": list(policy.hostnames),
        "expires_at": status.expires_at,
        "fullchain_sha256": hashlib.sha256(fullchain).hexdigest(),
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "state": "issuer-private-unbound",
    }
    root = state / "publications" / policy.certificate_id
    if not root.exists():
        root.mkdir(mode=0o700)
    protected_directory(root, owner=os.geteuid())
    # An interrupted staging write is uncertain evidence. Never erase it
    # automatically or treat a same-fingerprint final directory as proof
    # that the abandoned attempt did not modify private material.
    if any(item.name.startswith(".pending-") for item in root.iterdir()):
        raise PolicyError("publication-pending-manual-recovery")
    generation = status.fingerprint_sha256
    target = root / generation
    if target.exists() or target.is_symlink():
        # Existing publication must be byte-for-byte identical and private.
        for name, data in (("privkey.pem", key), ("fullchain.pem", fullchain),
                           ("receipt.json", json.dumps(record, sort_keys=True).encode())):
            raw = protected_file_read(state, Path("publications") / policy.certificate_id /
                                      generation / name, 1_048_576, private=True)
            if raw != data:
                raise PolicyError("publication-generation-conflict")
        return record
    dir_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    pending = ".pending-" + uuid4().hex
    try:
        os.mkdir(pending, mode=0o700, dir_fd=dir_fd)
        child = os.open(pending, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        try:
            _write(child, "fullchain.pem", fullchain)
            _write(child, "privkey.pem", key)
            _write(child, "receipt.json", json.dumps(record, sort_keys=True).encode())
            os.fsync(child)
        finally:
            os.close(child)
        os.rename(pending, generation, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return record
