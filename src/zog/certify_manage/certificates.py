"""Confined read-only inspection of certificate, chain and key material."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import os
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from .model import Authorization, CertificateStatus, PolicyError
from .security import protected_file_read, protected_directory

_NUMBERED = re.compile(r"[a-z]+[1-9][0-9]*\.pem\Z")
_FILENAMES = ("cert.pem", "privkey.pem", "fullchain.pem")

def _lineage_file(state: Path, name: str, filename: str, *, private: bool) -> bytes:
    live = state / "certbot" / "config" / "live" / name
    protected_directory(live, owner=os.geteuid())
    symlink = live / filename
    # Only Certbot's exact relative archive link is accepted. Never follow
    # arbitrary paths, and open the archive bytes with O_NOFOLLOW.
    if not symlink.is_symlink():
        raise PolicyError("invalid-certbot-live-link")
    link = os.readlink(symlink)
    prefix = "../../archive/" + name + "/"
    if not link.startswith(prefix):
        raise PolicyError("invalid-certbot-live-target")
    basename = link[len(prefix):]
    kind = filename[:-4]
    if not re.fullmatch(re.escape(kind) + r"[1-9][0-9]*\.pem", basename):
        raise PolicyError("invalid-certbot-archive-filename")
    relative = Path("certbot/config/archive") / name / basename
    return protected_file_read(state, relative, 1_048_576, private=private)

def inspect_cert(root: Path, policy: Authorization, *, now: datetime | None = None) -> CertificateStatus:
    now = now or datetime.now(timezone.utc)
    # root is <private-state>/certbot/config, not caller-selected host paths.
    state = root.parent.parent
    name = policy.certificate_id
    try:
        pem = _lineage_file(state, name, "cert.pem", private=False)
        key_pem = _lineage_file(state, name, "privkey.pem", private=True)
        chain = _lineage_file(state, name, "fullchain.pem", private=False)
        cert = x509.load_pem_x509_certificate(pem)
        first = x509.load_pem_x509_certificate(chain)
        if first.fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()):
            raise PolicyError("fullchain-leaf-mismatch")
        key = serialization.load_pem_private_key(key_pem, password=None)
        public = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if public != key_public:
            raise PolicyError("private-key-mismatch")
        names = tuple(sorted(cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)))
        if names != policy.hostnames:
            raise PolicyError("san-mismatch")
        valid_from, expires = cert.not_valid_before_utc, cert.not_valid_after_utc
        remaining = int((expires - now).total_seconds() // 86400)
        health = "valid" if valid_from <= now < expires else "expired-or-not-yet-valid"
        return CertificateStatus(name, policy.hostnames, health, valid_from.isoformat(), expires.isoformat(),
                                 cert.fingerprint(hashes.SHA256()).hex(), remaining)
    except FileNotFoundError:
        return CertificateStatus(name, policy.hostnames, "missing")
    except (ValueError, TypeError, x509.ExtensionNotFound, PolicyError, OSError):
        return CertificateStatus(name, policy.hostnames, "invalid", detail="lineage-verification-failed")
