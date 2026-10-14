"""Read existing Certbot material without returning private bytes."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import os
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID
from .model import Authorization, CertificateStatus, PolicyError

def _resolve_lineage(root: Path, lineage: str, filename: str) -> Path:
    # Certbot's live/ entries are symbolic links into the protected archive/.
    live = root / "live" / lineage / filename
    target = live.resolve(strict=True)
    archive = (root / "archive" / lineage).resolve(strict=True)
    if archive not in target.parents or not target.is_file():
        raise PolicyError("invalid-certbot-lineage")
    return target

def inspect_cert(root: Path, policy: Authorization, *, now: datetime | None = None) -> CertificateStatus:
    now = now or datetime.now(timezone.utc)
    base = policy.certificate_id
    try:
        cert_path = _resolve_lineage(root, base, "cert.pem")
        key_path = _resolve_lineage(root, base, "privkey.pem")
        fullchain_path = _resolve_lineage(root, base, "fullchain.pem")
        for p in (cert_path, key_path, fullchain_path):
            st = p.stat()
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022 or st.st_nlink != 1:
                raise PolicyError("unsafe-certificate-file")
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        fullchain = fullchain_path.read_bytes()
        first = x509.load_pem_x509_certificate(fullchain)
        if first.fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()):
            raise PolicyError("fullchain-leaf-mismatch")
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        public = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if public != key_public:
            raise PolicyError("private-key-mismatch")
        names = tuple(sorted(cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)))
        if names != policy.hostnames:
            raise PolicyError("san-mismatch")
        valid_from = cert.not_valid_before_utc
        expires = cert.not_valid_after_utc
        remaining = int((expires - now).total_seconds() // 86400)
        health = "valid" if valid_from <= now < expires else "expired-or-not-yet-valid"
        return CertificateStatus(base, policy.hostnames, health, valid_from.isoformat(), expires.isoformat(),
                                 cert.fingerprint(hashes.SHA256()).hex(), remaining)
    except FileNotFoundError:
        return CertificateStatus(base, policy.hostnames, "missing")
    except (ValueError, TypeError, x509.ExtensionNotFound, PolicyError, OSError) as error:
        return CertificateStatus(base, policy.hostnames, "invalid", detail="lineage-verification-failed")
