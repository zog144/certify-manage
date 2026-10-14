"""Strict and secret-free certificate authorization/status models."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

class PolicyError(ValueError):
    pass

_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SCHEMA = "zog-certify-manage-v1"

def hostname(value: object, *, wildcard: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.lower():
        raise PolicyError("invalid-hostname")
    raw = value[2:] if value.startswith("*.") and wildcard else value
    if raw == value and "*" in value or raw.endswith(".") or "." not in raw:
        raise PolicyError("invalid-hostname")
    if any(not _LABEL.fullmatch(piece) for piece in raw.split(".")):
        raise PolicyError("invalid-hostname")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise PolicyError("ip-address-not-allowed")
    return value

@dataclass(frozen=True)
class Authorization:
    certificate_id: str
    hostnames: tuple[str, ...]
    email: str
    acme_directory: str
    challenge: str
    dns_plugin: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Authorization":
        if not isinstance(data, dict) or set(data) != {"schema", "certificate_id", "hostnames", "email", "acme_directory", "challenge", "dns_plugin"}:
            raise PolicyError("invalid-policy-schema")
        if data["schema"] != _SCHEMA or not isinstance(data["certificate_id"], str) or not _ID.fullmatch(data["certificate_id"]):
            raise PolicyError("invalid-policy-id")
        challenge = data["challenge"]
        if challenge not in ("http-01", "dns-01"):
            raise PolicyError("unsupported-challenge")
        if (challenge == "http-01" and data["dns_plugin"] is not None) or (challenge == "dns-01" and data["dns_plugin"] != "dns-cloudflare"):
            raise PolicyError("unsupported-plugin")
        names = data["hostnames"]
        if not isinstance(names, list) or not 1 <= len(names) <= 20:
            raise PolicyError("invalid-hostnames")
        parsed = tuple(hostname(v, wildcard=challenge == "dns-01") for v in names)
        if len(set(parsed)) != len(parsed) or tuple(sorted(parsed)) != parsed:
            raise PolicyError("noncanonical-hostnames")
        email = data["email"]
        if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", email):
            raise PolicyError("invalid-email")
        url = data["acme_directory"]
        if not isinstance(url, str) or len(url) > 2048:
            raise PolicyError("invalid-acme-directory")
        try:
            parsed_url = urlsplit(url)
            valid = (parsed_url.scheme == "https" and parsed_url.hostname is not None and
                     parsed_url.username is None and parsed_url.password is None and
                     parsed_url.port in (None, 443) and not parsed_url.query and
                     not parsed_url.fragment and not parsed_url.hostname.startswith(".") and
                     parsed_url.path.startswith("/") and parsed_url.hostname.lower() == parsed_url.hostname)
        except ValueError:
            valid = False
        if not valid:
            raise PolicyError("invalid-acme-directory")
        return cls(data["certificate_id"], parsed, email, url, challenge, data["dns_plugin"])

    def canonical(self) -> dict:
        return {"schema": _SCHEMA, "certificate_id": self.certificate_id,
                "hostnames": list(self.hostnames), "email": self.email,
                "acme_directory": self.acme_directory, "challenge": self.challenge,
                "dns_plugin": self.dns_plugin}

    @property
    def fingerprint(self) -> str:
        raw = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()

@dataclass(frozen=True)
class CertificateStatus:
    certificate_id: str
    hostnames: tuple[str, ...]
    health: str
    valid_from: str | None = None
    expires_at: str | None = None
    fingerprint_sha256: str | None = None
    days_remaining: int | None = None
    operation: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict:
        return {**self.__dict__, "hostnames": list(self.hostnames)}
