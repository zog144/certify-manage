"""Strict, read-only peer-authenticated client for issuer's X.509 inspector."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import re
import secrets
import socket

from .inspection import SCHEMA, HEX, NONCE, _FIELDS, _json, _peer_uid, _unique_object, InspectionError
import json


class IssuerInspectionClient:
    def __init__(self, socket_path, *, expected_issuer_uid: int, timeout_seconds=5):
        self.socket_path = Path(socket_path)
        if (not self.socket_path.is_absolute()
                or ".." in self.socket_path.parts
                or str(self.socket_path) == "/"):
            raise InspectionError("invalid-inspector-socket")
        if type(expected_issuer_uid) is not int or expected_issuer_uid < 1000:
            raise InspectionError("invalid-issuer-uid")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 15:
            raise InspectionError("invalid-inspection-timeout")
        self.expected_issuer_uid = expected_issuer_uid
        self.timeout_seconds = float(timeout_seconds)

    def inspect(self) -> dict:
        nonce = secrets.token_hex(16)
        issued = datetime.now(timezone.utc)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(self.timeout_seconds)
            conn.connect(str(self.socket_path))
            # Both directions pin UIDs: the inspector authenticates our UID.
            if _peer_uid(conn) != self.expected_issuer_uid:
                raise InspectionError("inspector-peer-mismatch")
            conn.sendall(_json({"schema": SCHEMA, "operation": "inspect",
                                "nonce": nonce}) + b"\n")
            data = bytearray()
            while len(data) <= 4096:
                chunk = conn.recv(min(4097 - len(data), 512))
                if not chunk:
                    break
                data.extend(chunk)
                if b"\n" in chunk:
                    break
        if len(data) > 4096 or not data.endswith(b"\n") or data.count(b"\n") != 1:
            raise InspectionError("invalid-inspection-frame")
        try:
            reply = json.loads(data[:-1], object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError):
            raise InspectionError("invalid-inspection-json") from None
        if (type(reply) is not dict or set(reply) != {"ok", "result"}
                or reply["ok"] is not True or type(reply["result"]) is not dict):
            raise InspectionError("inspection-unavailable")
        value = reply["result"]
        if (set(value) != _FIELDS or value.get("schema") != SCHEMA
                or value.get("nonce") != nonce or value.get("tls_ready") is not False
                or type(value.get("issuer_verified")) is not bool
                or value.get("health") not in ("valid", "missing", "invalid", "uncertain",
                                               "expired-or-not-yet-valid")
                or type(value.get("certificate_id")) is not str
                or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", value["certificate_id"]) is None
                or type(value.get("hostnames")) is not list
                or not 1 <= len(value["hostnames"]) <= 20
                or any(type(x) is not str or len(x) > 253 for x in value["hostnames"])
                or type(value.get("policy_sha256")) is not str
                or HEX.fullmatch(value["policy_sha256"]) is None):
            raise InspectionError("invalid-inspection-evidence")
        for k in ("certificate_fingerprint_sha256", "valid_from", "expires_at",
                  "operation_updated_at", "operation", "outcome"):
            val = value[k]
            if val is not None and (type(val) is not str or len(val) > 90):
                raise InspectionError("invalid-inspection-field")
        if (value["certificate_fingerprint_sha256"] is not None
                and HEX.fullmatch(value["certificate_fingerprint_sha256"]) is None):
            raise InspectionError("invalid-inspection-fingerprint")
        if (value["days_remaining"] is not None
                and (type(value["days_remaining"]) is not int
                     or not -365000 <= value["days_remaining"] <= 365000)):
            raise InspectionError("invalid-inspection-days")
        try:
            observed = datetime.fromisoformat(value["observed_at"])
            if observed.tzinfo is None:
                raise ValueError("naive")
            observed = observed.astimezone(timezone.utc)
        except (ValueError, TypeError, OverflowError):
            raise InspectionError("invalid-inspection-time") from None
        if not (issued - timedelta(seconds=10) <= observed
                <= datetime.now(timezone.utc) + timedelta(minutes=2)):
            raise InspectionError("stale-inspection-response")
        if (value["issuer_verified"] and
                (value["health"] != "valid" or value["operation"] not in ("issue", "renew")
                 or value["outcome"] not in ("issued", "renewed", "unchanged")
                 or value["certificate_fingerprint_sha256"] is None
                 or not value["operation_updated_at"])):
            raise InspectionError("unsupported-positive-inspection")
        return value
