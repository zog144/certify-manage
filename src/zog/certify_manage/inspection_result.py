"""Canonical, bounded, invocation-scoped stdout record for selected inspect.

This does NOT establish the executed program, request ID, runtime, or
systemd invocation. The controller must bind this exact one-line record
to the SAVED selected inspect request and trusted journal invocation.
"""
from __future__ import annotations

from datetime import datetime
import json
import re

from .inspection import inspect_once
from .model import Authorization

SCHEMA = "zog-certify-inspection-result-v1"
PREFIX = "ZOG_CERTIFY_INSPECT_RESULT_V1 "
MAX_RECORD_BYTES = 4096
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CERT = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_FIELDS = frozenset({
    "schema", "certificate_id", "hostnames", "policy_sha256",
    "health", "certificate_fingerprint_sha256", "valid_from", "expires_at",
    "days_remaining", "operation", "outcome", "operation_updated_at",
    "issuer_verified", "observed_at", "tls_ready",
})
_HEALTH = frozenset({"valid", "missing", "invalid", "uncertain",
                     "expired-or-not-yet-valid"})
_OPERATIONS = frozenset({None, "issue", "renew", "recover"})
_OUTCOMES = frozenset({None, "issued", "renewed", "unchanged",
                       "recovered-unverified", "failed"})


class InspectionRecordError(ValueError):
    pass


def _timestamp(value: str) -> datetime:
    if type(value) is not str or not 1 <= len(value) <= 80:
        raise InspectionRecordError("invalid-inspection-time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InspectionRecordError("invalid-inspection-time") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InspectionRecordError("invalid-inspection-time")
    return parsed


def serialize_inspection_result(value: dict, policy: Authorization) -> str:
    """Return exactly one bounded ASCII line with a non-JSON marker.

    A missing or invalid certificate is still a *completed observation*,
    represented with issuer_verified=false. Exit 0 is not X.509 evidence.
    """
    if type(value) is not dict or set(value) != _FIELDS:
        raise InspectionRecordError("invalid-inspection-shape")
    if (value.get("schema") != SCHEMA
            or value.get("certificate_id") != policy.certificate_id
            or value.get("hostnames") != list(policy.hostnames)
            or value.get("policy_sha256") != policy.fingerprint
            or value.get("health") not in _HEALTH
            or type(value.get("issuer_verified")) is not bool
            or value.get("tls_ready") is not False
            or value.get("operation") not in _OPERATIONS
            or value.get("outcome") not in _OUTCOMES):
        raise InspectionRecordError("invalid-inspection-binding")
    leaf = value["certificate_fingerprint_sha256"]
    if leaf is not None and (type(leaf) is not str or _HEX.fullmatch(leaf) is None):
        raise InspectionRecordError("invalid-inspection-fingerprint")
    days = value["days_remaining"]
    if days is not None and (type(days) is not int or not -365000 <= days <= 365000):
        raise InspectionRecordError("invalid-inspection-days")
    if value["valid_from"] is not None:
        _timestamp(value["valid_from"])
    if value["expires_at"] is not None:
        _timestamp(value["expires_at"])
    _timestamp(value["observed_at"])
    if value["operation_updated_at"] is not None:
        _timestamp(value["operation_updated_at"])
    if value["issuer_verified"]:
        if (value["health"] != "valid"
                or leaf is None
                or value["operation"] not in ("issue", "renew")
                or value["outcome"] not in ("issued", "renewed", "unchanged")
                or not all((value["valid_from"], value["expires_at"],
                            value["operation_updated_at"], days is not None))):
            raise InspectionRecordError("unproven-inspection-verification")
    # ASCII JSON prevents embedded newlines and control-character injection
    # into journald records; exactly one marker is emitted to stdout.
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False)
    line = PREFIX + payload
    if "\n" in line or "\r" in line or len(line.encode("ascii")) > MAX_RECORD_BYTES:
        raise InspectionRecordError("inspection-record-too-large")
    return line


def selected_inspect(state, policy: Authorization) -> str:
    return serialize_inspection_result(inspect_once(state, policy), policy)
