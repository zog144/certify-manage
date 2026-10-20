"""Prevent drift between the install requirements and the real selected app spec.

No external controller required; this is a literal-source compatibility gate,
not an execution or trusted-installation claim.
"""
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "integration/host-install/issuer-installation-requirements-v1.json"
APPLICATION = ROOT / "integration/box-control/application.py"


def _application():
    tree = ast.parse(APPLICATION.read_text(encoding="utf8"))
    app = next(node for node in ast.walk(tree)
               if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Name)
               and node.func.id == "application")
    spec = {kw.arg: kw.value for kw in app.keywords}
    return ast.literal_eval(spec["name"]), ast.literal_eval(spec["execution_identity"]), ast.literal_eval(
        spec["writable_mounts"]), ast.literal_eval(spec["preparation_revision"]), tree


def test_requirements_are_nonsecret_pinned_and_read_only():
    doc = json.loads(REQUIREMENTS.read_text(encoding="utf8"))
    assert set(doc) == {
        "schema", "application", "status", "controller", "software", "state",
        "policy", "programs", "observation", "installation", "dns_01"
    }
    assert doc["schema"] == "zog-certify-issuer-installation-requirements-v1"
    assert doc["status"] == "requirements-only-not-runtime-attestation"
    assert doc["controller"]["selected_program_only"] is True
    assert doc["controller"]["durable_request_id_required"] is True
    assert doc["controller"]["reuse_request_id_on_lost_reply"] is True
    assert doc["controller"]["deny_when_unresolved_or_cleanup_pending"] is True
    assert doc["observation"]["issuer_verified_not_equal_exit_zero"] is True
    assert doc["observation"]["tls_ready"] is False
    assert doc["observation"]["max_result_bytes"] == 4096
    assert doc["observation"]["selected_inspect_marker"] == "ZOG_CERTIFY_INSPECT_RESULT_V1 "
    assert doc["software"]["artifact_has_secrets"] is False
    assert doc["policy"]["no_untrusted_fqdn_or_acme_directory_from_launch_request"] is True
    for key in ("first_boot_issue_automatically", "run_certbot_as_root",
                "create_new_issuer_uid_in_application", "read_station_vault",
                "public_acme_without_separate_approval", "nginx_reload",
                "network_traverse_tls_termination"):
        assert doc["installation"][key] is False
    assert doc["installation"]["certificate_identity_after_reboot"] == "preserve-existing"
    assert doc["state"]["expected_mode"] == "0700"
    assert doc["dns_01"]["secret_mode"] == "0600"
    assert doc["dns_01"]["rotate_only_while_issuer_quiescent"] is True
    assert doc["policy"]["missing_policy"] == "awaiting-operator-approved-hostname-challenge"
    forbidden = ("PRIVATE KEY", "dns_cloudflare_api_token =", "token =", "-----BEGIN", "account_key")
    raw = REQUIREMENTS.read_text(encoding="utf8")
    assert not any(value in raw for value in forbidden)


def test_install_requirements_match_source_selected_commands():
    doc = json.loads(REQUIREMENTS.read_text(encoding="utf8"))
    name, identity, mounts, revision, tree = _application()
    assert name == doc["application"] == "certify-manage"
    assert identity == doc["controller"]["execution_identity"] == "application"
    assert mounts == (doc["state"]["mount_name"],)
    assert revision == "certify-manage-state-v1"
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name)
             and node.func.id == "program"]
    seen = {}
    for call in calls:
        kw = {e.arg: e.value for e in call.keywords}
        prog = ast.literal_eval(kw["name"])
        command = ast.literal_eval(kw["command"])
        local = ast.literal_eval(kw["mounts"])
        assert prog not in seen
        assert local == {doc["state"]["mount_name"]: doc["state"]["guest_mount"]}
        assert command == (doc["software"]["launcher"], "-m", "zog.certify_manage",
                           prog, "--state", doc["state"]["guest_mount"],
                           "--policy", doc["policy"]["guest_file"])
        if "execution_timeout_seconds" in kw:
            timeout = ast.literal_eval(kw["execution_timeout_seconds"])
        else:
            timeout = None
        seen[prog] = timeout
    assert [(x["name"], x["timeout_seconds"] if "timeout_seconds" in x else None)
            for x in doc["programs"]] == [(name, seen[name]) for name in seen]
    assert doc["state"]["guest_mount"] == "/var/lib/zog-certify-manage"
    assert doc["policy"]["host_owner_directory"] == "/etc/zog/certify-policy"
    assert doc["policy"]["guest_file"] == "/run/zog-host/certify-policy/policy.json"


def test_issuer_config_and_selected_inspection_match_requirements():
    from zog.certify_manage.adapter import IMMUTABLE_CERTBOT
    from zog.certify_manage.inspection_result import (
        PREFIX, SCHEMA, MAX_RECORD_BYTES,
    )
    doc = json.loads(REQUIREMENTS.read_text(encoding="utf8"))
    assert doc["software"]["certbot"] == IMMUTABLE_CERTBOT
    assert doc["observation"]["selected_inspect_marker"] == PREFIX
    assert doc["observation"]["selected_inspect_schema"] == SCHEMA
    assert doc["observation"]["max_result_bytes"] == MAX_RECORD_BYTES
