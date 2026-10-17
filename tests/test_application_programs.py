"""Contract test for the review-only box-control program declaration.

Inspect its literal syntax; do not execute an untrusted application declaration.
"""
import ast
from pathlib import Path

def test_stage_is_a_separate_selected_program_with_existing_policy_and_state():
    source = Path(__file__).resolve().parents[1] / "integration/box-control/application.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
             and node.func.id == "program"]
    programs = {}
    for call in calls:
        keywords = {kw.arg: kw.value for kw in call.keywords}
        name = ast.literal_eval(keywords["name"])
        assert name not in programs, "duplicate program name"
        command = ast.literal_eval(keywords["command"])
        mounts = ast.literal_eval(keywords["mounts"])
        programs[name] = (command, mounts)
    assert set(programs) == {"prepare", "issue", "renew", "inspect", "stage"}
    stage_cmd, stage_mount = programs["stage"]
    assert stage_cmd == (
        "/applications/certify-manage/bin/python3", "-m", "zog.certify_manage", "stage",
        "--state", "/var/lib/zog-certify-manage",
        "--policy", "/run/zog-host/certify-policy/policy.json")
    for name, (command, mounts) in programs.items():
        assert mounts == {"certificate-data": "/var/lib/zog-certify-manage"}
        assert command[0] == "/applications/certify-manage/bin/python3"
        assert command[4:] == ("--state", "/var/lib/zog-certify-manage",
                                "--policy", "/run/zog-host/certify-policy/policy.json")
        assert command[3] == name
