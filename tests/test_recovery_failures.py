"""Fail-closed CLI, journal durability, and post-Certbot validation regressions."""
import json
import subprocess

import pytest

from zog.certify_manage.__main__ import main
from zog.certify_manage.manager import CertificateManager, CertificateError, UncertainOperation
from zog.certify_manage.model import Authorization
from test_manager import Runner, make_cert
from test_model import policy


def test_cli_never_prints_subprocess_timeout_argv(monkeypatch, capsys):
    import zog.certify_manage.__main__ as cli
    monkeypatch.setattr(cli, "trusted_policy", lambda path: json.dumps(policy()).encode())
    class Failing:
        def __init__(self, *args, **kwargs):
            pass
        def renew(self):
            raise subprocess.TimeoutExpired(
                ["/usr/bin/certbot", "--dns-cloudflare-credentials", "/private/token.ini"], 1)
    monkeypatch.setattr(cli, "CertificateManager", Failing)
    code = main(["renew"])
    out = capsys.readouterr()
    assert code == 2
    assert not out.out
    assert json.loads(out.err) == {"error": "certify-manage-operation-rejected"}
    assert "token.ini" not in out.err
    assert "Traceback" not in out.err


def test_cli_recovery_requires_explicit_flag(monkeypatch, capsys):
    import zog.certify_manage.__main__ as cli
    monkeypatch.setattr(cli, "trusted_policy", lambda path: json.dumps(policy()).encode())
    calls = []
    class Stub:
        def __init__(self, *args, **kwargs):
            pass
        def recover(self, *, acknowledge):
            calls.append(acknowledge)
            raise CertificateError("manual-recovery-blocked")
    monkeypatch.setattr(cli, "CertificateManager", Stub)
    assert main(["recover"]) == 2
    assert calls == [False]
    assert main(["recover", "--confirm-uncertain-recovery"]) == 2
    assert calls == [False, True]
    assert "manual-recovery-blocked" not in capsys.readouterr().err


def test_certbot_exit_zero_with_wrong_authorized_san_stays_uncertain(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    auth = Authorization.from_dict(policy(hostnames=["different.example.org"]))
    manager = CertificateManager(state, auth, Runner(state))
    with pytest.raises(UncertainOperation, match="certbot-lineage-not-valid"):
        manager.issue()
    assert manager.inspect().health == "uncertain"
    with pytest.raises(CertificateError, match="recover-requires-valid-lineage"):
        manager.recover(acknowledge=True)


def test_certbot_exit_zero_with_invalid_saved_account_retains_uncertainty(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    class WrongAccount(Runner):
        def run(self, argv):
            make_cert(self.state, "station-web")
            conf = self.state / "certbot/config/renewal/station-web.conf"
            conf.write_text(conf.read_text().replace("abcdef123456", "bad!"))
            return 0
    manager = CertificateManager(state, Authorization.from_dict(policy()), WrongAccount(state))
    with pytest.raises(Exception, match="renewal-account-or-server-mismatch"):
        manager.issue()
    assert manager.inspect().health == "uncertain"


def test_failed_terminal_journal_fsync_does_not_make_success_claim(tmp_path, monkeypatch):
    import zog.certify_manage.manager as module
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    manager = CertificateManager(state, Authorization.from_dict(policy()), Runner(state))
    original = module._save
    def fail_on_ready(path, data):
        if data.get("status") == "ready":
            raise OSError("synthetic disk-full")
        return original(path, data)
    monkeypatch.setattr(module, "_save", fail_on_ready)
    with pytest.raises(OSError, match="synthetic disk-full"):
        manager.issue()
    assert manager.inspect().health == "uncertain"
    with pytest.raises(UncertainOperation):
        manager.issue()
