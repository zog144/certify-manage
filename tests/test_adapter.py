from pathlib import Path
import os
import pytest

from zog.certify_manage.adapter import CertbotAdapter
from zog.certify_manage.model import Authorization, PolicyError
from test_model import policy

def test_http_args_use_isolated_paths(tmp_path):
    a = Authorization.from_dict(policy())
    args = CertbotAdapter().arguments("issue", tmp_path, a)
    assert "certonly" in args and "--webroot" in args
    assert "/etc/letsencrypt" not in " ".join(args)
    assert args[-2:] == ("-d", "station.example.org")
    assert not any("nginx" in v for v in args)

def test_dns_credentials_are_private(tmp_path):
    a = Authorization.from_dict(policy(challenge="dns-01", dns_plugin="dns-cloudflare"))
    (tmp_path / "dns").mkdir(mode=0o700)
    credential = tmp_path / "dns" / "cloudflare.ini"
    credential.write_text("dns_cloudflare_api_token = SYNTHETIC-DO-NOT-USE\\n")
    credential.chmod(0o600)
    args = CertbotAdapter().arguments("issue", tmp_path, a)
    assert "--dns-cloudflare" in args
    assert "NOT-A-LIVE-TOKEN" not in " ".join(args)
    credential.chmod(0o644)
    with pytest.raises(PolicyError):
        CertbotAdapter().arguments("issue", tmp_path, a)

def test_renew_selects_exact_lineage(tmp_path):
    a = Authorization.from_dict(policy())
    args = CertbotAdapter().arguments("renew", tmp_path, a)
    assert args[-3:] == ("--cert-name", "station-web", "--no-random-sleep-on-renew")
    assert "--webroot" not in args


def test_certbot_executable_is_exact_immutable_view_path(tmp_path):
    a = Authorization.from_dict(policy())
    args = CertbotAdapter().arguments("issue", tmp_path, a)
    assert args[0] == "/applications/certify-manage/bin/certbot"
    for value in (
        "/usr/bin/certbot",
        "/opt/zog/certbot",
        "/applications/other/bin/certbot",
    ):
        with pytest.raises(PolicyError, match="unapproved-certbot-executable"):
            CertbotAdapter(executable=value).arguments("issue", tmp_path, a)
