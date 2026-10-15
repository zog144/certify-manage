"""Exercise the actual installed Certbot + Cloudflare entry points offline."""
import os
import shutil
import subprocess

import pytest

@pytest.mark.skipif(shutil.which("certbot") is None, reason="Certbot is packaged in separate smoke job")
def test_certbot_and_dns_plugin_discoverable_without_acme(tmp_path):
    cmd = shutil.which("certbot")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": str(tmp_path)}
    version = subprocess.run([cmd, "--version"], capture_output=True,
                             text=True, timeout=30, env=env)
    assert version.returncode == 0
    assert "certbot 5.8.0" in version.stdout + version.stderr
    # plugins --text does not request any ACME account or challenge.
    args = [cmd, "--config-dir", str(tmp_path / "config"),
            "--work-dir", str(tmp_path / "work"),
            "--logs-dir", str(tmp_path / "logs"),
            "--no-directory-hooks", "plugins", "--text"]
    plugins = subprocess.run(args, capture_output=True, text=True,
                             timeout=60, env=env)
    assert plugins.returncode == 0, "certbot plugin discovery failed"
    assert "dns-cloudflare" in plugins.stdout.lower()

@pytest.mark.skipif(shutil.which("certbot") is None, reason="Certbot is packaged in separate smoke job")
def test_real_certbot_renew_and_certonly_cli_help(tmp_path):
    cmd = shutil.which("certbot")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": str(tmp_path)}
    for action in ("renew", "certonly"):
        result = subprocess.run([cmd, action, "--help", "--no-directory-hooks"],
            capture_output=True, text=True, env=env, timeout=30)
        assert result.returncode == 0
        assert "certbot" in (result.stdout + result.stderr).lower()
