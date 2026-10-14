"""Deterministic allowlisted Certbot command construction."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import subprocess
from .model import Authorization, PolicyError
from .security import secret_file

@dataclass(frozen=True)
class CertbotAdapter:
    executable: str = "/usr/bin/certbot"
    timeout_seconds: int = 1200

    def arguments(self, action: str, state: Path, policy: Authorization) -> tuple[str, ...]:
        if self.executable != "/usr/bin/certbot" and not self.executable.startswith("/opt/zog/"):
            raise PolicyError("unapproved-certbot-executable")
        if action not in ("issue", "renew"):
            raise PolicyError("unsupported-action")
        cfg = state / "certbot" / "config"
        base = [self.executable, "--non-interactive", "--no-directory-hooks", "--disable-renew-updates", "--config-dir", str(cfg),
                "--work-dir", str(state / "certbot" / "work"),
                "--logs-dir", str(state / "certbot" / "logs"),
                "--server", policy.acme_directory,
                "--no-eff-email"]
        if action == "renew":
            # Certbot reads persisted renewal configuration. Do not use
            # an external unapproved renewal configuration.
            return tuple(base + ["renew", "--cert-name", policy.certificate_id, "--no-random-sleep-on-renew"])
        args = base + ["certonly", "--agree-tos", "--email", policy.email,
                       "--cert-name", policy.certificate_id, "--keep-until-expiring"]
        if policy.challenge == "http-01":
            args += ["--webroot", "--webroot-path", str(state / "challenges" / policy.certificate_id)]
        elif policy.challenge == "dns-01" and policy.dns_plugin == "dns-cloudflare":
            secret = state / "dns" / "cloudflare.ini"
            secret_file(secret, owner=state.stat().st_uid)
            args += ["--dns-cloudflare", "--dns-cloudflare-credentials", str(secret)]
        else:
            raise PolicyError("unsupported-challenge")
        for domain in policy.hostnames:
            args += ["-d", domain]
        return tuple(args)

    def run(self, args: tuple[str, ...]) -> int:
        # Never log command output: provider plugins and Certbot errors may
        # accidentally contain account or credential material.
        try:
            proc = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, check=False,
                                  timeout=self.timeout_seconds, close_fds=True)
        except (OSError, subprocess.TimeoutExpired):
            return 127
        return proc.returncode
