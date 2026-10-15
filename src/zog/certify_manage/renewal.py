"""Fail-closed validation of Certbot's persisted renewal authority.

Certbot stores renewal settings in a ConfigObj-style INI file; importantly its
webroot_map is a *nested* [[webroot_map]] section, not standard configparser INI.
This validator never executes or rewrites that file. New unreviewed options
must block mutation until reviewed against a pinned Certbot version.
"""
from __future__ import annotations
from pathlib import Path
import re

from .model import Authorization, PolicyError
from .security import protected_file_read

_SAFE_RENEWAL = frozenset({
    "account", "server", "authenticator", "installer", "key_type",
    "rsa_key_size", "elliptic_curve", "reuse_key", "webroot_path",
    "dns_cloudflare_credentials", "pref_challs",
})
_SAFE_TOP = frozenset({
    "version", "archive_dir", "cert", "privkey", "chain", "fullchain",
    "renew_before_expiry",
})
_UNSAFE_CONFIG_ITEMS = frozenset({"cli.ini", "renewal-hooks"})

def _parse(raw: str) -> tuple[dict, dict, dict]:
    top, params, mapping = {}, {}, {}
    current = top
    section = "top"
    seen_sections = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[renewalparams]":
            if section != "top" or "params" in seen_sections:
                raise PolicyError("renewal-duplicate-section")
            seen_sections.add("params")
            section, current = "params", params
            continue
        if line == "[[webroot_map]]":
            if section != "params" or "map" in seen_sections:
                raise PolicyError("renewal-invalid-section")
            seen_sections.add("map")
            section, current = "map", mapping
            continue
        if line == "[acme_renewal_info]":
            # Certbot 5.x persists optional ACME Renewal Information metadata.
            if section not in ("params", "map") or "ari" in seen_sections:
                raise PolicyError("renewal-invalid-section")
            seen_sections.add("ari")
            section, current = "ari", {}
            continue
        if line.startswith("[") or "=" not in line:
            raise PolicyError("renewal-unknown-section")
        k, v = [part.strip() for part in line.split("=", 1)]
        if not re.fullmatch(r"[a-z][a-z0-9_]*", k) and section != "map":
            raise PolicyError("renewal-invalid-option-name")
        if not k or k in current or len(k) > 255 or len(v) > 4096:
            raise PolicyError("renewal-invalid-entry")
        if section == "ari":
            if k not in ("ari_retry_after", "ari_cert_id", "ari_explanation_url"):
                raise PolicyError("renewal-unknown-ari")
            # ARI metadata is not used to authorize actions.
        elif section == "top":
            if k not in _SAFE_TOP:
                raise PolicyError("renewal-unknown-top-option")
        elif section == "params":
            if k not in _SAFE_RENEWAL:
                raise PolicyError("renewal-unknown-parameter")
        elif section == "map":
            if not re.fullmatch(r"[a-z0-9.*-]+(?:\.[a-z0-9-]+)+", k):
                raise PolicyError("renewal-invalid-webroot-domain")
        current[k] = v
    if section == "top" or not params:
        raise PolicyError("renewal-params-missing")
    return top, params, mapping

def validate_renewal(state: Path, policy: Authorization, *, required: bool) -> str | None:
    config = state / "certbot" / "config"
    for name in _UNSAFE_CONFIG_ITEMS:
        if (config / name).exists() or (config / name).is_symlink():
            raise PolicyError("certbot-global-config-or-hooks-forbidden")
    renewal = config / "renewal"
    config_file = renewal / (policy.certificate_id + ".conf")
    if not config_file.exists() and not config_file.is_symlink():
        if required:
            raise PolicyError("renewal-config-missing")
        return None
    if config_file.is_symlink():
        raise PolicyError("renewal-symlink")
    names = sorted(p.name for p in renewal.iterdir())
    if names != [config_file.name]:
        raise PolicyError("unapproved-renewal-lineage")
    raw = protected_file_read(state, Path("certbot/config/renewal") / config_file.name, 65536)
    top, params, mapping = _parse(raw.decode("utf-8"))
    def exact(k: str, v: str) -> None:
        if top.get(k) != v:
            raise PolicyError("renewal-lineage-path-mismatch")
    path = config / "live" / policy.certificate_id
    exact("archive_dir", str(config / "archive" / policy.certificate_id))
    for filename in ("cert.pem", "privkey.pem", "chain.pem", "fullchain.pem"):
        exact(filename.split(".")[0], str(path / filename))
    if params.get("server") != policy.acme_directory or not re.fullmatch(r"[a-zA-Z0-9_-]{5,256}", params.get("account", "")):
        raise PolicyError("renewal-account-or-server-mismatch")
    if params.get("installer", "None") not in ("None", "none", ""):
        raise PolicyError("renewal-installer-forbidden")
    # Only known, bounded Certbot key preferences and challenges may be
    # restored. Keep this list narrow until genuine pinned-version fixtures
    # demonstrate additional compatible fields.
    if params.get("key_type", "ecdsa") not in ("rsa", "ecdsa"):
        raise PolicyError("renewal-unsupported-key-type")
    if "reuse_key" in params and params["reuse_key"] not in ("True", "False"):
        raise PolicyError("renewal-invalid-reuse-key")
    if "rsa_key_size" in params:
        n = params["rsa_key_size"]
        if not n.isdecimal() or not 2048 <= int(n) <= 8192:
            raise PolicyError("renewal-invalid-rsa-size")
    if "elliptic_curve" in params and params["elliptic_curve"] not in ("secp256r1", "secp384r1", "secp521r1"):
        raise PolicyError("renewal-invalid-curve")
    if "pref_challs" in params:
        names = [p.strip() for p in params["pref_challs"].split(",") if p.strip()]
        if not names or any(name != policy.challenge for name in names):
            raise PolicyError("renewal-challenge-policy-mismatch")
    if policy.challenge == "http-01":
        if params.get("authenticator") != "webroot" or "dns_cloudflare_credentials" in params:
            raise PolicyError("renewal-authenticator-mismatch")
        root = str(state / "challenges" / policy.certificate_id)
        if any(val != root for val in mapping.values()) or any(name not in policy.hostnames for name in mapping):
            raise PolicyError("renewal-webroot-map-mismatch")
        if "webroot_path" in params:
            roots = [x.strip() for x in params["webroot_path"].split(",") if x.strip()]
            if not roots or any(x != root for x in roots):
                raise PolicyError("renewal-webroot-path-mismatch")
        if not mapping and "webroot_path" not in params:
            raise PolicyError("renewal-webroot-missing")
        if mapping and "webroot_path" not in params and set(mapping) != set(policy.hostnames):
            raise PolicyError("renewal-incomplete-webroot-map")
    else:
        if params.get("authenticator") != "dns-cloudflare" or mapping or "webroot_path" in params:
            raise PolicyError("renewal-authenticator-mismatch")
        if params.get("dns_cloudflare_credentials") != str(state / "dns" / "cloudflare.ini"):
            raise PolicyError("renewal-credential-path-mismatch")

    return params["account"]
