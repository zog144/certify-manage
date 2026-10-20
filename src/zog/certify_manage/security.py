"""Reject weak ownership, symlinks and ambient executable lookup."""
import os
import hashlib
import re
from pathlib import Path
import stat

from .model import PolicyError

def _components(path: Path):
    absolute = path.absolute()
    if not absolute.is_absolute() or ".." in absolute.parts:
        raise PolicyError("invalid-path")
    current = Path("/")
    for piece in absolute.parts[1:]:
        current /= piece
        yield current

def protected_directory(path: Path, *, owner: int, mode_private: bool = True) -> None:
    for item in _components(path):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise PolicyError("unsafe-directory")
        if info.st_uid not in (0, owner) or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & 0o1000 and stat.S_ISDIR(info.st_mode))):
            raise PolicyError("unsafe-directory-owner")
    last = path.lstat()
    if last.st_uid != owner or (mode_private and (last.st_mode & 0o077)):
        raise PolicyError("state-permissions")

def trusted_policy(path: Path) -> bytes:
    if not path.is_absolute():
        raise PolicyError("policy-path-not-absolute")
    parent = path.parent
    for item in _components(parent):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PolicyError("unsafe-policy-parent")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
            raise PolicyError("unsafe-policy-file")
        return os.read(fd, 65537)
    finally:
        os.close(fd)

def secret_file(path: Path, *, owner: int) -> None:
    protected_directory(path.parent, owner=owner)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077 or info.st_nlink != 1:
            raise PolicyError("unsafe-secret-file")
    finally:
        os.close(fd)

def protected_file_read(state: Path, relative: Path, max_bytes: int, *, private: bool = False) -> bytes:
    """Read a private file through anchored NOFOLLOW directory descriptors."""
    if relative.is_absolute() or not relative.parts or any(
        bit in ("", ".", "..") for bit in relative.parts
    ):
        raise PolicyError("invalid-private-path")
    owner = os.geteuid()
    protected_directory(state, owner=owner)
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for segment in relative.parts[:-1]:
            child = os.open(segment, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            info = os.fstat(child)
            if info.st_uid != owner or info.st_mode & 0o022:
                os.close(child)
                raise PolicyError("unsafe-private-parent")
            os.close(fd)
            fd = child
        leaf = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or
                (info.st_mode & (0o077 if private else 0o022)) or info.st_nlink != 1 or info.st_size > max_bytes):
                raise PolicyError("unsafe-private-file")
            raw = os.read(leaf, max_bytes + 1)
            if len(raw) > max_bytes:
                raise PolicyError("private-file-too-large")
            return raw
        finally:
            os.close(leaf)
    finally:
        os.close(fd)

def cloudflare_credential_snapshot(state: Path) -> str:
    """Hash the exact approved issuer-owned token file, never disclose its bytes.

    Root-control authorizes zone/credential revision before provisioning;
    the issuer can independently enforce only the local file's restricted
    syntax, immutable file identity and stability during a Certbot attempt.
    """
    path = state / "dns" / "cloudflare.ini"
    secret_file(path, owner=os.geteuid())
    info = path.lstat()
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise PolicyError("unsafe-cloudflare-mode")
    raw = protected_file_read(state, Path("dns/cloudflare.ini"), 8192, private=True)
    if not re.fullmatch(rb"dns_cloudflare_api_token = [A-Za-z0-9_-]{20,4096}\n", raw):
        raise PolicyError("unsupported-cloudflare-credential-format")
    return hashlib.sha256(raw).hexdigest()
