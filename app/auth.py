"""Auth: scrypt passwords, token sessions, CSRF. stdlib only."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time

SESSION_TTL = 72 * 3600


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$14$8$1${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt_h, dk_h = stored.split("$")
        dk = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_h),
            n=2 ** int(n), r=int(r), p=int(p), dklen=32,
        )
        return hmac.compare_digest(dk.hex(), dk_h)
    except Exception:
        return False


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def api_token() -> tuple[str, str]:
    """Returns (public_token, sha256_hex) for storage."""
    tok = "dach_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(tok.encode()).hexdigest()
    return tok, digest


def now() -> int:
    return int(time.time())
