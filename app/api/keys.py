"""API key generation and verification.

Keys are hashed with SHA-256 rather than bcrypt/argon2, and that is deliberate:
a password needs a slow hash because it is low-entropy and human-chosen, while
these keys are 256 bits from `secrets.token_urlsafe`. There is nothing to brute
force, and a slow hash on every request would only cost latency.

The plaintext key exists exactly once, at creation. Only the hash is stored.
"""

from __future__ import annotations

import hashlib
import secrets

PREFIX = "scanspot_"


def generate_key() -> str:
    """A new key. Shown once and never recoverable afterwards."""
    return f"{PREFIX}{secrets.token_urlsafe(32)}"


def hash_key(key: str) -> str:
    return hashlib.sha256((key or "").encode("utf-8")).hexdigest()


def verify(key: str, expected_hash: str) -> bool:
    # Constant time, so a wrong key cannot be narrowed down by timing.
    return secrets.compare_digest(hash_key(key), expected_hash or "")


def redact(key: str) -> str:
    """A recognisable fragment for logs — never enough to use."""
    return f"{PREFIX}…{key[-4:]}" if key and len(key) > 4 else "…"
