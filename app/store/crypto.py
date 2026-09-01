"""Credential secrets at rest.

A credential is a *mapping* of secrets, not a single value: SNMPv3 carries an
authentication passphrase and a privacy passphrase alongside the community
string, so one column per secret would not have survived first contact.

    storage="inline"    secret_encrypted = Fernet(json({"community": "...", …}))
    storage="env_ref"   secret_refs      = {"community": "SNMP_COMMUNITY", …}

`env_ref` keeps values in the environment and never writes them to the database,
which is what anyone injecting secrets from Kubernetes Secrets or Vault wants.
Such a deployment needs no encryption key at all.

The key comes from `SCANSPOT_SECRET_KEY` (a urlsafe base64 Fernet key), and is
required only when an inline profile is actually read or written.

    docker compose exec scanner python -m app.store.crypto --generate
"""

from __future__ import annotations

import json
import os

from cryptography.fernet import Fernet, InvalidToken

ENV_KEY = "SCANSPOT_SECRET_KEY"


class SecretError(RuntimeError):
    pass


def generate_key() -> str:
    return Fernet.generate_key().decode("ascii")


def _fernet() -> Fernet:
    raw = (os.environ.get(ENV_KEY) or "").strip()
    if not raw:
        raise SecretError(
            f"{ENV_KEY} is not set. It is required to store or read a credential "
            "inline; profiles that reference environment variables "
            "(storage='env_ref') do not need it. Generate a key with: "
            "python -m app.store.crypto --generate"
        )
    try:
        return Fernet(raw.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise SecretError(
            f"{ENV_KEY} is not a valid Fernet key (expected 32 url-safe "
            "base64-encoded bytes)"
        ) from exc


# ── primitives ──────────────────────────────────────────────────────────────
def encrypt(secret: str) -> bytes:
    if secret is None:
        raise SecretError("refusing to encrypt a null secret")
    return _fernet().encrypt(secret.encode("utf-8"))


def decrypt(token: bytes) -> str:
    try:
        return _fernet().decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        # Almost always a rotated or mismatched key rather than corruption.
        raise SecretError(
            f"could not decrypt a stored credential: the value of {ENV_KEY} does "
            "not match the key it was encrypted with"
        ) from exc


# ── credential mappings ─────────────────────────────────────────────────────
def encrypt_secrets(secrets: dict[str, str]) -> bytes:
    """Encrypt the whole mapping as one document."""
    clean = {k: str(v) for k, v in (secrets or {}).items() if v not in (None, "")}
    return encrypt(json.dumps(clean, sort_keys=True))


def decrypt_secrets(token: bytes) -> dict[str, str]:
    if not token:
        return {}
    payload = decrypt(token)
    try:
        loaded = json.loads(payload)
    except ValueError as exc:
        raise SecretError("stored credential is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise SecretError("stored credential is not a mapping")
    return {str(k): str(v) for k, v in loaded.items()}


def resolve_secrets(
    storage: str,
    secret_encrypted: bytes | None = None,
    secret_refs: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return the plaintext secrets for a credential profile.

    An environment variable that is unset yields an absent key rather than an
    exception: a profile pointing at a variable nobody defined is a
    configuration mistake that should surface as an authentication failure
    against the device — with the device name in the log — not as a crash that
    takes the whole cycle down.
    """
    if storage == "inline":
        return decrypt_secrets(secret_encrypted) if secret_encrypted else {}
    if storage == "env_ref":
        resolved: dict[str, str] = {}
        for field, variable in (secret_refs or {}).items():
            value = (os.environ.get(str(variable)) or "").strip()
            if value:
                resolved[str(field)] = value
        return resolved
    raise SecretError(f"unknown credential storage mode '{storage}'")


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="app.store.crypto")
    parser.add_argument(
        "--generate",
        action="store_true",
        help="print a new Fernet key for SCANSPOT_SECRET_KEY",
    )
    args = parser.parse_args(argv)
    if args.generate:
        print(generate_key())
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
