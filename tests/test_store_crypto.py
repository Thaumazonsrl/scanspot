"""Tests for credential secrets at rest.

Two rules these defend: a deployment using only `env_ref` profiles must work
with no encryption key configured at all, and a wrong key must produce a
readable error rather than silent corruption.
"""

import pytest

from app.store.crypto import (
    ENV_KEY,
    SecretError,
    decrypt,
    decrypt_secrets,
    encrypt,
    encrypt_secrets,
    generate_key,
    resolve_secrets,
)


@pytest.fixture
def key(monkeypatch):
    value = generate_key()
    monkeypatch.setenv(ENV_KEY, value)
    return value


# ── primitives ──────────────────────────────────────────────────────────────


def test_round_trip(key):
    assert decrypt(encrypt("public-ro-community")) == "public-ro-community"


def test_ciphertext_does_not_contain_the_plaintext(key):
    assert b"s3cr3t" not in encrypt("s3cr3t-community")


def test_encryption_is_not_deterministic(key):
    """Fernet includes a random IV, so two encryptions of the same community
    string must not be comparable by anyone reading the database."""
    assert encrypt("same") != encrypt("same")


def test_a_missing_key_is_a_readable_error(monkeypatch):
    monkeypatch.delenv(ENV_KEY, raising=False)
    with pytest.raises(SecretError, match=ENV_KEY):
        encrypt("anything")


def test_a_malformed_key_is_a_readable_error(monkeypatch):
    monkeypatch.setenv(ENV_KEY, "not-a-fernet-key")
    with pytest.raises(SecretError, match="valid Fernet key"):
        encrypt("anything")


def test_a_rotated_key_is_reported_as_a_key_mismatch(monkeypatch):
    monkeypatch.setenv(ENV_KEY, generate_key())
    token = encrypt("community")
    monkeypatch.setenv(ENV_KEY, generate_key())
    with pytest.raises(SecretError, match="does not match"):
        decrypt(token)


# ── mappings ────────────────────────────────────────────────────────────────


def test_secrets_round_trip_as_a_mapping(key):
    """SNMPv3 carries two passphrases; one secret per profile was never enough."""
    secrets = {
        "community": "public-ro",
        "v3_auth_password": "auth-pass",
        "v3_priv_password": "priv-pass",
    }
    assert decrypt_secrets(encrypt_secrets(secrets)) == secrets


def test_empty_values_are_not_stored(key):
    token = encrypt_secrets({"community": "x", "v3_auth_password": "", "other": None})
    assert decrypt_secrets(token) == {"community": "x"}


def test_decrypting_nothing_yields_nothing(key):
    assert decrypt_secrets(b"") == {}
    assert decrypt_secrets(None) == {}


# ── resolve_secrets ─────────────────────────────────────────────────────────


def test_resolve_inline(key):
    token = encrypt_secrets({"community": "from-the-database"})
    assert resolve_secrets("inline", token, None) == {"community": "from-the-database"}


def test_resolve_env_ref_needs_no_encryption_key(monkeypatch):
    """The whole point of env_ref: Kubernetes Secrets and Vault users never set
    SCANSPOT_SECRET_KEY at all."""
    monkeypatch.delenv(ENV_KEY, raising=False)
    monkeypatch.setenv("SNMP_COMMUNITY", "from-the-environment")
    resolved = resolve_secrets("env_ref", None, {"community": "SNMP_COMMUNITY"})
    assert resolved == {"community": "from-the-environment"}


def test_resolve_env_ref_handles_several_variables(monkeypatch):
    monkeypatch.setenv("A_PASS", "auth")
    monkeypatch.setenv("P_PASS", "priv")
    resolved = resolve_secrets(
        "env_ref", None, {"v3_auth_password": "A_PASS", "v3_priv_password": "P_PASS"}
    )
    assert resolved == {"v3_auth_password": "auth", "v3_priv_password": "priv"}


def test_resolve_env_ref_strips_whitespace(monkeypatch):
    monkeypatch.setenv("SNMP_COMMUNITY", "  padded  ")
    assert resolve_secrets("env_ref", None, {"community": "SNMP_COMMUNITY"}) == {
        "community": "padded"
    }


def test_an_unset_variable_is_absent_rather_than_fatal(monkeypatch):
    """A profile pointing at a variable nobody defined should surface as an
    authentication failure naming the device, not a crash that takes the whole
    cycle down."""
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    monkeypatch.setenv("SNMP_COMMUNITY", "present")
    resolved = resolve_secrets(
        "env_ref",
        None,
        {"community": "SNMP_COMMUNITY", "v3_auth_password": "NOT_SET_ANYWHERE"},
    )
    assert resolved == {"community": "present"}


def test_resolve_inline_without_a_stored_secret_is_empty(key):
    assert resolve_secrets("inline", None, None) == {}


def test_resolve_rejects_an_unknown_storage_mode():
    with pytest.raises(SecretError, match="unknown credential storage"):
        resolve_secrets("carrier-pigeon", None, None)
