"""Tests for target loading — the store as the source of the device list.

This is the 2.0 behaviour change, so the properties worth pinning are: secrets
are referenced and never copied, several devices can carry genuinely different
credentials, and a broken target is skipped rather than aborting the cycle.
"""

import pytest

from app.config import AppConfig, LifecycleSettings, NetBoxSettings, ScannerSettings, SeedEntry
from app.store.bootstrap import ensure_site
from app.store.db import Database
from app.store.models import Base
from app.store.repository import Repository
from app.targets import apply_seed, load_targets, sync_credentials


@pytest.fixture
def db(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'targets.db'}")
    Base.metadata.create_all(database.engine)
    yield database
    database.dispose()


@pytest.fixture
def config(tmp_path):
    return AppConfig(
        netbox=NetBoxSettings(
            url="http://netbox:8080",
            token="t",
            verify_ssl=False,
            site_name="HQ",
            client_name="Example",
            default_prefix_len=24,
        ),
        lifecycle=LifecycleSettings(48, 7, True, "protected"),
        scanner=ScannerSettings(
            interval_minutes=20,
            run_on_start=True,
            log_level="INFO",
            dry_run=False,
            state_dir=tmp_path,
            snmp_default_version="2c",
            snmp_community="",
            snmp_timeout=5,
            snmp_retries=1,
            snmp_uplink_mac_threshold=12,
            snmp_v3_username="",
            snmp_v3_security_level="authPriv",
            snmp_v3_auth_protocol="SHA",
            snmp_v3_auth_password="",
            snmp_v3_priv_protocol="AES",
            snmp_v3_priv_password="",
        ),
    )


@pytest.fixture
def env(monkeypatch, tmp_path):
    """A deployment configured entirely through the environment."""
    monkeypatch.setenv("INVENTORY_FILE", str(tmp_path / "absent.yml"))
    monkeypatch.setenv("SNMP_COMMUNITY", "public-ro")
    monkeypatch.setenv("FORTIGATE_API_TOKEN", "fgt-token")
    monkeypatch.setenv("SNMP_DEFAULT_VERSION", "2c")


# ── credentials ─────────────────────────────────────────────────────────────


def test_builtin_profiles_reference_the_environment_not_its_values(db, config, env):
    """The secret must never be copied into the database by the import."""
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)

        profile = repo.credential("default", site)
        assert profile.storage == "env_ref"
        assert profile.secret_refs["community"] == "SNMP_COMMUNITY"
        assert profile.secret_encrypted is None
        # The value itself appears nowhere in the stored row.
        assert "public-ro" not in str(profile.secret_refs) + str(profile.params)


def test_credential_settings_resolve_the_secret_at_use_time(db, config, env):
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)

        settings = repo.credential_settings(repo.credential("default", site))
        assert settings["community"] == "public-ro"
        assert settings["snmp_version"] == "2c"


def test_sync_credentials_is_idempotent(db, config, env):
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)
        first = len(repo.session.query(type(repo.credential("default", site))).all())
        sync_credentials(repo, config, site)
        second = len(repo.session.query(type(repo.credential("default", site))).all())
        assert first == second


def test_inventory_profiles_record_the_variable_name(db, config, monkeypatch, tmp_path):
    """A ${VAR} placeholder becomes a reference, so the community string in the
    environment is never duplicated into the store."""
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(
        "credentials:\n"
        "  servers-ro:\n"
        "    type: snmp\n"
        "    snmp_version: 2c\n"
        "    community: ${SNMP_COMMUNITY_SERVERS}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("INVENTORY_FILE", str(inventory))
    monkeypatch.setenv("SNMP_COMMUNITY_SERVERS", "server-secret")

    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)

        profile = repo.credential("servers-ro", site)
        assert profile.secret_refs == {"community": "SNMP_COMMUNITY_SERVERS"}
        assert profile.params["snmp_version"] == "2c"
        assert repo.credential_settings(profile)["community"] == "server-secret"


def test_a_literal_secret_in_the_yaml_is_not_copied_into_the_store(
    db, config, monkeypatch, tmp_path
):
    """Refusing to copy it is deliberate: the operator keeps ownership of where
    the secret lives, and the failure is visible rather than silent duplication."""
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(
        "credentials:\n  legacy:\n    type: snmp\n    community: written-in-plain\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("INVENTORY_FILE", str(inventory))

    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)

        profile = repo.credential("legacy", site)
        assert profile.secret_refs == {}
        assert "written-in-plain" not in str(profile.params)


# ── seeding and loading ─────────────────────────────────────────────────────


def test_seed_creates_targets_and_is_idempotent(db, config, env):
    config.seeds = [
        SeedEntry(name="sw-01", host="10.0.0.10", method="snmp", credential="default"),
        SeedEntry(
            name="fw-01", host="10.0.0.1", method="fortios", credential="fortigate-default"
        ),
    ]
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)

        assert apply_seed(repo, config, site) == 2
        assert apply_seed(repo, config, site) == 0
        assert repo.target_count(site) == 2


def test_load_targets_splits_by_method_and_carries_credentials(db, config, env):
    config.seeds = [
        SeedEntry(name="sw-01", host="10.0.0.10", method="snmp", credential="default"),
        SeedEntry(
            name="fw-01", host="10.0.0.1", method="fortios", credential="fortigate-default"
        ),
    ]
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)
        apply_seed(repo, config, site)

        fortigates, switches = load_targets(repo, config, site)

    assert [f.name for f in fortigates] == ["fw-01"]
    assert [s.name for s in switches] == ["sw-01"]
    assert fortigates[0].api_token == "fgt-token"
    assert switches[0].community == "public-ro"


def test_two_switches_can_use_genuinely_different_communities(
    db, config, monkeypatch, tmp_path
):
    """The reason credential profiles exist at all."""
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(
        "credentials:\n"
        "  servers-ro:\n"
        "    type: snmp\n"
        "    community: ${SNMP_COMMUNITY_SERVERS}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("INVENTORY_FILE", str(inventory))
    monkeypatch.setenv("SNMP_COMMUNITY", "access-community")
    monkeypatch.setenv("SNMP_COMMUNITY_SERVERS", "server-community")

    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)
        repo.upsert_target(
            site,
            name="sw-access",
            address="10.0.0.10",
            method="snmp",
            credential=repo.credential("default", site),
        )
        repo.upsert_target(
            site,
            name="sw-servers",
            address="10.0.0.11",
            method="snmp",
            credential=repo.credential("servers-ro", site),
        )
        _, switches = load_targets(repo, config, site)

    by_name = {s.name: s for s in switches}
    assert by_name["sw-access"].community == "access-community"
    assert by_name["sw-servers"].community == "server-community"


def test_a_disabled_target_is_not_polled(db, config, env):
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)
        target, _ = repo.upsert_target(
            site,
            name="sw-01",
            address="10.0.0.10",
            method="snmp",
            credential=repo.credential("default", site),
        )
        target.enabled = False
        session.flush()

        _, switches = load_targets(repo, config, site)

    assert switches == []


def test_a_fortigate_without_a_token_is_skipped_not_fatal(db, config, monkeypatch, tmp_path):
    """One misconfigured device must not stop the other targets being polled."""
    monkeypatch.setenv("INVENTORY_FILE", str(tmp_path / "absent.yml"))
    monkeypatch.setenv("SNMP_COMMUNITY", "public-ro")
    monkeypatch.delenv("FORTIGATE_API_TOKEN", raising=False)

    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)
        repo.upsert_target(
            site,
            name="fw-01",
            address="10.0.0.1",
            method="fortios",
            credential=repo.credential("fortigate-default", site),
        )
        repo.upsert_target(
            site,
            name="sw-01",
            address="10.0.0.10",
            method="snmp",
            credential=repo.credential("default", site),
        )
        fortigates, switches = load_targets(repo, config, site)

    assert fortigates == []
    assert [s.name for s in switches] == ["sw-01"]


def test_a_vendor_override_reaches_the_poller_config(db, config, env):
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")
        sync_credentials(repo, config, site)
        repo.upsert_target(
            site,
            name="sw-01",
            address="10.0.0.10",
            method="snmp",
            credential=repo.credential("default", site),
            vendor_override="cisco",
        )
        _, switches = load_targets(repo, config, site)

    assert switches[0].vendor == "cisco"


# ── upsert semantics ────────────────────────────────────────────────────────


def test_reimporting_updates_rather_than_duplicates(db, config, env):
    """external_ref is what makes the NetBox import safe to re-run, even after
    the device was renamed and readdressed at the source."""
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")

        _, created = repo.upsert_target(
            site, name="sw-01", address="10.0.0.10", method="snmp",
            source="imported", external_ref="42",
        )
        assert created is True

        target, created_again = repo.upsert_target(
            site, name="sw-01-renamed", address="10.0.0.99", method="snmp",
            source="imported", external_ref="42",
        )
        assert created_again is False
        assert repo.target_count(site) == 1
        assert target.name == "sw-01-renamed"
        assert target.address == "10.0.0.99"


def test_targets_are_scoped_per_site(db, config, env):
    """The same management address exists at every branch office."""
    with db.session_scope() as session:
        repo = Repository(session)
        hq = ensure_site(session, "HQ")
        branch = ensure_site(session, "Branch")

        repo.upsert_target(hq, name="sw-01", address="192.168.1.10", method="snmp")
        repo.upsert_target(branch, name="sw-01", address="192.168.1.10", method="snmp")

        assert repo.target_count(hq) == 1
        assert repo.target_count(branch) == 1


def test_disable_missing_only_touches_imported_targets(db, config, env):
    """A target added by hand must survive an import that no longer lists it."""
    with db.session_scope() as session:
        repo = Repository(session)
        site = ensure_site(session, "HQ")

        manual, _ = repo.upsert_target(
            site, name="manual", address="10.0.0.1", method="snmp", source="manual"
        )
        imported, _ = repo.upsert_target(
            site, name="imported", address="10.0.0.2", method="snmp",
            source="imported", external_ref="7",
        )

        assert repo.disable_missing(site, seen_ids=[]) == 1
        assert manual.enabled is True
        assert imported.enabled is False
