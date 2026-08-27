"""Tests for the local store.

The properties worth defending here are the ones that would be expensive to
discover in production: site scoping, cascade behaviour on SQLite (which
silently ignores foreign keys unless a pragma is set), and the CHECK
constraints that keep "enum" columns honest.
"""

import pytest
from sqlalchemy.exc import IntegrityError

from app.store.db import Database
from app.store.models import (
    Base,
    CredentialProfile,
    Endpoint,
    EndpointAddress,
    Event,
    Run,
    Site,
    Target,
)


@pytest.fixture
def db(tmp_path):
    """A real file-backed SQLite database.

    Not :memory: — the connect-time pragmas (foreign_keys, WAL) are part of what
    is being tested, and an in-memory database does not exercise them the same
    way.
    """
    database = Database(url=f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(database.engine)
    yield database
    database.dispose()


@pytest.fixture
def site(db):
    with db.session_scope() as s:
        record = Site(slug="hq", name="Head Office")
        s.add(record)
    return record


# ── site scoping ────────────────────────────────────────────────────────────


def test_the_same_mac_may_exist_at_two_sites(db):
    """Different offices reuse hardware and address space. Identity is
    (site, mac) — this is the reason the site column exists."""
    with db.session_scope() as s:
        hq = Site(slug="hq", name="HQ")
        branch = Site(slug="branch", name="Branch")
        s.add_all([hq, branch])
        s.flush()
        s.add_all(
            [
                Endpoint(site_id=hq.id, mac="AA:BB:CC:DD:EE:FF"),
                Endpoint(site_id=branch.id, mac="AA:BB:CC:DD:EE:FF"),
            ]
        )

    with db.session_scope() as s:
        assert s.query(Endpoint).count() == 2


def test_the_same_mac_twice_at_one_site_is_rejected(db, site):
    with db.session_scope() as s:
        s.add(Endpoint(site_id=site.id, mac="AA:BB:CC:DD:EE:FF"))

    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(Endpoint(site_id=site.id, mac="AA:BB:CC:DD:EE:FF"))


def test_the_same_ip_may_exist_at_two_sites(db):
    """192.168.1.10 exists at practically every client. Uniqueness is per
    endpoint, never global."""
    with db.session_scope() as s:
        hq = Site(slug="hq", name="HQ")
        branch = Site(slug="branch", name="Branch")
        s.add_all([hq, branch])
        s.flush()
        a = Endpoint(site_id=hq.id, mac="AA:BB:CC:DD:EE:01")
        b = Endpoint(site_id=branch.id, mac="AA:BB:CC:DD:EE:02")
        s.add_all([a, b])
        s.flush()
        s.add_all(
            [
                EndpointAddress(endpoint_id=a.id, ip="192.168.1.10"),
                EndpointAddress(endpoint_id=b.id, ip="192.168.1.10"),
            ]
        )

    with db.session_scope() as s:
        assert s.query(EndpointAddress).count() == 2


# ── referential integrity ───────────────────────────────────────────────────


def test_sqlite_enforces_foreign_keys(db):
    """SQLite ignores foreign keys unless PRAGMA foreign_keys=ON is issued on
    every connection. If this regresses, every ON DELETE CASCADE in the schema
    becomes a silent no-op."""
    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(Endpoint(site_id=9999, mac="AA:BB:CC:DD:EE:FF"))


def test_deleting_an_endpoint_removes_its_addresses(db, site):
    with db.session_scope() as s:
        endpoint = Endpoint(site_id=site.id, mac="AA:BB:CC:DD:EE:FF")
        s.add(endpoint)
        s.flush()
        s.add(EndpointAddress(endpoint_id=endpoint.id, ip="10.0.0.5"))
        endpoint_id = endpoint.id

    with db.session_scope() as s:
        s.delete(s.get(Endpoint, endpoint_id))

    with db.session_scope() as s:
        assert s.query(EndpointAddress).count() == 0


def test_deleting_a_site_removes_its_discoveries(db, site):
    with db.session_scope() as s:
        s.add(Endpoint(site_id=site.id, mac="AA:BB:CC:DD:EE:FF"))
        s.add(Run(site_id=site.id, status="ok"))

    with db.session_scope() as s:
        s.delete(s.get(Site, site.id))

    with db.session_scope() as s:
        assert s.query(Endpoint).count() == 0
        assert s.query(Run).count() == 0


# ── CHECK constraints ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "telnet"),
        ("source", "magic"),
    ],
)
def test_targets_reject_unknown_vocabulary(db, site, field, value):
    payload = {
        "site_id": site.id,
        "name": "sw-01",
        "address": "10.0.0.10",
        "method": "snmp",
        "source": "manual",
        field: value,
    }
    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(Target(**payload))


def test_runs_reject_an_unknown_status(db, site):
    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(Run(site_id=site.id, status="probably-fine"))


def test_endpoints_reject_an_unknown_status(db, site):
    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(Endpoint(site_id=site.id, mac="AA:BB:CC:DD:EE:FF", status="weird"))


# ── targets ─────────────────────────────────────────────────────────────────


def test_a_target_address_is_unique_per_site_and_method(db, site):
    with db.session_scope() as s:
        s.add(Target(site_id=site.id, name="sw-01", address="10.0.0.10", method="snmp"))

    # Same address, different method: allowed — an L3 firewall can legitimately
    # be reachable both ways.
    with db.session_scope() as s:
        s.add(
            Target(site_id=site.id, name="fw-01", address="10.0.0.10", method="fortios")
        )

    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(
                Target(site_id=site.id, name="dup", address="10.0.0.10", method="snmp")
            )


def test_a_target_survives_deletion_of_its_credential_profile(db, site):
    """SET NULL, not CASCADE: losing a credential must not silently delete the
    target and stop it being polled without a trace."""
    with db.session_scope() as s:
        profile = CredentialProfile(name="default", kind="snmp", storage="env_ref")
        s.add(profile)
        s.flush()
        s.add(
            Target(
                site_id=site.id,
                name="sw-01",
                address="10.0.0.10",
                method="snmp",
                credential_profile_id=profile.id,
            )
        )
        profile_id = profile.id

    with db.session_scope() as s:
        s.delete(s.get(CredentialProfile, profile_id))

    with db.session_scope() as s:
        target = s.query(Target).one()
        assert target.credential_profile_id is None


# ── credential profiles ─────────────────────────────────────────────────────


def test_profile_names_are_unique_per_site(db, site):
    with db.session_scope() as s:
        s.add(CredentialProfile(site_id=site.id, name="default", kind="snmp"))

    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(CredentialProfile(site_id=site.id, name="default", kind="snmp"))


def test_has_secret_reports_without_exposing(db):
    """The API surfaces this instead of the secret itself."""
    inline = CredentialProfile(
        name="a", kind="snmp", storage="inline", secret_encrypted=b"x"
    )
    empty_inline = CredentialProfile(name="b", kind="snmp", storage="inline")
    env = CredentialProfile(
        name="c",
        kind="snmp",
        storage="env_ref",
        secret_refs={"community": "SNMP_COMMUNITY"},
    )
    unset_env = CredentialProfile(name="d", kind="snmp", storage="env_ref", secret_refs={})

    assert inline.has_secret is True
    assert empty_inline.has_secret is False
    assert env.has_secret is True
    assert unset_env.has_secret is False


def test_profiles_reject_an_unknown_storage_mode(db):
    with pytest.raises(IntegrityError):
        with db.session_scope() as s:
            s.add(CredentialProfile(name="x", kind="snmp", storage="carrier-pigeon"))


# ── events ──────────────────────────────────────────────────────────────────


def test_events_outlive_the_endpoint_run_that_created_them(db, site):
    """A run is deleted (retention), the event stays: history must not vanish
    because a cycle record was pruned."""
    with db.session_scope() as s:
        run = Run(site_id=site.id, status="ok")
        s.add(run)
        s.flush()
        s.add(
            Event(site_id=site.id, run_id=run.id, type="discovered", payload={"n": 1})
        )
        run_id = run.id

    with db.session_scope() as s:
        s.delete(s.get(Run, run_id))

    with db.session_scope() as s:
        event = s.query(Event).one()
        assert event.run_id is None
        assert event.payload == {"n": 1}


# ── session handling ────────────────────────────────────────────────────────


def test_session_scope_rolls_back_on_failure(db, site):
    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        with db.session_scope() as s:
            s.add(Endpoint(site_id=site.id, mac="AA:BB:CC:DD:EE:FF"))
            raise Boom

    with db.session_scope() as s:
        assert s.query(Endpoint).count() == 0
