"""Tests for keeping the store bounded.

Two mechanisms, both of which must forget the right things and remember the
irreplaceable ones: the event log is pruned, and raw captures exist only when
explicitly asked for.
"""

from datetime import timedelta

import pytest

from app.models import CollectionResult, SwitchPortLocation
from app.store.bootstrap import ensure_site, run_migrations
from app.store.db import Database
from app.store.models import Endpoint, Event, RawObservation
from app.store.persist import (
    begin_run,
    persist_raw,
    persist_result,
    prune_events,
)
from app.utils import utcnow


@pytest.fixture
def db(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'r.db'}")
    run_migrations(database)
    yield database
    database.dispose()


@pytest.fixture
def now():
    return utcnow()


def cycle(db, result, when):
    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        run = begin_run(session, site, result, when)
        persist_result(session, site, run, result, when)
        return run.id


def lease(mac, ip, switch=None, port=None):
    result = CollectionResult()
    obs = result.observation(mac)
    obs.ips.add(ip)
    obs.dynamic_ips.add(ip)
    if switch:
        obs.location = SwitchPortLocation(switch=switch, port=port, vlan=None)
    return result


# ── event pruning ───────────────────────────────────────────────────────────


def test_only_the_latest_of_each_type_survives(db, now):
    """A laptop on DHCP would otherwise write an ip_added row every day for
    years."""
    for day, ip in enumerate(["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]):
        cycle(db, lease("AA:BB:CC:DD:EE:01", ip), now + timedelta(days=day))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        assert session.query(Event).filter_by(type="ip_added").count() == 4
        prune_events(session, site, now, retention_days=365, keep_per_type=1)

    with db.session_scope() as session:
        added = session.query(Event).filter_by(type="ip_added").all()
        assert len(added) == 1
        assert added[0].payload["ip"] == "10.0.0.8", "the surviving row is the newest"


def test_keeping_more_than_one_is_a_setting_not_a_rewrite(db, now):
    for day, ip in enumerate(["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]):
        cycle(db, lease("AA:BB:CC:DD:EE:01", ip), now + timedelta(days=day))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        prune_events(session, site, now, retention_days=365, keep_per_type=3)

    with db.session_scope() as session:
        assert session.query(Event).filter_by(type="ip_added").count() == 3


def test_different_types_are_counted_separately(db, now):
    """Keeping one ip_added must not cost you the discovered row."""
    cycle(db, lease("AA:BB:CC:DD:EE:01", "10.0.0.5", "sw-01", "Gi1/0/1"), now)
    cycle(db, lease("AA:BB:CC:DD:EE:01", "10.0.0.6", "sw-02", "Gi1/0/9"), now + timedelta(days=1))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        prune_events(session, site, now, retention_days=365, keep_per_type=1)

    with db.session_scope() as session:
        kinds = {e.type for e in session.query(Event).all()}
        assert {"discovered", "ip_added", "moved"} <= kinds


def test_old_events_are_dropped_by_date(db, now):
    cycle(db, lease("AA:BB:CC:DD:EE:01", "10.0.0.5"), now - timedelta(days=400))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        assert session.query(Event).count() > 0
        prune_events(session, site, now, retention_days=365, keep_per_type=0)

    with db.session_scope() as session:
        assert session.query(Event).count() == 0


def test_pruning_never_touches_the_endpoint_itself(db, now):
    """first_seen_at is the irreplaceable value, and it does not live in the
    event log — which is what makes pruning safe."""
    cycle(db, lease("AA:BB:CC:DD:EE:01", "10.0.0.5"), now - timedelta(days=400))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        prune_events(session, site, now, retention_days=1, keep_per_type=1)

    with db.session_scope() as session:
        endpoint = session.query(Endpoint).one()
        assert endpoint.mac == "AA:BB:CC:DD:EE:01"
        assert endpoint.first_seen_at is not None


def test_both_limits_can_be_disabled(db, now):
    for day, ip in enumerate(["10.0.0.5", "10.0.0.6"]):
        cycle(db, lease("AA:BB:CC:DD:EE:01", ip), now + timedelta(days=day))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        before = session.query(Event).count()
        assert prune_events(session, site, now, retention_days=0, keep_per_type=0) == 0
        assert session.query(Event).count() == before


# ── raw capture ─────────────────────────────────────────────────────────────


def test_nothing_is_captured_when_the_switch_is_off():
    """Zero cost when off, not merely small: nothing is even collected."""
    result = CollectionResult()          # capture_raw defaults to False
    result.capture("sw-01", "snmp", "fdb", {"a": 1})
    assert result.raw == []


def test_captures_are_collected_when_on():
    result = CollectionResult(capture_raw=True)
    result.capture("sw-01", "snmp", "fdb", {"a": 1})
    result.capture("sw-01", "snmp", "sysDescr", {"value": "Cisco IOS"})
    assert [c.kind for c in result.raw] == ["fdb", "sysDescr"]


def test_a_list_payload_is_wrapped_so_the_column_stays_an_object():
    result = CollectionResult(capture_raw=True)
    result.capture("fw-01", "fortios", "arp", [{"ip": "10.0.0.1"}])
    assert result.raw[0].payload == {"items": [{"ip": "10.0.0.1"}]}


def test_raw_is_stored_and_readable(db, now):
    result = CollectionResult(capture_raw=True)
    result.capture("sw-01", "snmp", "sysDescr", {"value": "Cisco IOS 15.2"})

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        run = begin_run(session, site, result, now)
        assert persist_raw(session, site, run, result, keep_runs=3) == 1

    with db.session_scope() as session:
        row = session.query(RawObservation).one()
        assert row.device == "sw-01"
        assert row.payload["value"] == "Cisco IOS 15.2"


def test_only_the_last_runs_of_raw_are_kept(db, now):
    """A full forwarding database per switch per cycle is not something to
    accumulate quietly."""
    for i in range(5):
        result = CollectionResult(capture_raw=True)
        result.capture("sw-01", "snmp", "fdb", {"cycle": i})
        with db.session_scope() as session:
            site = ensure_site(session, "HQ")
            run = begin_run(session, site, result, now + timedelta(hours=i))
            persist_raw(session, site, run, result, keep_runs=2)

    with db.session_scope() as session:
        cycles = sorted(r.payload["cycle"] for r in session.query(RawObservation).all())
        assert cycles == [3, 4], "only the two most recent runs survive"


def test_persisting_nothing_is_not_an_error(db, now):
    result = CollectionResult(capture_raw=True)
    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        run = begin_run(session, site, result, now)
        assert persist_raw(session, site, run, result) == 0
