"""Tests for writing a collection result into the store.

What matters here is that current state stays current and history stays
complete: an endpoint that moves port keeps one row and gains an event, and an
address that goes away is released rather than lingering on two hosts.
"""

from datetime import timedelta

import pytest

from app.models import CollectionResult, DhcpPool, L3Interface, SwitchInfo, SwitchPortLocation
from app.store.bootstrap import ensure_site, run_migrations
from app.store.db import Database
from app.store.models import DhcpPool as DhcpPoolRow
from app.store.models import Endpoint, EndpointAddress, Event, Prefix, Run, Vlan
from app.store.persist import (
    DISCOVERED,
    IP_ADDED,
    IP_REMOVED,
    MOVED,
    RETURNED,
    WENT_OFFLINE,
    begin_run,
    finish_run,
    mark_stale_offline,
    persist_result,
)
from app.utils import utcnow


@pytest.fixture
def db(tmp_path):
    database = Database(url=f"sqlite:///{tmp_path / 'p.db'}")
    run_migrations(database)
    yield database
    database.dispose()


@pytest.fixture
def now():
    return utcnow()


def observation(result, mac, ips=(), switch=None, port=None, vlan=None,
                hostname="", reserved=False, dynamic=()):
    obs = result.observation(mac)
    obs.ips.update(ips)
    obs.dynamic_ips.update(dynamic)
    if reserved:
        obs.static_reservation = True
        obs.reserved_ips.update(ips)
    if hostname:
        obs.hostname = hostname
    if switch:
        obs.location = SwitchPortLocation(switch=switch, port=port, vlan=vlan)
    return obs


def run_cycle(db, result, now, prefix_len=24):
    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        run = begin_run(session, site, result, now)
        stats = persist_result(session, site, run, result, now, prefix_len)
        return stats


# ── endpoints ───────────────────────────────────────────────────────────────


def test_a_new_endpoint_is_created_with_a_discovered_event(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"], hostname="laptop")

    stats = run_cycle(db, result, now)
    assert stats["created"] == 1

    with db.session_scope() as session:
        endpoint = session.query(Endpoint).one()
        assert endpoint.mac == "AA:BB:CC:DD:EE:01"
        assert endpoint.hostname == "laptop"
        assert endpoint.status == "active"
        assert [a.ip for a in endpoint.addresses] == ["10.0.0.5"]
        types = {e.type for e in session.query(Event).all()}
        assert DISCOVERED in types and IP_ADDED in types


def test_polling_twice_does_not_duplicate_the_endpoint(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"])

    run_cycle(db, result, now)
    stats = run_cycle(db, result, now + timedelta(minutes=20))

    assert stats["created"] == 0
    assert stats["updated"] == 1
    with db.session_scope() as session:
        assert session.query(Endpoint).count() == 1
        assert session.query(EndpointAddress).count() == 1


def test_the_same_mac_at_two_sites_stays_separate(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["192.168.1.10"])

    with db.session_scope() as session:
        for name in ("HQ", "Branch"):
            site = ensure_site(session, name)
            run = begin_run(session, site, result, now)
            persist_result(session, site, run, result, now)

    with db.session_scope() as session:
        assert session.query(Endpoint).count() == 2


# ── movement ────────────────────────────────────────────────────────────────


def test_moving_port_updates_state_and_records_an_event(db, now):
    first = CollectionResult()
    observation(first, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"], switch="sw-01", port="Gi1/0/1")
    run_cycle(db, first, now)

    second = CollectionResult()
    observation(second, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"], switch="sw-02", port="Gi1/0/9")
    stats = run_cycle(db, second, now + timedelta(hours=1))

    assert stats["moved"] == 1
    with db.session_scope() as session:
        endpoint = session.query(Endpoint).one()
        assert endpoint.switch_name == "sw-02"
        assert endpoint.switch_port == "Gi1/0/9"

        moved = session.query(Event).filter_by(type=MOVED).one()
        assert moved.payload["from"] == "sw-01/Gi1/0/1"
        assert moved.payload["to"] == "sw-02/Gi1/0/9"


def test_staying_on_the_same_port_records_nothing(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"], switch="sw-01", port="Gi1/0/1")

    run_cycle(db, result, now)
    run_cycle(db, result, now + timedelta(hours=1))

    with db.session_scope() as session:
        assert session.query(Event).filter_by(type=MOVED).count() == 0


# ── addresses ───────────────────────────────────────────────────────────────


def test_a_new_lease_releases_the_previous_address(db, now):
    """The old IP may already belong to another host; two endpoints claiming it
    would be a lie."""
    first = CollectionResult()
    observation(first, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"], dynamic=["10.0.0.5"])
    run_cycle(db, first, now)

    second = CollectionResult()
    observation(second, "AA:BB:CC:DD:EE:01", ips=["10.0.0.9"], dynamic=["10.0.0.9"])
    stats = run_cycle(db, second, now + timedelta(hours=1))

    assert stats["ips_removed"] == 1
    with db.session_scope() as session:
        assert [a.ip for a in session.query(EndpointAddress).all()] == ["10.0.0.9"]
        assert session.query(Event).filter_by(type=IP_REMOVED).one().payload["ip"] == "10.0.0.5"


def test_address_kind_follows_the_observation(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"], reserved=True)
    observation(result, "AA:BB:CC:DD:EE:02", ips=["10.0.0.6"], dynamic=["10.0.0.6"])
    observation(result, "AA:BB:CC:DD:EE:03", ips=["10.0.0.7"])
    run_cycle(db, result, now)

    with db.session_scope() as session:
        kinds = {a.ip: a.kind for a in session.query(EndpointAddress).all()}
    assert kinds == {"10.0.0.5": "reserved", "10.0.0.6": "dhcp", "10.0.0.7": "active"}


def test_prefix_length_comes_from_the_routed_interfaces(db, now):
    result = CollectionResult()
    result.l3_interfaces.append(
        L3Interface(device="fw", name="lan", address="10.0.5.1", prefix_len=26)
    )
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.5.9"])
    run_cycle(db, result, now, prefix_len=24)

    with db.session_scope() as session:
        assert session.query(EndpointAddress).one().prefix_len == 26


def test_an_endpoint_with_neither_address_nor_port_is_ignored(db, now):
    result = CollectionResult()
    result.observation("AA:BB:CC:DD:EE:01")  # seen, but nothing known about it
    run_cycle(db, result, now)

    with db.session_scope() as session:
        assert session.query(Endpoint).count() == 0


# ── infrastructure ──────────────────────────────────────────────────────────


def test_prefixes_vlans_and_pools_are_recorded(db, now):
    result = CollectionResult()
    result.l3_interfaces.append(
        L3Interface(device="fw", name="lan", address="10.0.0.1", prefix_len=24, vlan_id=10)
    )
    switch = SwitchInfo(name="sw-01", host="10.0.0.10", vendor="cisco")
    switch.vlans = {"10": "users", "20": "voice"}
    result.switches.append(switch)
    result.pools.append(
        DhcpPool(firewall="fw", server_id="1", interface="lan",
                 start_ip="10.0.0.100", end_ip="10.0.0.200")
    )
    run_cycle(db, result, now)

    with db.session_scope() as session:
        assert session.query(Prefix).one().cidr == "10.0.0.0/24"
        assert {v.vid: v.name for v in session.query(Vlan).all()} == {10: "users", 20: "voice"}
        pool = session.query(DhcpPoolRow).one()
        assert (pool.start_ip, pool.end_ip) == ("10.0.0.100", "10.0.0.200")


def test_reconciling_infrastructure_twice_does_not_duplicate(db, now):
    result = CollectionResult()
    result.l3_interfaces.append(
        L3Interface(device="fw", name="lan", address="10.0.0.1", prefix_len=24)
    )
    switch = SwitchInfo(name="sw-01", host="10.0.0.10", vendor="cisco")
    switch.vlans = {"10": "users"}
    result.switches.append(switch)

    run_cycle(db, result, now)
    run_cycle(db, result, now + timedelta(hours=1))

    with db.session_scope() as session:
        assert session.query(Prefix).count() == 1
        assert session.query(Vlan).count() == 1


# ── ageing ──────────────────────────────────────────────────────────────────


def test_stale_endpoints_go_offline_but_are_not_deleted(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"])
    run_cycle(db, result, now - timedelta(hours=100))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        assert mark_stale_offline(session, site, now, offline_after_hours=48) == 1

    with db.session_scope() as session:
        endpoint = session.query(Endpoint).one()
        assert endpoint.status == "offline"
        assert session.query(Event).filter_by(type=WENT_OFFLINE).count() == 1


def test_a_recently_seen_endpoint_is_left_alone(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"])
    run_cycle(db, result, now - timedelta(hours=1))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        assert mark_stale_offline(session, site, now, offline_after_hours=48) == 0


def test_an_endpoint_that_comes_back_is_recorded_as_returned(db, now):
    result = CollectionResult()
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"])
    run_cycle(db, result, now - timedelta(hours=100))

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        mark_stale_offline(session, site, now, offline_after_hours=48)

    run_cycle(db, result, now)

    with db.session_scope() as session:
        assert session.query(Endpoint).one().status == "active"
        assert session.query(Event).filter_by(type=RETURNED).count() == 1


# ── runs ────────────────────────────────────────────────────────────────────


def test_a_run_records_the_collection_outcome(db, now):
    result = CollectionResult()
    result.firewalls_ok = 1
    result.switches_ok = 2
    result.switches_failed = 1
    observation(result, "AA:BB:CC:DD:EE:01", ips=["10.0.0.5"])

    with db.session_scope() as session:
        site = ensure_site(session, "HQ")
        run = begin_run(session, site, result, now)
        run_id = run.id

    with db.session_scope() as session:
        finish_run(session, run_id, "degraded", now + timedelta(seconds=42), 42.0)

    with db.session_scope() as session:
        run = session.query(Run).one()
        assert run.status == "degraded"
        assert run.duration_seconds == 42.0
        assert (run.firewalls_ok, run.switches_ok, run.switches_failed) == (1, 2, 1)
        assert run.mac_count == 1
