"""Writing a collection result into scanspot's own store.

This is what turns the store from a target list into a source of truth. It runs
*before* the backend sync, deliberately: what the network reported is recorded
even when NetBox is unreachable, and the backends become exporters of this data
rather than the place it lives.

Two shapes of data, kept apart on purpose:

  `endpoints` / `endpoint_addresses`   current state, one row per (site, mac)
  `events`                             append-only log of what changed

Storing a snapshot per cycle instead would grow without bound — a few thousand
endpoints polled hourly is millions of rows a month — while answering no
question the pair above cannot.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from ..models import CollectionResult
from ..prefixes import PrefixIndex
from .models import (
    DhcpPool,
    Endpoint,
    EndpointAddress,
    Event,
    Prefix,
    Run,
    Site,
    Vlan,
)

log = logging.getLogger("persist")

# Event vocabulary. Deliberately not a CHECK constraint: this list will grow,
# and a migration per new event type would be friction for no safety.
DISCOVERED = "discovered"
IP_ADDED = "ip_added"
IP_REMOVED = "ip_removed"
MOVED = "moved"
RETURNED = "returned"
WENT_OFFLINE = "went_offline"


def _event(session: Session, site: Site, run: Run | None, endpoint, type_: str, **payload):
    session.add(
        Event(
            site_id=site.id,
            endpoint_id=getattr(endpoint, "id", None),
            run_id=getattr(run, "id", None),
            type=type_,
            payload=payload,
        )
    )


# ── runs ────────────────────────────────────────────────────────────────────
def begin_run(session: Session, site: Site, result: CollectionResult, started: datetime) -> Run:
    """Record the cycle as soon as collection is done, before any sync."""
    run = Run(
        site_id=site.id,
        started_at=started,
        status="idle",
        firewalls_ok=result.firewalls_ok,
        firewalls_failed=result.firewalls_failed,
        switches_ok=result.switches_ok,
        switches_failed=result.switches_failed,
        mac_count=len(result.observations),
    )
    session.add(run)
    session.flush()
    return run


def finish_run(
    session: Session, run_id: int, status: str, finished: datetime, duration: float | None
) -> None:
    run = session.get(Run, run_id)
    if run is None:
        return
    run.status = status
    run.finished_at = finished
    run.duration_seconds = duration


# ── discovery ───────────────────────────────────────────────────────────────
def persist_result(
    session: Session,
    site: Site,
    run: Run,
    result: CollectionResult,
    now: datetime,
    default_prefix_len: int = 24,
) -> dict[str, int]:
    """Merge one collection pass into the store. Returns a small summary."""
    index = PrefixIndex(default_prefix_len)
    for iface in result.l3_interfaces:
        index.add_cidr(iface.cidr)

    stats = {"created": 0, "updated": 0, "moved": 0, "ips_added": 0, "ips_removed": 0}

    existing = {
        endpoint.mac: endpoint
        for endpoint in session.query(Endpoint).filter_by(site_id=site.id).all()
    }

    for mac, obs in sorted(result.observations.items()):
        if not obs.ips and obs.location is None:
            continue

        endpoint = existing.get(mac)
        is_new = endpoint is None
        if is_new:
            endpoint = Endpoint(site_id=site.id, mac=mac, first_seen_at=now)
            session.add(endpoint)
            session.flush()
            existing[mac] = endpoint
            stats["created"] += 1
        else:
            stats["updated"] += 1

        _apply_endpoint(session, site, run, endpoint, obs, now, is_new, stats)
        _apply_addresses(session, site, run, endpoint, obs, index, now, stats)

    _persist_prefixes(session, site, result, now)
    _persist_vlans(session, site, result, now)
    _persist_pools(session, site, result, now)

    log.info(
        "store: %d endpoint(s) created, %d updated, %d moved, %d address(es) added",
        stats["created"],
        stats["updated"],
        stats["moved"],
        stats["ips_added"],
    )
    return stats


def _apply_endpoint(session, site, run, endpoint, obs, now, is_new, stats) -> None:
    if is_new:
        _event(
            session, site, run, endpoint, DISCOVERED,
            mac=obs.mac, sources=obs.source_label,
        )
    elif endpoint.status != "active":
        # Back after having been aged out. Worth a line in the history: it is
        # usually a laptop returning, occasionally a device that was believed
        # decommissioned.
        _event(session, site, run, endpoint, RETURNED, last_seen=str(endpoint.last_seen_at))

    if obs.location is not None:
        moved = (
            endpoint.switch_name != obs.location.switch
            or endpoint.switch_port != obs.location.port
        )
        if moved and not is_new and endpoint.switch_name:
            _event(
                session, site, run, endpoint, MOVED,
                **{
                    "from": f"{endpoint.switch_name}/{endpoint.switch_port}",
                    "to": f"{obs.location.switch}/{obs.location.port}",
                },
            )
            stats["moved"] += 1
        endpoint.switch_name = obs.location.switch
        endpoint.switch_port = obs.location.port
        endpoint.vlan = str(obs.location.vlan) if obs.location.vlan else None

    if obs.hostname:
        endpoint.hostname = obs.hostname
    if obs.firewall:
        endpoint.firewall = obs.firewall
        endpoint.firewall_interface = obs.firewall_interface or None

    endpoint.static_reservation = obs.static_reservation
    endpoint.status = "active"
    endpoint.last_seen_at = now
    endpoint.last_run_id = run.id


def _apply_addresses(session, site, run, endpoint, obs, index, now, stats) -> None:
    current = {row.ip: row for row in endpoint.addresses}

    for ip in sorted(obs.ips):
        row = current.pop(ip, None)
        kind = obs.status_for(ip)
        if row is None:
            session.add(
                EndpointAddress(
                    endpoint_id=endpoint.id,
                    ip=ip,
                    prefix_len=index.prefix_len_for(ip),
                    kind=kind,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            stats["ips_added"] += 1
            _event(session, site, run, endpoint, IP_ADDED, ip=ip, kind=kind)
        else:
            row.kind = kind
            row.last_seen_at = now
            row.prefix_len = index.prefix_len_for(ip)

    # Anything left over is an address this MAC no longer holds — a lease that
    # moved on. Removed rather than kept: the address may already belong to
    # another host, and two endpoints claiming it would be a lie.
    for ip, row in current.items():
        session.delete(row)
        stats["ips_removed"] += 1
        _event(session, site, run, endpoint, IP_REMOVED, ip=ip)


def _persist_prefixes(session, site, result, now) -> None:
    seen: set[str] = set()
    known = {row.cidr: row for row in session.query(Prefix).filter_by(site_id=site.id).all()}

    for iface in result.l3_interfaces:
        import ipaddress

        try:
            network = str(ipaddress.ip_interface(iface.cidr).network)
        except ValueError:
            continue
        if network in seen:
            continue
        seen.add(network)

        row = known.get(network)
        if row is None:
            row = Prefix(site_id=site.id, cidr=network, first_seen_at=now)
            session.add(row)
            known[network] = row
        row.source_device = iface.device
        row.source_interface = iface.name
        row.vlan_id = iface.vlan_id
        row.description = (iface.alias or iface.description or "")[:255] or None
        row.last_seen_at = now


def _persist_vlans(session, site, result, now) -> None:
    known = {row.vid: row for row in session.query(Vlan).filter_by(site_id=site.id).all()}

    for switch in result.switches:
        for raw_vid, name in switch.vlans.items():
            try:
                vid = int(raw_vid)
            except (TypeError, ValueError):
                continue
            if not 1 <= vid <= 4094:
                continue
            row = known.get(vid)
            if row is None:
                row = Vlan(site_id=site.id, vid=vid, first_seen_at=now)
                session.add(row)
                known[vid] = row
            row.name = (name or "")[:64] or None
            row.last_seen_at = now


def _persist_pools(session, site, result, now) -> None:
    known = {
        (row.start_ip, row.end_ip): row
        for row in session.query(DhcpPool).filter_by(site_id=site.id).all()
    }

    for pool in result.pools:
        key = (pool.start_ip, pool.end_ip)
        row = known.get(key)
        if row is None:
            row = DhcpPool(
                site_id=site.id,
                start_ip=pool.start_ip,
                end_ip=pool.end_ip,
                first_seen_at=now,
            )
            session.add(row)
            known[key] = row
        row.firewall = pool.firewall
        row.interface = pool.interface
        row.enabled = pool.enabled
        row.last_seen_at = now


# ── ageing ──────────────────────────────────────────────────────────────────
def mark_stale_offline(
    session: Session, site: Site, now: datetime, offline_after_hours: int
) -> int:
    """Flag endpoints not seen for a while. Nothing is deleted here.

    Deletion in the store is a separate decision from deletion in a backend:
    the history in `events` is the reason the store exists, and throwing it away
    because a laptop was on holiday would defeat the point.
    """
    cutoff = now - timedelta(hours=offline_after_hours)
    stale = (
        session.query(Endpoint)
        .filter(Endpoint.site_id == site.id)
        .filter(Endpoint.status == "active")
        .filter(Endpoint.last_seen_at < cutoff)
        .all()
    )
    for endpoint in stale:
        endpoint.status = "offline"
        _event(
            session, site, None, endpoint, WENT_OFFLINE,
            last_seen=str(endpoint.last_seen_at),
        )
    if stale:
        log.info("store: %d endpoint(s) marked offline", len(stale))
    return len(stale)
