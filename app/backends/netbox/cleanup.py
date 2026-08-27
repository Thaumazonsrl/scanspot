"""Lifecycle management — graceful degradation of stale records.

Two thresholds, both from .env:

  OFFLINE_AFTER_HOURS (default 48)
      IPAddress -> status "Deprecated", Device -> status "Offline".
      Nothing is removed; the record stays visible with its history.

  DELETE_AFTER_DAYS (default 7)
      The record is removed and the address is freed.

Hard guarantees, in order of precedence:

  1. Only objects tagged `auto-discovered` are ever considered. Anything a
     human created in the NetBox UI is invisible to this module.
  2. FortiGate static DHCP reservations are NEVER deleted — not after 7 days,
     not after a year. They are recognised by the `static-dhcp-reservation`
     tag, by the `scanner_static_reservation` custom field, or by an IP status
     of "Reserved". They may still be flipped to Deprecated so an operator can
     see the host is gone, but the record survives until the reservation is
     removed from the firewall.
  3. Objects carrying PROTECTED_TAG are exempt from deletion too.
  4. Infrastructure (firewalls, switches) is exempt: only devices with the
     "Discovered Endpoint" role are candidates.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import pynetbox

from ...config import LifecycleSettings
from ...utils import from_iso, slugify, to_iso
from .client import (
    CF_LAST_SEEN,
    CF_STATIC,
    ROLE_ENDPOINT,
    TAG_DISCOVERED,
    TAG_INFRASTRUCTURE,
    TAG_RESERVATION,
    NetBoxClient,
)
from .sync import apply_changes

log = logging.getLogger("cleanup")


@dataclass
class CleanupStats:
    ips_deprecated: int = 0
    ips_deleted: int = 0
    devices_offline: int = 0
    devices_deleted: int = 0
    exempt_reservations: int = 0
    stamped: int = 0
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.ips_deprecated} IP(s) deprecated, {self.ips_deleted} deleted; "
            f"{self.devices_offline} device(s) offline, {self.devices_deleted} deleted; "
            f"{self.exempt_reservations} static reservation(s) kept"
        )


def _is_reservation(client: NetBoxClient, record) -> bool:
    if client.has_tag(record, TAG_RESERVATION):
        return True
    if (getattr(record, "custom_fields", None) or {}).get(CF_STATIC):
        return True
    status = getattr(record, "status", None)
    return str(getattr(status, "value", status) or "").lower() == "reserved"


def _is_protected(client: NetBoxClient, record, protected_tag: str) -> bool:
    return bool(protected_tag) and client.has_tag(record, protected_tag)


def _last_seen(record) -> datetime | None:
    return from_iso((getattr(record, "custom_fields", None) or {}).get(CF_LAST_SEEN))


def run_cleanup(
    client: NetBoxClient, settings: LifecycleSettings, now: datetime
) -> CleanupStats:
    stats = CleanupStats()
    offline_cutoff = now - timedelta(hours=settings.offline_after_hours)
    delete_cutoff = now - timedelta(days=settings.delete_after_days)

    log.info(
        "cleanup: offline before %s, delete before %s (auto-delete %s)",
        to_iso(offline_cutoff),
        to_iso(delete_cutoff),
        "enabled" if settings.enable_auto_delete else "DISABLED",
    )

    _cleanup_addresses(client, settings, stats, offline_cutoff, delete_cutoff, now)
    _cleanup_devices(client, settings, stats, offline_cutoff, delete_cutoff, now)

    log.info("cleanup: %s", stats.summary())
    return stats


# ─────────────────────────────────────────────────────────────── addresses ──
def _cleanup_addresses(
    client: NetBoxClient,
    settings: LifecycleSettings,
    stats: CleanupStats,
    offline_cutoff: datetime,
    delete_cutoff: datetime,
    now: datetime,
) -> None:
    try:
        records = list(
            client.api.ipam.ip_addresses.filter(tag=slugify(TAG_DISCOVERED))
        )
    except pynetbox.RequestError as exc:
        log.error("could not list discovered addresses: %s", exc)
        return

    for record in records:
        last_seen = _last_seen(record)
        if last_seen is None:
            # A discovered record with no timestamp (e.g. created by an older
            # version). Stamp it now so the clock starts from a known point
            # instead of deleting it on the spot.
            apply_changes(
                client,
                record,
                {"custom_fields": {CF_LAST_SEEN: to_iso(now)}},
                f"IP {record.address} (initial timestamp)",
            )
            stats.stamped += 1
            continue

        if last_seen >= offline_cutoff:
            continue

        reservation = _is_reservation(client, record)
        protected = _is_protected(client, record, settings.protected_tag)

        if last_seen < delete_cutoff and settings.enable_auto_delete:
            if reservation:
                # The reservation still exists on the firewall: keep the
                # record forever, only flag it as currently unreachable.
                stats.exempt_reservations += 1
                if _deprecate(client, record, f"IP {record.address}", last_seen):
                    stats.ips_deprecated += 1
                continue
            if protected:
                if _deprecate(client, record, f"IP {record.address}", last_seen):
                    stats.ips_deprecated += 1
                continue

            deleted = client.write(f"delete stale IP {record.address}", record.delete)
            if deleted or client.dry_run:
                if not client.dry_run:
                    log.info(
                        "deleted %s — not seen since %s",
                        record.address,
                        to_iso(last_seen),
                    )
                stats.ips_deleted += 1
            continue

        if _deprecate(client, record, f"IP {record.address}", last_seen):
            stats.ips_deprecated += 1
            if reservation:
                stats.exempt_reservations += 1


def _deprecate(client: NetBoxClient, record, label: str, last_seen: datetime) -> bool:
    status = str(getattr(getattr(record, "status", None), "value", "") or "")
    if status == "deprecated":
        return False
    description = str(getattr(record, "description", "") or "")
    marker = f"[offline since {to_iso(last_seen)}]"
    if marker not in description:
        description = f"{marker} {description}".strip()[:200]
    return apply_changes(
        client, record, {"status": "deprecated", "description": description}, label
    )


# ───────────────────────────────────────────────────────────────── devices ──
def _cleanup_devices(
    client: NetBoxClient,
    settings: LifecycleSettings,
    stats: CleanupStats,
    offline_cutoff: datetime,
    delete_cutoff: datetime,
    now: datetime,
) -> None:
    try:
        records = list(
            client.api.dcim.devices.filter(
                tag=slugify(TAG_DISCOVERED), role=slugify(ROLE_ENDPOINT)
            )
        )
    except pynetbox.RequestError as exc:
        log.error("could not list discovered devices: %s", exc)
        return

    for device in records:
        # Infrastructure never expires, whatever its tags say.
        if client.has_tag(device, TAG_INFRASTRUCTURE):
            continue

        last_seen = _last_seen(device)
        if last_seen is None:
            apply_changes(
                client,
                device,
                {"custom_fields": {CF_LAST_SEEN: to_iso(now)}},
                f"device '{device.name}' (initial timestamp)",
            )
            stats.stamped += 1
            continue

        if last_seen >= offline_cutoff:
            continue

        reservation = _is_reservation(client, device)
        protected = _is_protected(client, device, settings.protected_tag)

        if last_seen < delete_cutoff and settings.enable_auto_delete:
            if reservation or protected:
                stats.exempt_reservations += 1 if reservation else 0
                if _mark_offline(client, device):
                    stats.devices_offline += 1
                continue
            if _delete_device(client, device, last_seen):
                stats.devices_deleted += 1
            continue

        if _mark_offline(client, device):
            stats.devices_offline += 1


def _mark_offline(client: NetBoxClient, device) -> bool:
    status = str(getattr(getattr(device, "status", None), "value", "") or "")
    if status == "offline":
        return False
    return apply_changes(client, device, {"status": "offline"}, f"device '{device.name}'")


def _delete_device(client: NetBoxClient, device, last_seen: datetime) -> bool:
    """Remove a device and free the addresses it still holds.

    Addresses are deleted first so nothing is left dangling if the device
    delete is rejected, and so a reservation that has since been added on the
    firewall is preserved rather than dragged down with the device.
    """
    try:
        addresses = list(client.api.ipam.ip_addresses.filter(device_id=device.id))
    except pynetbox.RequestError as exc:
        log.error("could not list addresses of '%s': %s", device.name, exc)
        return False

    for record in addresses:
        if _is_reservation(client, record) or not client.has_tag(record, TAG_DISCOVERED):
            # Detach instead of delete: the record must outlive the device.
            apply_changes(
                client,
                record,
                {"assigned_object_type": None, "assigned_object_id": None},
                f"IP {record.address} (detached from expiring device)",
            )
            continue
        client.write(f"delete IP {record.address}", record.delete)

    deleted = client.write(f"delete stale device '{device.name}'", device.delete)
    if not (deleted or client.dry_run):
        return False
    if not client.dry_run:
        log.info("deleted device '%s' — not seen since %s", device.name, to_iso(last_seen))
    return True
