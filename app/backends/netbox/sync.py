"""NetBox synchronisation.

Order of operations in one cycle:

  1. prefixes          from FortiGate routed interfaces
  2. DHCP pools        from FortiGate DHCP servers -> ipam.IPRange, role
                       "DHCP Pool"
  3. infrastructure    the FortiGate(s) and the polled switches as Devices
  4. endpoints         MAC-anchored Device + Interface + IPAddress

Rules that matter:

  * The MAC address is the anchor. An endpoint is located through its MAC, so a
    new DHCP lease updates the existing Device/Interface instead of creating a
    duplicate. Its previous, now-unused dynamic IP is released.
  * A FortiGate static DHCP reservation makes the IP `reserved` and stamps the
    permanent flag that the cleanup honours.
  * Objects that do not carry the `auto-discovered` tag were created by a human.
    The scanner records discovery data on them but never rewrites their status,
    description or tags, and never deletes them.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime

import pynetbox

from ...config import AppConfig
from ...models import CollectionResult, L3Interface, Observation, SwitchInfo
from ...prefixes import PrefixIndex
from ...utils import mac_suffix, sanitize_device_name, to_iso
from .client import (
    CF_FIREWALL,
    CF_FIRST_SEEN,
    CF_LAST_SEEN,
    CF_SOURCE,
    CF_STATIC,
    CF_SWITCH,
    CF_SWITCH_PORT,
    CF_VLAN,
    TAG_DHCP_LEASE,
    TAG_DISCOVERED,
    TAG_INFRASTRUCTURE,
    TAG_RESERVATION,
    NetBoxClient,
    save_record,
)

log = logging.getLogger("sync")

ENDPOINT_INTERFACE_NAME = "nic0"
INTERFACE_TYPE_VIRTUAL = "virtual"
INTERFACE_TYPE_ACCESS = "1000base-t"


# ─────────────────────────────────────────────────────────── prefix lookup ──
def build_prefix_index(
    client: NetBoxClient, interfaces: list[L3Interface], default_len: int
) -> PrefixIndex:
    """Seed a PrefixIndex from this cycle's routed interfaces and from NetBox.

    The lookup itself is pure arithmetic and lives in `app/prefixes.py`; only
    the preload is NetBox-specific, which is why it lives here.
    """
    index = PrefixIndex(default_len)
    for iface in interfaces:
        index.add_cidr(iface.cidr)
    try:
        for prefix in client.api.ipam.prefixes.all():
            index.add_cidr(str(prefix.prefix))
    except (pynetbox.RequestError, OSError) as exc:
        log.warning("could not preload prefixes from NetBox: %s", exc)
    return index


# ────────────────────────────────────────────────────────────── generic io ──
def _scalar(value):
    """Flatten a pynetbox related object / choice into a comparable value."""
    if value is None:
        return None
    for attribute in ("value", "id"):
        if hasattr(value, attribute):
            return getattr(value, attribute)
    return value


def apply_changes(client: NetBoxClient, record, updates: dict, label: str) -> bool:
    """Patch `record` with only the fields that actually differ."""
    changed: dict = {}

    for key, value in updates.items():
        if key == "custom_fields":
            current = dict(getattr(record, "custom_fields", None) or {})
            delta = {k: v for k, v in value.items() if current.get(k) != v}
            if delta:
                current.update(delta)
                changed["custom_fields"] = current
            continue
        if _scalar(getattr(record, key, None)) != _scalar(value):
            changed[key] = _scalar(value)

    if not changed:
        return False
    client.write(f"update {label} ({', '.join(sorted(changed))})", lambda: save_record(record, **changed))
    return True


def ensure_tags(client: NetBoxClient, record, tag_names: list[str], label: str) -> None:
    """Add missing tags without removing tags a human may have added."""
    wanted = {name for name in tag_names if name in client.tags}
    missing = [name for name in wanted if not client.has_tag(record, name)]
    if not missing:
        return
    ids = [_scalar(tag) for tag in (getattr(record, "tags", None) or [])]
    ids = [i for i in ids if isinstance(i, int)]
    ids.extend(client.tags[name].id for name in missing)
    client.write(
        f"tag {label} with {', '.join(missing)}",
        lambda: save_record(record, tags=sorted(set(ids))),
    )


# ──────────────────────────────────────────────────────────────────── vlans ──
def sync_vlans(client: NetBoxClient, result: CollectionResult) -> None:
    """Create the VLANs the switches actually have configured.

    Runs before sync_prefixes so that a VLAN carries its real dot1q name
    rather than the name of the first routed interface that referenced it.
    """
    if client.site is None:
        return

    named: dict[int, str] = {}
    for switch in result.switches:
        for raw_vid, name in switch.vlans.items():
            try:
                vid = int(raw_vid)
            except (TypeError, ValueError):
                continue
            if 1 <= vid <= 4094:
                named.setdefault(vid, name)

    created = 0
    for vid, name in sorted(named.items()):
        existing = client.api.ipam.vlans.get(vid=vid, site_id=client.site.id)
        if existing is None:
            record = client.write(
                f"create VLAN {vid} ({name})",
                lambda v=vid, n=name: client.api.ipam.vlans.create(
                    vid=v,
                    name=n[:64],
                    site=client.site.id,
                    status="active",
                    tags=client.tag_ids(TAG_DISCOVERED),
                ),
            )
            if record is not None:
                created += 1
        elif client.has_tag(existing, TAG_DISCOVERED):
            apply_changes(client, existing, {"name": name[:64]}, f"VLAN {vid}")

    if named:
        log.info("vlans: %d discovered, %d created", len(named), created)


# ──────────────────────────────────────────────────────────────── prefixes ──
def sync_prefixes(client: NetBoxClient, result: CollectionResult) -> None:
    seen: set[str] = set()
    for iface in result.l3_interfaces:
        try:
            network = str(ipaddress.ip_interface(iface.cidr).network)
        except ValueError:
            continue
        if network in seen:
            continue
        seen.add(network)

        description = " / ".join(
            part
            for part in (iface.alias, iface.description, f"{iface.device}:{iface.name}")
            if part
        )[:200]

        existing = client.api.ipam.prefixes.get(prefix=network)
        if existing is None:
            payload = {
                "prefix": network,
                "status": "active",
                "description": description,
                "tags": client.tag_ids(TAG_DISCOVERED),
            }
            if client.site is not None:
                payload["site"] = client.site.id
            vlan = _ensure_vlan(client, iface)
            if vlan is not None:
                payload["vlan"] = vlan.id
            created = client.write(
                f"create prefix {network}",
                lambda p=payload: client.api.ipam.prefixes.create(**p),
            )
            if created is not None:
                log.info("created prefix %s (%s)", network, description or "-")
        elif client.has_tag(existing, TAG_DISCOVERED):
            apply_changes(
                client, existing, {"description": description}, f"prefix {network}"
            )

    if seen:
        log.info("prefixes: %d routed subnet(s) reconciled", len(seen))


def _ensure_vlan(client: NetBoxClient, iface: L3Interface):
    if not iface.vlan_id or client.site is None:
        return None
    try:
        existing = client.api.ipam.vlans.get(vid=iface.vlan_id, site_id=client.site.id)
        if existing is not None:
            return existing
        name = sanitize_device_name(iface.alias or iface.name) or f"vlan{iface.vlan_id}"
        return client.write(
            f"create VLAN {iface.vlan_id}",
            lambda: client.api.ipam.vlans.create(
                vid=iface.vlan_id,
                name=name[:64],
                site=client.site.id,
                status="active",
                tags=client.tag_ids(TAG_DISCOVERED),
            ),
        )
    except pynetbox.RequestError as exc:
        log.debug("VLAN %s not created: %s", iface.vlan_id, exc)
        return None


# ─────────────────────────────────────────────────────────────── DHCP pools ──
def sync_dhcp_pools(
    client: NetBoxClient, result: CollectionResult, index: PrefixIndex
) -> None:
    if not result.pools:
        return

    existing_ranges = {}
    for item in client.api.ipam.ip_ranges.all():
        key = (
            str(item.start_address).split("/")[0],
            str(item.end_address).split("/")[0],
        )
        existing_ranges[key] = item

    for pool in result.pools:
        key = (pool.start_ip, pool.end_ip)
        description = f"FortiGate DHCP pool — {pool.label}"[:200]
        status = "active" if pool.enabled else "deprecated"

        record = existing_ranges.get(key)
        if record is None:
            payload = {
                "start_address": index.cidr_for(pool.start_ip),
                "end_address": index.cidr_for(pool.end_ip),
                "status": status,
                "description": description,
                "tags": client.tag_ids(TAG_DISCOVERED, TAG_DHCP_LEASE),
            }
            if client.dhcp_pool_role is not None:
                payload["role"] = client.dhcp_pool_role.id
            created = client.write(
                f"create DHCP pool range {pool.start_ip}-{pool.end_ip}",
                lambda p=payload: client.api.ipam.ip_ranges.create(**p),
            )
            if created is not None:
                log.info(
                    "created DHCP pool %s-%s [%s]", pool.start_ip, pool.end_ip, pool.label
                )
        elif client.has_tag(record, TAG_DISCOVERED):
            updates = {"status": status, "description": description}
            if client.dhcp_pool_role is not None:
                updates["role"] = client.dhcp_pool_role.id
            apply_changes(
                client, record, updates, f"DHCP pool {pool.start_ip}-{pool.end_ip}"
            )

    log.info("DHCP pools: %d range(s) reconciled", len(result.pools))


# ────────────────────────────────────────────────────────── infrastructure ──
def sync_infrastructure(
    client: NetBoxClient,
    config: AppConfig,
    result: CollectionResult,
    index: PrefixIndex,
    now: datetime,
) -> dict[str, object]:
    """Create the firewalls and switches themselves. Never auto-deleted."""
    devices: dict[str, object] = {}

    for fgt in config.fortigates:
        if not fgt.sync_device:
            continue
        device = _ensure_infrastructure_device(
            client,
            name=fgt.name,
            role=client.role_firewall,
            device_type=client.type_firewall,
            comments=f"FortiGate at {fgt.host} (vdom {fgt.vdom}). "
            "Polled by scanspot via the FortiOS REST API.",
            now=now,
            source="fortigate-api",
        )
        if device is None:
            continue
        devices[fgt.name] = device
        for iface in result.l3_interfaces:
            if iface.device != fgt.name:
                continue
            _ensure_firewall_interface(client, device, iface, index, now)

    for switch in result.switches:
        hardware = _discovered_hardware(client, switch)
        device = _ensure_infrastructure_device(
            client,
            name=switch.name,
            role=client.role_switch,
            device_type=hardware["device_type"] or client.type_switch,
            comments=_switch_comments(switch),
            now=now,
            source="snmp",
            serial=hardware["serial"],
            platform=hardware["platform"],
        )
        if device is not None:
            devices[switch.name] = device

    # Only the ports that actually have an endpoint behind them get created,
    # so the switch does not fill NetBox with hundreds of empty interfaces.
    for obs in result.observations.values():
        if obs.location is None:
            continue
        device = devices.get(obs.location.switch)
        if device is not None:
            _ensure_switch_port(client, device, obs.location.port)

    return devices


def _discovered_hardware(client: NetBoxClient, switch: SwitchInfo) -> dict:
    """Turn an SNMP identity into the NetBox objects that represent it."""
    empty = {"device_type": None, "platform": None, "serial": ""}
    identity = switch.identity
    if identity is None or not identity.manufacturer:
        return empty

    manufacturer = client.ensure_manufacturer(identity.manufacturer)
    if manufacturer is None:
        return empty

    device_type = None
    if identity.model:
        device_type = client.ensure_device_type(identity.model, manufacturer)

    platform = None
    if identity.platform:
        platform = client.ensure_platform(identity.platform, manufacturer)

    return {
        "device_type": device_type,
        "platform": platform,
        "serial": identity.serial,
    }


def _switch_comments(switch: SwitchInfo) -> str:
    lines = [f"{switch.vendor} device at {switch.host}, polled via SNMP."]
    if switch.identity is not None:
        lines.append(switch.identity.describe())
        if switch.identity.sys_object_id:
            lines.append(f"sysObjectID: {switch.identity.sys_object_id}")
    if switch.sys_name:
        lines.append(f"sysName: {switch.sys_name}")
    if switch.sys_descr:
        lines.append(switch.sys_descr)
    return "\n".join(lines)


def _ensure_infrastructure_device(
    client: NetBoxClient,
    name: str,
    role,
    device_type,
    comments: str,
    now: datetime,
    source: str,
    serial: str = "",
    platform=None,
):
    if client.site is None or role is None or device_type is None:
        return None

    device = client.api.dcim.devices.get(name=name, site_id=client.site.id)
    custom_fields = {
        CF_LAST_SEEN: to_iso(now),
        CF_SOURCE: source,
        CF_STATIC: False,
    }
    if device is None:
        payload = {
            "name": name,
            "role": role,
            "device_type": device_type,
            "status": "active",
            "comments": comments[:1000],
            "tags": client.tag_ids(TAG_INFRASTRUCTURE),
            "custom_fields": {**custom_fields, CF_FIRST_SEEN: to_iso(now)},
        }
        if serial:
            payload["serial"] = serial
        if platform is not None:
            payload["platform"] = platform.id
        device = client.create_device(**payload)
        if device is not None:
            log.info("created infrastructure device '%s'", name)
        return device

    updates: dict = {"status": "active", "custom_fields": custom_fields, "comments": comments[:1000]}

    # The discovered model only overwrites a placeholder type, or one the
    # scanner itself put there. A type a human chose is left alone.
    if device_type is not None and getattr(device.device_type, "id", None) != device_type.id:
        scanner_owned = str(
            (getattr(device, "custom_fields", None) or {}).get(CF_SOURCE) or ""
        ) == source
        if client.is_generic_type(device) or scanner_owned:
            log.info(
                "device '%s': type %s -> %s (discovered via SNMP)",
                name,
                getattr(device.device_type, "model", "?"),
                device_type.model,
            )
            updates["device_type"] = device_type.id
        else:
            log.debug(
                "device '%s' keeps its manually assigned type %s",
                name,
                getattr(device.device_type, "model", "?"),
            )

    if serial and str(getattr(device, "serial", "") or "") != serial:
        updates["serial"] = serial
    if platform is not None and getattr(
        getattr(device, "platform", None), "id", None
    ) != platform.id:
        updates["platform"] = platform.id

    apply_changes(client, device, updates, f"device '{name}'")
    ensure_tags(client, device, [TAG_INFRASTRUCTURE], f"device '{name}'")
    return device


def _ensure_firewall_interface(
    client: NetBoxClient, device, iface: L3Interface, index: PrefixIndex, now: datetime
) -> None:
    if not iface.name:
        return
    interface = client.api.dcim.interfaces.get(device_id=device.id, name=iface.name)
    if interface is None:
        interface = client.write(
            f"create interface {device.name}/{iface.name}",
            lambda: client.api.dcim.interfaces.create(
                device=device.id,
                name=iface.name,
                type=INTERFACE_TYPE_VIRTUAL,
                enabled=str(iface.status).lower() != "down",
                description=(iface.alias or iface.description)[:200],
                tags=client.tag_ids(TAG_INFRASTRUCTURE),
            ),
        )
    if interface is None:
        return

    address = iface.cidr
    record = _find_ip(client, iface.address)
    if record is None:
        client.write(
            f"create firewall IP {address}",
            lambda: client.api.ipam.ip_addresses.create(
                address=address,
                status="active",
                assigned_object_type="dcim.interface",
                assigned_object_id=interface.id,
                description=f"{iface.device} interface {iface.name}"[:200],
                tags=client.tag_ids(TAG_INFRASTRUCTURE),
                custom_fields={
                    CF_FIRST_SEEN: to_iso(now),
                    CF_LAST_SEEN: to_iso(now),
                    CF_SOURCE: "fortigate-api",
                    CF_STATIC: False,
                    CF_FIREWALL: f"{iface.device}:{iface.name}",
                },
            ),
        )
    else:
        apply_changes(
            client,
            record,
            {
                "custom_fields": {
                    CF_LAST_SEEN: to_iso(now),
                    CF_SOURCE: "fortigate-api",
                    CF_FIREWALL: f"{iface.device}:{iface.name}",
                }
            },
            f"firewall IP {address}",
        )


def _ensure_switch_port(client: NetBoxClient, device, port_name: str):
    interface = client.api.dcim.interfaces.get(device_id=device.id, name=port_name)
    if interface is not None:
        return interface
    return client.write(
        f"create switch port {device.name}/{port_name}",
        lambda: client.api.dcim.interfaces.create(
            device=device.id,
            name=port_name,
            type=INTERFACE_TYPE_ACCESS,
            description="Discovered via SNMP forwarding database",
            tags=client.tag_ids(TAG_INFRASTRUCTURE),
        ),
    )


# ─────────────────────────────────────────────────────────────── endpoints ──
def sync_endpoints(
    client: NetBoxClient, result: CollectionResult, index: PrefixIndex, now: datetime
) -> None:
    created = updated = skipped = 0

    for mac in sorted(result.observations):
        obs = result.observations[mac]
        if not obs.ips and obs.location is None:
            skipped += 1
            continue
        try:
            was_created = _sync_one_endpoint(client, obs, index, now)
        except pynetbox.RequestError as exc:
            log.error("endpoint %s failed: %s", mac, str(exc)[:300])
            continue
        if was_created:
            created += 1
        else:
            updated += 1

    log.info(
        "endpoints: %d created, %d updated, %d skipped (no address, no location)",
        created,
        updated,
        skipped,
    )


def _sync_one_endpoint(
    client: NetBoxClient, obs: Observation, index: PrefixIndex, now: datetime
) -> bool:
    # ── 1. locate through the MAC anchor ────────────────────────────────────
    interface = client.find_interface_by_mac(obs.mac)
    device = None
    is_new = False

    if interface is not None:
        device_id = _scalar(getattr(interface, "device", None))
        if device_id is not None:
            device = client.api.dcim.devices.get(device_id)

    if device is None:
        device = _create_endpoint_device(client, obs, now)
        if device is None:
            return False
        is_new = True
        interface = client.write(
            f"create interface {ENDPOINT_INTERFACE_NAME} on {device.name}",
            lambda: client.api.dcim.interfaces.create(
                device=device.id,
                name=ENDPOINT_INTERFACE_NAME,
                type=INTERFACE_TYPE_VIRTUAL,
                description=f"MAC {obs.mac}",
                tags=client.tag_ids(TAG_DISCOVERED),
            ),
        )
        if interface is None:
            return False

    client.assign_mac(interface, obs.mac)

    managed = client.has_tag(device, TAG_DISCOVERED) or is_new

    # ── 2. device attributes ────────────────────────────────────────────────
    custom_fields = {
        CF_LAST_SEEN: to_iso(now),
        CF_SOURCE: obs.source_label,
        CF_STATIC: obs.static_reservation,
        CF_FIREWALL: f"{obs.firewall}:{obs.firewall_interface}".strip(":"),
    }
    if obs.location is not None:
        custom_fields[CF_SWITCH] = obs.location.switch
        custom_fields[CF_SWITCH_PORT] = obs.location.port
        if obs.location.vlan:
            custom_fields[CF_VLAN] = str(obs.location.vlan)

    updates: dict = {"custom_fields": custom_fields}
    if managed:
        updates["status"] = "active"
        preferred = _preferred_device_name(client, obs, device)
        if preferred and preferred != device.name:
            updates["name"] = preferred
        updates["comments"] = _device_comments(obs)[:1000]
    apply_changes(client, device, updates, f"device '{device.name}'")

    tags = [TAG_DISCOVERED]
    if obs.static_reservation:
        tags.append(TAG_RESERVATION)
    elif obs.dynamic_ips:
        tags.append(TAG_DHCP_LEASE)
    if managed:
        ensure_tags(client, device, tags, f"device '{device.name}'")

    # ── 3. addresses ────────────────────────────────────────────────────────
    primary = None
    for ip in sorted(obs.ips):
        record = _sync_ip(client, obs, ip, interface, index, now)
        if record is not None and _is_better_primary(record, primary, obs, ip):
            primary = record

    _release_stale_addresses(client, obs, interface, now)

    if primary is not None and managed:
        apply_changes(
            client, device, {"primary_ip4": primary.id}, f"device '{device.name}' primary IP"
        )

    return is_new


def _create_endpoint_device(client: NetBoxClient, obs: Observation, now: datetime):
    if client.site is None or client.role_endpoint is None or client.type_endpoint is None:
        log.error("bootstrap incomplete — cannot create endpoint for %s", obs.mac)
        return None

    name = _new_device_name(client, obs)
    device = client.create_device(
        name=name,
        role=client.role_endpoint,
        device_type=client.type_endpoint,
        status="active",
        comments=_device_comments(obs)[:1000],
        tags=client.tag_ids(
            TAG_DISCOVERED,
            TAG_RESERVATION if obs.static_reservation else TAG_DHCP_LEASE,
        ),
        custom_fields={
            CF_FIRST_SEEN: to_iso(now),
            CF_LAST_SEEN: to_iso(now),
            CF_SOURCE: obs.source_label,
            CF_STATIC: obs.static_reservation,
        },
    )
    if device is not None:
        log.info(
            "discovered %s '%s' (%s)%s",
            "reserved host" if obs.static_reservation else "endpoint",
            name,
            obs.mac,
            f" on {obs.location.switch}/{obs.location.port}" if obs.location else "",
        )
    return device


def _new_device_name(client: NetBoxClient, obs: Observation) -> str:
    suffix = mac_suffix(obs.mac)
    base = sanitize_device_name(obs.hostname) if obs.hostname else ""
    if not base:
        return f"host-{suffix}"
    if client.site is not None and client.api.dcim.devices.get(
        name=base, site_id=client.site.id
    ):
        return f"{base}-{suffix}"[:64]
    return base[:64]


def _preferred_device_name(client: NetBoxClient, obs: Observation, device) -> str | None:
    """Upgrade a placeholder name once the DHCP hostname becomes known."""
    if not obs.hostname:
        return None
    current = str(device.name or "")
    if not current.startswith("host-"):
        return None
    return _new_device_name(client, obs)


def _device_comments(obs: Observation) -> str:
    lines = [
        "Automatically discovered by scanspot.",
        f"MAC: {obs.mac}",
        f"Sources: {obs.source_label or 'n/a'}",
    ]
    if obs.location:
        vlan = f" (VLAN {obs.location.vlan})" if obs.location.vlan else ""
        lines.append(f"Switch port: {obs.location.switch} / {obs.location.port}{vlan}")
    if obs.firewall:
        lines.append(
            f"FortiGate: {obs.firewall}"
            + (f" / {obs.firewall_interface}" if obs.firewall_interface else "")
        )
    if obs.static_reservation:
        lines.append(
            "STATIC DHCP RESERVATION on the FortiGate — exempt from auto-deletion."
        )
        if obs.reservation_description:
            lines.append(f"Reservation note: {obs.reservation_description}")
    return "\n".join(lines)


def _find_ip(client: NetBoxClient, ip: str):
    for record in client.api.ipam.ip_addresses.filter(address=ip):
        if str(record.address).split("/")[0] == ip:
            return record
    return None


def _sync_ip(
    client: NetBoxClient,
    obs: Observation,
    ip: str,
    interface,
    index: PrefixIndex,
    now: datetime,
):
    status = obs.status_for(ip)
    description = _ip_description(obs, ip)
    custom_fields = {
        CF_LAST_SEEN: to_iso(now),
        CF_SOURCE: obs.source_label,
        CF_STATIC: obs.static_reservation and ip in obs.reserved_ips,
        CF_FIREWALL: f"{obs.firewall}:{obs.firewall_interface}".strip(":"),
    }
    if obs.location is not None:
        custom_fields[CF_SWITCH] = obs.location.switch
        custom_fields[CF_SWITCH_PORT] = obs.location.port
        if obs.location.vlan:
            custom_fields[CF_VLAN] = str(obs.location.vlan)

    record = _find_ip(client, ip)

    if record is None:
        tags = [TAG_DISCOVERED]
        if status == "reserved":
            tags.append(TAG_RESERVATION)
        elif status == "dhcp":
            tags.append(TAG_DHCP_LEASE)
        payload = {
            "address": index.cidr_for(ip),
            "status": status,
            "description": description,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": interface.id,
            "tags": client.tag_ids(*tags),
            "custom_fields": {**custom_fields, CF_FIRST_SEEN: to_iso(now)},
        }
        if obs.hostname:
            payload["dns_name"] = obs.hostname.lower()[:255]
        return client.write(
            f"create IP {payload['address']} ({status})",
            lambda p=payload: client.api.ipam.ip_addresses.create(**p),
        )

    # Existing record. Manual entries keep their status/description/tags.
    managed = client.has_tag(record, TAG_DISCOVERED)
    updates: dict = {"custom_fields": custom_fields}

    if _scalar(getattr(record, "assigned_object_id", None)) != interface.id:
        # An address that moved to another host (new DHCP lease, recycled IP)
        # cannot be reassigned while the previous owner still advertises it as
        # its primary address — NetBox rejects the PATCH outright.
        _release_primary_reference(client, record)
        updates["assigned_object_type"] = "dcim.interface"
        updates["assigned_object_id"] = interface.id

    if managed:
        updates["status"] = status
        updates["description"] = description
        if obs.hostname:
            updates["dns_name"] = obs.hostname.lower()[:255]

    apply_changes(client, record, updates, f"IP {record.address}")

    if managed:
        tags = [TAG_DISCOVERED]
        if status == "reserved":
            tags.append(TAG_RESERVATION)
        elif status == "dhcp":
            tags.append(TAG_DHCP_LEASE)
        ensure_tags(client, record, tags, f"IP {record.address}")

    return record


def _release_primary_reference(client: NetBoxClient, record) -> None:
    """Clear primary_ip4/6 on whichever device currently claims `record`."""
    assigned = getattr(record, "assigned_object", None)
    device_id = _scalar(getattr(assigned, "device", None)) if assigned else None
    if device_id is None:
        return

    device = client.api.dcim.devices.get(device_id)
    if device is None:
        return

    for field in ("primary_ip4", "primary_ip6"):
        if _scalar(getattr(device, field, None)) != record.id:
            continue
        client.write(
            f"release {field} {record.address} from '{device.name}'",
            lambda f=field: save_record(device, **{f: None}),
        )


def _ip_description(obs: Observation, ip: str) -> str:
    if obs.static_reservation and ip in obs.reserved_ips:
        note = f" — {obs.reservation_description}" if obs.reservation_description else ""
        return f"FortiGate static DHCP reservation for {obs.mac}{note}"[:200]
    if ip in obs.dynamic_ips:
        expiry = obs.lease_expiry.get(ip)
        suffix = f", lease expires in {expiry}s" if expiry else ""
        return f"DHCP lease for {obs.mac}{suffix}"[:200]
    return f"Discovered host {obs.mac} ({obs.source_label})"[:200]


def _is_better_primary(record, current, obs: Observation, ip: str) -> bool:
    if current is None:
        return True
    priority = {"reserved": 3, "active": 2, "dhcp": 1}
    new_rank = priority.get(obs.status_for(ip), 0)
    current_rank = priority.get(str(_scalar(getattr(current, "status", None))), 0)
    return new_rank > current_rank


def _release_stale_addresses(
    client: NetBoxClient, obs: Observation, interface, now: datetime
) -> None:
    """A known MAC with a new lease must not keep its old address assigned.

    Only auto-discovered, non-reserved addresses are released; the record is
    detached and deprecated, then the normal retention window deletes it.
    """
    try:
        assigned = list(
            client.api.ipam.ip_addresses.filter(interface_id=interface.id)
        )
    except pynetbox.RequestError as exc:
        log.debug("could not list addresses of interface %s: %s", interface.id, exc)
        return

    for record in assigned:
        ip = str(record.address).split("/")[0]
        if ip in obs.ips:
            continue
        if not client.has_tag(record, TAG_DISCOVERED):
            continue
        if client.has_tag(record, TAG_RESERVATION) or (record.custom_fields or {}).get(
            CF_STATIC
        ):
            continue
        log.info(
            "releasing stale address %s from %s (MAC moved to %s)",
            record.address,
            obs.mac,
            ", ".join(sorted(obs.ips)) or "no address",
        )
        apply_changes(
            client,
            record,
            {
                "status": "deprecated",
                "assigned_object_type": None,
                "assigned_object_id": None,
                "description": f"Released — {obs.mac} moved to a new address"[:200],
            },
            f"stale IP {record.address}",
        )
