"""Multi-vendor SNMP collector (net-snmp CLI backend).

Goal: map every endpoint MAC to the physical switch port it was learned on.

Strategy, applied per switch in this order (`vlan_indexing: auto`):

  1. Q-BRIDGE  dot1qTpFdbPort   .1.3.6.1.2.1.17.7.1.2.2.1.2
     VLAN-aware, single walk, supported by FortiSwitch, Aruba/HPE, Huawei,
     Alcatel, Juniper and modern Cisco. Index = fdbId . 6 MAC octets.

  2. BRIDGE    dot1dTpFdbPort   .1.3.6.1.2.1.17.4.3.1.2
     Classic table. Index = 6 MAC octets.

  3. Per-VLAN BRIDGE-MIB, for Cisco IOS classic which exposes one BRIDGE-MIB
     instance per VLAN:
        SNMPv2c -> community string "public@100"
        SNMPv3  -> context name    "vlan-100"
     The VLAN list comes from CISCO-VTP-MIB vtpVlanState.

Bridge port numbers are translated to interface names through
dot1dBasePortIfIndex -> ifName (falling back to ifDescr).

Ports that have learned more MACs than `uplink_mac_threshold` are treated as
trunks/uplinks: their MACs are collected but no access-port location is
recorded, otherwise every endpoint in the building would appear to live on the
core uplink.

ipNetToMediaPhysAddress is walked as a bonus: L3 switches contribute extra
IP<->MAC bindings for subnets the FortiGate does not route.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass

from .. import identity as identity_mod
from ..config import SwitchConfig
from ..models import (
    SOURCE_SNMP_ARP,
    SOURCE_SNMP_FDB,
    CollectionResult,
    L3Interface,
    SwitchInfo,
    SwitchPortLocation,
)
from ..utils import is_usable_ip, mac_from_octets, netmask_to_prefixlen, normalize_mac

log = logging.getLogger("snmp")

OID_SYS_DESCR = ".1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = ".1.3.6.1.2.1.1.5.0"
OID_IF_DESCR = ".1.3.6.1.2.1.2.2.1.2"
OID_IF_NAME = ".1.3.6.1.2.1.31.1.1.1.1"
OID_DOT1D_BASE_PORT_IFINDEX = ".1.3.6.1.2.1.17.1.4.1.2"
OID_DOT1D_TP_FDB_PORT = ".1.3.6.1.2.1.17.4.3.1.2"
OID_DOT1Q_TP_FDB_PORT = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
OID_DOT1Q_VLAN_STATIC_NAME = ".1.3.6.1.2.1.17.7.1.4.3.1.1"
OID_IP_NET_TO_MEDIA_PHYS = ".1.3.6.1.2.1.4.22.1.2"
OID_IP_AD_ENT_IFINDEX = ".1.3.6.1.2.1.4.20.1.2"
OID_IP_AD_ENT_NETMASK = ".1.3.6.1.2.1.4.20.1.3"
OID_VTP_VLAN_STATE = ".1.3.6.1.4.1.9.9.46.1.3.1.1.2"
OID_VTP_VLAN_NAME = ".1.3.6.1.4.1.9.9.46.1.3.1.1.4"

# ifName of a switched virtual interface: Vlan10, vlan10, Vlan-interface10
_SVI_NAME = re.compile(r"^vlan[\s\-_]?(\d{1,4})$", re.IGNORECASE)

AUTH_PROTOCOLS = {
    "MD5": "MD5",
    "SHA": "SHA",
    "SHA1": "SHA",
    "SHA224": "SHA-224",
    "SHA-224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA-256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA-384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA-512": "SHA-512",
}
PRIV_PROTOCOLS = {
    "DES": "DES",
    "AES": "AES",
    "AES128": "AES",
    "AES-128": "AES",
    "AES192": "AES-192",
    "AES-192": "AES-192",
    "AES256": "AES-256",
    "AES-256": "AES-256",
}

# Vendors whose classic platforms need per-VLAN BRIDGE-MIB indexing
PER_VLAN_VENDORS = {"cisco"}


class SnmpError(RuntimeError):
    pass


@dataclass
class _FdbEntry:
    mac: str
    bridge_port: int
    vlan: str | None


# ─────────────────────────────────────────────────────────────── transport ──


def _binary(version: str) -> str:
    # snmpbulkwalk (GETBULK) is v2c+. v1 has to fall back to GETNEXT.
    return "snmpwalk" if version == "1" else "snmpbulkwalk"


def _auth_args(cfg: SwitchConfig, community_suffix: str | None, context: str | None):
    args: list[str] = []
    if cfg.snmp_version in ("1", "2c"):
        community = cfg.community
        if community_suffix:
            community = f"{community}@{community_suffix}"
        args += ["-v", cfg.snmp_version, "-c", community]
    else:
        level = cfg.v3_security_level or "authPriv"
        args += ["-v", "3", "-l", level, "-u", cfg.v3_username]
        if level in ("authNoPriv", "authPriv"):
            proto = AUTH_PROTOCOLS.get(cfg.v3_auth_protocol.upper(), "SHA")
            args += ["-a", proto, "-A", cfg.v3_auth_password]
        if level == "authPriv":
            proto = PRIV_PROTOCOLS.get(cfg.v3_priv_protocol.upper(), "AES")
            args += ["-x", proto, "-X", cfg.v3_priv_password]
        if context:
            args += ["-n", context]
    return args


def _walk(
    cfg: SwitchConfig,
    oid: str,
    community_suffix: str | None = None,
    context: str | None = None,
) -> dict[str, str]:
    """Walk `oid` and return {numeric-oid: value}.

    -Oqn keeps the output free of MIB translation and quoting, which makes the
    parsing deterministic across net-snmp versions.
    """
    command = [
        _binary(cfg.snmp_version),
        "-Oqn",
        "-t",
        str(cfg.timeout),
        "-r",
        str(cfg.retries),
        *_auth_args(cfg, community_suffix, context),
        cfg.target,
        oid,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=cfg.timeout * (cfg.retries + 1) * 12 + 30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SnmpError(f"walk of {oid} timed out") from None
    except FileNotFoundError:
        raise SnmpError("net-snmp tools are missing from the image") from None

    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        raise SnmpError(stderr.splitlines()[0] if stderr else f"walk of {oid} failed")

    values: dict[str, str] = {}
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        key, _, value = line.partition(" ")
        if not key.startswith("."):
            continue
        value = value.strip().strip('"')
        if value in ("No Such Object available on this agent at this OID", ""):
            continue
        values[key] = value
    return values


def _walk_safe(cfg: SwitchConfig, oid: str, **kwargs) -> dict[str, str]:
    try:
        return _walk(cfg, oid, **kwargs)
    except SnmpError as exc:
        log.debug("[%s] %s", cfg.name, exc)
        return {}


def _index_after(oid: str, base: str) -> list[str]:
    """Return the index components of `oid` relative to `base`."""
    base = base if base.startswith(".") else f".{base}"
    if not oid.startswith(base + "."):
        return []
    return oid[len(base) + 1 :].split(".")


# ────────────────────────────────────────────────────────────────── polling ──


def collect(cfg: SwitchConfig, result: CollectionResult) -> SwitchInfo:
    """Poll one switch and merge its FDB/ARP knowledge into `result`."""
    info = SwitchInfo(name=cfg.name, host=cfg.host, vendor=cfg.vendor)

    if shutil.which(_binary(cfg.snmp_version)) is None:
        info.error = "net-snmp tools not installed"
        raise SnmpError(info.error)

    # Reachability probe. A failure here is fatal for this switch: sysDescr is
    # the one object every SNMP agent on earth implements.
    info.sys_descr = next(iter(_walk(cfg, OID_SYS_DESCR).values()), "")
    info.sys_name = next(iter(_walk_safe(cfg, OID_SYS_NAME).values()), "")
    info.reachable = True

    info.identity = _probe_identity(cfg, info)
    log.info("[%s] %s", cfg.name, info.identity.describe())

    # Let the discovered vendor drive the MAC-table strategy when the operator
    # did not pin one: a Cisco found by sysObjectID gets the per-VLAN walk on
    # this very cycle, without anybody having to type "cisco" anywhere.
    if cfg.vendor in ("", "generic", "auto"):
        detected = info.identity.vendor_key
        if detected != "generic":
            log.debug("[%s] vendor auto-detected as '%s'", cfg.name, detected)
            cfg.vendor = detected
            info.vendor = detected

    if_names = _interface_names(cfg)
    base_port_ifindex = _bridge_port_map(cfg)
    info.ports = {
        str(ifindex): name for ifindex, name in if_names.items() if name
    }

    info.vlans = _vlan_names(cfg)
    _merge_l3_interfaces(cfg, if_names, result)

    entries = _read_fdb(cfg, base_port_ifindex)
    _merge_fdb(cfg, entries, base_port_ifindex, if_names, result)
    _merge_snmp_arp(cfg, result)

    log.info(
        "[%s] %d FDB entries on %d ports, %d VLANs",
        cfg.name,
        len(entries),
        len({e.bridge_port for e in entries}),
        len(info.vlans),
    )
    return info


def _probe_identity(cfg: SwitchConfig, info: SwitchInfo):
    """sysObjectID + ENTITY-MIB -> manufacturer, model, serial, OS."""
    sys_object_id = next(
        iter(_walk_safe(cfg, identity_mod.OID_SYS_OBJECT_ID).values()), ""
    )
    return identity_mod.build(
        sys_object_id=sys_object_id,
        sys_descr=info.sys_descr,
        sys_name=info.sys_name,
        entity_rows=_entity_rows(cfg),
    )


def _entity_rows(cfg: SwitchConfig) -> dict[str, dict[str, str]]:
    """Parse the columns of entPhysicalTable we care about into rows.

    Walked column by column rather than as a subtree: the full table on a large
    chassis carries a row per transceiver and per fan, which is a lot of
    traffic for four values.
    """
    columns = {
        "class": identity_mod.OID_ENT_PHYSICAL_CLASS,
        "model": identity_mod.OID_ENT_PHYSICAL_MODEL,
        "serial": identity_mod.OID_ENT_PHYSICAL_SERIAL,
        "mfg": identity_mod.OID_ENT_PHYSICAL_MFG,
        "sw": identity_mod.OID_ENT_PHYSICAL_SW_REV,
    }
    rows: dict[str, dict[str, str]] = {}
    for key, oid in columns.items():
        for walked_oid, value in _walk_safe(cfg, oid).items():
            index = _index_after(walked_oid, oid)
            if len(index) != 1:
                continue
            rows.setdefault(index[0], {})[key] = value
        # entPhysicalClass missing means no ENTITY-MIB at all: stop early.
        if key == "class" and not rows:
            return {}
    return rows


def _vlan_names(cfg: SwitchConfig) -> dict[str, str]:
    """{vid: name} for the NetBox VLAN objects.

    Q-BRIDGE first. Classic Cisco IOS does not populate dot1qVlanStaticName at
    all — on those the names only exist in CISCO-VTP-MIB — so fall back to it
    rather than reporting a switch as having no VLANs.
    """
    vlans: dict[str, str] = {}
    for oid, value in _walk_safe(cfg, OID_DOT1Q_VLAN_STATIC_NAME).items():
        index = _index_after(oid, OID_DOT1Q_VLAN_STATIC_NAME)
        if len(index) == 1 and index[0].isdigit() and value:
            vlans[index[0]] = value[:64]
    if vlans:
        return vlans

    for oid, value in _walk_safe(cfg, OID_VTP_VLAN_NAME).items():
        # index = mgmtDomainIndex . vlanIndex
        index = _index_after(oid, OID_VTP_VLAN_NAME)
        if len(index) != 2 or not index[1].isdigit() or not value:
            continue
        vid = int(index[1])
        if 1 <= vid < 1002:  # skip the legacy FDDI/token-ring reserved range
            vlans[str(vid)] = value[:64]
    return vlans


def _merge_l3_interfaces(
    cfg: SwitchConfig, if_names: dict[int, str], result: CollectionResult
) -> None:
    """ipAddrTable -> the subnets this device routes.

    On an L3 switch this is what makes "which addresses in this /24 are free"
    answerable in NetBox without a FortiGate in the picture.
    """
    netmasks = _walk_safe(cfg, OID_IP_AD_ENT_NETMASK)
    if not netmasks:
        return
    ifindexes = _walk_safe(cfg, OID_IP_AD_ENT_IFINDEX)

    for oid, netmask in netmasks.items():
        address = ".".join(_index_after(oid, OID_IP_AD_ENT_NETMASK))
        if not is_usable_ip(address):
            continue
        prefix_len = netmask_to_prefixlen(netmask)
        if prefix_len is None or prefix_len >= 31:
            continue

        ifindex_raw = ifindexes.get(f"{OID_IP_AD_ENT_IFINDEX}.{address}", "")
        name = ""
        if ifindex_raw.isdigit():
            name = if_names.get(int(ifindex_raw), "")
        name = name or f"ip-{address}"

        svi = _SVI_NAME.match(name.strip())
        result.l3_interfaces.append(
            L3Interface(
                device=cfg.name,
                name=name,
                address=address,
                prefix_len=prefix_len,
                vlan_id=int(svi.group(1)) if svi else None,
                description=f"SNMP ipAddrTable on {cfg.name}",
            )
        )


def _interface_names(cfg: SwitchConfig) -> dict[int, str]:
    names: dict[int, str] = {}
    for oid, value in _walk_safe(cfg, OID_IF_DESCR).items():
        index = _index_after(oid, OID_IF_DESCR)
        if len(index) == 1 and index[0].isdigit():
            names[int(index[0])] = value
    # ifName is the short, operator-facing name (Gi1/0/12) — prefer it.
    for oid, value in _walk_safe(cfg, OID_IF_NAME).items():
        index = _index_after(oid, OID_IF_NAME)
        if len(index) == 1 and index[0].isdigit() and value:
            names[int(index[0])] = value
    return names


def _bridge_port_map(
    cfg: SwitchConfig, community_suffix: str | None = None, context: str | None = None
) -> dict[int, int]:
    """dot1dBasePort -> ifIndex."""
    mapping: dict[int, int] = {}
    walked = _walk_safe(
        cfg, OID_DOT1D_BASE_PORT_IFINDEX, community_suffix=community_suffix, context=context
    )
    for oid, value in walked.items():
        index = _index_after(oid, OID_DOT1D_BASE_PORT_IFINDEX)
        if len(index) == 1 and index[0].isdigit() and value.isdigit():
            mapping[int(index[0])] = int(value)
    return mapping


def _read_fdb(cfg: SwitchConfig, base_port_ifindex: dict[int, int]) -> list[_FdbEntry]:
    mode = cfg.vlan_indexing

    if mode in ("auto", "none"):
        entries = _read_qbridge_fdb(cfg)
        if entries:
            return entries
        entries = _read_dot1d_fdb(cfg)
        if entries or mode == "none":
            return entries

    if mode in ("auto", "community", "context"):
        entries = _read_per_vlan_fdb(cfg, base_port_ifindex)
        if entries:
            return entries

    return []


def _read_qbridge_fdb(cfg: SwitchConfig) -> list[_FdbEntry]:
    entries: list[_FdbEntry] = []
    for oid, value in _walk_safe(cfg, OID_DOT1Q_TP_FDB_PORT).items():
        index = _index_after(oid, OID_DOT1Q_TP_FDB_PORT)
        # index = fdbId (1 sub-id, usually the VLAN) + 6 MAC octets
        if len(index) < 7 or not value.isdigit():
            continue
        mac = mac_from_octets(index[-6:])
        port = int(value)
        if not mac or port <= 0:
            continue
        vlan = index[0] if index[0].isdigit() and index[0] != "0" else None
        entries.append(_FdbEntry(mac=mac, bridge_port=port, vlan=vlan))
    return entries


def _read_dot1d_fdb(
    cfg: SwitchConfig,
    community_suffix: str | None = None,
    context: str | None = None,
    vlan: str | None = None,
) -> list[_FdbEntry]:
    entries: list[_FdbEntry] = []
    walked = _walk_safe(
        cfg, OID_DOT1D_TP_FDB_PORT, community_suffix=community_suffix, context=context
    )
    for oid, value in walked.items():
        index = _index_after(oid, OID_DOT1D_TP_FDB_PORT)
        if len(index) < 6 or not value.isdigit():
            continue
        mac = mac_from_octets(index[-6:])
        port = int(value)
        if not mac or port <= 0:
            continue
        entries.append(_FdbEntry(mac=mac, bridge_port=port, vlan=vlan))
    return entries


def _vlan_list(cfg: SwitchConfig) -> list[str]:
    """Active VLAN ids from CISCO-VTP-MIB (vtpVlanState == 1 -> operational)."""
    vlans: list[str] = []
    for oid, value in _walk_safe(cfg, OID_VTP_VLAN_STATE).items():
        index = _index_after(oid, OID_VTP_VLAN_STATE)
        # index = mgmtDomainIndex . vlanIndex
        if len(index) == 2 and index[1].isdigit() and value.strip() == "1":
            vlan = index[1]
            if int(vlan) < 1002:  # skip the legacy FDDI/token-ring vlans
                vlans.append(vlan)
    return sorted(set(vlans), key=int)


def _read_per_vlan_fdb(
    cfg: SwitchConfig, base_port_ifindex: dict[int, int]
) -> list[_FdbEntry]:
    """Cisco IOS classic: one BRIDGE-MIB instance per VLAN."""
    if cfg.vlan_indexing == "auto" and cfg.vendor not in PER_VLAN_VENDORS:
        return []

    use_context = cfg.snmp_version == "3" or cfg.vlan_indexing == "context"
    vlans = _vlan_list(cfg)
    if not vlans:
        return []

    log.debug("[%s] per-VLAN FDB walk over %d VLANs", cfg.name, len(vlans))
    entries: list[_FdbEntry] = []
    for vlan in vlans:
        suffix = None if use_context else vlan
        context = f"vlan-{vlan}" if use_context else None

        vlan_entries = _read_dot1d_fdb(
            cfg, community_suffix=suffix, context=context, vlan=vlan
        )
        if not vlan_entries:
            continue
        # Bridge-port numbering is per-VLAN too; refresh the translation table.
        vlan_map = _bridge_port_map(cfg, community_suffix=suffix, context=context)
        for entry in vlan_entries:
            if entry.bridge_port in vlan_map:
                base_port_ifindex.setdefault(entry.bridge_port, vlan_map[entry.bridge_port])
        entries.extend(vlan_entries)
    return entries


def _merge_fdb(
    cfg: SwitchConfig,
    entries: list[_FdbEntry],
    base_port_ifindex: dict[int, int],
    if_names: dict[int, str],
    result: CollectionResult,
) -> None:
    # Count MACs per port so uplinks/trunks can be excluded from port mapping.
    per_port: dict[int, set[str]] = {}
    for entry in entries:
        per_port.setdefault(entry.bridge_port, set()).add(entry.mac)

    uplinks = {
        port
        for port, macs in per_port.items()
        if len(macs) > cfg.uplink_mac_threshold
    }
    if uplinks:
        log.debug(
            "[%s] %d port(s) exceed the uplink threshold and will not be mapped",
            cfg.name,
            len(uplinks),
        )

    for entry in entries:
        obs = result.observation(entry.mac)
        obs.merge_source(SOURCE_SNMP_FDB)

        if entry.bridge_port in uplinks:
            continue
        ifindex = base_port_ifindex.get(entry.bridge_port, entry.bridge_port)
        port_name = if_names.get(ifindex) or f"BridgePort-{entry.bridge_port}"

        # First non-uplink switch wins; access-layer switches are polled in
        # inventory order, so put access switches before the core if a MAC can
        # legitimately appear on two of them.
        if obs.location is None:
            obs.location = SwitchPortLocation(
                switch=cfg.name, port=port_name, vlan=entry.vlan
            )


def _merge_snmp_arp(cfg: SwitchConfig, result: CollectionResult) -> None:
    """ipNetToMediaPhysAddress: IP <-> MAC learned by an L3 switch."""
    for oid, value in _walk_safe(cfg, OID_IP_NET_TO_MEDIA_PHYS).items():
        index = _index_after(oid, OID_IP_NET_TO_MEDIA_PHYS)
        # index = ifIndex . 4 IPv4 octets
        if len(index) != 5:
            continue
        ip = ".".join(index[1:])
        mac = normalize_mac(value)
        if not mac or not is_usable_ip(ip):
            continue
        obs = result.observation(mac)
        obs.merge_source(SOURCE_SNMP_ARP)
        obs.ips.add(ip)
