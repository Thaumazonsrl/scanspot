"""In-memory data model shared between the collectors, the correlator and the
NetBox sync layer.

Everything is keyed on the MAC address, because the MAC is the only identifier
that survives a DHCP lease change. IPs come and go; the MAC is the anchor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoids a cycle: identity has no dependency on the models
    from .identity import DeviceIdentity

# Provenance flags recorded on every observation
SOURCE_ARP = "fortigate-arp"
SOURCE_DHCP = "fortigate-dhcp"
SOURCE_RESERVATION = "fortigate-reservation"
SOURCE_SNMP_FDB = "snmp-fdb"
SOURCE_SNMP_ARP = "snmp-arp"


@dataclass
class DhcpPool:
    """A configured DHCP range on a FortiGate interface."""

    firewall: str
    server_id: str
    interface: str
    start_ip: str
    end_ip: str
    netmask: str = ""
    gateway: str = ""
    enabled: bool = True

    @property
    def label(self) -> str:
        return f"{self.firewall}/{self.interface} #{self.server_id}"


@dataclass
class L3Interface:
    """A routed interface — the source of NetBox Prefixes.

    Produced both by the FortiGate collector (interface list) and by the SNMP
    collector (ipAddrTable on an L3 switch), so `device` is whichever appliance
    owns the interface, not necessarily a firewall.
    """

    device: str
    name: str
    address: str
    prefix_len: int
    vlan_id: int | None = None
    alias: str = ""
    description: str = ""
    status: str = "up"

    @property
    def cidr(self) -> str:
        return f"{self.address}/{self.prefix_len}"


@dataclass
class SwitchPortLocation:
    """Where a MAC was learned on the access layer."""

    switch: str
    port: str
    vlan: str | None = None


@dataclass
class SwitchInfo:
    """Identity + port inventory of a polled switch."""

    name: str
    host: str
    vendor: str
    sys_name: str = ""
    sys_descr: str = ""
    reachable: bool = False
    ports: dict[str, str] = field(default_factory=dict)  # ifIndex -> port name
    error: str = ""

    # Filled by the SNMP identity probe (sysObjectID + ENTITY-MIB). Drives the
    # real Manufacturer / DeviceType / serial written to NetBox.
    identity: "DeviceIdentity | None" = None
    # vid -> VLAN name, from dot1qVlanStaticName
    vlans: dict[str, str] = field(default_factory=dict)


@dataclass
class Observation:
    """Everything the current cycle learned about one MAC address."""

    mac: str
    ips: set[str] = field(default_factory=set)
    hostname: str = ""
    sources: set[str] = field(default_factory=set)
    firewall: str = ""
    firewall_interface: str = ""
    location: SwitchPortLocation | None = None

    # Static DHCP reservation state, taken from the FortiGate configuration.
    # This is the flag that makes a record permanent.
    static_reservation: bool = False
    reserved_ips: set[str] = field(default_factory=set)
    reservation_description: str = ""

    # IPs that fall inside a configured DHCP pool (i.e. temporary leases)
    dynamic_ips: set[str] = field(default_factory=set)
    lease_expiry: dict[str, str] = field(default_factory=dict)

    def merge_source(self, source: str) -> None:
        self.sources.add(source)

    @property
    def source_label(self) -> str:
        return ",".join(sorted(self.sources))

    def status_for(self, ip: str) -> str:
        """Map an observed IP to a NetBox IPAddress status.

        reserved -> FortiGate static DHCP reservation (permanent)
        dhcp     -> temporary lease from a configured pool
        active   -> statically configured host seen in ARP
        """
        if self.static_reservation and ip in self.reserved_ips:
            return "reserved"
        if ip in self.dynamic_ips:
            return "dhcp"
        return "active"


@dataclass
class CollectionResult:
    """Aggregated output of one collection pass across all devices."""

    observations: dict[str, Observation] = field(default_factory=dict)
    pools: list[DhcpPool] = field(default_factory=list)
    l3_interfaces: list[L3Interface] = field(default_factory=list)
    switches: list[SwitchInfo] = field(default_factory=list)
    firewalls_ok: int = 0
    firewalls_failed: int = 0
    switches_ok: int = 0
    switches_failed: int = 0

    def observation(self, mac: str) -> Observation:
        obs = self.observations.get(mac)
        if obs is None:
            obs = Observation(mac=mac)
            self.observations[mac] = obs
        return obs

    def summary(self) -> str:
        reserved = sum(1 for o in self.observations.values() if o.static_reservation)
        located = sum(1 for o in self.observations.values() if o.location)
        ips = sum(len(o.ips) for o in self.observations.values())
        return (
            f"{len(self.observations)} MACs / {ips} IPs "
            f"({reserved} static reservations, {located} mapped to a switch port); "
            f"firewalls {self.firewalls_ok} ok / {self.firewalls_failed} failed, "
            f"switches {self.switches_ok} ok / {self.switches_failed} failed"
        )
