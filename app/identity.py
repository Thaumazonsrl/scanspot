"""Who is this device? Vendor, model, serial and OS, from SNMP.

Three sources, in decreasing order of trust:

  1. ENTITY-MIB (.1.3.6.1.2.1.47.1.1.1.1) — the physical entity table. The row
     whose entPhysicalClass is 3 (chassis) carries entPhysicalModelName and
     entPhysicalSerialNum, i.e. the exact orderable part number and the serial
     printed on the box. Cisco, Aruba/HPE, Juniper, Huawei, Extreme and
     FortiSwitch all populate it. This is the only source that yields a serial.

  2. sysObjectID (.1.3.6.1.2.1.1.2.0) — always present, never ambiguous. Its
     7th arc is the IANA Private Enterprise Number:

         .1.3.6.1.4.1.9.1.2494
          └─────┬────┘ │ └┬─┘
            iso.org…    │  └── vendor-private model id
             enterprises└───── PEN 9 = Cisco

     The PEN gives the manufacturer with certainty even when sysDescr is
     unparseable, so it is what drives the Manufacturer object in NetBox.

  3. sysDescr (.1.3.6.1.2.1.1.1.0) — free text. Parsed with per-vendor regexes
     to recover the model and the OS version when ENTITY-MIB is absent (cheap
     switches, Linux hosts, MikroTik).

Nothing here does I/O: `snmp.py` performs the walks and hands the raw values
over, which keeps the vendor knowledge in one testable place.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

log = logging.getLogger("identity")

# ── OIDs (walked by snmp.py) ────────────────────────────────────────────────
OID_SYS_OBJECT_ID = ".1.3.6.1.2.1.1.2.0"

OID_ENT_PHYSICAL_DESCR = ".1.3.6.1.2.1.47.1.1.1.1.2"
OID_ENT_PHYSICAL_CLASS = ".1.3.6.1.2.1.47.1.1.1.1.5"
OID_ENT_PHYSICAL_NAME = ".1.3.6.1.2.1.47.1.1.1.1.7"
OID_ENT_PHYSICAL_HW_REV = ".1.3.6.1.2.1.47.1.1.1.1.8"
OID_ENT_PHYSICAL_SW_REV = ".1.3.6.1.2.1.47.1.1.1.1.10"
OID_ENT_PHYSICAL_SERIAL = ".1.3.6.1.2.1.47.1.1.1.1.11"
OID_ENT_PHYSICAL_MFG = ".1.3.6.1.2.1.47.1.1.1.1.12"
OID_ENT_PHYSICAL_MODEL = ".1.3.6.1.2.1.47.1.1.1.1.13"

ENT_CLASS_CHASSIS = "3"

_ENTERPRISE_PREFIX = ".1.3.6.1.4.1."

# ── IANA Private Enterprise Numbers ─────────────────────────────────────────
# Only entries that have been verified are listed: a wrong mapping silently
# writes a wrong Manufacturer into the client's database, which is worse than
# an honest "Enterprise <n>" placeholder. Add new ones as they are met.
ENTERPRISES: dict[int, str] = {
    9: "Cisco",
    11: "HPE",                      # ProCurve / classic HP networking
    29671: "Cisco Meraki",
    12356: "Fortinet",
    14823: "Aruba Networks",        # wireless controllers and APs
    47196: "HPE Aruba",             # ArubaOS-CX switches
    25506: "H3C",                   # also HPE Comware
    2011: "Huawei",
    2636: "Juniper Networks",
    6486: "Alcatel-Lucent Enterprise",
    1916: "Extreme Networks",
    30065: "Arista Networks",
    1588: "Brocade",
    25053: "Ruckus Networks",
    14988: "MikroTik",
    41112: "Ubiquiti Networks",
    11863: "TP-Link",
    171: "D-Link",
    890: "Zyxel",
    4526: "NETGEAR",
    43: "3Com",
    674: "Dell",
    6027: "Dell Networking",
    232: "HPE",                     # iLO / ProLiant agents
    25461: "Palo Alto Networks",
    2620: "Check Point",
    3097: "WatchGuard",
    2604: "Sophos",
    3375: "F5 Networks",
    5951: "Citrix",
    318: "APC",
    534: "Eaton",
    476: "Vertiv",
    6574: "Synology",
    24681: "QNAP",
    10642: "Zebra",
    368: "Axis Communications",
    253: "Xerox",
    641: "Lexmark",
    367: "Ricoh",
    1347: "Kyocera",
    1602: "Canon",
    1248: "Seiko Epson",
    2435: "Brother",
    18334: "Konica Minolta",
    6889: "Avaya",
    343: "Intel",
    311: "Microsoft",
    42: "Oracle",
    8072: "Net-SNMP",               # generic Linux/BSD agent
    2021: "Net-SNMP",               # legacy UCD-SNMP branch
}

# Manufacturer name -> the vendor key snmp.py uses to pick a MAC-table strategy
VENDOR_KEYS: dict[str, str] = {
    "cisco": "cisco",
    "cisco meraki": "cisco",
    "fortinet": "fortinet",
    "hpe": "hpe",
    "hpe aruba": "aruba",
    "aruba networks": "aruba",
    "h3c": "hpe",
    "huawei": "huawei",
    "juniper networks": "juniper",
    "alcatel-lucent enterprise": "alcatel",
    "extreme networks": "generic",
    "arista networks": "generic",
}


@dataclass
class DeviceIdentity:
    """What SNMP was able to establish about a device."""

    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    os_name: str = ""
    os_version: str = ""
    sys_object_id: str = ""
    sys_name: str = ""
    sys_descr: str = ""
    # Which source produced the model: entity-mib | sysdescr | sysobjectid
    model_source: str = ""

    @property
    def platform(self) -> str:
        """NetBox Platform name, e.g. 'Cisco IOS 15.2(7)E3'."""
        parts = [self.os_name, self.os_version]
        name = " ".join(part for part in parts if part).strip()
        if not name:
            return ""
        if self.manufacturer and not name.lower().startswith(
            self.manufacturer.split()[0].lower()
        ):
            name = f"{self.manufacturer} {name}"
        return name[:100]

    @property
    def vendor_key(self) -> str:
        return VENDOR_KEYS.get(self.manufacturer.strip().lower(), "generic")

    def describe(self) -> str:
        bits = [self.manufacturer or "unknown vendor", self.model or "unknown model"]
        if self.serial:
            bits.append(f"s/n {self.serial}")
        if self.os_version:
            bits.append(f"{self.os_name} {self.os_version}".strip())
        return " / ".join(bits)


# ────────────────────────────────────────────────────────────── sysObjectID ──
def enterprise_number(sys_object_id: str) -> int | None:
    """Extract the IANA PEN from a sysObjectID."""
    text = (sys_object_id or "").strip()
    if not text:
        return None
    if not text.startswith("."):
        text = f".{text}"
    if not text.startswith(_ENTERPRISE_PREFIX):
        return None
    tail = text[len(_ENTERPRISE_PREFIX) :].split(".")
    if not tail or not tail[0].isdigit():
        return None
    return int(tail[0])


def manufacturer_for(sys_object_id: str) -> str:
    """Manufacturer name for a sysObjectID, never empty."""
    pen = enterprise_number(sys_object_id)
    if pen is None:
        return ""
    known = ENTERPRISES.get(pen)
    if known:
        return known
    log.info(
        "unknown SNMP enterprise number %d (sysObjectID %s) — "
        "recorded as a placeholder manufacturer",
        pen,
        sys_object_id,
    )
    return f"Enterprise {pen}"


# ───────────────────────────────────────────────────────────────── sysDescr ──
# Ordered: the first rule that matches wins. Named groups model/os/version are
# all optional; whatever a rule can extract is used.
_SYSDESCR_RULES: list[tuple[str, re.Pattern]] = [
    (
        "cisco-ios",
        re.compile(
            r"Cisco IOS Software.*?\((?P<model>[A-Z0-9_\-]+?)[\-_]"
            r"[A-Z0-9]*?M?\),\s*Version\s+(?P<version>[\w.()]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "cisco-ios-generic",
        re.compile(
            r"(?P<os>Cisco IOS[\- ]?XE|Cisco IOS).*?Version\s+(?P<version>[\w.()]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "cisco-nxos",
        re.compile(
            r"(?P<os>NX-OS).*?[Vv]ersion\s+(?P<version>[\w.()]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "fortinet",
        re.compile(
            r"(?P<model>Forti\w+[\w\-]*)\s+v(?P<version>[\d.]+),\s*build",
            re.IGNORECASE,
        ),
    ),
    (
        "aruba-cx",
        re.compile(
            r"Aruba\s+(?:\w+\s+)?(?P<model>[A-Z0-9][\w\-+/]*)"
            r"(?:\s+Switch)?.*?revision\s+(?P<version>[\w.]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "procurve",
        re.compile(
            r"(?:ProCurve|HP|HPE)\s+\S*\s*Switch\s+(?P<model>[\w\-]+)"
            r".*?revision\s+(?P<version>[\w.]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "comware",
        re.compile(
            r"(?P<os>Comware).*?Software Version\s+(?P<version>[\w.]+)"
            r".*?(?:HPE|HP|H3C)\s+(?P<model>[\w\-]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "huawei-vrp",
        re.compile(
            r"(?P<os>VRP).*?Version\s+(?P<version>[\w.]+)\s*\((?P<model>[\w\-]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "juniper",
        re.compile(
            r"Juniper Networks.*?\b(?P<model>[a-z]{2,3}\d{3,4}[\w\-]*)\b"
            r".*?(?P<os>JUNOS)\s+(?P<version>[\w.\-]+)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "alcatel",
        re.compile(
            r"Alcatel-Lucent.*?(?P<model>OS\d{4}[\w\-]*).*?"
            r"(?P<version>\d+\.\d+\.\d+[\w.]*)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "extremexos",
        re.compile(
            r"(?P<os>ExtremeXOS)\s*\((?P<model>[\w\-]+)\)\s*version\s+(?P<version>[\w.]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "mikrotik",
        re.compile(r"(?P<os>RouterOS)\s+(?P<model>[\w\-+]+)", re.IGNORECASE),
    ),
    (
        "linux",
        re.compile(
            r"^(?P<os>Linux)\s+\S+\s+(?P<version>[\w.\-]+)",
            re.IGNORECASE,
        ),
    ),
]

_OS_BY_RULE = {
    "cisco-ios": "IOS",
    "cisco-ios-generic": "IOS",
    "cisco-nxos": "NX-OS",
    "fortinet": "FortiOS",
    "aruba-cx": "ArubaOS",
    "procurve": "ProCurve",
    "comware": "Comware",
    "huawei-vrp": "VRP",
    "juniper": "JUNOS",
    "alcatel": "AOS",
    "extremexos": "ExtremeXOS",
    "mikrotik": "RouterOS",
    "linux": "Linux",
}


def parse_sys_descr(sys_descr: str) -> dict[str, str]:
    """Best-effort model / OS / version extraction from the sysDescr string."""
    text = " ".join((sys_descr or "").split())
    if not text:
        return {}

    for rule_name, pattern in _SYSDESCR_RULES:
        match = pattern.search(text)
        if match is None:
            continue
        groups = {k: (v or "").strip() for k, v in match.groupdict().items()}
        found = {key: value for key, value in groups.items() if value}
        if not found:
            continue
        found.setdefault("os", _OS_BY_RULE.get(rule_name, ""))
        log.debug("sysDescr matched rule '%s': %s", rule_name, found)
        return found
    return {}


# ──────────────────────────────────────────────────────────────── ENTITY-MIB ──
def chassis_from_entity(rows: dict[str, dict[str, str]]) -> dict[str, str]:
    """Pick the chassis row out of a parsed entPhysicalTable.

    Stacked switches expose one chassis row per member; the lowest index is the
    stack master, which is the unit whose serial belongs on the NetBox device.
    """
    chassis = [
        (index, row)
        for index, row in rows.items()
        if row.get("class") == ENT_CLASS_CHASSIS
    ]
    if not chassis:
        return {}

    def sort_key(item: tuple[str, dict[str, str]]):
        index = item[0]
        return (0, int(index)) if index.isdigit() else (1, 0)

    chassis.sort(key=sort_key)
    index, row = chassis[0]
    if len(chassis) > 1:
        log.debug("%d chassis entries found, using entPhysicalIndex %s", len(chassis), index)
    return row


# ──────────────────────────────────────────────────────────────────── build ──
def build(
    sys_object_id: str = "",
    sys_descr: str = "",
    sys_name: str = "",
    entity_rows: dict[str, dict[str, str]] | None = None,
) -> DeviceIdentity:
    """Combine every available signal into one identity."""
    identity = DeviceIdentity(
        sys_object_id=(sys_object_id or "").strip(),
        sys_name=(sys_name or "").strip(),
        sys_descr=" ".join((sys_descr or "").split()),
    )

    identity.manufacturer = manufacturer_for(identity.sys_object_id)

    parsed = parse_sys_descr(identity.sys_descr)
    chassis = chassis_from_entity(entity_rows or {})

    # Model: ENTITY-MIB first, then sysDescr, then the sysObjectID itself so
    # that the device still lands under a distinguishable type.
    model = _clean(chassis.get("model"))
    if model:
        identity.model_source = "entity-mib"
    if not model:
        model = _clean(parsed.get("model"))
        if model:
            identity.model_source = "sysdescr"
    if not model and identity.sys_object_id:
        model = f"Unknown {identity.sys_object_id.rsplit('.', 1)[-1]}"
        identity.model_source = "sysobjectid"
    identity.model = model[:100]

    identity.serial = _clean(chassis.get("serial"))[:50]

    # A manufacturer name straight from the box beats the PEN table when the
    # PEN is unknown to us, but never overrides a verified mapping.
    entity_mfg = _clean(chassis.get("mfg"))
    if entity_mfg and (
        not identity.manufacturer or identity.manufacturer.startswith("Enterprise ")
    ):
        identity.manufacturer = entity_mfg[:100]

    identity.os_name = _clean(parsed.get("os"))
    identity.os_version = _clean(parsed.get("version")) or _clean(chassis.get("sw"))

    return identity


def _clean(value: str | None) -> str:
    """SNMP strings arrive padded, quoted or with embedded newlines."""
    if not value:
        return ""
    text = " ".join(str(value).split()).strip().strip('"').strip()
    # net-snmp renders an empty octet string as an empty pair of quotes
    if text in ("", '""', "NULL", "N/A", "Not Specified", "not set"):
        return ""
    return text
