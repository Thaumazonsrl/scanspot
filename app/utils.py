"""Small shared helpers: MAC normalisation, IP maths, timestamps, slugs."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

_HEX_ONLY = re.compile(r"[^0-9a-fA-F]")
_SLUG_STRIP = re.compile(r"[^a-z0-9]+")

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


# ─────────────────────────────────────────────────────────────── timestamps ──
def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_iso(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def from_iso(value) -> datetime | None:
    """Parse a timestamp written by this scanner. Tolerant of legacy formats."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def age(moment: datetime | None, now: datetime | None = None) -> timedelta | None:
    if moment is None:
        return None
    return (now or utcnow()) - moment


# ───────────────────────────────────────────────────────────────────── MACs ──
def normalize_mac(raw) -> str | None:
    """Return AA:BB:CC:DD:EE:FF, or None when the input is not a usable MAC.

    Accepts every representation seen in the wild: colon, hyphen, dot
    (Cisco aabb.ccdd.eeff), bare hex, and 0x-prefixed SNMP hex strings.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        text = text[2:]
    digits = _HEX_ONLY.sub("", text)
    if len(digits) != 12:
        return None
    mac = ":".join(digits[i : i + 2] for i in range(0, 12, 2)).upper()
    return mac if is_usable_mac(mac) else None


def mac_from_octets(octets) -> str | None:
    """Build a MAC from the 6 decimal octets embedded in an SNMP OID index."""
    try:
        values = [int(o) for o in octets]
    except (TypeError, ValueError):
        return None
    if len(values) != 6 or any(v < 0 or v > 255 for v in values):
        return None
    return normalize_mac("".join(f"{v:02x}" for v in values))


def is_usable_mac(mac: str) -> bool:
    """Reject broadcast, all-zero and multicast addresses.

    A multicast MAC (least-significant bit of the first octet set) is never an
    endpoint NIC, so anchoring a Device on one would create garbage.
    """
    digits = mac.replace(":", "")
    if len(digits) != 12:
        return False
    if digits in ("000000000000", "FFFFFFFFFFFF"):
        return False
    return int(digits[0:2], 16) & 0x01 == 0


def mac_suffix(mac: str, octets: int = 3) -> str:
    return mac.replace(":", "")[-octets * 2 :].lower()


# ────────────────────────────────────────────────────────────────────── IPs ──
def is_valid_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_usable_ip(value) -> bool:
    """Filter out loopback/link-local/multicast/unspecified addresses."""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def netmask_to_prefixlen(netmask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask.strip()}").prefixlen
    except ValueError:
        return None


def parse_forti_ip_field(value) -> tuple[str, int] | None:
    """FortiOS returns interface addresses as '10.0.0.1 255.255.255.0'.

    Also accepts '10.0.0.1/24' and a bare address.
    Returns (address, prefixlen).
    """
    if not value:
        return None
    text = str(value).strip()
    if not text or text.startswith("0.0.0.0"):
        return None
    try:
        if " " in text:
            addr, mask = text.split(None, 1)
            plen = netmask_to_prefixlen(mask)
            if plen is None:
                return None
            return addr, plen
        iface = ipaddress.ip_interface(text)
        return str(iface.ip), iface.network.prefixlen
    except ValueError:
        return None


def ip_in_range(ip: str, start: str, end: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return ipaddress.ip_address(start) <= addr <= ipaddress.ip_address(end)
    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────────── names ──
def slugify(value: str, max_length: int = 100) -> str:
    slug = _SLUG_STRIP.sub("-", str(value).strip().lower()).strip("-")
    return (slug or "unnamed")[:max_length].strip("-")


def sanitize_device_name(value: str, max_length: int = 64) -> str:
    """Turn a DHCP hostname into something safe to use as a NetBox device name."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value).strip()).strip("-._")
    return cleaned[:max_length]
