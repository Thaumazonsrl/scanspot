"""Tests for the MAC / IP / timestamp helpers.

These are the functions every collector feeds its raw wire data through, so a
regression here silently corrupts whatever lands in NetBox.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.utils import (
    age,
    from_iso,
    ip_in_range,
    is_usable_ip,
    is_usable_mac,
    is_valid_ip,
    mac_from_octets,
    mac_suffix,
    netmask_to_prefixlen,
    normalize_mac,
    parse_forti_ip_field,
    sanitize_device_name,
    slugify,
    to_iso,
)

# ─────────────────────────────────────────────────────────────────────── MACs ──


@pytest.mark.parametrize(
    "raw",
    [
        "AA:BB:CC:DD:EE:FF",
        "aa:bb:cc:dd:ee:ff",
        "aa-bb-cc-dd-ee-ff",
        "aabb.ccdd.eeff",       # Cisco dotted-triplet
        "aabbccddeeff",
        "0xAABBCCDDEEFF",       # SNMP hex string
        " AA:BB:CC:DD:EE:FF ",
    ],
)
def test_normalize_mac_accepts_every_wire_format(raw):
    assert normalize_mac(raw) == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "   ",
        "AA:BB:CC",                 # too short
        "AA:BB:CC:DD:EE:FF:00",     # too long
        "ZZ:BB:CC:DD:EE:FF",        # not hex
    ],
)
def test_normalize_mac_rejects_unusable_input(raw):
    assert normalize_mac(raw) is None


@pytest.mark.parametrize(
    "raw",
    [
        "FF:FF:FF:FF:FF:FF",        # broadcast
        "00:00:00:00:00:00",        # all zero
        "01:00:5E:00:00:FB",        # IPv4 multicast (mDNS)
        "33:33:00:00:00:01",        # IPv6 multicast
    ],
)
def test_normalize_mac_rejects_non_endpoint_addresses(raw):
    """Anchoring a Device on a multicast or broadcast MAC would create garbage."""
    assert normalize_mac(raw) is None


def test_is_usable_mac_distinguishes_unicast_from_multicast():
    assert is_usable_mac("AA:BB:CC:DD:EE:FF") is True
    # The multicast bit is the least-significant bit of the first octet.
    assert is_usable_mac("01:BB:CC:DD:EE:FF") is False


def test_mac_from_octets_builds_from_snmp_oid_index():
    assert mac_from_octets(["170", "187", "204", "221", "238", "255"]) == "AA:BB:CC:DD:EE:FF"
    assert mac_from_octets([170, 187, 204, 221, 238, 255]) == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize(
    "octets",
    [
        ["170", "187", "204"],                       # wrong count
        ["256", "187", "204", "221", "238", "255"],  # out of range
        ["-1", "187", "204", "221", "238", "255"],
        ["aa", "187", "204", "221", "238", "255"],   # not decimal
        [],
    ],
)
def test_mac_from_octets_rejects_bad_indices(octets):
    assert mac_from_octets(octets) is None


def test_mac_suffix_is_lowercase_and_sized():
    assert mac_suffix("AA:BB:CC:DD:EE:FF") == "ddeeff"
    assert mac_suffix("AA:BB:CC:DD:EE:FF", octets=2) == "eeff"


# ──────────────────────────────────────────────────────────────────────── IPs ──


def test_is_valid_ip():
    assert is_valid_ip("10.0.0.1") is True
    assert is_valid_ip("2001:db8::1") is True
    assert is_valid_ip("999.1.1.1") is False
    assert is_valid_ip("nonsense") is False


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.254", "172.16.4.9", "8.8.8.8"])
def test_is_usable_ip_accepts_real_hosts(ip):
    assert is_usable_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",      # loopback
        "169.254.10.1",   # link-local / APIPA
        "224.0.0.251",    # multicast
        "0.0.0.0",        # unspecified
        "240.0.0.1",      # reserved
        "not-an-ip",
        "",
    ],
)
def test_is_usable_ip_filters_noise(ip):
    assert is_usable_ip(ip) is False


def test_netmask_to_prefixlen():
    assert netmask_to_prefixlen("255.255.255.0") == 24
    assert netmask_to_prefixlen("255.255.0.0") == 16
    assert netmask_to_prefixlen("255.255.255.255") == 32
    assert netmask_to_prefixlen(" 255.255.254.0 ") == 23


@pytest.mark.parametrize("mask", ["not-a-mask", "255.0.255.0", ""])
def test_netmask_to_prefixlen_rejects_invalid(mask):
    """A non-contiguous mask is not a prefix length and must not be guessed at."""
    assert netmask_to_prefixlen(mask) is None


def test_parse_forti_ip_field_space_separated():
    """FortiOS returns interface addresses as '10.0.0.1 255.255.255.0'."""
    assert parse_forti_ip_field("10.0.0.1 255.255.255.0") == ("10.0.0.1", 24)


def test_parse_forti_ip_field_accepts_cidr_and_bare_address():
    assert parse_forti_ip_field("10.0.0.1/24") == ("10.0.0.1", 24)
    assert parse_forti_ip_field("10.0.0.1") == ("10.0.0.1", 32)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "0.0.0.0 0.0.0.0",      # an unconfigured FortiGate interface
        "0.0.0.0/0",
        "garbage",
        "10.0.0.1 not-a-mask",
    ],
)
def test_parse_forti_ip_field_rejects_unconfigured_interfaces(value):
    assert parse_forti_ip_field(value) is None


def test_ip_in_range_is_inclusive_at_both_ends():
    assert ip_in_range("10.0.0.50", "10.0.0.10", "10.0.0.100") is True
    assert ip_in_range("10.0.0.10", "10.0.0.10", "10.0.0.100") is True
    assert ip_in_range("10.0.0.100", "10.0.0.10", "10.0.0.100") is True
    assert ip_in_range("10.0.0.9", "10.0.0.10", "10.0.0.100") is False
    assert ip_in_range("10.0.0.101", "10.0.0.10", "10.0.0.100") is False


def test_ip_in_range_rejects_invalid_input():
    assert ip_in_range("nonsense", "10.0.0.10", "10.0.0.100") is False


# ────────────────────────────────────────────────────────────────────── names ──


def test_slugify():
    assert slugify("Main Site") == "main-site"
    assert slugify("DHCP Pool") == "dhcp-pool"
    assert slugify("  Hello!!!   World  ") == "hello-world"
    assert slugify("Cisco IOS 15.2(7)E3") == "cisco-ios-15-2-7-e3"


def test_slugify_never_returns_empty():
    """An empty slug would collide across every unnamed object in NetBox."""
    assert slugify("") == "unnamed"
    assert slugify("---") == "unnamed"
    assert slugify("!!!") == "unnamed"


def test_slugify_truncates_and_never_ends_in_a_dash():
    result = slugify("a" * 200, max_length=10)
    assert len(result) <= 10
    assert not result.endswith("-")


def test_sanitize_device_name():
    assert sanitize_device_name("my host!") == "my-host"
    assert sanitize_device_name("  .laptop-01.  ") == "laptop-01"
    assert sanitize_device_name("PC_014") == "PC_014"


def test_sanitize_device_name_respects_the_netbox_length_limit():
    assert len(sanitize_device_name("x" * 200)) == 64


# ───────────────────────────────────────────────────────────────── timestamps ──


def test_to_iso_and_from_iso_round_trip():
    moment = datetime(2026, 1, 31, 12, 30, 45, tzinfo=timezone.utc)
    assert to_iso(moment) == "2026-01-31T12:30:45Z"
    assert from_iso(to_iso(moment)) == moment


def test_to_iso_assumes_utc_for_naive_input():
    assert to_iso(datetime(2026, 1, 31, 12, 0, 0)) == "2026-01-31T12:00:00Z"


def test_from_iso_returns_an_aware_utc_datetime():
    parsed = from_iso("2026-01-31T12:00:00Z")
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timedelta(0)


def test_from_iso_tolerates_a_naive_legacy_timestamp():
    """Records written by older versions must not be treated as un-timestamped:
    cleanup would otherwise re-stamp them and restart the retention clock."""
    parsed = from_iso("2026-01-31T12:00:00")
    assert parsed == datetime(2026, 1, 31, 12, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", [None, "", "garbage", 12345, [], {}])
def test_from_iso_rejects_anything_unparseable(value):
    assert from_iso(value) is None


def test_age():
    now = datetime(2026, 1, 31, 12, 0, 0, tzinfo=timezone.utc)
    earlier = now - timedelta(hours=5)
    assert age(earlier, now) == timedelta(hours=5)
    assert age(None, now) is None
