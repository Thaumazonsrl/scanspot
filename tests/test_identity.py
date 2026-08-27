"""Tests for SNMP device identification.

`identity.py` does no I/O, which is the whole reason the vendor knowledge lives
there: a wrong mapping here writes a wrong Manufacturer into somebody's source
of truth, and nobody notices until an audit.
"""

import pytest

from app.identity import (
    build,
    chassis_from_entity,
    enterprise_number,
    manufacturer_for,
    parse_sys_descr,
)

# Real sysDescr strings, kept verbatim — the regexes exist to survive these.
SYSDESCR_IOS = (
    "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
    "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)"
)
SYSDESCR_IOS_XE = (
    "Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software "
    "(CAT9K_IOSXE), Version 17.3.4, RELEASE SOFTWARE (fc3)"
)
SYSDESCR_NXOS = "Cisco Nexus Operating System (NX-OS) Software, Version 9.3(5)"
SYSDESCR_FORTIGATE = "FortiGate-60F v7.2.5,build1517,230606 (GA.M)"
SYSDESCR_MIKROTIK = "RouterOS CRS326-24G-2S+"
SYSDESCR_LINUX = "Linux nas01 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 x86_64"


# ───────────────────────────────────────────────────────────────── sysObjectID ──


def test_enterprise_number_extracts_the_iana_pen():
    # .1.3.6.1.4.1.<PEN>.… — the 7th arc is the enterprise number.
    assert enterprise_number(".1.3.6.1.4.1.9.1.2494") == 9
    assert enterprise_number(".1.3.6.1.4.1.12356.101.1.1") == 12356


def test_enterprise_number_tolerates_a_missing_leading_dot():
    assert enterprise_number("1.3.6.1.4.1.9.1.2494") == 9


@pytest.mark.parametrize(
    "oid",
    [
        "",
        None,
        ".1.3.6.1.2.1.1.1.0",       # not under enterprises
        ".1.3.6.1.4.1",             # no PEN arc
        ".1.3.6.1.4.1.abc.1",       # non-numeric PEN
    ],
)
def test_enterprise_number_returns_none_for_non_enterprise_oids(oid):
    assert enterprise_number(oid) is None


def test_manufacturer_for_known_vendors():
    assert manufacturer_for(".1.3.6.1.4.1.9.1.2494") == "Cisco"
    assert manufacturer_for(".1.3.6.1.4.1.12356.101.1.1") == "Fortinet"
    assert manufacturer_for(".1.3.6.1.4.1.47196.4.1.1") == "HPE Aruba"


def test_manufacturer_for_unknown_pen_is_an_honest_placeholder():
    """A placeholder is better than a guess: it is the signal to extend the
    ENTERPRISES table, and it never writes a wrong vendor into NetBox."""
    assert manufacturer_for(".1.3.6.1.4.1.99999.1.1") == "Enterprise 99999"


def test_manufacturer_for_returns_empty_when_there_is_no_pen():
    assert manufacturer_for("") == ""
    assert manufacturer_for(".1.3.6.1.2.1.1.1.0") == ""


# ──────────────────────────────────────────────────────────────────── sysDescr ──


def test_parse_sys_descr_cisco_ios():
    parsed = parse_sys_descr(SYSDESCR_IOS)
    assert parsed["os"] == "IOS"
    assert parsed["version"] == "15.0(2)SE11"
    assert "C2960" in parsed["model"]


def test_parse_sys_descr_cisco_ios_xe():
    parsed = parse_sys_descr(SYSDESCR_IOS_XE)
    assert parsed["version"] == "17.3.4"
    assert "IOS" in parsed["os"]


def test_parse_sys_descr_nxos():
    parsed = parse_sys_descr(SYSDESCR_NXOS)
    assert parsed["os"] == "NX-OS"
    assert parsed["version"] == "9.3(5)"


def test_parse_sys_descr_fortigate():
    parsed = parse_sys_descr(SYSDESCR_FORTIGATE)
    assert parsed["model"] == "FortiGate-60F"
    assert parsed["version"] == "7.2.5"
    assert parsed["os"] == "FortiOS"


def test_parse_sys_descr_mikrotik():
    parsed = parse_sys_descr(SYSDESCR_MIKROTIK)
    assert parsed["os"] == "RouterOS"
    assert parsed["model"] == "CRS326-24G-2S+"


def test_parse_sys_descr_linux():
    parsed = parse_sys_descr(SYSDESCR_LINUX)
    assert parsed["os"] == "Linux"
    assert parsed["version"].startswith("5.15.0")


def test_parse_sys_descr_normalises_embedded_whitespace():
    """SNMP strings arrive with newlines and padding; the rules assume one line."""
    noisy = "Cisco IOS Software, C2960 Software\n   (C2960-LANBASEK9-M),\n Version 15.0(2)SE11,"
    assert parse_sys_descr(noisy)["version"] == "15.0(2)SE11"


@pytest.mark.parametrize("value", ["", None, "   ", "Some unbranded device"])
def test_parse_sys_descr_returns_empty_when_nothing_matches(value):
    assert parse_sys_descr(value) == {}


# ────────────────────────────────────────────────────────────────── ENTITY-MIB ──


def test_chassis_from_entity_picks_the_chassis_row():
    rows = {
        "1": {"class": "3", "model": "WS-C2960-24TT-L", "serial": "FOC1234X5YZ"},
        "2": {"class": "10", "model": "GLC-SX-MM"},          # a transceiver
        "3": {"class": "6", "model": "PWR-C1-350WAC"},        # a power supply
    }
    chassis = chassis_from_entity(rows)
    assert chassis["serial"] == "FOC1234X5YZ"
    assert chassis["model"] == "WS-C2960-24TT-L"


def test_chassis_from_entity_prefers_the_stack_master():
    """Stacked switches expose one chassis row per member; the lowest
    entPhysicalIndex is the master, and its serial is the one on the device."""
    rows = {
        "10": {"class": "3", "serial": "MEMBER-TWO"},
        "1": {"class": "3", "serial": "MASTER-ONE"},
    }
    assert chassis_from_entity(rows)["serial"] == "MASTER-ONE"


def test_chassis_from_entity_sorts_numerically_not_lexically():
    rows = {
        "2": {"class": "3", "serial": "SECOND"},
        "10": {"class": "3", "serial": "TENTH"},
    }
    assert chassis_from_entity(rows)["serial"] == "SECOND"


@pytest.mark.parametrize("rows", [{}, None, {"1": {"class": "6"}}])
def test_chassis_from_entity_returns_empty_without_a_chassis(rows):
    assert chassis_from_entity(rows or {}) == {}


# ─────────────────────────────────────────────────────────────────────── build ──


def test_build_prefers_entity_mib_over_sysdescr_for_the_model():
    identity = build(
        sys_object_id=".1.3.6.1.4.1.9.1.2494",
        sys_descr=SYSDESCR_IOS,
        entity_rows={"1": {"class": "3", "model": "WS-C2960-24TT-L", "serial": "FOC1"}},
    )
    assert identity.manufacturer == "Cisco"
    assert identity.model == "WS-C2960-24TT-L"
    assert identity.model_source == "entity-mib"
    assert identity.serial == "FOC1"


def test_build_falls_back_to_sysdescr_without_entity_mib():
    identity = build(sys_object_id=".1.3.6.1.4.1.12356.101.1.1", sys_descr=SYSDESCR_FORTIGATE)
    assert identity.manufacturer == "Fortinet"
    assert identity.model == "FortiGate-60F"
    assert identity.model_source == "sysdescr"
    assert identity.serial == ""


def test_build_falls_back_to_sysobjectid_when_nothing_else_parses():
    """The device must still land under a distinguishable type."""
    identity = build(sys_object_id=".1.3.6.1.4.1.9.1.2494", sys_descr="unparseable")
    assert identity.model == "Unknown 2494"
    assert identity.model_source == "sysobjectid"


def test_build_lets_entity_mib_name_an_unknown_vendor():
    """A name straight off the chassis beats an 'Enterprise <n>' placeholder."""
    identity = build(
        sys_object_id=".1.3.6.1.4.1.99999.1",
        entity_rows={"1": {"class": "3", "mfg": "Obscure Networks", "model": "X1"}},
    )
    assert identity.manufacturer == "Obscure Networks"


def test_build_never_lets_entity_mib_override_a_verified_pen():
    """The PEN is unambiguous; entPhysicalMfgName is free text and often an OEM."""
    identity = build(
        sys_object_id=".1.3.6.1.4.1.9.1.2494",
        entity_rows={"1": {"class": "3", "mfg": "Some OEM Reseller", "model": "X1"}},
    )
    assert identity.manufacturer == "Cisco"


def test_build_cleans_padded_and_quoted_snmp_strings():
    identity = build(
        sys_object_id=".1.3.6.1.4.1.9.1.2494",
        entity_rows={"1": {"class": "3", "model": '  "WS-C2960"  ', "serial": "N/A"}},
    )
    assert identity.model == "WS-C2960"
    assert identity.serial == ""      # "N/A" is not a serial number


def test_platform_is_prefixed_with_the_manufacturer():
    identity = build(sys_object_id=".1.3.6.1.4.1.9.1.2494", sys_descr=SYSDESCR_IOS)
    assert identity.platform == "Cisco IOS 15.0(2)SE11"


def test_platform_is_not_double_prefixed():
    identity = build(sys_object_id=".1.3.6.1.4.1.12356.101.1.1", sys_descr=SYSDESCR_FORTIGATE)
    assert identity.platform.count("Forti") >= 1
    assert not identity.platform.startswith("Fortinet Fortinet")


def test_platform_is_empty_without_an_os():
    identity = build(sys_object_id=".1.3.6.1.4.1.9.1.2494", sys_descr="unparseable")
    assert identity.platform == ""


def test_vendor_key_drives_the_mac_table_strategy():
    """This is what gets a Cisco the per-VLAN BRIDGE-MIB walk on the first poll
    without anybody configuring it."""
    assert build(sys_object_id=".1.3.6.1.4.1.9.1.2494").vendor_key == "cisco"
    assert build(sys_object_id=".1.3.6.1.4.1.12356.101.1").vendor_key == "fortinet"
    assert build(sys_object_id=".1.3.6.1.4.1.47196.4.1").vendor_key == "aruba"
    assert build(sys_object_id=".1.3.6.1.4.1.99999.1").vendor_key == "generic"


def test_build_survives_a_device_that_answers_nothing():
    identity = build()
    assert identity.manufacturer == ""
    assert identity.model == ""
    assert identity.serial == ""
    assert identity.platform == ""
    assert identity.vendor_key == "generic"
