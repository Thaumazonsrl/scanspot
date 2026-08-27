"""Tests for PrefixIndex — "what mask does this address belong to?".

Getting this wrong writes addresses into the backend under the wrong prefix,
which is precisely the question ("how much of this subnet is free?") the tool
exists to answer.

Pure arithmetic: these tests import no backend and need no dependencies.
"""

from app.prefixes import PrefixIndex


def test_falls_back_to_the_configured_default():
    index = PrefixIndex(default_len=24)
    assert index.prefix_len_for("10.0.0.5") == 24
    assert index.cidr_for("10.0.0.5") == "10.0.0.5/24"


def test_uses_a_known_network():
    index = PrefixIndex(default_len=24)
    index.add_cidr("10.0.0.0/16")
    assert index.prefix_len_for("10.0.5.9") == 16


def test_longest_match_wins():
    """A routed /26 inside a /16 must not be reported as a /16."""
    index = PrefixIndex(default_len=24)
    index.add_cidr("10.0.0.0/16")
    index.add_cidr("10.0.5.0/26")
    assert index.prefix_len_for("10.0.5.9") == 26
    assert index.prefix_len_for("10.0.99.9") == 16


def test_an_address_outside_every_known_network_gets_the_default():
    index = PrefixIndex(default_len=25)
    index.add_cidr("10.0.0.0/16")
    assert index.prefix_len_for("192.168.1.1") == 25


def test_add_cidr_accepts_a_host_address_and_normalises_it():
    index = PrefixIndex(default_len=24)
    index.add_cidr("10.0.5.9/26")          # strict=False -> 10.0.5.0/26
    assert index.prefix_len_for("10.0.5.1") == 26


def test_add_cidr_ignores_junk_rather_than_raising():
    """A malformed interface address from a device must not abort the cycle."""
    index = PrefixIndex(default_len=24)
    index.add_cidr("not-a-cidr")
    index.add_cidr("")
    index.add_cidr("999.1.1.1/24")
    assert index.prefix_len_for("10.0.0.1") == 24


def test_ipv6_defaults_to_64_not_the_ipv4_default():
    index = PrefixIndex(default_len=24)
    assert index.prefix_len_for("2001:db8::1") == 64


def test_ipv6_networks_do_not_match_ipv4_addresses():
    index = PrefixIndex(default_len=24)
    index.add_cidr("2001:db8::/32")
    assert index.prefix_len_for("10.0.0.1") == 24


def test_an_unparseable_address_gets_the_default():
    index = PrefixIndex(default_len=24)
    index.add_cidr("10.0.0.0/16")
    assert index.prefix_len_for("nonsense") == 24


def test_duplicate_networks_are_only_stored_once():
    index = PrefixIndex(default_len=24)
    index.add_cidr("10.0.0.0/16")
    index.add_cidr("10.0.0.0/16")
    assert len(index._networks) == 1
