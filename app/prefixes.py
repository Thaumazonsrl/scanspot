"""Answering "what mask does this address belong to?".

Discovered addresses arrive bare — the ARP table and the SNMP forwarding
database report a host, never a prefix length. Getting this wrong files an
address under the wrong prefix, which breaks exactly the question scanspot
exists to answer: how much of this subnet is free?

Pure IP arithmetic, no backend dependency. Populating the index from a source of
truth is the backend's job (see `backends/netbox/sync.py::build_prefix_index`).
"""

from __future__ import annotations

import ipaddress


class PrefixIndex:
    """Longest-match lookup over the networks known to this cycle.

    Sources, longest match wins: routed interfaces discovered this cycle (they
    are authoritative and fresh), then prefixes already recorded in the backend,
    then the configured default.
    """

    def __init__(self, default_len: int):
        self.default_len = default_len
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    def add_cidr(self, cidr: str) -> None:
        """Register a network. Malformed input is ignored rather than raised:
        one bad interface address must not abort a whole cycle."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return
        if network not in self._networks:
            self._networks.append(network)

    def prefix_len_for(self, ip: str) -> int:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return self.default_len
        best = None
        for network in self._networks:
            if address.version == network.version and address in network:
                if best is None or network.prefixlen > best:
                    best = network.prefixlen
        if best is not None:
            return best
        # The configured default is an IPv4 assumption; /64 is the only sane
        # default for IPv6.
        return self.default_len if address.version == 4 else 64

    def cidr_for(self, ip: str) -> str:
        return f"{ip}/{self.prefix_len_for(ip)}"
