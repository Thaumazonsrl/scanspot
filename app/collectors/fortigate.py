"""FortiGate collector — FortiOS REST API.

Four things are pulled from every firewall:

  monitor/network/arp        live ARP table            -> IP <-> MAC
  monitor/system/dhcp        active DHCP leases        -> IP <-> MAC + hostname
  cmdb/system.dhcp/server    DHCP servers              -> pools + STATIC
                                                          RESERVATIONS
  cmdb/system/interface      routed interfaces         -> prefixes / VLANs

The `reserved-address` list of each DHCP server is the authoritative source for
static reservations. Entries there are flagged permanent and become exempt from
the auto-deletion logic — including reservations whose IP lies outside the
pool's ip-range, which is exactly why the config is read instead of relying on
the lease table alone.

Authentication is the standard REST API key in an `Authorization: Bearer`
header. The key must belong to a REST API Admin with read access to
System / Network / Router.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..config import FortiGateConfig
from ..models import (
    SOURCE_ARP,
    SOURCE_DHCP,
    SOURCE_RESERVATION,
    CollectionResult,
    DhcpPool,
    L3Interface,
)
from ..utils import (
    ip_in_range,
    is_usable_ip,
    normalize_mac,
    parse_forti_ip_field,
    sanitize_device_name,
)

log = logging.getLogger("fortigate")


class FortiGateError(RuntimeError):
    pass


class FortiGateClient:
    def __init__(self, cfg: FortiGateConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {cfg.api_token}",
                "Accept": "application/json",
            }
        )
        self.session.verify = cfg.verify_ssl
        retry = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        if not cfg.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── low level ───────────────────────────────────────────────────────────
    def _get(self, path: str, **params) -> list[dict]:
        url = f"{self.cfg.base_url}{path}"
        params.setdefault("vdom", self.cfg.vdom)
        try:
            # `verify` is passed per request on purpose. Setting it on the
            # session is not enough: requests replaces a None per-request value
            # with REQUESTS_CA_BUNDLE (which the Dockerfile sets so pip works
            # behind a TLS-inspecting proxy) and that then takes precedence
            # over session.verify — silently turning FORTIGATE_VERIFY_SSL=false
            # into a no-op against the self-signed certificate every FortiGate
            # ships with.
            response = self.session.get(
                url,
                params=params,
                timeout=self.cfg.timeout,
                verify=self.cfg.verify_ssl,
            )
        except requests.RequestException as exc:
            raise FortiGateError(f"{path}: {exc}") from exc

        if response.status_code == 401:
            raise FortiGateError(
                f"{path}: 401 Unauthorized — check FORTIGATE_API_TOKEN and the "
                "REST API admin's Trusted Hosts (this VM's IP must be allowed)"
            )
        if response.status_code == 403:
            raise FortiGateError(
                f"{path}: 403 Forbidden — the API admin profile lacks read access"
            )
        if response.status_code >= 400:
            raise FortiGateError(f"{path}: HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise FortiGateError(f"{path}: response was not JSON") from exc

        results = payload.get("results", [])
        if isinstance(results, dict):  # some monitor endpoints return a mapping
            results = list(results.values())
        return results if isinstance(results, list) else []

    def _get_optional(self, path: str, **params) -> list[dict]:
        """A missing endpoint on an older FortiOS must not abort the cycle."""
        try:
            return self._get(path, **params)
        except FortiGateError as exc:
            log.warning("[%s] %s", self.cfg.name, exc)
            return []

    # ── collectors ──────────────────────────────────────────────────────────
    def arp_table(self) -> list[dict]:
        return self._get("/api/v2/monitor/network/arp")

    def dhcp_leases(self) -> list[dict]:
        return self._get_optional("/api/v2/monitor/system/dhcp")

    def dhcp_servers(self) -> list[dict]:
        return self._get_optional("/api/v2/cmdb/system.dhcp/server")

    def interfaces(self) -> list[dict]:
        return self._get_optional("/api/v2/cmdb/system/interface")

    def system_status(self) -> dict:
        results = self._get_optional("/api/v2/monitor/system/status")
        return results[0] if results else {}


# ─────────────────────────────────────────────────────────────────────────────
# Collection into the shared result object
# ─────────────────────────────────────────────────────────────────────────────


def collect(cfg: FortiGateConfig, result: CollectionResult) -> None:
    """Poll one FortiGate and merge everything it knows into `result`."""
    client = FortiGateClient(cfg)

    # A cheap call first: fail fast and loudly on credential/reachability
    # problems instead of half-populating the result.
    arp_entries = client.arp_table()
    result.capture(cfg.name, "fortios", "monitor/network/arp", {"items": arp_entries})

    pools = _collect_dhcp_config(client, cfg, result)
    _collect_interfaces(client, cfg, result)
    _collect_arp(arp_entries, cfg, result, pools)
    _collect_leases(client, cfg, result, pools)

    log.info(
        "[%s] ARP %d entries, %d DHCP pools, %d L3 interfaces",
        cfg.name,
        len(arp_entries),
        len(pools),
        sum(1 for i in result.l3_interfaces if i.device == cfg.name),
    )


def _collect_dhcp_config(
    client: FortiGateClient, cfg: FortiGateConfig, result: CollectionResult
) -> list[DhcpPool]:
    """Read pools AND static reservations from the DHCP server configuration."""
    pools: list[DhcpPool] = []

    servers = client.dhcp_servers()
    # The authoritative source for static reservations. When a reservation is
    # not picked up, this is the thing to look at.
    result.capture(cfg.name, "fortios", "cmdb/system.dhcp/server", {"items": servers})

    for server in servers:
        server_id = str(server.get("id", ""))
        interface = str(server.get("interface", "") or "")
        enabled = str(server.get("status", "enable")).lower() == "enable"
        netmask = str(server.get("netmask", "") or "")
        gateway = str(server.get("default-gateway", "") or "")

        for entry in server.get("ip-range") or []:
            start = str(entry.get("start-ip", "") or "")
            end = str(entry.get("end-ip", "") or "")
            if not (is_usable_ip(start) and is_usable_ip(end)):
                continue
            pool = DhcpPool(
                firewall=cfg.name,
                server_id=server_id,
                interface=interface,
                start_ip=start,
                end_ip=end,
                netmask=netmask,
                gateway=gateway,
                enabled=enabled,
            )
            pools.append(pool)
            result.pools.append(pool)

        # ---- static DHCP reservations -------------------------------------
        # `action` is assign | block | reserved. Only assign/reserved bind an
        # IP to a MAC; `block` denies the MAC and must not create a record.
        for reservation in server.get("reserved-address") or []:
            action = str(reservation.get("action", "assign") or "assign").lower()
            if action == "block":
                continue
            mac = normalize_mac(reservation.get("mac"))
            ip = str(reservation.get("ip", "") or "").strip()
            if not mac or not is_usable_ip(ip):
                continue

            obs = result.observation(mac)
            obs.merge_source(SOURCE_RESERVATION)
            obs.static_reservation = True
            obs.reserved_ips.add(ip)
            obs.ips.add(ip)
            obs.firewall = obs.firewall or cfg.name
            obs.firewall_interface = obs.firewall_interface or interface
            description = str(reservation.get("description", "") or "").strip()
            if description and not obs.reservation_description:
                obs.reservation_description = description
            # A reservation must never be treated as a temporary lease, even
            # when its IP sits inside the pool range.
            obs.dynamic_ips.discard(ip)

    reserved_macs = sum(1 for o in result.observations.values() if o.static_reservation)
    if reserved_macs:
        log.info("[%s] %d static DHCP reservations (permanent)", cfg.name, reserved_macs)
    return pools


def _collect_interfaces(
    client: FortiGateClient, cfg: FortiGateConfig, result: CollectionResult
) -> None:
    for iface in client.interfaces():
        parsed = parse_forti_ip_field(iface.get("ip"))
        if not parsed:
            continue
        address, prefix_len = parsed
        if not is_usable_ip(address):
            continue
        vlan_raw = iface.get("vlanid")
        try:
            vlan_id = int(vlan_raw) if vlan_raw not in (None, "", 0, "0") else None
        except (TypeError, ValueError):
            vlan_id = None

        result.l3_interfaces.append(
            L3Interface(
                device=cfg.name,
                name=str(iface.get("name", "") or ""),
                address=address,
                prefix_len=prefix_len,
                vlan_id=vlan_id,
                alias=str(iface.get("alias", "") or ""),
                description=str(iface.get("description", "") or ""),
                status=str(iface.get("status", "up") or "up"),
            )
        )


def _collect_arp(
    entries: list[dict],
    cfg: FortiGateConfig,
    result: CollectionResult,
    pools: list[DhcpPool],
) -> None:
    for entry in entries:
        mac = normalize_mac(entry.get("mac"))
        ip = str(entry.get("ip", "") or "").strip()
        if not mac or not is_usable_ip(ip):
            continue

        obs = result.observation(mac)
        obs.merge_source(SOURCE_ARP)
        obs.ips.add(ip)
        obs.firewall = obs.firewall or cfg.name
        interface = str(entry.get("interface", "") or "")
        if interface and not obs.firewall_interface:
            obs.firewall_interface = interface
        if ip not in obs.reserved_ips and _in_any_pool(ip, pools):
            obs.dynamic_ips.add(ip)


def _collect_leases(
    client: FortiGateClient,
    cfg: FortiGateConfig,
    result: CollectionResult,
    pools: list[DhcpPool],
) -> None:
    for lease in client.dhcp_leases():
        mac = normalize_mac(lease.get("mac"))
        ip = str(lease.get("ip", "") or "").strip()
        if not mac or not is_usable_ip(ip):
            continue

        obs = result.observation(mac)
        obs.merge_source(SOURCE_DHCP)
        obs.ips.add(ip)
        obs.firewall = obs.firewall or cfg.name

        interface = str(lease.get("interface", "") or "")
        if interface and not obs.firewall_interface:
            obs.firewall_interface = interface

        hostname = sanitize_device_name(lease.get("hostname") or "")
        if hostname and not obs.hostname:
            obs.hostname = hostname

        expiry = lease.get("expire_time") or lease.get("expire")
        if expiry:
            obs.lease_expiry[ip] = str(expiry)

        # FortiOS marks reserved leases either through `status` or `reserved`.
        # Treat both as confirmation of a static reservation, but the cmdb
        # config read earlier remains the authoritative source.
        status = str(lease.get("status", "") or "").lower()
        if status == "reserved" or _truthy(lease.get("reserved")):
            obs.static_reservation = True
            obs.reserved_ips.add(ip)
            obs.merge_source(SOURCE_RESERVATION)
            obs.dynamic_ips.discard(ip)
        elif ip not in obs.reserved_ips and _in_any_pool(ip, pools):
            obs.dynamic_ips.add(ip)


def _in_any_pool(ip: str, pools: list[DhcpPool]) -> bool:
    return any(ip_in_range(ip, p.start_ip, p.end_ip) for p in pools)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "enable"}
