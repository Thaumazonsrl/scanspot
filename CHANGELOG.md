# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

* A formal backend interface. The package is already split so that collectors
  and domain logic know nothing about NetBox; the interface itself will be
  defined alongside the second backend rather than guessed at from one.
* Nautobot support.
* phpIPAM support (IPAM objects only — it has no DCIM model to receive
  device types, serials or switch-port locations).
* A read API so other systems can consume the discovery data directly.

## [1.0.0] — 2026-08-27

First public release. Extracted from a single-site NetBox appliance that had
been running in production.

### Added

* **FortiGate collector** over the FortiOS REST API: live ARP table, configured
  DHCP pools, active leases, static DHCP reservations (`reserved-address`) and
  routed interfaces.
* **Multi-vendor SNMP collector** built on the net-snmp CLI tools, with three
  MAC-table strategies tried in order — Q-BRIDGE `dot1qTpFdbPort`, classic
  BRIDGE `dot1dTpFdbPort`, and per-VLAN BRIDGE-MIB for classic Cisco IOS
  (`community@vlan` under v2c, context `vlan-<id>` under v3).
* **Device identification** from `sysObjectID` (IANA enterprise number →
  manufacturer), ENTITY-MIB (model and chassis serial, stack-master aware) and
  per-vendor `sysDescr` parsing, covering 50+ enterprise numbers.
* **NetBox sync**: prefixes, VLANs, DHCP pools as `ipam.IPRange`, infrastructure
  devices, and MAC-anchored endpoint devices with their addresses and
  switch-port location.
* **MAC-anchored correlation** — a host that changes DHCP lease updates its
  existing Device and Interface instead of creating a duplicate, and its
  previous dynamic address is detached and deprecated in the same cycle.
* **Scan targets read from NetBox** on every cycle: tag a device `scan-target`
  and fill in its *Scan address* custom field. No file to edit, no restart.
* **Credential indirection** — devices name a profile; the community string or
  API token behind that name never leaves `.env`.
* **Lifecycle management** — 48h to Deprecated/Offline, 7d to deletion, with
  static DHCP reservations, protected tags, infrastructure and hand-created
  objects all exempt.
* **Safety rails**: a cycle in which no data source responded skips both the
  sync and the cleanup; every write funnels through one method so `DRY_RUN`
  is airtight; only `auto-discovered` objects are ever modified or removed.
* **NetBox version tolerance** — handles the first-class `MACAddress` object of
  NetBox ≥ 4.2 as well as the interface attribute of ≤ 4.1, plus the
  `role`/`device_role` and `object_types`/`content_types` renames.
* **Storage-agnostic package layout.** Collectors (`app/collectors/`) and the
  domain model speak only scanspot's own vocabulary; everything NetBox-specific
  is confined to `app/backends/netbox/`. The prefix longest-match index is pure
  arithmetic in `app/prefixes.py` with no backend dependency.
* Advisory locking so a manual `--once` cannot race the scheduled cycle.
* Container healthcheck backed by a heartbeat file.
* `--check`, `--once` and `-v/--version` command-line entry points.

[Unreleased]: https://github.com/Thaumazonsrl/scanspot/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Thaumazonsrl/scanspot/releases/tag/v1.0.0
