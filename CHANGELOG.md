# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* **Local store** (`app/store/`) — SQLAlchemy models, engine with a configurable
  DSN (`SCANSPOT_DB_URL`, SQLite by default, PostgreSQL opt-in), Fernet
  encryption for credential secrets, and Alembic migrations applied by the
  container itself on startup. Schema and rationale: `docs/design/store.md`.
* `site` is a first-class dimension: identity is `(site_id, mac)`, so the same
  address space and the same hardware may appear at more than one office.
* Credential profiles support two storage modes: `inline` (encrypted in the
  database, manageable without a restart) and `env_ref` (the value stays in the
  environment, for Kubernetes Secrets and Vault users). Secrets are a mapping,
  so SNMPv3's two passphrases are first-class rather than a special case.
* Credential profiles defined in `inventory.yml` as `${VAR}` are recorded as
  *references* to that variable — the secret itself is never copied into the
  database.

* **HTTP API** (`app/api/`, FastAPI) served from the same process as the
  scheduler, so the container stays a single unit. Manage scan targets and
  credential profiles, trigger a scan, and read health. OpenAPI document at
  `/api/openapi.json`, docs at `/api/docs`.
  * Authentication by API key (`X-API-Key` or `Authorization: Bearer`), hashed
    with SHA-256. A first key is generated on startup and logged **once**.
  * `/api/v1/health` needs no key — a Kubernetes probe cannot carry one — and
    exposes no infrastructure detail, not even the database password.
  * **Secrets are never returned.** Credential responses carry `has_secret` and
    not the value, nor the names of the environment variables referenced.
  * The API starts *before* NetBox is waited on. A fresh NetBox takes minutes to
    migrate, and that is precisely when targets need to be manageable.
* **Discovery is persisted to the store**, before the backend sync and
  unconditionally: what the network reported is recorded even when NetBox is
  unreachable. Backends are exporters of this data, not the place it lives.
  * `endpoints` / `endpoint_addresses` hold current state, one row per
    `(site, mac)`; `events` is an append-only change log — discovered, moved,
    ip_added, ip_removed, went_offline, returned. No per-cycle snapshot, which
    at a few thousand endpoints would be millions of rows a month.
  * Endpoints not seen for `OFFLINE_AFTER_HOURS` are flagged offline in the
    store. Nothing is deleted there: the history is the reason it exists.
  * Read endpoints: `/devices`, `/devices/{mac}`, `/prefixes`, `/vlans`,
    `/runs`, `/events`, all filterable and paginated.
  * A store failure does not cost the NetBox sync, and a sync failure does not
    cost the stored record.

### Changed

* **Scan targets live in scanspot's store, not in NetBox.** NetBox still offers
  them: devices tagged `scan-target` are imported every cycle, so the workflow
  is unchanged from a user's point of view. Ownership is now explicit — imported
  targets are refreshed from NetBox and disabled when the tag goes away, targets
  created any other way are never touched by the import, and a NetBox outage
  disables nothing.
* `app/backends/netbox/targets.py` is gone. Loading lives in `app/targets.py`
  (backend-neutral); the one-shot 1.x import lives in
  `app/backends/netbox/import_targets.py`.
* The `inventory.yml` seed now creates targets in the store instead of NetBox
  devices, and `state/seeded.json` is no longer used — a target with
  `source="seed"` records the same thing.

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
