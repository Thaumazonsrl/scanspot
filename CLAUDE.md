# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

scanspot polls network devices and writes what it finds into a source of truth.
Today that means: FortiGate REST + multi-vendor SNMP in, NetBox out.

It is published from a single-site appliance that runs in production, so the
code is older than the repository. Behaviour that looks over-careful usually is
not — see *Invariants* below.

## Commands

The scanner is **Linux-only** (`main.py` uses `fcntl`), so it cannot run
directly on a Windows host — go through Docker.

```bash
pip install -r requirements-dev.txt && python -m pytest   # tests, no network needed
docker compose build
docker compose run --rm scanner python -m app.main --check   # config + connectivity
docker compose exec scanner python -m app.main --once        # one cycle
docker compose exec scanner python -m app.main --version
docker compose logs -f scanner
```

There is no linter and no formatter. The validation loop for a change is:
`pytest` → `docker compose build` → `--check` → `--once` with `DRY_RUN=true`.

## Architecture

### One cycle (`app/main.py::_run_cycle`)

```
targets.load_targets      read the device list OUT OF NetBox (every cycle)
  ↓
collect_all               fortigate.collect (REST) + snmp.collect (net-snmp CLI)
  ↓                       → one CollectionResult, keyed by MAC
sync_vlans → sync_prefixes → sync_dhcp_pools → sync_infrastructure → sync_endpoints
  ↓
run_cleanup               age out stale records
  ↓
_write_heartbeat          /app/state/last_run.json — the healthcheck's liveness proof
```

### The seam that matters

This is the single most important thing to understand before changing anything,
because the roadmap depends on it.

The package layout *is* the seam — everything outside `app/backends/` is
backend-neutral, and that is a property to preserve, not an accident.

```
app/
├── models.py  identity.py  utils.py  config.py  prefixes.py   ← domain, neutral
├── main.py  logging_setup.py  healthcheck.py                  ← orchestration
├── collectors/   fortigate.py  snmp.py                        ← sources, neutral
└── backends/
    └── netbox/   client.py  sync.py  cleanup.py  targets.py   ← NetBox-only
```

| Layer | Knows about NetBox? |
|---|---|
| `models.py` — `Observation` / `CollectionResult` | **No**, pure domain objects |
| `collectors/` | **No** — they speak only the domain model |
| `identity.py`, `utils.py`, `prefixes.py` | **No** — and `identity.py` does no I/O at all |
| `config.py` | **No** |
| `main.py` | Only through the client object it is handed |
| `backends/netbox/` | **Yes, entirely** |

`prefixes.py` holds the longest-match lookup as pure arithmetic; the NetBox
preload that seeds it lives in `backends/netbox/sync.py::build_prefix_index`.
That split is why `tests/test_prefix_index.py` needs no dependencies at all.

**Do not import anything from `backends/` into the domain layer or the
collectors.** If you need to, the abstraction is in the wrong place.

### Invariants

Breaking one of these silently corrupts somebody's source of truth.

* **Every write funnels through `NetBoxClient.write()`.** That single method is
  what makes `DRY_RUN=true` airtight and turns an API error into a log line
  instead of an aborted cycle. A direct `.create()`/`.save()` outside it breaks
  both.
* **The MAC is the anchor.** Endpoints are located via
  `find_interface_by_mac`, so a new DHCP lease updates the existing
  Device/Interface instead of duplicating it. IPs are transient; the MAC is not.
* **Objects without the `auto-discovered` tag were created by a human.** Stamp
  the discovery custom fields on them; never rewrite their status, description
  or tags, and never delete them.
* **A collection outage must never look like an empty network.** If
  `firewalls_ok + switches_ok == 0`, the sync *and* the cleanup are skipped and
  the cycle is reported `failed`.
* **Static DHCP reservations are never deleted.** Read from the FortiGate
  *configuration* (`reserved-address`), not the lease table, so reservations
  outside a pool range are caught too.
* **Cycles hold an advisory lock** on `/app/state/cycle.lock`, which is what
  makes `exec … --once` safe alongside the scheduler.
* **NetBox version tolerance.** `backends/netbox/client.py` handles the ≥4.2 first-class
  `MACAddress` object and the ≤4.1 interface attribute, plus the
  `role`/`device_role` and `object_types`/`content_types` renames. Keep both
  paths.

### SNMP specifics

Shells out to `snmpbulkwalk`/`snmpwalk` (`-Oqn`, numeric OIDs) rather than using
a Python SNMP stack — deliberate, for vendor-quirk coverage. `_read_fdb` tries
Q-BRIDGE `dot1qTpFdbPort` → classic BRIDGE `dot1dTpFdbPort` → per-VLAN
BRIDGE-MIB for classic Cisco IOS (`community@vlan` under v2c, context
`vlan-<id>` under v3). The vendor detected from `sysObjectID` picks the strategy
on the first poll.

A port that learned more than `SNMP_UPLINK_MAC_THRESHOLD` (12) MACs is treated
as a trunk: MACs recorded, no port location attached.

An unmapped IANA enterprise number yields an `Enterprise <n>` placeholder and a
log line. Only add **verified** mappings to `ENTERPRISES` — a wrong one writes a
wrong vendor into a customer database, which is worse than an honest placeholder.

## Direction (not yet public — keep out of README)

The README deliberately claims **NetBox only**. Do not advertise the following
until it ships; early adopters arriving for Nautobot and finding NetBox costs
more credibility than the feature is worth.

The intended end state is *a network discovery service with pluggable
backends*, not a NetBox tool:

1. **Backend abstraction.** ✅ *Package move done in 1.0.0* — the NetBox code
   lives under `app/backends/netbox/` and `PrefixIndex` is a domain module.
   **Still to do:** the interface itself. Define it in **scanspot's**
   vocabulary (`upsert_prefix`, `upsert_endpoint`, `load_targets`, `expire`),
   never in NetBox's. It is deliberately absent for now: the right shape is not
   knowable from one implementation, and an interface derived from NetBox alone
   would just be NetBox's API wearing a hat. Write it *with* the second backend.
2. **Backends are bidirectional.** Each one both *sources* scan scope (subnets,
   devices to poll) and *receives* findings. NetBox does both today.
3. **Nautobot** second. It is a 2020 NetBox fork with a near-identical object
   graph and `pynautobot` mirrors `pynetbox`. Friction: Nautobot models Status
   as a first-class object where NetBox uses choice strings; custom-field
   creation differs; Nautobot 2.x restructured roles.
4. **phpIPAM** third, and it is the one that tests the design. It is IPAM-only:
   no device types, no manufacturers, no platforms, no serials, no interface
   model. Prefixes, addresses and VLANs map; the DCIM half has nowhere to go.
   Handle this with explicit capability flags (`supports_dcim`,
   `supports_custom_fields`), not scattered `try/except`. Note that phpIPAM is a
   perfectly good *source* of scan scope even though it is a poor *sink*.
5. **Local store of record (SQLite).** The unlock for everything else. Scan
   targets currently live in NetBox, which is elegant only while NetBox is
   present — phpIPAM has nowhere to keep them. Once scanspot owns its own state:
   targets live there, the API serves from there, cleanup runs against local
   state instead of querying a remote IPAM, and backends become exporters rather
   than three systems of record kept in sync.
6. **Read/write API** (FastAPI). `GET` observations/devices/targets, `POST`
   targets and scan triggers, API-key auth. Depends on step 5.

"Monitor" in project descriptions means **tracking and status** — first seen,
last seen, offline — not health polling or alerting. scanspot is not an NMS and
should not grow into one.

### Kubernetes caveat, for when the API lands

The cycle lock is an `fcntl` lock on a file in the state volume. It serialises
cycles **within one container** and does nothing across pods. Two replicas will
scan and write simultaneously. Before supporting multi-replica deployments this
needs a real distributed lock (a lease in the backend, or Kubernetes
`coordination.k8s.io/Lease`). Until then: `replicas: 1`.

`python -m app.healthcheck` works as-is as an exec liveness probe.

## Gotchas

* **`verify=` must be passed per request** in `collectors/fortigate.py`. The Dockerfile sets
  `REQUESTS_CA_BUNDLE` so pip works behind a TLS-inspecting proxy, and requests
  lets that env var override `session.verify` — silently turning
  `FORTIGATE_VERIFY_SSL=false` into a no-op against the self-signed certificate
  every FortiGate ships with. `backends/netbox/client.py` solves the same
  problem with `session.trust_env = False`.
* **`certs/` is baked into the image** at build time and `*.crt` is gitignored.
  The CA identifies the network you built on. Never commit one; never ship one
  built on your own proxy to a customer.
* **`sysDescr` yields the software image name** (`C2960-LANBASEK9`), not the
  orderable part number (`WS-C2960-24TT-L`). Correct, and why ENTITY-MIB wins
  when both are present. Not a bug.
* **`.env` holds every secret.** Never echo it into logs, tests or generated
  files.
