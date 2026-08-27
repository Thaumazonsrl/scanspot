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
prepare_targets           store → poller configs (NetBox import runs first)
  ↓
collect_all               fortigate.collect (REST) + snmp.collect (net-snmp CLI)
  ↓                       → one CollectionResult, keyed by MAC
_record_run               ★ STORE FIRST — runs, endpoints, addresses, events,
  ↓                         prefixes, vlans, pools. Unconditional.
sync_* (NetBox)           the backend, as an exporter of what was just stored
  ↓
run_cleanup               age out stale NetBox records
  ↓
finish_run                close the run row (status, duration)
  ↓
_write_heartbeat          /app/state/last_run.json — the healthcheck's liveness
```

**Order matters.** The store is written before the backend and independently of
it: what the network reported survives a NetBox outage, and a store failure does
not cost the NetBox sync. Inverting this would make NetBox the source of truth
again and undo the whole 2.0 direction.

The heartbeat file and the `runs` table both exist on purpose. The file is the
container healthcheck's liveness proof — cheap, no database needed. The table is
the history the API serves.

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
5. **Local store of record.** ✅ *Built.* Schema and rationale in
   **`docs/design/store.md`** — read that before touching this area.
   SQLite by default, PostgreSQL opt-in via `SCANSPOT_DB_URL`, never the
   backend's own database. `site` is a first-class dimension, so identity is
   `(site, mac)`. Migrations are applied by the container on startup.

   **Target ownership is the rule to preserve.** The store is authoritative.
   NetBox *offers* targets — `import_targets` runs every cycle, one-way — and:

   * `source="imported"` targets belong to NetBox: refreshed from it, disabled
     when the tag disappears;
   * targets created any other way are never touched by the import;
   * a failed NetBox fetch disables **nothing** — an outage must not look like
     "every device was untagged".

   There is deliberately no two-way sync: a target in the store but absent from
   NetBox was either deleted there or created here, and nothing in the data
   distinguishes the two.
6. **Read/write API** (FastAPI). ✅ *Built* (`app/api/`), served from the
   scheduler's own process so the container stays one unit. Targets,
   credentials, health, scan triggering, and the discovery reads — `/devices`,
   `/prefixes`, `/vlans`, `/runs`, `/events`.

   Invariants for this area:
   * `/health` stays unauthenticated and leaks nothing (the DSN is redacted).
   * **No endpoint ever returns a secret**, including the names of referenced
     environment variables.
   * The API starts *before* the NetBox wait loop. Reordering that would
     reintroduce the bug where a fresh NetBox makes targets unmanageable for
     minutes.
   * Imported targets are read-only over the API: editing one is refused,
     because the next import would revert it.

   **The API exposes the full domain model, not a NetBox-shaped subset.**
   First-party backends (NetBox, later Nautobot) are ours to maintain; everyone
   else integrates over the API — LibreNMS, Zabbix, an in-house CMDB. Trimming
   the payload to what NetBox can hold would silently rob those integrators of
   serials, VLANs and switch-port location. Contract stability matters more here
   than for first-party code: we can refactor our own exporter, not theirs.
   Webhooks/events belong next to this, so integrating does not mean polling.
   `examples/exporters/` carries unsupported sample scripts to show the shape.
7. **Distributed collectors.** A remote agent is `app/collectors/` plus
   `app/models.py` and nothing else — no backend, no store — POSTing a
   `CollectionResult` over HTTPS to the central instance. Push, not pull: remote
   sites sit behind NAT. Each collector gets its own site-scoped API key, and
   must buffer locally when the WAN is down.

"Monitor" in project descriptions means **tracking and status** — first seen,
last seen, offline — not health polling or alerting. scanspot is not an NMS and
should not grow into one.

### Kubernetes caveat, for when the API lands

The cycle lock is an `fcntl` lock on a file in the state volume. It serialises
cycles **within one container** and does nothing across pods. Two replicas will
scan and write simultaneously.

The 2.0 store answers this, and the two choices travel together:

| `SCANSPOT_DB_URL` | Lock | Deployment |
|---|---|---|
| SQLite (default) | `fcntl` on the state volume | single node, `replicas: 1` |
| PostgreSQL | `pg_advisory_lock()` | multi-replica safe |

Until the store lands: `replicas: 1`, no exceptions.

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
