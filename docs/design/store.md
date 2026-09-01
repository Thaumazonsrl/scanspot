# Design — local store (2.0)

Status: **proposal**. Written before implementation so the schema decisions that
are expensive to change later get made deliberately.

## Why scanspot needs its own store

Today scan targets live in NetBox: a device tagged `scan-target` with four
custom fields. That is elegant while NetBox is the only backend, and impossible
otherwise — phpIPAM has no DCIM model, so there is nowhere to put them.

More fundamentally: **the store of record cannot depend on which backend is
being synced to.** Once scanspot owns its own state, backends become exporters
rather than three systems of record kept in agreement.

### Decisions taken

| | |
|---|---|
| **Target ownership** | scanspot's store is authoritative. NetBox can *offer* targets through an explicit import; there is no continuous two-way sync |
| **Engine** | SQLite by default, PostgreSQL opt-in via `SCANSPOT_DB_URL` |
| **Never** | the backend's own database. It would couple us to NetBox's schema, migrations and Postgres version, and break every non-NetBox backend |
| **Locking** | file advisory lock with SQLite (single node); `pg_advisory_lock()` with Postgres (enables multi-replica) |
| **Site** | a first-class dimension from day one, not retrofitted |

### Why not two-way target sync

Deletion is ambiguous. A target present in the store but absent from NetBox was
either deleted there or created here, and nothing in the data distinguishes the
two. Add loops, races with the running cycle, and the fact that phpIPAM cannot
hold targets at all — meaning the behaviour could not be uniform across backends
anyway — and an explicit import wins on every axis that matters.

The NetBox plugin makes this *feel* bidirectional: an "Add to scanspot" button
on the device page calls the API. The user experience is native; the
architecture stays one-way.

## Schema

Types are written generically. Timestamps are UTC.

### Tenancy

```
sites
  id            pk
  slug          unique
  name
  created_at

collectors                      -- a remote agent, or the central instance
  id            pk
  site_id       fk sites
  name
  api_key_hash                  -- never store the key itself
  version                       -- reported by the agent
  last_seen_at
  enabled
```

**Why `site` must exist from the start.** Different offices reuse RFC1918: two
sites will both contain `192.168.1.10`, and both may contain the same MAC after
hardware is moved. Identity is therefore `(site_id, mac)`, never `mac` alone,
and prefixes are scoped per site. Retrofitting this later means rewriting every
uniqueness constraint and every query.

Today's global `NETBOX_SITE` becomes a per-target attribute.

### Credentials

```
credential_profiles
  id            pk
  site_id       fk sites, nullable      -- null = available to every site
  name
  kind                                  -- snmp | fortios
  storage                               -- inline | env_ref
  secret_encrypted  blob, nullable      -- Fernet, key from SCANSPOT_SECRET_KEY
  env_var           text, nullable      -- name of the variable to read
  params            json                -- snmp_version, v3_username, security
                                        -- level, port, vdom, timeout …
  created_at, updated_at
  unique (site_id, name)
```

Two storage modes, deliberately:

* **`inline`** — encrypted at rest in the store, managed through the API or the
  plugin. No restart to add a FortiGate.
* **`env_ref`** — the profile names an environment variable and the value is
  read at use time. Anyone injecting secrets from Kubernetes Secrets or Vault
  does not want them in your database, and those are the same people who ask for
  a Kubernetes deployment.

**Secrets are never returned by the API.** Write-only fields; reads expose
`has_secret: true` and nothing else.

### Targets

```
targets
  id            pk
  site_id       fk sites
  name
  address                               -- IP or hostname
  method                                -- snmp | fortios
  credential_profile_id  fk
  vendor_override        nullable
  enabled
  source                                -- manual | imported | seed
  external_ref           nullable       -- e.g. the NetBox device id it came from
  created_at, updated_at
  unique (site_id, address, method)
```

`source` and `external_ref` let an import be repeated without duplicating, and
let the UI show where a target came from.

### Discovery state

Current state, plus an append-only change log. **Not one snapshot per cycle** —
at 5000 endpoints and hourly cycles that would be ~120k rows a day. Current
state stays bounded; the event log is what gives "tracking" for free, and can be
pruned independently.

```
endpoints                               -- one row per (site, mac)
  id            pk
  site_id       fk sites
  mac
  hostname             nullable
  status                                -- active | offline | deprecated
  static_reservation   bool
  switch_name          nullable
  switch_port          nullable
  vlan                 nullable
  firewall             nullable
  firewall_interface   nullable
  first_seen_at, last_seen_at
  last_run_id   fk runs
  unique (site_id, mac)

endpoint_addresses
  id            pk
  endpoint_id   fk endpoints
  ip
  prefix_len
  kind                                  -- active | dhcp | reserved
  first_seen_at, last_seen_at
  unique (endpoint_id, ip)

events                                  -- append-only
  id            pk
  site_id       fk sites
  endpoint_id   fk endpoints, nullable
  run_id        fk runs
  type                                  -- discovered | ip_changed | port_changed
                                        -- | went_offline | reservation_added | …
  payload       json
  created_at
```

### Infrastructure findings

```
prefixes
  id, site_id, cidr, source_device, source_interface, vlan_id,
  description, first_seen_at, last_seen_at
  unique (site_id, cidr)

vlans
  id, site_id, vid, name, first_seen_at, last_seen_at
  unique (site_id, vid)

dhcp_pools
  id, site_id, firewall, interface, start_ip, end_ip, enabled,
  first_seen_at, last_seen_at
```

### Cycles

```
runs
  id            pk
  site_id       fk sites
  collector_id  fk collectors, nullable
  started_at, finished_at
  status                                -- ok | degraded | failed | idle | error | skipped
  firewalls_ok, firewalls_failed
  switches_ok,  switches_failed
  mac_count
  duration_seconds
  error         nullable
```

This replaces `state/last_run.json`. The healthcheck reads the newest row.

### Backend synchronisation

```
backend_syncs
  id            pk
  backend                               -- netbox | nautobot | …
  object_type                           -- endpoint | prefix | vlan | dhcp_pool
  local_id
  remote_id
  last_synced_at
  last_status
  unique (backend, object_type, local_id)
```

Makes pushes idempotent, survives a backend that renumbers, and lets a backend
that *cannot* hold an object type simply have no rows for it — no data is lost
locally, which is what makes a degraded backend acceptable rather than lossy.

### API access

```
api_keys
  id, name, key_hash, scopes, site_id nullable,   -- null = all sites
  created_at, last_used_at, revoked_at
```

A collector's key is scoped to its own site and can write only its own
observations.

## Migration from 1.x

On first 2.0 start against an empty store:

1. If `NETBOX_URL` is configured, import every device tagged `scan-target` into
   `targets`, mapping the four custom fields and recording
   `source = imported`, `external_ref = <netbox device id>`.
2. Import the profiles from `inventory.yml` as `env_ref` profiles — they already
   reference `${VAR}`, so no secret moves into the database unless the operator
   later chooses `inline`.
3. Seed a default site from `NETBOX_SITE`.
4. Carry over `state/seeded.json` so the first-run seed is not replayed.

The import is one-shot and idempotent by `external_ref`. Afterwards the
`scan-target` tag is no longer consulted; the README and the plugin both point
at the new workflow.

This is a **breaking change** and ships as 2.0.

## Decided

* **Event retention — both limits, applied together.** `EVENT_RETENTION_DAYS`
  (365) drops anything older; `EVENT_KEEP_PER_TYPE` (1) keeps only the most
  recent event of each type per endpoint. The second is what matters in
  practice: a laptop on DHCP would otherwise write an `ip_added` row every day
  for years. Nothing irreplaceable is lost, because `first_seen_at` and
  `last_seen_at` live on the endpoint row and are never pruned — the log only
  holds the narrative. Both are tunable; raise `EVENT_KEEP_PER_TYPE` to keep
  more history, set either to 0 to disable that half.

* **Raw observations — opt-in, off by default.** `CAPTURE_RAW` stores the
  unaltered device replies (`sysDescr`, `sysObjectID`, ENTITY-MIB, the FDB and
  its two translation maps, the FortiGate ARP table and DHCP configuration) in
  `raw_observations`, readable through `GET /api/v1/raw`. Only the last
  `RAW_KEEP_RUNS` (3) cycles are retained.

  The case for it is specific to this project: vendor quirks are the hard part,
  and diagnosing one currently means standing in front of the device again. The
  case against is volume — a full forwarding database per switch per cycle. An
  interruttore satisfies both: nothing is even collected when it is off, so the
  cost is zero rather than small.

## Open questions

* **Roaming MACs.** A device physically moved between sites appears as two
  endpoints under `(site, mac)`. Correct for inventory, arguably wrong for asset
  tracking. Leave as-is for 2.0 and revisit if it comes up in practice.
* **Site mapping.** Is a scanspot site 1:1 with a NetBox Site, or looser (a
  Tenant, a Location)? Affects the sync layer, not this schema.
* **Collector protocol.** Full `CollectionResult` per cycle, or incremental
  deltas? Full is simpler and the payload is small; revisit if WAN cost bites.
