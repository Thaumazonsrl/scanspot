# scanspot

**Network discovery that owns its data.**

scanspot polls the equipment you already have — a FortiGate over its REST API,
switches over SNMP — correlates what they report into a coherent picture of the
network, and keeps that picture in its own store. From there it feeds whatever
you use: NetBox out of the box, anything else over an HTTP API that exposes the
complete model rather than a convenient subset.

Nothing leaves your network. It reads with a read-only firewall key and a
read-only SNMP credential, and writes only where you point it.

```
 ┌── collectors ─────────┐   ┌── store ───────┐   ┌── consumers ──────────────┐
 │  FortiGate    REST    │   │                │   │  NetBox       built in    │
 │  Switches     SNMP    │──►│   scanspot's   │──►│  Web UI       built in    │
 │                       │   │   own record   │   │  HTTP API     anything    │
 │  storage-agnostic     │   │   of the truth │   │               you like    │
 └───────────────────────┘   └────────────────┘   └───────────────────────────┘
```

The middle box is the point. Collectors know nothing about where data will be
stored, and consumers are readers of a record that already exists — so a NetBox
outage costs you nothing, and adding a second destination costs one exporter
rather than a rewrite.

---

## What it answers

Questions that are hard to answer from the devices themselves, and that scanspot
answers after a single cycle:

| | |
|---|---|
| Which addresses in this subnet are used, and which are free? | routed prefixes, so utilisation is real |
| What is behind this MAC or this IP? | correlated across firewall and switches |
| Which switch and which port is this host on? | from the forwarding database, uplinks excluded |
| What hardware is actually installed? | vendor, model and chassis serial, from SNMP |
| When did this laptop move desk? | the change log |
| What has gone missing? | ageing, without deleting anything you cannot recover |

---

## How it is put together

Three layers, and the boundaries between them are the design:

**Collectors** (`app/collectors/`) speak to devices and produce a
vendor-neutral result. They know nothing about NetBox or any other backend. A
new protocol is a new collector and touches nothing else.

**The store** (`app/store/`) is scanspot's own record: scan targets, credential
profiles, discovered endpoints and their addresses, prefixes, VLANs, DHCP
pools, cycle history and a change log. SQLite by default — nothing extra to
run — with PostgreSQL available through one setting.

**Consumers** read from the store. NetBox is one, written and maintained here.
The web UI is another. The HTTP API is the open one: it carries the whole
domain model, so an integration you write yourself has exactly the same data
the built-in one does.

That last point is deliberate. Trimming the API to what NetBox happens to hold
would quietly rob anyone integrating something else of serials, VLANs and
switch-port locations — the parts that are hard to obtain and worth having.

---

## Requirements

* Docker with the Compose v2 plugin.
* Somewhere to reach the equipment: TCP 443 to the FortiGate, UDP 161 to the
  switches.
* **Optional** — a NetBox instance if you want the built-in integration.
  Developed and tested against **NetBox 4.1.11**. The MAC-address data model
  changed in 4.2; scanspot detects the version at startup and adapts, so the
  two can be upgraded independently, but 4.2+ has not yet been exercised in
  anger and reports either way are welcome.

No internet access is needed at run time — only to pull or build the image.

---

## Quick start

```bash
git clone https://github.com/Thaumazonsrl/scanspot.git
cd scanspot

cp .env.example .env
# set NETBOX_URL and NETBOX_TOKEN, plus SNMP_COMMUNITY and/or FORTIGATE_API_TOKEN

docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
docker compose logs -f scanner
```

The log prints an API key **once** on first start. Save it: only its hash is
kept.

```
WARNING [api] A first API key has been generated. It is shown ONCE:
WARNING [api]     scanspot_EXAMPLE0KEY0DO0NOT0USE0THIS0VALUE00
```

Then open **http://localhost:8080** and paste it.

> Released versions are published to GHCR and `docker compose up -d` pulls them
> without building. While 2.0 is unreleased, build from source as above.

Run your first cycle with `DRY_RUN=true` in `.env` if you would rather look
before anything is written — it polls everything and logs what it *would* do,
to NetBox and to its own store alike.

---

## The web UI

**http://localhost:8080** — the normal place to work.

* **Targets** — add a device to the scan, enable, disable, remove. Name,
  address, method, credential profile, optional vendor override.
* **Credentials** — named profiles that targets point at. Each holds either the
  *name of an environment variable* (the value stays outside the database, which
  is what Kubernetes Secrets and Vault users want) or the value itself,
  encrypted at rest.

One static page talking to the same `/api/v1` endpoints as everything else, so
there is no privileged internal path: whatever the UI can do, so can you.

The key lives in the browser and travels as a header. There is no cookie, and
therefore nothing for CSRF to attack.

---

## Preparing your devices

### FortiGate — a read-only REST API admin

`System > Administrators > Create New > REST API Admin`

1. **Administrator Profile**: read-only on **System**, **Network** and **Router**
2. **Trusted Hosts**: the scanspot host's `/32` — do this; it is the only thing
   standing between the token and the rest of the LAN
3. Copy the generated key into `FORTIGATE_API_TOKEN`. It is shown once.

```
config system accprofile
    edit "netbox-ro"
        set sysgrp read
        set netgrp read
        set routegrp read
    next
end
config system api-user
    edit "scanspot"
        set accprofile "netbox-ro"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost <HOST-IP> 255.255.255.255
            next
        end
    next
end
execute api-user generate-key scanspot
```

scanspot reads the live **ARP table**, configured **DHCP pools**, active
**leases**, **static reservations** (`reserved-address`) and the routed
**interfaces**.

### Switches — read-only SNMP

Indicative; adapt to your OS version.

```
! Cisco IOS / IOS-XE — v2c is strongly preferred, see the note below
snmp-server community NB-READ RO 20
access-list 20 permit <HOST-IP>

! Cisco IOS — SNMPv3
snmp-server group NETBOX v3 priv
snmp-server user scanspot NETBOX v3 auth sha <AUTHPASS> priv aes 128 <PRIVPASS>

! Aruba CX
snmp-server community NB-READ
snmpv3 user scanspot auth sha auth-pass plaintext <AUTHPASS> priv aes priv-pass plaintext <PRIVPASS>

! HPE / ProCurve
snmp-server community "NB-READ" operator

# Huawei
snmp-agent sys-info version v2c
snmp-agent community read cipher NB-READ

! Alcatel OmniSwitch
snmp community-map NB-READ user scanspot enable

# Juniper
set snmp community NB-READ authorization read-only
```

> **Cisco IOS note.** Classic IOS exposes the MAC table as one BRIDGE-MIB
> instance *per VLAN*, reachable as `community@vlan` under SNMPv2c. Under SNMPv3
> the same data needs one `snmp-server group … context vlan-<id>` per VLAN,
> which is tedious. On Cisco access switches, **use v2c with an ACL** unless
> policy forbids it. scanspot handles both — see `vlan_indexing` in
> `inventory.yml`.

---

## Adding a device to the scan

Three ways, all ending in the same place — scanspot's store:

**From the web UI.** Targets → fill the form → Add. The normal way.

**From the API.**

```bash
curl -s -X POST localhost:8080/api/v1/targets \
     -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
     -d '{"name":"sw-core-01","address":"10.0.0.10","method":"snmp"}'
```

**From NetBox**, if you already work there. Tag a device `scan-target`, fill in
its *Scan address* custom field, and it is imported on the next cycle. This is
one-way and explicit about ownership:

* imported targets belong to NetBox — refreshed from it, and **disabled** (not
  deleted) when the tag goes away, so their history survives;
* targets created any other way are never touched by the import;
* a NetBox outage disables nothing, because an unreachable NetBox must not look
  like "somebody untagged every device".

**Credentials are never stored in NetBox.** A target names a *profile*; the
community string or API token behind that name lives in scanspot, either
referenced from the environment or encrypted at rest.

---

## The NetBox integration

The built-in exporter. Everything scanspot discovers becomes real IPAM/DCIM
objects:

| Discovered | Becomes | Notes |
|---|---|---|
| SNMP `sysObjectID` | `dcim.Manufacturer` | IANA enterprise number → vendor, unambiguous |
| ENTITY-MIB / `sysDescr` | `dcim.DeviceType` + `serial` | the real model and the serial on the chassis |
| OS version | `dcim.Platform` | e.g. *Cisco IOS 15.2(4)E10* |
| Switch VLAN table | `ipam.VLAN` | `dot1qVlanStaticName`, falling back to CISCO-VTP-MIB |
| Routed interface | `ipam.Prefix` | one per subnet — this is what makes *used vs free* answerable |
| FortiGate DHCP range | `ipam.IPRange`, role **DHCP Pool** | status follows the server's enable/disable |
| Active DHCP lease | `ipam.IPAddress` status **DHCP** | tagged `dhcp-lease` |
| **Static DHCP reservation** | `ipam.IPAddress` status **Reserved** | tagged `static-dhcp-reservation`, **never auto-deleted** |
| Host in ARP outside any pool | `ipam.IPAddress` status **Active** | a statically configured host |
| Any endpoint MAC | `dcim.Device` + `dcim.Interface` | role *Discovered Endpoint*, anchored on the MAC |
| MAC seen on a switch port | custom fields **Switch** / **Switch port** / **Discovered VLAN** | uplinks excluded, see below |

Custom fields are created automatically under a *Network Scanner* group, along
with the tags `auto-discovered`, `dhcp-lease`, `static-dhcp-reservation`,
`network-infrastructure` and `scan-target`.

Where to look afterwards: **IPAM → Prefixes** for utilisation, the device page
for switch and port, **Devices → Device Types** for what hardware you actually
own.

---

## Integrating anything else

The API is not a thin wrapper over the NetBox exporter — it is the same store,
served whole. Interactive docs at **`/api/docs`**, machine-readable at
`/api/openapi.json`.

| | |
|---|---|
| `GET /health` | last cycle and counts. **No key needed** — a probe cannot carry one |
| `GET/POST /targets`, `PATCH`, `DELETE` | the device list |
| `GET/POST /credentials`, `PATCH`, `DELETE` | profiles. Never returns a secret |
| `GET /devices`, `/devices/{mac}` | discovered endpoints and their addresses |
| `GET /prefixes`, `/vlans` | routed subnets and VLANs |
| `GET /runs` | cycle history |
| `GET /events` | the change log — moved, new lease, went offline |
| `GET /raw` | unaltered device replies, when `CAPTURE_RAW` is on |
| `POST /scan` | run a cycle now |

A worked example — fifteen lines that feed something scanspot has never heard of:

```python
import requests

API = "http://localhost:8080/api/v1"
HEAD = {"X-API-Key": "scanspot_…"}

for device in requests.get(f"{API}/devices", headers=HEAD, params={"limit": 500}).json():
    if not device["switch_port"]:
        continue
    your_cmdb.upsert(
        mac=device["mac"],
        hostname=device["hostname"],
        addresses=[a["ip"] for a in device["addresses"]],
        location=f'{device["switch_name"]}/{device["switch_port"]}',
        vlan=device["vlan"],
        last_seen=device["last_seen_at"],
    )
```

Filters and pagination are on every listing (`?switch=`, `?status=`, `?type=`,
`?limit=`, `?offset=`), so polling a large estate is cheap.

`examples/exporters/` holds unsupported sample scripts. Contributions welcome;
they are illustrations, not products.

---

## How devices are identified

1. **`sysObjectID`** (`.1.3.6.1.2.1.1.2.0`) — its 7th arc is the IANA Private
   Enterprise Number (`.1.3.6.1.4.1.9.…` = 9 = Cisco). This determines the
   manufacturer and cannot be ambiguous.
2. **ENTITY-MIB** — the chassis row carries the orderable part number and the
   real serial. The preferred source of the model, and the only source of a
   serial.
3. **`sysDescr`** — parsed with per-vendor regexes as a fallback for kit that
   does not implement ENTITY-MIB. It usually yields the software image name
   (`C3750E-UNIVERSALK9`) rather than the orderable part number, which is
   exactly why ENTITY-MIB wins when both are present.

An enterprise number that is not in the table produces a placeholder
manufacturer named `Enterprise <n>` and a log line — that is your cue to add the
mapping to `ENTERPRISES` in `app/identity.py`. **Pull requests adding verified
mappings are the most useful contribution to this project.**

The detected vendor also selects the MAC-table strategy automatically, so a
Cisco gets the per-VLAN BRIDGE-MIB walk on its very first poll without anybody
configuring it.

---

## Correlation rules

* **The MAC is the anchor.** An endpoint is located through its MAC, so when a
  host gets a different DHCP lease the existing record is updated — no
  duplicate. Its previous address is released in the same cycle, because that
  address may already belong to somebody else.
* **A static reservation beats a lease.** An IP configured as a
  `reserved-address` on the FortiGate is marked *Reserved* even when it sits
  inside a pool range, and reservations outside every pool are picked up too,
  because the DHCP **configuration** is read — not just the lease table.
* **Uplinks are not access ports.** A port that has learned more than
  `SNMP_UPLINK_MAC_THRESHOLD` MACs (default 12) is treated as a trunk: its MACs
  are recorded, but no port location is attached to them.

---

## Lifecycle

| Age since last seen | Temporary record | Static DHCP reservation |
|---|---|---|
| < `OFFLINE_AFTER_HOURS` (48h) | untouched | untouched |
| ≥ 48h | flagged offline / deprecated | flagged, kept |
| ≥ `DELETE_AFTER_DAYS` (7d) | deleted in NetBox, address freed | **kept forever** |

Four guarantees:

1. **Only objects tagged `auto-discovered` are ever touched** in NetBox.
   Anything created by hand there is invisible to the cleanup.
2. **Static DHCP reservations are never deleted.**
3. Anything tagged `PROTECTED_TAG` (default `protected`) is exempt.
4. **A collection outage cannot cause a mass deletion.** If no data source
   answers, the sync *and* the cleanup are skipped and the cycle is reported as
   failed.

In scanspot's own store nothing is ever deleted by ageing — endpoints are
flagged offline and keep their history.

### Keeping the change log bounded

Two limits, applied together:

* `EVENT_RETENTION_DAYS` (365) — nothing older survives;
* `EVENT_KEEP_PER_TYPE` (1) — per device and per kind of change, only the most
  recent. Without it, a laptop on DHCP writes a row every day forever.

Neither loses anything irreplaceable: first-seen and last-seen live on the
device record, which is never pruned. The log only holds the narrative.

---

## Configuration

Everything is environment variables; [`.env.example`](.env.example) documents
each with its default. The ones worth knowing:

| | |
|---|---|
| `NETBOX_URL`, `NETBOX_TOKEN` | the built-in exporter. Omit to run without NetBox |
| `SCANSPOT_DB_URL` | SQLite by default; PostgreSQL for multi-replica |
| `SCANSPOT_SECRET_KEY` | needed only to store credentials encrypted in the database |
| `API_ENABLED`, `API_PORT` | the API and the web UI |
| `DRY_RUN` | poll and log, write nothing — anywhere |
| `CAPTURE_RAW` | keep unaltered device replies for debugging. Off by default |

`inventory.yml` holds named credential profiles and an optional first-run seed.
Since 2.0 it is a convenience, not a requirement: everything in it can be
managed from the UI or the API instead.

---

## Operations

```bash
docker compose logs -f scanner
docker compose exec scanner python -m app.main --check    # config + connectivity
docker compose exec scanner python -m app.main --once     # scan now
docker compose exec scanner python -m app.main --version
```

`--once` is safe at any time: cycles take an advisory lock, so it exits with
*"another scan cycle is already running"* rather than racing the scheduled one.

The container healthcheck (`python -m app.healthcheck`) reports unhealthy if no
cycle has completed within two intervals plus ten minutes, or if the last cycle
reached no data source at all.

Set `LOG_LEVEL=DEBUG` for collector-level output.

### When a device is identified wrongly

Turn on `CAPTURE_RAW`, run one cycle, and read what the device actually said:

```bash
curl -s -H "X-API-Key: $KEY" 'localhost:8080/api/v1/raw?device=sw-core-01'
```

`sysDescr`, `sysObjectID`, ENTITY-MIB, the forwarding database and the two maps
used to translate it. Enough to work out the problem from your desk instead of
going back to the site. Turn it off afterwards — a full forwarding database per
switch per cycle adds up.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `401 Unauthorized` from the FortiGate | wrong token, or the host's IP is not in the API admin's **Trusted Hosts** |
| `403 Forbidden` from the FortiGate | the API admin profile lacks *read* on System/Network/Router |
| `no data source responded` | firewall/switch unreachable — check routing and the SNMP ACL. Nothing is aged out in this state |
| **Every device unreachable, but you can ping it from the host** | the Docker bridge overlaps your LAN — see the note in `docker-compose.yml` |
| `no scan target defined` | nothing added yet — use the UI |
| Device keeps the **Generic Switch** type in NetBox | the poll never succeeded, or a human assigned the type by hand (never overwritten) |
| Manufacturer shows as `Enterprise 12345` | that PEN is not in the table — add it to `ENTERPRISES` in `app/identity.py` |
| A switch returns 0 FDB entries | it only exposes the per-VLAN BRIDGE-MIB. Set the target's vendor override to `cisco`, or add `vlan_indexing: community` to its profile |
| Every endpoint appears on one port | that port is an uplink and the threshold is too high — lower `SNMP_UPLINK_MAC_THRESHOLD` |
| SNMPv3 errors on a v2c switch | the profile's `snmp_version` is not `1` or `2c`, so the poller falls back to v3. Check it in the UI |
| `docker build` fails with `CERTIFICATE_VERIFY_FAILED` | TLS-inspecting proxy — see [`certs/README.md`](certs/README.md) |

---

## Security notes

* Credentials should be **read-only**, and the FortiGate key restricted with
  Trusted Hosts.
* **Secrets never come back out of the API.** Credential responses carry
  `has_secret` and nothing else — not the value, not even the names of the
  environment variables referenced.
* The API speaks plain HTTP and has no rate limiting. Keep it on the management
  network or put TLS in front of it. `API_ENABLED=false` turns it off.
* **Known limitation — SNMP credentials appear on the command line.** scanspot
  shells out to `snmpbulkwalk`, so the community string and SNMPv3 passphrases
  are visible in `/proc/<pid>/cmdline` to anything sharing the container's PID
  namespace. The container runs as a single unprivileged user and does not share
  its namespace by default.
* scanspot records what the network reports; it does not authenticate endpoints.
  A host that spoofs a MAC is recorded as that MAC.

Reporting a vulnerability: [SECURITY.md](SECURITY.md).

---

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests need neither a NetBox nor a network. The layout keeps the storage
backend at arm's length — everything outside `app/backends/` knows nothing about
NetBox, and that property is what makes further integrations possible:

```
app/
├── models.py  identity.py  utils.py  prefixes.py  config.py
├── store/            the record of truth, plus its migrations
├── api/              HTTP API and the web UI
├── collectors/       fortigate.py  snmp.py
└── backends/netbox/  client.py  sync.py  cleanup.py  import_targets.py
```

`app/identity.py` does no I/O by design: `app/collectors/snmp.py` performs the
walks and hands raw values over, which keeps the vendor knowledge in one
testable place. It is the easiest place to contribute.

Contributions are covered by the [DCO](CONTRIBUTING.md) — `git commit -s`. There
is no CLA, and there will not be one.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Support

scanspot is maintained alongside client work, not as a full-time project. So
that nobody has to guess:

* **Issues** — expect a first reply within about two weeks. Reports that a
  device is identified wrongly get fixed fastest when they include the
  `sysObjectID` and the verbatim `sysDescr`, because those can be fixed without
  owning the hardware. There is an issue template that asks for exactly that.
* **Pull requests** — same timescale. A verified vendor mapping with a test is
  usually merged as it stands.
* **Security reports** — a different clock, see [SECURITY.md](SECURITY.md).
* **No commercial support** is offered through this repository.

If that cadence does not suit you, the licence lets you fork it, and it is
built to be forked: the collectors know nothing about the storage layer, and
the API carries the whole model.

---

## Roadmap

Shipped is described above; this is what is not:

* **A NetBox plugin** — a scanspot tab on the device page, a "Scan now" button,
  target management inside NetBox itself. It talks to the API, so it stays thin.
* **Webhooks**, so integrating does not mean polling.
* **Nautobot**, then **phpIPAM**. Each integration is classified on two
  independent axes — *supplies scan scope* and *receives discoveries* — because
  they are not the same thing. phpIPAM is a fine source of subnets to scan and a
  poor destination for device inventory, having no DCIM model at all.

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
