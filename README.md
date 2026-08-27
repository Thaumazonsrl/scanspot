# scanspot

**Keep NetBox current from the network itself.** scanspot polls a FortiGate and
your switches on a schedule, correlates what they report, and writes the result
into NetBox as real IPAM/DCIM objects — prefixes, VLANs, DHCP pools, addresses,
devices, and the switch port every endpoint is plugged into.

Nothing leaves your network. It reads with a read-only firewall API key and a
read-only SNMP credential, and writes only to your own NetBox.

```
  FortiGate  ──REST──►┐
  (ARP, DHCP pools,   │
   leases, static     ├──►  scanspot  ──pynetbox──►  NetBox
   reservations)      │
  Switches   ──SNMP──►┘
  (MAC address tables, VLANs, ENTITY-MIB)
```

---

## What you get

After one cycle, NetBox can answer questions it could not answer before:

| Question | Where the answer appears |
|---|---|
| Which addresses in this subnet are used, and which are free? | **IPAM → Prefixes**, the utilisation bar and the *IP Addresses* tab |
| What is behind this MAC or IP? | global search |
| Which switch and port is this host on? | the Device page → *Switch* / *Switch port* |
| What hardware is actually installed? | **Devices → Device Types**, grouped by manufacturer |
| Which VLANs exist? | **IPAM → VLANs** |
| What has gone missing? | **Devices** filtered on status *Offline* |

| Discovered | Becomes | Notes |
|---|---|---|
| SNMP `sysObjectID` | `dcim.Manufacturer` | IANA enterprise number → vendor, unambiguous |
| ENTITY-MIB / `sysDescr` | `dcim.DeviceType` + `serial` | the real model and the serial on the chassis |
| OS version | `dcim.Platform` | e.g. *Cisco IOS 15.0(2)SE11* |
| Switch VLAN table | `ipam.VLAN` | `dot1qVlanStaticName`, falling back to CISCO-VTP-MIB |
| Routed interface | `ipam.Prefix` | one per subnet — this is what makes *used vs free* answerable |
| FortiGate DHCP range | `ipam.IPRange`, role **DHCP Pool** | status follows the server's enable/disable |
| Active DHCP lease | `ipam.IPAddress` status **DHCP** | tagged `dhcp-lease` |
| **Static DHCP reservation** | `ipam.IPAddress` status **Reserved** | tagged `static-dhcp-reservation`, **never auto-deleted** |
| Host in ARP outside any pool | `ipam.IPAddress` status **Active** | a statically configured host |
| Any endpoint MAC | `dcim.Device` + `dcim.Interface` | role *Discovered Endpoint*, anchored on the MAC |
| MAC seen on a switch port | custom fields **Switch** / **Switch port** / **Discovered VLAN** | uplinks excluded, see below |

Custom fields are created automatically under a *Network Scanner* group, and
tags `auto-discovered`, `dhcp-lease`, `static-dhcp-reservation`,
`network-infrastructure` and `scan-target` are created on first run.

---

## Requirements

* Docker with the Compose v2 plugin.
* A **NetBox 4.x** instance and a write-enabled API token. Developed and tested
  against **NetBox 4.1.11**. The MAC-address data model changed in NetBox 4.2;
  scanspot detects the version at startup and adapts, so both sides can be
  upgraded independently — but 4.2+ has not yet been exercised in anger, and
  reports either way are welcome.
* Network reachability from the container: TCP 443 to the FortiGate, UDP 161 to
  the switches.

No internet access is needed at run time — only to pull or build the image.

---

## Quick start

```bash
git clone https://github.com/Thaumazonsrl/scanspot.git
cd scanspot

cp .env.example .env
# set NETBOX_URL and NETBOX_TOKEN, plus SNMP_COMMUNITY and/or FORTIGATE_API_TOKEN

# The image is pulled from GHCR — nothing is built locally.
# If the package is private, authenticate once on this host first:
#   echo <TOKEN> | docker login ghcr.io -u <github-username> --password-stdin

docker compose run --rm scanner python -m app.main --check   # validate config + connectivity
```

To build from source instead — contributors, or a host that cannot reach
ghcr.io:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

Then add your first device (below), and run a cycle:

```bash
docker compose up -d
docker compose logs -f scanner
```

You are up when the log prints `scan cycle finished`.

> **Run your first cycle with `DRY_RUN=true`.** scanspot will poll everything
> and log exactly what it *would* write, without touching NetBox. Once the
> output looks right, set it back to `false` and `docker compose restart scanner`.

---

## Preparing your devices

### FortiGate — a read-only REST API admin

`System > Administrators > Create New > REST API Admin`

1. **Administrator Profile**: read-only on **System**, **Network** and **Router**
2. **Trusted Hosts**: the scanspot host's `/32` — do this; it is the only thing
   standing between the token and the rest of the LAN
3. Copy the generated API key into `FORTIGATE_API_TOKEN`. It is shown once.

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

Tag a device in NetBox and scanspot picks it up on the next cycle. No file to
edit, no container to restart — this happens entirely in the browser.

> **Where the list actually lives.** From 2.0 scanspot keeps its own store, and
> that store is authoritative. NetBox still *offers* targets — the import below
> runs every cycle — but it is one-way: a device you tagged is owned by NetBox
> and refreshed from it, while a target created any other way is never touched
> by the import. Untagging a device disables its target rather than deleting it,
> so its discovery history survives. This is what will let scanspot work with
> backends that have no device model to hold a target at all.

1. **Devices → Devices → Add**
   * *Role*: **Network Switch**, or **Firewall** for a FortiGate
   * *Device type*: **Generic Switch** — a placeholder. The first successful
     poll replaces it with the real manufacturer and model.
2. In the **Network Scanner** section of the same form:

   | Field | Value |
   |---|---|
   | **Scan address** | management IP. Empty uses the device's primary IP |
   | **Scan method** | `SNMP` or `FortiGate REST API`. Empty follows the role |
   | **Credential profile** | a profile name from `inventory.yml`. Empty means `default` |
   | **SNMP vendor override** | leave empty — detected from `sysObjectID` |

3. Add the tag **`scan-target`** and save.

It is picked up on the next cycle, or immediately with
`docker compose exec scanner python -m app.main --once`.

Removing a device is the reverse: delete the `scan-target` tag, or set the
status to anything but Active/Staged.

**Credentials are never stored in NetBox.** The device names a *profile*; the
community string or API token behind that name lives in `.env`. Someone with
read access to NetBox learns which devices are polled, not how.

---

## The API

scanspot exposes an HTTP API over its own store — manage targets, trigger a
scan, and let other systems consume what it discovers. Interactive docs at
**`http://<host>:8080/api/docs`**, machine-readable at `/api/openapi.json`.

On first start a key is generated and printed to the log **once**:

```
WARNING [api] A first API key has been generated. It is shown ONCE:
WARNING [api]     scanspot_k5l99Tj601A_dJWNXJtCrZKRi5m2O9S1RBHINhVhWUk
```

Only its hash is stored, so save it there and then.

```bash
KEY=scanspot_…

curl -s localhost:8080/api/v1/health                       # no key needed

curl -s -H "X-API-Key: $KEY" localhost:8080/api/v1/targets

curl -s -X POST localhost:8080/api/v1/targets \
     -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
     -d '{"name":"sw-core-01","address":"10.0.0.10","method":"snmp"}'

curl -s -X POST -H "X-API-Key: $KEY" localhost:8080/api/v1/scan
```

### What it exposes

| | |
|---|---|
| `/health` | last cycle, counts. **No key needed** |
| `/targets` | the device list — create, edit, disable, delete |
| `/credentials` | profiles. Never returns a secret |
| `/devices`, `/devices/{mac}` | discovered endpoints, with their addresses |
| `/prefixes`, `/vlans` | the routed subnets and VLANs found |
| `/runs` | cycle history |
| `/events` | the change log — moved port, new lease, went offline |
| `POST /scan` | run a cycle now |

`/devices` carries **everything the collectors learned** — switch port, VLAN,
firewall interface, reservation state — not the subset a particular backend
happens to store. That is deliberate: it is what makes writing an exporter into
LibreNMS, Zabbix or an in-house CMDB worth the effort.

```bash
curl -s -H "X-API-Key: $KEY" 'localhost:8080/api/v1/devices?switch=sw-core-01'
curl -s -H "X-API-Key: $KEY" 'localhost:8080/api/v1/events?type=moved'
```

Two properties worth knowing:

* **Secrets never come back out.** Credential responses carry `has_secret` and
  nothing else — not the community string, not even the names of the
  environment variables it references.
* **The API is up before NetBox is.** A fresh NetBox spends minutes applying its
  own migrations, and that is exactly when you want to add targets. The API only
  needs scanspot's store.

It speaks plain HTTP and has no rate limiting. Keep it on the management
network, or put TLS in front of it. `API_ENABLED=false` turns it off entirely.

## How devices are identified

1. **`sysObjectID`** (`.1.3.6.1.2.1.1.2.0`) — its 7th arc is the IANA Private
   Enterprise Number (`.1.3.6.1.4.1.9.…` = 9 = Cisco). This determines the
   Manufacturer and cannot be ambiguous.
2. **ENTITY-MIB** — the chassis row carries the orderable part number and the
   real serial. The preferred source of the model, and the only source of a
   serial.
3. **`sysDescr`** — parsed with per-vendor regexes as a fallback for kit that
   does not implement ENTITY-MIB. It usually yields the software image name
   (`C2960-LANBASEK9`) rather than the orderable part number, which is exactly
   why ENTITY-MIB wins when both are present.

An enterprise number that is not in the table produces a placeholder
manufacturer named `Enterprise <n>` and a log line — that is your cue to add the
mapping to `ENTERPRISES` in `app/identity.py`. **Pull requests adding verified
mappings are very welcome.**

The detected vendor also selects the MAC-table strategy automatically, so a
Cisco gets the per-VLAN BRIDGE-MIB walk on its very first poll without anybody
configuring it. A device type a human assigned by hand is never overwritten.

---

## Correlation rules

* **The MAC is the anchor.** An endpoint is located through its MAC, so when a
  host gets a different DHCP lease the existing Device/Interface is updated —
  no duplicate is created. Its previous dynamic address is detached and
  deprecated in the same cycle.
* **A static reservation beats a lease.** An IP configured as a
  `reserved-address` on the FortiGate is marked *Reserved* even when it sits
  inside a pool range, and reservations outside every pool are picked up too,
  because the DHCP **configuration** is read — not just the lease table.
* **Uplinks are not access ports.** A port that has learned more than
  `SNMP_UPLINK_MAC_THRESHOLD` MACs (default 12) is treated as a trunk: its MACs
  are still recorded, but no port location is attached to them.

---

## Lifecycle and auto-cleanup

| Age since last seen | Temporary record | Static DHCP reservation |
|---|---|---|
| < `OFFLINE_AFTER_HOURS` (48h) | untouched | untouched |
| ≥ 48h | IP → **Deprecated**, Device → **Offline** | IP → **Deprecated** (kept) |
| ≥ `DELETE_AFTER_DAYS` (7d) | **deleted**, address freed | **kept forever** |

`ENABLE_AUTO_DELETE=false` turns the destructive half off entirely and leaves
everything at Deprecated/Offline.

Four guarantees:

1. **Only objects tagged `auto-discovered` are ever touched.** Anything you
   created by hand in the NetBox UI is invisible to the cleanup, and scanspot
   will not rewrite its status, description or tags either — it only stamps the
   discovery custom fields on it.
2. **Static DHCP reservations are never deleted.** They survive until the
   reservation is removed from the FortiGate, at which point the record
   re-enters the normal 48h/7d cycle.
3. Anything tagged with `PROTECTED_TAG` (default `protected`) is exempt.
4. **A collection outage cannot cause a mass deletion.** If no data source
   answers in a cycle, the sync *and* the cleanup are skipped entirely and the
   cycle is reported as failed.

---

## Configuration

Everything is environment variables; [`.env.example`](.env.example) documents
each one with its default.

`inventory.yml` holds two things, and deliberately not the device list:

* **`credentials:`** — named profiles that devices in NetBox point at by name.
  `${VAR}` placeholders are resolved from the environment, so no secret is
  written into the YAML. Define extra profiles when you have more than one
  community string or more than one firewall token.
* **`seed:`** — devices created in NetBox on the **first run only**, so the GUI
  is not empty on day one. Recorded in `/app/state/seeded.json`; a seeded device
  you later edit or delete is never silently recreated. Delete that file to
  replay the seed deliberately.

---

## Operations

```bash
docker compose logs -f scanner                                   # follow
docker compose exec scanner python -m app.main --check           # config + connectivity
docker compose exec scanner python -m app.main --once            # scan now
docker compose restart scanner                                   # apply .env / inventory.yml
```

`--once` is safe to run at any time: cycles take an advisory lock, so it exits
with *"another scan cycle is already running"* rather than racing the scheduled
one and creating duplicate records.

The container healthcheck (`python -m app.healthcheck`) reads the heartbeat at
`/app/state/last_run.json` and reports unhealthy if no cycle has completed
within two intervals plus ten minutes, or if the last cycle reached no data
source at all.

Set `LOG_LEVEL=DEBUG` for collector-level output.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `401 Unauthorized` from the FortiGate | wrong `FORTIGATE_API_TOKEN`, or the host's IP is not in the API admin's **Trusted Hosts** |
| `403 Forbidden` from the FortiGate | the API admin profile lacks *read* on System/Network/Router |
| `no data source responded` | firewall/switch unreachable — check routing and the SNMP ACL. NetBox is deliberately left untouched in this state |
| **Every device unreachable, but you can ping it from the host** | the Docker bridge overlaps your LAN — see the note at the bottom of `docker-compose.yml` |
| `no scan target defined` | nothing carries the `scan-target` tag yet |
| `points at the credential profile '…' which is not defined` | typo in the device's *Credential profile* field, or the profile is missing from `inventory.yml` |
| Device stays on the **Generic Switch** type | the poll never succeeded, or a human assigned the type by hand (which is never overwritten) |
| Manufacturer shows as `Enterprise 12345` | that PEN is not in the table — add it to `ENTERPRISES` in `app/identity.py` |
| A switch returns 0 FDB entries | it only exposes the per-VLAN BRIDGE-MIB. Set the device's *SNMP vendor override* to `cisco`, or add `vlan_indexing: community` to its credential profile |
| Every endpoint appears on one port | that port is an uplink and the threshold is too high — lower `SNMP_UPLINK_MAC_THRESHOLD` |
| `docker build` fails with `CERTIFICATE_VERIFY_FAILED` | you are behind a TLS-inspecting proxy — see [`certs/README.md`](certs/README.md) |

---

## Security notes

* `.env` holds every secret and is gitignored. The FortiGate key and the SNMP
  credentials should be **read-only**, and the FortiGate key restricted with
  Trusted Hosts.
* The NetBox API token must be write-enabled — that is what lets scanspot
  populate NetBox. Scope it to this application and rotate it by changing
  `NETBOX_TOKEN` and deleting the old token in the NetBox UI.
* **Known limitation — SNMP credentials appear on the command line.** scanspot
  shells out to `snmpbulkwalk`, so the community string and the SNMPv3
  passphrases are visible in `/proc/<pid>/cmdline` to anything sharing the
  container's PID namespace. The container runs as a single unprivileged user
  and does not share its namespace by default, so the practical exposure is
  small — but use dedicated read-only credentials, ACL'd to this host, and do
  not run untrusted processes in this container.
* Discovery data is only as trustworthy as the devices reporting it. scanspot
  writes what the network tells it; it does not authenticate endpoints.

---

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The tests cover the pure logic — `app/identity.py` (enterprise numbers,
`sysDescr` parsing, ENTITY-MIB chassis selection), `app/utils.py` (MAC and IP
normalisation, timestamps) and the prefix longest-match index. They need neither
a NetBox nor a network.

`app/identity.py` does no I/O by design: `app/collectors/snmp.py` performs the
walks and hands raw values over, which keeps the vendor knowledge in one
testable place. That is the easiest place to contribute.

The package layout keeps the storage backend at arm's length — collectors and
domain logic live outside `app/backends/` and know nothing about NetBox:

```
app/
├── models.py  identity.py  utils.py  prefixes.py  config.py
├── collectors/   fortigate.py  snmp.py
└── backends/netbox/   client.py  sync.py  cleanup.py  targets.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
