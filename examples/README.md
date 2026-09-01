# Examples

**Unsupported.** These are illustrations of how to consume scanspot's API, not
products. Nothing here is covered by the test suite or by any promise of
stability. Copy what is useful and make it yours.

## exporters/

| | |
|---|---|
| `csv_inventory.py` | the discovered inventory as CSV. Standard library only |

```bash
python exporters/csv_inventory.py --key scanspot_… > inventory.csv
python exporters/csv_inventory.py --key scanspot_… --switch sw-core-01
python exporters/csv_inventory.py --key scanspot_… --status offline
```

## Why these exist

scanspot's API carries the whole domain model — serials, VLANs, switch-port
locations, reservation state — not the subset a particular destination happens
to accept. That is what makes feeding an in-house CMDB, a monitoring system or
a spreadsheet a short script rather than a plugin.

The pattern is always the same:

```python
GET /api/v1/devices?limit=200&offset=0     # walk the pages
    → mac, hostname, addresses[], switch_name, switch_port, vlan,
      firewall, static_reservation, status, first_seen_at, last_seen_at
```

Add `?switch=`, `?status=` or `?mac=` to narrow it, and `/events` if you want
changes rather than current state.

## Contributing one

Welcome, with two conditions:

* **say what you tested it against** — a version, a product, a date;
* **no credentials, no real addresses, no customer hostnames** in the example
  or in the pull request.

An exporter that has only ever run against a mock is still useful, but say so
in the docstring. Better an honest illustration than a false promise.
