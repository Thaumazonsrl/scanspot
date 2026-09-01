#!/usr/bin/env python3
"""Export the discovered inventory to CSV.

An illustration of the point, not a product: scanspot's API carries the whole
model, so feeding something it has never heard of is a short script rather than
a plugin.

Standard library only — no pip install, runs anywhere Python does.

    python csv_inventory.py --url http://localhost:8080 --key scanspot_… > inventory.csv
    python csv_inventory.py --switch sw-core-01          # one switch
    python csv_inventory.py --status offline             # what went missing

UNSUPPORTED. Copy it, change it, make it yours.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

FIELDS = [
    "mac",
    "hostname",
    "addresses",
    "switch",
    "port",
    "vlan",
    "firewall",
    "reserved",
    "status",
    "first_seen",
    "last_seen",
]

PAGE = 200


def fetch(url: str, key: str, path: str, params: dict) -> list[dict]:
    """One page of results, or raise something readable."""
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/v1{path}?{query}",
        headers={"X-API-Key": key},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise SystemExit("The API key was rejected.") from None
        raise SystemExit(f"HTTP {exc.code} from {path}: {exc.read()[:200]!r}") from None
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach {url}: {exc.reason}") from None


def devices(url: str, key: str, **filters):
    """Walk every page. Estates are larger than one page more often than not."""
    offset = 0
    while True:
        page = fetch(url, key, "/devices", {**filters, "limit": PAGE, "offset": offset})
        if not page:
            return
        yield from page
        if len(page) < PAGE:
            return
        offset += PAGE


def row(device: dict) -> dict:
    return {
        "mac": device["mac"],
        "hostname": device.get("hostname") or "",
        # Semicolons: a host with two addresses is common, and a comma would
        # fight the CSV.
        "addresses": ";".join(a["ip"] for a in device.get("addresses", [])),
        "switch": device.get("switch_name") or "",
        "port": device.get("switch_port") or "",
        "vlan": device.get("vlan") or "",
        "firewall": device.get("firewall") or "",
        "reserved": "yes" if device.get("static_reservation") else "",
        "status": device.get("status") or "",
        "first_seen": device.get("first_seen_at") or "",
        "last_seen": device.get("last_seen_at") or "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--key", required=True, help="scanspot API key")
    parser.add_argument("--switch", help="only endpoints on this switch")
    parser.add_argument("--status", help="active | offline | deprecated")
    parser.add_argument(
        "--mapped-only",
        action="store_true",
        help="skip endpoints with no switch port (seen only by the firewall)",
    )
    args = parser.parse_args()

    writer = csv.DictWriter(sys.stdout, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()

    written = 0
    for device in devices(args.url, args.key, switch=args.switch, status=args.status):
        if args.mapped_only and not device.get("switch_port"):
            continue
        writer.writerow(row(device))
        written += 1

    print(f"{written} endpoint(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
