"""Where the scanner gets its device list.

NetBox is the source of truth. A device is polled when it carries the
`scan-target` tag; everything else about how to reach it comes from four
custom fields on the device itself:

    Scan address        IP or hostname   (empty -> the device's primary IP)
    Scan method         snmp | fortios   (empty -> inferred from the role)
    Credential profile  profile name     (empty -> "default")
    SNMP vendor         cisco, aruba…    (empty -> auto-detected sysObjectID)

Credentials never live in NetBox: the profile name is a pointer into the
`credentials` section of inventory.yml, whose values come from .env. Somebody
with read access to NetBox therefore learns which devices are polled, but not
the community string or the API token.

inventory.yml also holds an optional `seed` list. It is applied exactly once,
on the first run against an empty NetBox, purely so the operator has something
to look at and copy. From then on the GUI wins: a seeded device that gets
edited or deleted is never silently recreated.
"""

from __future__ import annotations

import json
import logging

from ...config import AppConfig, FortiGateConfig, SeedEntry, SwitchConfig
from ...identity import VENDOR_KEYS
from ...utils import slugify
from .client import (
    CF_CREDENTIAL,
    CF_METHOD,
    CF_TARGET,
    CF_VENDOR,
    METHOD_FORTIOS,
    METHOD_SNMP,
    TAG_SCAN_TARGET,
    NetBoxClient,
)

log = logging.getLogger("targets")


# ────────────────────────────────────────────────────────────────── seeding ──
def seed(client: NetBoxClient, config: AppConfig) -> int:
    """Create the inventory.yml seed devices in NetBox. Runs once per install."""
    if not config.seeds:
        return 0

    done = _load_seed_state(config)
    pending = [entry for entry in config.seeds if entry.name not in done]
    if not pending:
        return 0

    created = 0
    for entry in pending:
        if _seed_one(client, entry):
            created += 1
        # Recorded either way: a seed that failed because the operator had
        # already created the device by hand must not be retried forever.
        done.add(entry.name)

    _save_seed_state(config, done)
    if created:
        log.info(
            "seeded %d device(s) into NetBox — manage them from the GUI from now on",
            created,
        )
    return created


def _seed_one(client: NetBoxClient, entry: SeedEntry) -> bool:
    if client.site is None:
        return False

    existing = client.api.dcim.devices.get(name=entry.name, site_id=client.site.id)
    if existing is not None:
        log.info("seed '%s' skipped: the device already exists", entry.name)
        return False

    is_firewall = entry.method == METHOD_FORTIOS
    role = client.role_firewall if is_firewall else client.role_switch
    device_type = client.type_firewall if is_firewall else client.type_switch
    if role is None or device_type is None:
        return False

    device = client.create_device(
        name=entry.name,
        role=role,
        device_type=device_type,
        status="active",
        comments=f"Seeded from inventory.yml. Polled at {entry.host} "
        f"via {entry.method}.",
        tags=client.tag_ids(TAG_SCAN_TARGET),
        custom_fields={
            CF_TARGET: entry.host,
            CF_METHOD: entry.method,
            CF_CREDENTIAL: entry.credential,
            CF_VENDOR: entry.vendor,
        },
    )
    if device is None:
        return False
    log.info("seeded device '%s' (%s via %s)", entry.name, entry.host, entry.method)
    return True


def _load_seed_state(config: AppConfig) -> set[str]:
    path = config.seed_state_file
    if not path.is_file():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return set(payload.get("seeded") or [])
    except (OSError, ValueError) as exc:
        log.warning("unreadable seed state %s: %s", path, exc)
        return set()


def _save_seed_state(config: AppConfig, names: set[str]) -> None:
    try:
        config.scanner.state_dir.mkdir(parents=True, exist_ok=True)
        config.seed_state_file.write_text(
            json.dumps({"seeded": sorted(names)}, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        log.warning("could not persist the seed state: %s", exc)


# ──────────────────────────────────────────────────────────────── discovery ──
def load_targets(
    client: NetBoxClient, config: AppConfig
) -> tuple[list[FortiGateConfig], list[SwitchConfig]]:
    """Read every scan target out of NetBox and turn it into a poller config."""
    fortigates: list[FortiGateConfig] = []
    switches: list[SwitchConfig] = []

    try:
        devices = list(
            client.api.dcim.devices.filter(tag=slugify(TAG_SCAN_TARGET))
        )
    except Exception as exc:
        log.error("could not read the scan targets from NetBox: %s", exc)
        return [], []

    for device in devices:
        # pynetbox renders a choice as its label ("Active"), so compare the
        # underlying value instead.
        status = getattr(device, "status", None)
        status = str(getattr(status, "value", status) or "").lower()
        if status not in ("", "active", "staged", "none"):
            log.info(
                "skipping scan target '%s': its status is '%s'", device.name, status
            )
            continue

        custom = dict(getattr(device, "custom_fields", None) or {})
        address = _address_for(device, custom)
        if not address:
            log.warning(
                "device '%s' is tagged '%s' but has neither a Scan address nor "
                "a primary IP — skipped",
                device.name,
                TAG_SCAN_TARGET,
            )
            continue

        method = _method_for(device, custom)
        profile = config.credential(_text(custom.get(CF_CREDENTIAL)) or _default_profile(method))
        if not profile:
            log.error(
                "device '%s' points at the credential profile '%s', which is "
                "not defined in inventory.yml — skipped",
                device.name,
                _text(custom.get(CF_CREDENTIAL)),
            )
            continue

        if method == METHOD_FORTIOS:
            target = _build_fortigate(device, address, profile)
            if target is not None:
                fortigates.append(target)
        else:
            switches.append(_build_switch(device, address, profile, custom, config))

    log.info(
        "scan targets from NetBox: %d firewall(s), %d switch(es)",
        len(fortigates),
        len(switches),
    )
    return fortigates, switches


def _build_fortigate(device, address: str, profile: dict) -> FortiGateConfig | None:
    raw = {**profile, "name": device.name, "host": address}
    raw.pop("type", None)
    if not raw.get("api_token"):
        log.error(
            "FortiGate '%s' has no api_token in its credential profile — skipped",
            device.name,
        )
        return None
    return FortiGateConfig.from_dict(raw)


def _build_switch(
    device, address: str, profile: dict, custom: dict, config: AppConfig
) -> SwitchConfig:
    raw = {**profile, "name": device.name, "host": address}
    raw.pop("type", None)

    # Vendor precedence: explicit override, then whatever a previous cycle
    # discovered and wrote into the device type. snmp.py falls back to
    # sysObjectID auto-detection when this is still "generic".
    vendor = _text(custom.get(CF_VENDOR)).lower()
    if not vendor:
        vendor = _vendor_from_manufacturer(device)
    if vendor:
        raw["vendor"] = vendor

    return SwitchConfig.from_dict(raw, config.scanner)


def _vendor_from_manufacturer(device) -> str:
    device_type = getattr(device, "device_type", None)
    manufacturer = getattr(device_type, "manufacturer", None)
    name = str(getattr(manufacturer, "name", "") or "").strip().lower()
    return VENDOR_KEYS.get(name, "")


def _address_for(device, custom: dict) -> str:
    explicit = _text(custom.get(CF_TARGET))
    if explicit:
        return explicit
    for attribute in ("primary_ip4", "primary_ip", "primary_ip6"):
        record = getattr(device, attribute, None)
        address = str(getattr(record, "address", "") or "")
        if address:
            return address.split("/")[0]
    return ""


def _method_for(device, custom: dict) -> str:
    declared = _text(custom.get(CF_METHOD)).lower()
    if declared in (METHOD_SNMP, METHOD_FORTIOS):
        return declared
    if declared:
        log.warning(
            "device '%s' has an unrecognised scan method '%s' — falling back "
            "to the role",
            device.name,
            declared,
        )
    # NetBox 4.x renamed Device.device_role to Device.role.
    role = getattr(device, "role", None) or getattr(device, "device_role", None)
    slug = str(getattr(role, "slug", "") or "")
    return METHOD_FORTIOS if "firewall" in slug else METHOD_SNMP


def _default_profile(method: str) -> str:
    return "fortigate-default" if method == METHOD_FORTIOS else "default"


def _text(value) -> str:
    """Custom-field values arrive as None, str, or a {value,label} dict."""
    if value is None:
        return ""
    if isinstance(value, dict):
        value = value.get("value", "")
    return str(value).strip()
