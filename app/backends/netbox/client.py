"""NetBox access layer.

Responsibilities:
  * a configured, retrying pynetbox session
  * one-time idempotent bootstrap of everything the sync needs (tags, custom
    fields, site, device roles, generic device types, the "DHCP Pool" IP-range
    role)
  * a version-tolerant MAC anchor: NetBox <= 4.1 stores the MAC on the
    interface, NetBox >= 4.2 stores it as a first-class MACAddress object.
    Both are handled behind one interface so the stack keeps working when the
    client upgrades their NetBox image.
  * DRY_RUN support — every write goes through this module, so a single flag
    makes the whole scanner read-only.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Callable

import pynetbox
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ...config import NetBoxSettings
from ...utils import slugify

log = logging.getLogger("netbox")

# ── custom fields (see bootstrap) ───────────────────────────────────────────
CF_FIRST_SEEN = "scanner_first_seen"
CF_LAST_SEEN = "scanner_last_seen"
CF_SOURCE = "scanner_source"
CF_STATIC = "scanner_static_reservation"
CF_SWITCH = "scanner_switch"
CF_SWITCH_PORT = "scanner_switch_port"
CF_VLAN = "scanner_vlan"
CF_FIREWALL = "scanner_firewall"

# ── custom fields that make a Device a scan target (operator-facing) ─────────
CF_TARGET = "scanner_address"
CF_METHOD = "scanner_method"
CF_CREDENTIAL = "scanner_credential"
CF_VENDOR = "scanner_vendor"

METHOD_SNMP = "snmp"
METHOD_FORTIOS = "fortios"
METHOD_CHOICES = [
    [METHOD_SNMP, "SNMP (switch, router, L3 device)"],
    [METHOD_FORTIOS, "FortiGate REST API"],
]

# ── tags ────────────────────────────────────────────────────────────────────
TAG_DISCOVERED = "auto-discovered"
TAG_RESERVATION = "static-dhcp-reservation"
TAG_DHCP_LEASE = "dhcp-lease"
TAG_INFRASTRUCTURE = "network-infrastructure"
TAG_SCAN_TARGET = "scan-target"

# ── roles / types created on first run ──────────────────────────────────────
ROLE_ENDPOINT = "Discovered Endpoint"
ROLE_SWITCH = "Network Switch"
ROLE_FIREWALL = "Firewall"
MANUFACTURER_GENERIC = "Generic"
TYPE_ENDPOINT = "Generic Endpoint"
TYPE_SWITCH = "Generic Switch"
TYPE_FIREWALL = "Generic Firewall"
IPRANGE_ROLE_DHCP = "DHCP Pool"

_OBJECT_TYPES = ["dcim.device", "ipam.ipaddress"]

_CUSTOM_FIELDS: list[dict[str, Any]] = [
    {
        "name": CF_FIRST_SEEN,
        "label": "First seen",
        "type": "text",
        "description": "UTC timestamp of the first discovery (ISO 8601).",
    },
    {
        "name": CF_LAST_SEEN,
        "label": "Last seen",
        "type": "text",
        "description": "UTC timestamp of the last discovery (ISO 8601). "
        "Drives the offline/cleanup logic.",
    },
    {
        "name": CF_SOURCE,
        "label": "Discovery source",
        "type": "text",
        "description": "Which collectors saw this object during the last cycle.",
    },
    {
        "name": CF_STATIC,
        "label": "Static DHCP reservation",
        "type": "boolean",
        "description": "Set when the FortiGate holds a static DHCP reservation "
        "for this MAC. Permanently exempt from auto-deletion.",
    },
    {
        "name": CF_SWITCH,
        "label": "Switch",
        "type": "text",
        "description": "Access switch the MAC was learned on (SNMP FDB).",
    },
    {
        "name": CF_SWITCH_PORT,
        "label": "Switch port",
        "type": "text",
        "description": "Physical port the MAC was learned on (SNMP FDB).",
    },
    {
        "name": CF_VLAN,
        "label": "Discovered VLAN",
        "type": "text",
        "description": "VLAN id reported by the switch forwarding database.",
    },
    {
        "name": CF_FIREWALL,
        "label": "FortiGate",
        "type": "text",
        "description": "Firewall / interface the address was observed on.",
    },
    # ── the four fields an operator fills in from the GUI ───────────────────
    {
        "name": CF_TARGET,
        "label": "Scan address",
        "type": "text",
        "object_types": ["dcim.device"],
        "description": "IP or hostname the scanner polls. Leave empty to use "
        "the device's primary IP.",
    },
    {
        "name": CF_METHOD,
        "label": "Scan method",
        "type": "select",
        "choices": METHOD_CHOICES,
        "object_types": ["dcim.device"],
        "description": "How to poll this device. Empty falls back to the "
        "device role (Firewall -> FortiGate API, anything else -> SNMP).",
    },
    {
        "name": CF_CREDENTIAL,
        "label": "Credential profile",
        "type": "text",
        "object_types": ["dcim.device"],
        "description": "Name of a profile from the 'credentials' section of "
        "inventory.yml. Empty means 'default'.",
    },
    {
        "name": CF_VENDOR,
        "label": "SNMP vendor override",
        "type": "text",
        "object_types": ["dcim.device"],
        "description": "Forces the MAC-table strategy (cisco, fortinet, aruba, "
        "hpe, huawei, alcatel, juniper, generic). Empty = auto-detect from "
        "sysObjectID.",
    },
]

_TAGS: list[dict[str, str]] = [
    {
        "name": TAG_DISCOVERED,
        "color": "2196f3",
        "description": "Created by scanspot. Only tagged objects "
        "are ever touched by the automatic cleanup.",
    },
    {
        "name": TAG_RESERVATION,
        "color": "4caf50",
        "description": "Static DHCP reservation on the FortiGate. Never "
        "auto-deleted.",
    },
    {
        "name": TAG_DHCP_LEASE,
        "color": "ffc107",
        "description": "Temporary DHCP lease from a FortiGate pool.",
    },
    {
        "name": TAG_INFRASTRUCTURE,
        "color": "607d8b",
        "description": "Firewall / switch managed by the scanner. Never "
        "auto-deleted.",
    },
    {
        "name": TAG_SCAN_TARGET,
        "color": "e91e63",
        "description": "Poll this device on every cycle. Add the tag from the "
        "GUI to put a new switch or firewall under scan.",
    },
]


class NetBoxClient:
    def __init__(self, settings: NetBoxSettings, dry_run: bool = False):
        self.settings = settings
        self.dry_run = dry_run

        session = requests.Session()
        session.verify = settings.verify_ssl
        if not settings.verify_ssl:
            # pynetbox owns the request calls, so `verify` cannot be passed per
            # request here. Without this, REQUESTS_CA_BUNDLE from the image
            # would override session.verify and re-enable verification against
            # a NetBox published with a private certificate.
            session.trust_env = False
        session.mount(
            "http://",
            HTTPAdapter(
                max_retries=Retry(
                    total=3,
                    backoff_factor=1,
                    status_forcelist=(429, 500, 502, 503, 504),
                )
            ),
        )
        session.mount(
            "https://",
            HTTPAdapter(
                max_retries=Retry(
                    total=3,
                    backoff_factor=1,
                    status_forcelist=(429, 500, 502, 503, 504),
                )
            ),
        )
        if not settings.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.api = pynetbox.api(settings.url, token=settings.token)
        self.api.http_session = session

        self.version: tuple[int, int] = (0, 0)
        self._bootstrapped = False
        self._cache: dict[str, Any] = {}

        # Populated by bootstrap()
        self.site = None
        self.role_endpoint = None
        self.role_switch = None
        self.role_firewall = None
        self.type_endpoint = None
        self.type_switch = None
        self.type_firewall = None
        self.dhcp_pool_role = None
        self.tags: dict[str, Any] = {}

    # ── plumbing ────────────────────────────────────────────────────────────
    def connect(self) -> None:
        status = self.api.status()
        raw = str(status.get("netbox-version", "0.0"))
        match = re.match(r"(\d+)\.(\d+)", raw)
        self.version = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
        log.info(
            "connected to NetBox %s at %s%s",
            raw,
            self.settings.url,
            " (DRY RUN — no writes)" if self.dry_run else "",
        )

    @property
    def uses_mac_objects(self) -> bool:
        """NetBox >= 4.2 models MAC addresses as separate objects."""
        return self.version >= (4, 2)

    def write(self, description: str, action: Callable[[], Any]) -> Any:
        """Single funnel for every mutating call, so DRY_RUN is airtight."""
        if self.dry_run:
            log.info("[dry-run] %s", description)
            return None
        try:
            return action()
        except pynetbox.RequestError as exc:
            log.error("%s failed: %s", description, _short_error(exc))
            return None
        except requests.RequestException as exc:
            log.error("%s failed: %s", description, exc)
            return None

    # ── bootstrap ───────────────────────────────────────────────────────────
    def bootstrap(self) -> None:
        """Create everything the sync depends on. Safe to call every cycle;
        the work is done once per process."""
        if self._bootstrapped:
            return

        self._ensure_custom_fields()
        for spec in _TAGS:
            tag = self._ensure_tag(spec)
            if tag is not None:
                self.tags[spec["name"]] = tag

        self.site = self._ensure(
            self.api.dcim.sites,
            {"slug": slugify(self.settings.site_name)},
            {
                "name": self.settings.site_name,
                "slug": slugify(self.settings.site_name),
                "status": "active",
                "description": f"Managed by scanspot "
                f"({self.settings.client_name})",
            },
            label=f"site '{self.settings.site_name}'",
        )

        self.role_endpoint = self._ensure_device_role(
            ROLE_ENDPOINT, "9e9e9e", "Endpoint discovered by the network scanner"
        )
        self.role_switch = self._ensure_device_role(
            ROLE_SWITCH, "2196f3", "Access/distribution switch polled via SNMP"
        )
        self.role_firewall = self._ensure_device_role(
            ROLE_FIREWALL, "f44336", "FortiGate firewall polled via REST API"
        )

        manufacturer = self._ensure(
            self.api.dcim.manufacturers,
            {"slug": slugify(MANUFACTURER_GENERIC)},
            {"name": MANUFACTURER_GENERIC, "slug": slugify(MANUFACTURER_GENERIC)},
            label="manufacturer 'Generic'",
        )
        if manufacturer is not None:
            self.type_endpoint = self._ensure_device_type(TYPE_ENDPOINT, manufacturer)
            self.type_switch = self._ensure_device_type(TYPE_SWITCH, manufacturer)
            self.type_firewall = self._ensure_device_type(TYPE_FIREWALL, manufacturer)

        self.dhcp_pool_role = self._ensure(
            self.api.ipam.roles,
            {"slug": slugify(IPRANGE_ROLE_DHCP)},
            {
                "name": IPRANGE_ROLE_DHCP,
                "slug": slugify(IPRANGE_ROLE_DHCP),
                "description": "DHCP range configured on a FortiGate",
            },
            label="IPAM role 'DHCP Pool'",
        )

        self._bootstrapped = True

    def _ensure(self, endpoint, lookup: dict, payload: dict, label: str):
        cache_key = f"{endpoint.name}:{sorted(lookup.items())}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        existing = endpoint.get(**lookup)
        if existing is None:
            existing = self.write(f"create {label}", lambda: endpoint.create(**payload))
            if existing is not None:
                log.info("created %s", label)
        self._cache[cache_key] = existing
        return existing

    def _ensure_device_role(self, name: str, color: str, description: str):
        return self._ensure(
            self.api.dcim.device_roles,
            {"slug": slugify(name)},
            {
                "name": name,
                "slug": slugify(name),
                "color": color,
                "description": description,
            },
            label=f"device role '{name}'",
        )

    def _ensure_device_type(self, model: str, manufacturer):
        return self._ensure(
            self.api.dcim.device_types,
            {"slug": slugify(model)},
            {
                "model": model,
                "slug": slugify(model),
                "manufacturer": manufacturer.id,
                "u_height": 0,
            },
            label=f"device type '{model}'",
        )

    def _ensure_tag(self, spec: dict):
        return self._ensure(
            self.api.extras.tags,
            {"slug": slugify(spec["name"])},
            {
                "name": spec["name"],
                "slug": slugify(spec["name"]),
                "color": spec["color"],
                "description": spec["description"],
            },
            label=f"tag '{spec['name']}'",
        )

    def _ensure_custom_fields(self) -> None:
        for spec in _CUSTOM_FIELDS:
            if self.api.extras.custom_fields.get(name=spec["name"]) is not None:
                continue
            payload = {
                "name": spec["name"],
                "label": spec["label"],
                "type": spec["type"],
                "description": spec["description"],
                "group_name": "Network Scanner",
                "required": False,
            }

            # A select field needs a choice set; if this NetBox does not expose
            # the endpoint, degrade to free text rather than skipping the field.
            if spec["type"] == "select":
                choice_set = self._ensure_choice_set(spec["name"], spec["choices"])
                if choice_set is None:
                    payload["type"] = "text"
                    log.warning(
                        "custom field '%s' created as free text: this NetBox "
                        "rejected the choice set",
                        spec["name"],
                    )
                else:
                    payload["choice_set"] = choice_set.id

            created = self._create_custom_field(
                payload, spec.get("object_types", _OBJECT_TYPES)
            )
            if created is not None:
                log.info("created custom field '%s'", spec["name"])

    def _ensure_choice_set(self, name: str, choices: list[list[str]]):
        endpoint = getattr(self.api.extras, "custom_field_choice_sets", None)
        if endpoint is None:
            return None
        try:
            existing = endpoint.get(name=name)
        except (pynetbox.RequestError, requests.RequestException):
            return None
        if existing is not None:
            return existing
        return self.write(
            f"create choice set '{name}'",
            lambda: endpoint.create(name=name, extra_choices=choices),
        )

    def _create_custom_field(self, payload: dict, object_types: list[str]):
        """`content_types` was renamed to `object_types` during the NetBox 4.x
        cycle. Try the modern name, fall back to the legacy one, and only
        complain if both are rejected."""
        if self.dry_run:
            log.info("[dry-run] create custom field '%s'", payload["name"])
            return None

        last_error = None
        for key in ("object_types", "content_types"):
            try:
                return self.api.extras.custom_fields.create(
                    **payload, **{key: list(object_types)}
                )
            except pynetbox.RequestError as exc:
                last_error = exc
            except requests.RequestException as exc:
                log.error("could not create custom field '%s': %s", payload["name"], exc)
                return None

        log.error(
            "could not create custom field '%s': %s",
            payload["name"],
            _short_error(last_error),
        )
        return None

    # ── discovered hardware ─────────────────────────────────────────────────
    def ensure_manufacturer(self, name: str):
        """Manufacturer discovered via sysObjectID, created on demand."""
        clean = (name or "").strip()
        if not clean:
            return None
        return self._ensure(
            self.api.dcim.manufacturers,
            {"slug": slugify(clean)},
            {"name": clean[:100], "slug": slugify(clean)},
            label=f"manufacturer '{clean}'",
        )

    def ensure_device_type(self, model: str, manufacturer):
        """DeviceType for a discovered model.

        u_height 0 keeps the type usable without anybody having to rack it: the
        point here is inventory truth, not elevation drawings.
        """
        clean = (model or "").strip()
        if not clean or manufacturer is None:
            return None
        # Slugs are global in NetBox, so a bare "2960" from two vendors would
        # collide. Qualifying with the manufacturer keeps them apart.
        slug = slugify(f"{manufacturer.name}-{clean}")
        return self._ensure(
            self.api.dcim.device_types,
            {"slug": slug},
            {
                "model": clean[:100],
                "slug": slug,
                "manufacturer": manufacturer.id,
                "u_height": 0,
            },
            label=f"device type '{manufacturer.name} {clean}'",
        )

    def ensure_platform(self, name: str, manufacturer=None):
        """Platform = the OS the device runs, e.g. 'Cisco IOS 15.2(7)E3'."""
        clean = (name or "").strip()
        if not clean:
            return None
        payload = {"name": clean[:100], "slug": slugify(clean)}
        if manufacturer is not None:
            payload["manufacturer"] = manufacturer.id
        return self._ensure(
            self.api.dcim.platforms,
            {"slug": slugify(clean)},
            payload,
            label=f"platform '{clean}'",
        )

    def create_device(self, **payload):
        """Create a Device, tolerating the `device_role` -> `role` rename that
        landed in NetBox 3.6, and a late name collision from a concurrent run."""
        if self.dry_run:
            log.info("[dry-run] create device '%s'", payload.get("name"))
            return None

        role = payload.pop("role")
        device_type = payload.pop("device_type")
        base = {**payload, "device_type": device_type.id, "site": self.site.id}

        errors: list[str] = []
        for role_key in ("role", "device_role"):
            try:
                return self.api.dcim.devices.create(**base, **{role_key: role.id})
            except pynetbox.RequestError as exc:
                errors.append(f"{role_key}: {_short_error(exc)}")
                message = str(getattr(exc, "error", "") or exc).lower()
                # NetBox has worded this collision differently across releases:
                # "already exists" (<=4.0) and "name must be unique per site"
                # (4.1+). Match both, or every recycled hostname is lost.
                collision = "already exists" in message or "must be unique" in message
                if collision and base.get("name"):
                    base["name"] = f"{base['name']}-{uuid.uuid4().hex[:4]}"[:64]
                    log.warning("device name collision, retrying as '%s'", base["name"])
                    try:
                        return self.api.dcim.devices.create(
                            **base, **{role_key: role.id}
                        )
                    except pynetbox.RequestError as retry_exc:
                        errors.append(f"{role_key} retry: {_short_error(retry_exc)}")

        # Both spellings are reported: on a modern NetBox the `device_role`
        # attempt always fails with "role is required", which would otherwise
        # hide the real reason the first attempt was rejected.
        log.error("create device '%s' failed — %s", base.get("name"), " | ".join(errors))
        return None

    def is_generic_type(self, device) -> bool:
        """True when the device still carries one of the placeholder types.

        Used to decide whether an SNMP-discovered model may overwrite what is
        on the device: a type a human picked is never clobbered.
        """
        device_type = getattr(device, "device_type", None)
        model = str(getattr(device_type, "model", "") or "")
        return model in (TYPE_ENDPOINT, TYPE_SWITCH, TYPE_FIREWALL)

    # ── tag helpers ─────────────────────────────────────────────────────────
    def tag_ids(self, *names: str) -> list[int]:
        return [self.tags[name].id for name in names if name in self.tags]

    @staticmethod
    def has_tag(obj, name: str) -> bool:
        for tag in getattr(obj, "tags", None) or []:
            candidate = getattr(tag, "slug", None) or getattr(tag, "name", None) or str(tag)
            if str(candidate).lower() in (name.lower(), slugify(name)):
                return True
        return False

    # ── MAC anchor (version tolerant) ───────────────────────────────────────
    def find_interface_by_mac(self, mac: str):
        """Return the dcim.Interface currently owning `mac`, or None.

        This is what makes the scanner idempotent: a device that gets a new IP
        is found through its MAC and updated instead of being duplicated.
        """
        if self.uses_mac_objects:
            record = self._first(self.api.dcim.mac_addresses.filter(mac_address=mac))
            if record is None:
                return None
            object_type = str(getattr(record, "assigned_object_type", "") or "")
            object_id = getattr(record, "assigned_object_id", None)
            if object_type != "dcim.interface" or not object_id:
                return None
            return self.api.dcim.interfaces.get(object_id)

        return self._first(self.api.dcim.interfaces.filter(mac_address=mac))

    def assign_mac(self, interface, mac: str) -> None:
        """Bind `mac` to `interface`, whichever data model this NetBox uses."""
        if not self.uses_mac_objects:
            if str(getattr(interface, "mac_address", "") or "").upper() != mac:
                self.write(
                    f"set MAC {mac} on {interface}",
                    lambda: save_record(interface, mac_address=mac),
                )
            return

        record = self._first(self.api.dcim.mac_addresses.filter(mac_address=mac))
        if record is None:
            record = self.write(
                f"create MAC object {mac}",
                lambda: self.api.dcim.mac_addresses.create(
                    mac_address=mac,
                    assigned_object_type="dcim.interface",
                    assigned_object_id=interface.id,
                ),
            )
            if record is None:
                return
        elif getattr(record, "assigned_object_id", None) != interface.id:
            self.write(
                f"reassign MAC {mac} to {interface}",
                lambda: save_record(
                    record,
                    assigned_object_type="dcim.interface",
                    assigned_object_id=interface.id,
                ),
            )

        current = getattr(interface, "primary_mac_address", None)
        if getattr(current, "id", None) != record.id:
            self.write(
                f"set primary MAC {mac} on {interface}",
                lambda: save_record(interface, primary_mac_address=record.id),
            )

    # ── misc ────────────────────────────────────────────────────────────────
    @staticmethod
    def _first(record_set):
        for item in record_set:
            return item
        return None


# ─────────────────────────────────────────────────────────────── utilities ──
def save_record(record, **fields) -> Any:
    """Set the given fields on a pynetbox record and PATCH it."""
    for key, value in fields.items():
        setattr(record, key, value)
    record.save()
    return record


def _short_error(exc) -> str:
    if exc is None:
        return "unknown error"
    text = str(getattr(exc, "error", "") or exc)
    return text.replace("\n", " ")[:400]
