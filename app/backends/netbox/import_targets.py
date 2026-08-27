"""One-shot import of 1.x scan targets out of NetBox.

Until 1.x, NetBox *was* the target list: a device tagged `scan-target` carrying
four custom fields. From 2.0 the store owns targets, so an existing deployment
needs its list carried across exactly once.

This is an explicit import, not a background reconciliation. Two-way sync was
considered and rejected: a target present in the store but absent from NetBox
was either deleted there or created here, and nothing in the data distinguishes
the two. Re-running the import is safe — `external_ref` holds the NetBox device
id, so a device that was renamed or readdressed is updated rather than
duplicated.
"""

from __future__ import annotations

import logging

from ...config import AppConfig
from ...store.models import Site
from ...store.repository import Repository
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

log = logging.getLogger("import")


def import_targets(
    client: NetBoxClient, repo: Repository, site: Site, config: AppConfig
) -> int:
    """Import every device tagged `scan-target`. Returns how many were created.

    Runs every cycle, so tagging a device in NetBox still puts it under scan
    without a restart — the 1.x workflow is preserved. Ownership is explicit:

      * `source="imported"` targets belong to NetBox. They are refreshed from
        it, and disabled when the tag goes away.
      * targets created any other way are never touched here.
    """
    try:
        devices = list(client.api.dcim.devices.filter(tag=slugify(TAG_SCAN_TARGET)))
    except Exception as exc:
        # A NetBox outage must not look like "every target was untagged".
        log.error("could not read scan targets from NetBox: %s", exc)
        return 0

    created = 0
    seen: list[int] = []
    for device in devices:
        if not _is_scannable(device):
            continue

        custom = dict(getattr(device, "custom_fields", None) or {})
        address = _address_for(device, custom)
        if not address:
            log.warning(
                "device '%s' is tagged '%s' but has neither a Scan address nor a "
                "primary IP — not imported",
                device.name,
                TAG_SCAN_TARGET,
            )
            continue

        method = _method_for(device, custom)
        profile_name = _text(custom.get(CF_CREDENTIAL)) or (
            "fortigate-default" if method == METHOD_FORTIOS else "default"
        )
        profile = repo.credential(profile_name, site)
        if profile is None:
            log.error(
                "device '%s' points at the credential profile '%s', which is not "
                "defined — not imported",
                device.name,
                profile_name,
            )
            continue

        target, was_created = repo.upsert_target(
            site,
            name=str(device.name),
            address=address,
            method=method,
            credential=profile,
            vendor_override=_text(custom.get(CF_VENDOR)).lower(),
            source="imported",
            external_ref=str(device.id),
        )
        seen.append(target.id)
        if was_created:
            created += 1

    if created:
        log.info("imported %d scan target(s) from NetBox", created)

    # Only reached when the fetch succeeded, so an untagged device is a genuine
    # removal rather than a connectivity problem.
    repo.disable_missing(site, seen_ids=seen)
    return created


def _is_scannable(device) -> bool:
    # pynetbox renders a choice as its label ("Active"), so compare the value.
    status = getattr(device, "status", None)
    status = str(getattr(status, "value", status) or "").lower()
    if status in ("", "active", "staged", "none"):
        return True
    log.info("skipping '%s': its NetBox status is '%s'", device.name, status)
    return False


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
            "device '%s' has an unrecognised scan method '%s' — falling back to "
            "its role",
            device.name,
            declared,
        )
    # NetBox 4.x renamed Device.device_role to Device.role.
    role = getattr(device, "role", None) or getattr(device, "device_role", None)
    slug = str(getattr(role, "slug", "") or "")
    return METHOD_FORTIOS if "firewall" in slug else METHOD_SNMP


def _text(value) -> str:
    """Custom-field values arrive as None, str, or a {value,label} dict."""
    if value is None:
        return ""
    if isinstance(value, dict):
        value = value.get("value", "")
    return str(value).strip()
