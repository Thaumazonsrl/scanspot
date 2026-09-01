"""Where the scanner gets its device list — from 2.0, its own store.

Until 1.x this read NetBox directly: a device tagged `scan-target` with four
custom fields. Elegant while NetBox was the only backend, and impossible
otherwise — phpIPAM has no DCIM model, so there is nowhere to put a target.

The store is now authoritative. NetBox can still *offer* targets, through the
one-shot import in `backends/netbox/import_targets.py`, but there is no
continuous two-way sync: deletion would be ambiguous in both directions.

This module is backend-neutral on purpose. It converts stored targets into the
poller configurations the collectors expect, and nothing here knows what a
NetBox is.
"""

from __future__ import annotations

import logging

from .config import (
    AppConfig,
    FortiGateConfig,
    SwitchConfig,
    env_str,
    env_var_reference,
    expand_placeholders,
)
from .store.models import SECRET_FIELDS, Site
from .store.repository import Repository

log = logging.getLogger("targets")

METHOD_SNMP = "snmp"
METHOD_FORTIOS = "fortios"

# Built-in profiles, assembled from .env so a minimal deployment needs no YAML.
# Recorded as references, never as copies: the secret stays in the environment.
_BUILTIN: dict[str, dict] = {
    "default": {
        "kind": "snmp",
        "secret_refs": {
            "community": "SNMP_COMMUNITY",
            "v3_auth_password": "SNMP_V3_AUTH_PASSWORD",
            "v3_priv_password": "SNMP_V3_PRIV_PASSWORD",
        },
        "param_env": {
            "snmp_version": "SNMP_DEFAULT_VERSION",
            "v3_username": "SNMP_V3_USERNAME",
            "v3_security_level": "SNMP_V3_SECURITY_LEVEL",
            "v3_auth_protocol": "SNMP_V3_AUTH_PROTOCOL",
            "v3_priv_protocol": "SNMP_V3_PRIV_PROTOCOL",
        },
    },
    "fortigate-default": {
        "kind": "fortios",
        "secret_refs": {"api_token": "FORTIGATE_API_TOKEN"},
        "param_env": {
            "port": "FORTIGATE_PORT",
            "vdom": "FORTIGATE_VDOM",
            "verify_ssl": "FORTIGATE_VERIFY_SSL",
            "timeout": "FORTIGATE_TIMEOUT",
        },
    },
}


# ── credentials ─────────────────────────────────────────────────────────────
def sync_credentials(repo: Repository, config: AppConfig, site: Site | None = None) -> int:
    """Mirror the configured credential profiles into the store.

    Profiles defined in inventory.yml as `${VAR}` become references to that
    variable. A literal secret written into the YAML is *not* copied into the
    database — it stays where the operator put it and the profile records no
    reference, which surfaces as an authentication failure naming the device
    rather than as a silent duplication of the secret.
    """
    from .config import load_raw_credentials

    synced = 0

    for name, spec in _BUILTIN.items():
        params = {
            key: env_str(variable)
            for key, variable in spec["param_env"].items()
            if env_str(variable)
        }
        repo.upsert_credential(
            name, spec["kind"], params=params, secret_refs=dict(spec["secret_refs"])
        )
        synced += 1

    for name, raw in load_raw_credentials().items():
        kind = str(raw.get("type") or "snmp").strip().lower()
        if kind not in SECRET_FIELDS:
            log.warning("credential profile '%s' has unknown type '%s' — skipped", name, kind)
            continue

        secret_refs: dict[str, str] = {}
        params: dict = {}
        for key, value in raw.items():
            if key == "type":
                continue
            if key in SECRET_FIELDS[kind]:
                variable = env_var_reference(value)
                if variable:
                    secret_refs[key] = variable
                elif value not in (None, ""):
                    log.warning(
                        "credential profile '%s' holds a literal value for '%s' in "
                        "inventory.yml; it is not copied into the store — use "
                        "${ENV_VAR} instead",
                        name,
                        key,
                    )
                continue
            # Ordinary settings are resolved; only secrets stay as references.
            # Storing "${SNMP_DEFAULT_VERSION:-2c}" verbatim would leave the
            # version matching neither "1" nor "2c", and the SNMP poller would
            # quietly attempt v3 against a v2c switch.
            params[key] = expand_placeholders(value)

        repo.upsert_credential(name, kind, params=params, secret_refs=secret_refs)
        synced += 1

    log.debug("credential profiles in store: %d", synced)
    return synced


def _default_profile(method: str) -> str:
    return "fortigate-default" if method == METHOD_FORTIOS else "default"


# ── seed ────────────────────────────────────────────────────────────────────
def apply_seed(repo: Repository, config: AppConfig, site: Site) -> int:
    """Create the inventory.yml seed targets. Only ever on an empty store.

    In 1.x this created NetBox devices and remembered itself in
    state/seeded.json. Targets carrying `source="seed"` now serve the same
    purpose, and the operator owns them from that moment on.
    """
    if not config.seeds:
        return 0

    created = 0
    for entry in config.seeds:
        profile = repo.credential(entry.credential or _default_profile(entry.method), site)
        _, was_created = repo.upsert_target(
            site,
            name=entry.name,
            address=entry.host,
            method=entry.method,
            credential=profile,
            vendor_override=entry.vendor,
            source="seed",
        )
        if was_created:
            created += 1
            log.info("seeded target '%s' (%s via %s)", entry.name, entry.host, entry.method)
    return created


# ── loading ─────────────────────────────────────────────────────────────────
def load_targets(
    repo: Repository, config: AppConfig, site: Site | None = None
) -> tuple[list[FortiGateConfig], list[SwitchConfig]]:
    """Turn stored targets into poller configurations."""
    fortigates: list[FortiGateConfig] = []
    switches: list[SwitchConfig] = []

    for target in repo.targets(site, enabled_only=True):
        settings = repo.credential_settings(target.credential)
        if not settings:
            log.error(
                "target '%s' has no usable credential profile — skipped", target.name
            )
            continue

        raw = {**settings, "name": target.name, "host": target.address}
        raw.pop("type", None)

        if target.method == METHOD_FORTIOS:
            if not raw.get("api_token"):
                log.error(
                    "FortiGate '%s' has no api_token in its credential profile "
                    "— skipped",
                    target.name,
                )
                continue
            fortigates.append(FortiGateConfig.from_dict(raw))
        else:
            if target.vendor_override:
                raw["vendor"] = target.vendor_override
            switches.append(SwitchConfig.from_dict(raw, config.scanner))

    log.info(
        "scan targets from the store: %d firewall(s), %d switch(es)",
        len(fortigates),
        len(switches),
    )
    return fortigates, switches
